from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from uuid import uuid4

import pytest

import test_receipts as receipt_cases
import test_durable_execution as execution_cases
import test_receipt_retention as retention_cases
import test_execution_recovery as recovery_cases
import test_execution_replay as replay_cases
import test_dispatch_outcomes as outcome_cases
from test_metadata_storage import repositories, stores
from encrypted_witness_helpers import witness_factory
from universal_connection_service.encrypted_receipt_store import EncryptedStateStore
from universal_connection_service.metadata_crypto import MetadataCryptoError
from universal_connection_service.persistence import StateStore
from universal_connection_service.receipts import ReceiptError


@pytest.fixture
def encrypted_stores(repositories, tmp_path):
    opened = []
    with ExitStack() as stack:
        witnesses = None
        def factory():
            nonlocal witnesses
            store = EncryptedStateStore(repositories())
            opened.append(store)
            if witnesses is None:
                witnesses = stack.enter_context(witness_factory(store, tmp_path))
            store._test_witness = witnesses()
            return store
        try:
            yield factory
        finally:
            for store in opened:
                store.close()


@pytest.mark.parametrize("case", [
    receipt_cases.test_reopen_returns_original_receipt_and_same_provider_key,
    receipt_cases.test_concurrent_instances_have_one_dispatch_winner,
    receipt_cases.test_unresolved_receipt_cannot_be_dispatched_again,
    receipt_cases.test_completion_outbox_and_acknowledgement_survive_restart,
    receipt_cases.test_tenant_isolation_and_outbox_ack_scope,
    execution_cases.test_status_only_never_prepares_or_dispatches_even_with_valid_approval,
    execution_cases.test_restart_retry_returns_encrypted_result_without_consuming_again,
    execution_cases.test_changed_input_conflicts_even_after_success,
    execution_cases.test_exception_after_effect_is_unknown_and_never_dispatched_again,
    execution_cases.test_result_access_rechecks_policy_and_actor_before_decryption,
    execution_cases.test_wrong_key_cannot_read_result_or_trigger_new_execution,
    execution_cases.test_missing_operation_id_and_untrusted_credential_fail_closed,
    execution_cases.test_reapproval_of_prepared_operation_is_safe_after_revocation,
    execution_cases.test_key_rotation_reads_old_receipts_and_uses_new_key,
    execution_cases.test_registered_effect_capability_cannot_be_mislabeled_read,
    execution_cases.test_two_service_instances_share_one_approval_and_effect,
    recovery_cases.test_lookup_recovers_after_restart_with_original_key_and_single_effect,
    recovery_cases.test_lookup_rejects_provider_account_mismatch,
    recovery_cases.test_legacy_receipt_cannot_gain_recovery_by_configuration_change,
    recovery_cases.test_reconciliation_http_requires_scope_and_organization,
    recovery_cases.test_final_no_effect_requires_prevention_of_late_execution,
    outcome_cases.test_pending_survives_restart_and_only_lookup_can_advance,
    outcome_cases.test_structured_contract_rejects_unqualified_success,
], ids=lambda case: case.__name__)
def test_existing_receipt_and_execution_contracts_with_encryption(encrypted_stores, case):
    case(encrypted_stores)


@pytest.mark.parametrize("case", [
    execution_cases.test_completion_storage_failure_leaves_unknown_and_blocks_retry,
    execution_cases.test_completion_ack_lost_returns_unknown_then_recovers_stored_success,
    receipt_cases.test_lost_dispatch_commit_ack_does_not_allow_second_dispatch,
    retention_cases.test_expired_payload_deleted_but_restart_cannot_repeat_effect,
    retention_cases.test_retention_requires_decryption_key_and_preserves_unexpired_results,
    retention_cases.test_purge_is_scoped_atomic_and_idempotent_between_workers,
], ids=lambda case: case.__name__)
def test_failure_and_retention_contracts_with_encryption(encrypted_stores, monkeypatch, case):
    case(encrypted_stores, monkeypatch)


@pytest.mark.parametrize("case", [
    replay_cases.test_restart_replay_uses_same_key_deadline_and_consumed_approval,
    replay_cases.test_parallel_replays_cannot_create_a_second_effect,
    replay_cases.test_provider_deadline_cannot_outlive_original_approval,
    replay_cases.test_replay_endpoint_needs_distinct_scope_and_never_starts_new_operation,
], ids=lambda case: case.__name__)
def test_replay_contracts_with_encryption(encrypted_stores, tmp_path, case):
    case(encrypted_stores, tmp_path)


@pytest.mark.parametrize("invalid", ["revoked", "expired", "different", "missing"])
def test_encrypted_replay_requires_original_authorization(encrypted_stores, tmp_path, monkeypatch, invalid):
    replay_cases.test_replay_requires_original_still_valid_approval(encrypted_stores, tmp_path, monkeypatch, invalid)


def test_dispatch_rolls_back_encrypted_approval_if_attempt_write_fails(encrypted_stores, monkeypatch):
    store = encrypted_stores()
    req = execution_cases.request()
    raw = execution_cases.approve(store, req, raw=req.actor.organization_id)
    svc, provider = execution_cases.build_service(store, req)
    def fail(*args):
        raise OSError("synthetic unavailable disk")
    with monkeypatch.context() as patch:
        patch.setattr(store, "_append_execution_attempt", fail)
        result = execution_cases.execute(svc, req, raw)
    assert provider.calls == 0 and result.status == "failed"
    receipt = store.get_receipt(req.actor.organization_id, req.operation_id)
    assert receipt.state == "prepared" and receipt.attempt_count == 0
    from universal_connection_service.approvals import approval_ref_hash
    assert store.get_approval(approval_ref_hash(raw)).consumed_at is None
    assert execution_cases.execute(svc, req, raw).status == "success"
    assert provider.calls == 1


def test_completion_and_audit_delivery_each_remain_atomic(encrypted_stores, monkeypatch):
    store = encrypted_stores()
    intent = receipt_cases.intent()
    receipt = store.prepare_receipt(intent)
    running = store.begin_dispatch(intent.organization_id, intent.operation_id, receipt.version, "attempt")
    insert = store.repository.insert
    def fail_outbox(conn, domain, *args):
        if domain == "pending-outbox":
            raise OSError("synthetic unavailable disk")
        return insert(conn, domain, *args)
    with monkeypatch.context() as patch:
        patch.setattr(store.repository, "insert", fail_outbox)
        with pytest.raises(OSError):
            store.complete_receipt(intent.organization_id, intent.operation_id, running.version, "succeeded", result_ciphertext="synthetic-encrypted-result")
    assert store.get_receipt(intent.organization_id, intent.operation_id) == running
    assert store.get_receipt_result(intent.organization_id, intent.operation_id) is None
    assert store.pending_receipt_audit(intent.organization_id) == []
    final = store.complete_receipt(intent.organization_id, intent.operation_id, running.version, "succeeded", result_ciphertext="synthetic-encrypted-result")
    acknowledge = store._acknowledge_audit
    def fail_after_ack(*args):
        acknowledge(*args)
        raise OSError("lost before commit")
    with monkeypatch.context() as patch:
        patch.setattr(store, "_acknowledge_audit", fail_after_ack)
        with pytest.raises(OSError):
            store.deliver_receipt_audit(intent.organization_id)
    assert store.list_audit(intent.organization_id) == []
    assert len(store.pending_receipt_audit(intent.organization_id)) == 1
    assert store.deliver_receipt_audit(intent.organization_id) == 1
    assert store.deliver_receipt_audit(intent.organization_id) == 0
    assert store.list_audit(intent.organization_id)[0].audit_id == final.audit_id


def test_encrypted_notices_quarantine_metrics_and_plaintext_guard(encrypted_stores):
    store, second = encrypted_stores(), encrypted_stores()
    assert isinstance(store, StateStore)
    intent = receipt_cases.intent(organizationId="private-tenant-" + uuid4().hex)
    receipt = store.prepare_receipt(intent)
    running = store.begin_dispatch(intent.organization_id, intent.operation_id, receipt.version, "private-request")
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda s: s.record_execution_notice(intent.organization_id, receipt.receipt_id, "OUTCOME_UNKNOWN"), [store, second]))
    notices = second.execution_notices(intent.organization_id)
    assert len(notices) == 1 and notices[0]["observations"] == 2
    assert second.execution_notices("other-org") == []
    assert second.execution_metrics(intent.organization_id)["unknownReceipts"] == 1
    final = store.complete_receipt(intent.organization_id, intent.operation_id, running.version, "succeeded")
    assert second.execution_metrics(intent.organization_id)["outboxBacklog"] == 1
    conflicted = second.quarantine_conflicting_outcome(intent.organization_id, intent.operation_id, "failed_no_effect")
    assert conflicted.state == "succeeded" and conflicted.outcome_conflicted
    assert second.get_receipt(intent.organization_id, intent.operation_id).audit_id == final.audit_id
    assert {row["code"] for row in store.execution_notices(intent.organization_id)} == {"OUTCOME_UNKNOWN", "EXECUTION_OUTCOME_CONFLICT"}
    with store.repository.transaction() as conn:
        rows = store.repository.store._receipt_query(conn, "SELECT * FROM metadata_document").fetchall()
        assert intent.organization_id not in repr([dict(row) for row in rows])
        with pytest.raises(MetadataCryptoError, match="PLAINTEXT_RECEIPT_ACCESS_FORBIDDEN"):
            store._receipt_query(conn, "SELECT * FROM execution_receipt")
    assert store.repository.store.get_receipt(intent.organization_id, intent.operation_id) is None


def test_encrypted_payload_purge_does_not_remove_identity_or_audit(encrypted_stores):
    store = encrypted_stores()
    intent = receipt_cases.intent()
    prepared = store.prepare_receipt(intent)
    running = store.begin_dispatch(intent.organization_id, intent.operation_id, prepared.version, "request")
    final = store.complete_receipt(intent.organization_id, intent.operation_id, running.version, "succeeded", result_ciphertext="opaque")
    assert store.purge_receipt_result(intent.organization_id, intent.operation_id, final.version, "opaque")
    assert store.get_receipt_result(intent.organization_id, intent.operation_id) is None
    assert store.prepare_receipt(intent).state == "succeeded"
    assert len(store.pending_receipt_audit(intent.organization_id)) == 1
    with pytest.raises(ReceiptError, match="RECEIPT_STATE_CONFLICT"):
        store.begin_dispatch(intent.organization_id, intent.operation_id, final.version + 1, "retry")
