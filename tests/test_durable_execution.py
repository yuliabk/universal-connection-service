import asyncio
import sqlite3
import subprocess
import sys
from datetime import timedelta
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import pytest

from test_receipts import stores  # same real SQLite/PostgreSQL contract fixture
from universal_connection_service.approvals import ApprovalRecord, approval_ref_hash
from universal_connection_service.contracts import ConnectionRequest, ConnectorManifest, ConnectorResult, ExecutionContext
from universal_connection_service.execution import DurableExecutor, ExecutionTarget, ResultCipher, executor_from_env
from universal_connection_service.policy import DefaultPolicyEngine
from universal_connection_service.receipts import execution_binding, utc_now
from universal_connection_service.registry import ConnectorRegistry, Registration
from universal_connection_service.service import ConnectionService


class WriteConnector:
    def __init__(self, fail=False):
        self.calls = 0
        self.fail = fail

    def manifest(self):
        return ConnectorManifest(connectorId="write-1", serviceId="records", name="Synthetic write",
                                 version="1.0.0", strategy="api", capabilities=("records.write",))

    async def execute(self, capability, input, ctx):
        self.calls += 1
        if self.fail:
            raise TimeoutError("untrusted exception with synthetic-secret")
        return ConnectorResult(status="success", data={"value": input["value"]})


def request(organization=None):
    return ConnectionRequest(requestId="request-1", operationId="operation-1",
        actor={"organizationId": organization or "org-" + uuid4().hex, "userId": "user", "agentId": "agent"},
        service={"id": "records", "name": "Records"}, capability="records.write", operation="update",
        input={"value": "synthetic-sensitive-result"})


def make_target(req):
    return ExecutionTarget(organizationId=req.actor.organization_id, serviceId="records", capability="records.write",
        providerAccountId="account-1", connectorId="write-1", connectorVersion="1.0.0", operations=("update",),
        userIds=("user",), agentIds=("agent",), allowNoCredentials=True, successIsFinal=True, resultRetentionSeconds=3600)


def build_service(store, req, connector=None, cipher=None, target=None, policy=None):
    connector = connector or WriteConnector()
    registry = ConnectorRegistry()
    registry.register(Registration(connector=connector, status="trusted", organization_id=req.actor.organization_id))
    executor = DurableExecutor(store, cipher or ResultCipher({"test": b"x" * 32}, "test"), (target or make_target(req),))
    return ConnectionService(registry, policy_engine=policy, durable_executor=executor), connector


def approve(store, req, raw="synthetic-approval", **updates):
    values = dict(approvalRefHash=approval_ref_hash(raw), requestId=req.request_id,
        organizationId=req.actor.organization_id, userId=req.actor.user_id, agentId=req.actor.agent_id,
        serviceId="records", capability=req.capability, operation=req.operation, operationId=req.operation_id,
        bindingDigest=execution_binding(req, "account-1"), expiresAt=utc_now() + timedelta(minutes=5))
    values.update(updates)
    store.put_approval(ApprovalRecord(**values))
    return raw


def execute(service, req, approval="synthetic-approval", **ctx_values):
    return asyncio.run(service.execute(req, ExecutionContext(requestId=req.request_id,
        organizationId=req.actor.organization_id, userId=req.actor.user_id, approvalId=approval, **ctx_values)))


def test_restart_retry_returns_encrypted_result_without_consuming_again(stores):
    store = stores()
    req = request()
    approve(store, req)
    svc, connector = build_service(store, req)
    first = execute(svc, req)
    assert first.status == "success"
    assert first.execution_state == "succeeded"
    assert first.data == {"value": "synthetic-sensitive-result"}
    assert connector.calls == 1
    reopened = stores()
    second_service, second_connector = build_service(reopened, req)
    second = execute(second_service, req.model_copy(update={"request_id": "retry-after-restart"}), approval=None)
    assert second.status == "success"
    assert second.receipt_id == first.receipt_id
    assert second.audit_id == first.audit_id
    assert second.data == first.data
    assert second_connector.calls == 0
    receipt = reopened.get_receipt(req.actor.organization_id, req.operation_id)
    envelope = reopened.get_receipt_result(req.actor.organization_id, req.operation_id)
    assert "synthetic-sensitive-result" not in envelope
    assert "synthetic-sensitive-result" not in receipt.model_dump_json()
    events = reopened.pending_receipt_audit(req.actor.organization_id)
    assert len(events) == 1
    assert "synthetic-sensitive-result" not in events[0].model_dump_json()
    assert "synthetic-approval" not in receipt.model_dump_json()


@pytest.mark.parametrize("updates,code", [
    ({"operationId": "other"}, "APPROVAL_SCOPE_MISMATCH"),
    ({"bindingDigest": "f" * 64}, "APPROVAL_SCOPE_MISMATCH"),
    ({"operationId": None, "bindingDigest": None}, "APPROVAL_SCOPE_MISMATCH"),
    ({"revokedAt": utc_now()}, "APPROVAL_REVOKED"),
    ({"expiresAt": utc_now() - timedelta(seconds=5)}, "APPROVAL_EXPIRED"),
])
def test_invalid_bound_approval_blocks_dispatch(stores, updates, code):
    store = stores()
    req = request()
    approve(store, req, raw="approval-" + req.actor.organization_id, **updates)
    svc, connector = build_service(store, req)
    result = execute(svc, req, approval="approval-" + req.actor.organization_id)
    assert result.error.code == code
    assert connector.calls == 0
    assert store.get_receipt(req.actor.organization_id, req.operation_id).state == "prepared"


def test_changed_input_conflicts_even_after_success(stores):
    store = stores()
    req = request()
    raw = approve(store, req, raw=req.actor.organization_id)
    svc, connector = build_service(store, req)
    assert execute(svc, req, raw).status == "success"
    changed = req.model_copy(update={"input": {"value": "changed"}})
    assert execute(svc, changed, raw).error.code == "IDEMPOTENCY_CONFLICT"
    assert connector.calls == 1


def test_exception_after_effect_is_unknown_and_never_dispatched_again(stores):
    store = stores()
    req = request()
    raw = approve(store, req, raw=req.actor.organization_id)
    svc, connector = build_service(store, req, connector=WriteConnector(fail=True))
    result = execute(svc, req, raw)
    assert result.error.code == "OUTCOME_UNKNOWN"
    assert not result.error.retryable
    assert "synthetic-secret" not in result.model_dump_json()
    reopened, new_connector = build_service(stores(), req)
    result = execute(reopened, req, raw)
    assert result.error.code == "OUTCOME_UNKNOWN"
    assert new_connector.calls == 0
    assert connector.calls == 1


def test_completion_storage_failure_leaves_unknown_and_blocks_retry(stores, monkeypatch):
    store = stores()
    req = request()
    raw = approve(store, req, raw=req.actor.organization_id)
    svc, connector = build_service(store, req)
    def fail(*args, **kwargs):
        raise OSError("synthetic disk failure")
    monkeypatch.setattr(store, "complete_receipt", fail)
    result = execute(svc, req, raw)
    assert result.error.code == "OUTCOME_UNKNOWN"
    assert store.get_receipt(req.actor.organization_id, req.operation_id).state == "dispatching"
    assert execute(svc, req, raw).error.code == "OUTCOME_UNKNOWN"
    assert connector.calls == 1


def test_atomic_approval_consumption_rolls_back_when_attempt_insert_fails(stores, monkeypatch):
    store = stores()
    req = request()
    raw = approve(store, req, raw=req.actor.organization_id)
    svc, connector = build_service(store, req)
    real = store._receipt_query
    def fail(conn, sql, args=()):
        if "INSERT INTO execution_attempt" in sql:
            raise OSError("synthetic attempt insert failure")
        return real(conn, sql, args)
    monkeypatch.setattr(store, "_receipt_query", fail)
    result = execute(svc, req, raw)
    assert result.status == "failed"
    reopened = stores()
    assert reopened.get_approval(approval_ref_hash(raw)).consumed_at is None
    assert reopened.get_receipt(req.actor.organization_id, req.operation_id).state == "prepared"
    assert connector.calls == 0


def test_result_access_rechecks_policy_and_actor_before_decryption(stores):
    store = stores()
    req = request()
    raw = approve(store, req, raw=req.actor.organization_id)
    svc, connector = build_service(store, req)
    assert execute(svc, req, raw).status == "success"
    other = req.model_copy(deep=True)
    other.actor.user_id = "other"
    result = execute(svc, other, raw)
    assert result.error.code == "EXECUTION_TARGET_DENIED"
    assert result.receipt_id is None
    assert result.data is None
    denied, _ = build_service(store, req, policy=DefaultPolicyEngine(denied_capabilities=("records.write",)))
    assert execute(denied, req, raw).error.code == "POLICY_DENIED"
    assert connector.calls == 1


def test_wrong_key_cannot_read_result_or_trigger_new_execution(stores):
    store = stores()
    req = request()
    raw = approve(store, req, raw=req.actor.organization_id)
    svc, _ = build_service(store, req)
    assert execute(svc, req, raw).status == "success"
    broken, connector = build_service(store, req, cipher=ResultCipher({"test": b"y" * 32}, "test"))
    result = execute(broken, req, raw)
    assert result.error.code == "RESULT_UNAVAILABLE"
    assert result.execution_state == "succeeded"
    assert connector.calls == 0


def test_missing_operation_id_and_untrusted_credential_fail_closed(stores):
    store = stores()
    req = request()
    svc, connector = build_service(store, req)
    assert execute(svc, req.model_copy(update={"operation_id": None})).error.code == "OPERATION_ID_REQUIRED"
    assert execute(svc, req, credentialHandle="different-account-handle").error.code == "EXECUTION_ACCOUNT_MISMATCH"
    assert connector.calls == 0


def test_app_config_rejects_partial_or_invalid_secret_without_echo(monkeypatch, stores):
    monkeypatch.setenv("UCS_RECEIPT_KEYRING_JSON", "bad-secret")
    monkeypatch.delenv("UCS_EXECUTION_TARGETS_JSON", raising=False)
    with pytest.raises(RuntimeError, match="Durable execution configuration is invalid") as exc:
        executor_from_env(stores())
    assert "bad-secret" not in str(exc.value)


def test_reapproval_of_prepared_operation_is_safe_after_revocation(stores):
    store = stores()
    req = request()
    raw = approve(store, req, raw=req.actor.organization_id)
    assert store.revoke_execution_approval(req.actor.organization_id, approval_ref_hash(raw))
    svc, connector = build_service(store, req)
    assert execute(svc, req, raw).error.code == "APPROVAL_REVOKED"
    replacement = approve(store, req, raw=req.actor.organization_id + "-new")
    assert execute(svc, req, replacement).status == "success"
    assert connector.calls == 1
    assert store.get_approval(approval_ref_hash(raw)).consumed_at is None
    assert store.get_approval(approval_ref_hash(replacement)).consumed_at is not None


def test_key_rotation_reads_old_receipts_and_uses_new_key(stores):
    store = stores()
    req = request()
    raw = approve(store, req, raw=req.actor.organization_id)
    svc, _ = build_service(store, req)
    assert execute(svc, req, raw).status == "success"
    rotated = ResultCipher({"test": b"x" * 32, "new": b"n" * 32}, "new")
    svc, connector = build_service(stores(), req, cipher=rotated)
    assert execute(svc, req, raw).status == "success"
    assert connector.calls == 0


def test_expired_result_retains_operation_tombstone(stores, monkeypatch):
    store = stores()
    req = request()
    raw = approve(store, req, raw=req.actor.organization_id)
    svc, connector = build_service(store, req)
    assert execute(svc, req, raw).status == "success"
    now = utc_now()
    monkeypatch.setattr("universal_connection_service.execution.utc_now", lambda: now + timedelta(days=2))
    result = execute(svc, req, raw)
    assert result.error.code == "RESULT_EXPIRED"
    assert result.execution_state == "succeeded"
    assert connector.calls == 1
    assert store.get_receipt(req.actor.organization_id, req.operation_id).state == "succeeded"


def test_crash_after_provider_effect_blocks_new_process_retry(tmp_path):
    database = tmp_path / "ucs.sqlite3"
    provider_db = tmp_path / "provider.sqlite3"
    req = request()
    worker = """
import os, sqlite3, sys
sys.path.insert(0, 'tests')
from test_durable_execution import WriteConnector, build_service, approve, execute
from universal_connection_service.contracts import ConnectionRequest
from universal_connection_service.persistence import SQLiteStateStore
req = ConnectionRequest.model_validate_json(sys.argv[3])
class CrashAfterEffect(WriteConnector):
    async def execute(self, capability, input, ctx):
        with sqlite3.connect(sys.argv[2]) as provider:
            provider.execute('CREATE TABLE effects (operation_id TEXT)')
            provider.execute('INSERT INTO effects VALUES (?)', (req.operation_id,))
        os._exit(42)
store = SQLiteStateStore(sys.argv[1])
approve(store, req)
service, _ = build_service(store, req, connector=CrashAfterEffect())
execute(service, req)
"""
    result = subprocess.run([sys.executable, "-c", worker, str(database), str(provider_db), req.model_dump_json()], timeout=30)
    assert result.returncode == 42
    from universal_connection_service.persistence import SQLiteStateStore
    reopened = SQLiteStateStore(database)
    try:
        service, connector = build_service(reopened, req)
        result = execute(service, req)
        assert result.error.code == "OUTCOME_UNKNOWN"
        assert not result.error.retryable
        assert connector.calls == 0
        with sqlite3.connect(provider_db) as provider:
            assert provider.execute("SELECT count(*) FROM effects").fetchone()[0] == 1
    finally:
        reopened.close()


def test_write_cannot_bypass_receipts_even_when_policy_allows():
    from universal_connection_service.policy import PolicyEvaluation
    from universal_connection_service.contracts import RiskAssessment
    class AllowPolicy:
        def evaluate(self, facts):
            return PolicyEvaluation(decision="ALLOW", reasons=(), risk=RiskAssessment(level="LOW", reasons=()))
    req = request()
    connector = WriteConnector()
    registry = ConnectorRegistry()
    registry.register(Registration(connector=connector, status="trusted", organization_id=req.actor.organization_id))
    svc = ConnectionService(registry, policy_engine=AllowPolicy())
    result = execute(svc, req)
    assert result.error.code == "DURABLE_EXECUTION_REQUIRED"
    assert connector.calls == 0


def test_registered_effect_capability_cannot_be_mislabeled_read(stores):
    store = stores()
    req = request()
    svc, connector = build_service(store, req)
    result = execute(svc, req.model_copy(update={"operation": "read", "read_only": True}))
    assert result.error.code == "EXECUTION_TARGET_DENIED"
    assert connector.calls == 0


def test_two_service_instances_share_one_approval_and_effect(stores):
    first_store, second_store = stores(), stores()
    req = request()
    raw = approve(first_store, req, raw=req.actor.organization_id)
    connector = WriteConnector()
    first, _ = build_service(first_store, req, connector=connector)
    second, _ = build_service(second_store, req, connector=connector)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda svc: execute(svc, req, raw), (first, second)))
    assert any(result.status == "success" for result in results)
    assert all(result.status == "success" or result.error.code == "OUTCOME_UNKNOWN" for result in results)
    assert connector.calls == 1
    assert execute(second, req, raw).status == "success"
    assert connector.calls == 1


def test_completion_ack_lost_returns_unknown_then_recovers_stored_success(stores, monkeypatch):
    store = stores()
    req = request()
    raw = approve(store, req, raw=req.actor.organization_id)
    svc, connector = build_service(store, req)
    real_complete = store.complete_receipt
    def lost_ack(*args, **kwargs):
        real_complete(*args, **kwargs)
        raise ConnectionError("lost result acknowledgement")
    monkeypatch.setattr(store, "complete_receipt", lost_ack)
    assert execute(svc, req, raw).error.code == "OUTCOME_UNKNOWN"
    assert execute(svc, req, raw).status == "success"
    assert connector.calls == 1


def test_expiry_between_preparation_and_dispatch_blocks_execution(stores, monkeypatch):
    store = stores()
    req = request()
    raw = approve(store, req, raw=req.actor.organization_id)
    svc, connector = build_service(store, req)
    real_prepare = store.prepare_receipt
    now = utc_now()
    def expire_after_prepare(intent):
        receipt = real_prepare(intent)
        monkeypatch.setattr("universal_connection_service.receipt_store.utc_now", lambda: now + timedelta(days=1))
        return receipt
    monkeypatch.setattr(store, "prepare_receipt", expire_after_prepare)
    assert execute(svc, req, raw).error.code == "APPROVAL_EXPIRED"
    assert connector.calls == 0
