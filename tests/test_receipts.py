import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from uuid import uuid4

import pytest
from pydantic import SecretStr

from universal_connection_service.contracts import ConnectionRequest
from universal_connection_service.persistence import SQLiteStateStore
from universal_connection_service.receipts import ExecutionIntent, ReceiptError, ReceiptStore, execution_binding


@pytest.fixture(params=["sqlite", "postgres"])
def stores(request, tmp_path):
    opened = []
    if request.param == "postgres":
        dsn = os.getenv("UCS_TEST_POSTGRES_URL")
        if not dsn:
            pytest.skip("UCS_TEST_POSTGRES_URL is not configured")
        from universal_connection_service.postgres_store import PostgresStateStore, PostgresStoreConfig
        def factory():
            store = PostgresStateStore(PostgresStoreConfig(dsn=SecretStr(dsn), sslmode="disable", autoMigrate=True))
            store.test_witness_path = tmp_path / "independent-witness.sqlite3"
            opened.append(store)
            return store
    else:
        def factory():
            store = SQLiteStateStore(tmp_path / "receipts.sqlite3")
            opened.append(store)
            return store
    yield factory
    for store in opened:
        store.close()


def intent(**updates):
    fields = dict(organizationId="org-" + uuid4().hex, operationId="op-1", requestId="request-1",
                  userId="user", agentId="agent", serviceId="records", providerAccountId="account-1",
                  capability="records.write", operation="update", bindingDigest="a" * 64,
                  connectorId="records-v1", connectorVersion="1.0.0")
    fields.update(updates)
    return ExecutionIntent(**fields)


def test_reopen_returns_original_receipt_and_same_provider_key(stores):
    first = stores()
    expected = intent()
    receipt = first.prepare_receipt(expected)
    second = stores()
    assert isinstance(second, ReceiptStore)
    retry = expected.model_copy(update={"request_id": "request-2", "connector_version": "2.0.0"})
    assert second.prepare_receipt(retry) == receipt
    assert second.get_receipt(expected.organization_id, expected.operation_id) == receipt


@pytest.mark.parametrize("field,value", [("binding_digest", "b" * 64), ("user_id", "other"), ("agent_id", "other"), ("provider_account_id", "other"), ("capability", "other"), ("operation", "delete")])
def test_key_conflict_cannot_overwrite_intent(stores, field, value):
    store = stores()
    original = intent()
    receipt = store.prepare_receipt(original)
    with pytest.raises(ReceiptError, match="IDEMPOTENCY_CONFLICT"):
        store.prepare_receipt(original.model_copy(update={field: value}))
    assert store.get_receipt(original.organization_id, original.operation_id) == receipt


def test_concurrent_instances_have_one_dispatch_winner(stores):
    instances = [stores(), stores()]
    original = intent()
    def run(store):
        prepared = store.prepare_receipt(original)
        try:
            return store.begin_dispatch(original.organization_id, original.operation_id, 0, "attempt-request")
        except ReceiptError as exc:
            return exc.code
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(run, instances))
    assert results.count("RECEIPT_STATE_CONFLICT") == 1
    winner = next(value for value in results if not isinstance(value, str))
    assert winner.state == "dispatching"
    assert winner.attempt_count == 1
    assert winner.attempt_id
    assert winner.version == 1


def test_unresolved_receipt_cannot_be_dispatched_again(stores):
    store = stores()
    original = intent()
    receipt = store.prepare_receipt(original)
    receipt = store.begin_dispatch(original.organization_id, original.operation_id, receipt.version, "r")
    receipt = store.mark_unresolved(original.organization_id, original.operation_id, receipt.version, "unknown")
    with pytest.raises(ReceiptError, match="RECEIPT_STATE_CONFLICT"):
        stores().begin_dispatch(original.organization_id, original.operation_id, receipt.version, "retry")
    assert store.get_receipt(original.organization_id, original.operation_id).state == "unknown"


def test_completion_outbox_and_acknowledgement_survive_restart(stores):
    store = stores()
    original = intent()
    receipt = store.prepare_receipt(original)
    receipt = store.begin_dispatch(original.organization_id, original.operation_id, receipt.version, "r")
    receipt = store.complete_receipt(original.organization_id, original.operation_id, receipt.version, "succeeded", result_ref="opaque-result-1")
    reopened = stores()
    events = reopened.pending_receipt_audit(original.organization_id)
    assert len(events) == 1
    assert events[0].event_id == receipt.audit_id
    assert events[0].receipt_id == receipt.receipt_id
    assert reopened.get_receipt(original.organization_id, original.operation_id) == receipt
    assert reopened.acknowledge_receipt_audit(original.organization_id, receipt.audit_id)
    assert reopened.acknowledge_receipt_audit(original.organization_id, receipt.audit_id)
    assert reopened.pending_receipt_audit(original.organization_id) == []
    with pytest.raises(ReceiptError, match="RECEIPT_STATE_CONFLICT"):
        reopened.complete_receipt(original.organization_id, original.operation_id, receipt.version, "failed_no_effect")


def test_tenant_isolation_and_outbox_ack_scope(stores):
    store = stores()
    original = intent()
    store.prepare_receipt(original)
    assert store.get_receipt("other-org", original.operation_id) is None
    with pytest.raises(ReceiptError, match="RECEIPT_NOT_FOUND"):
        store.begin_dispatch("other-org", original.operation_id, 0, "r")
    receipt = store.begin_dispatch(original.organization_id, original.operation_id, 0, "r")
    receipt = store.complete_receipt(original.organization_id, original.operation_id, receipt.version, "succeeded")
    assert not store.acknowledge_receipt_audit("other-org", receipt.audit_id)
    assert store.pending_receipt_audit("other-org") == []
    assert len(store.pending_receipt_audit(original.organization_id)) == 1
    separate = store.prepare_receipt(original.model_copy(update={"organization_id": "other-org"}))
    assert separate.receipt_id != receipt.receipt_id


def test_outbox_failure_rolls_back_receipt_completion(stores, monkeypatch):
    store = stores()
    original = intent()
    store.prepare_receipt(original)
    dispatched = store.begin_dispatch(original.organization_id, original.operation_id, 0, "r")
    real_query = store._receipt_query
    def query(conn, sql, args=()):
        if "INSERT INTO execution_outbox" in sql:
            raise RuntimeError("simulated outbox disk failure")
        return real_query(conn, sql, args)
    monkeypatch.setattr(store, "_receipt_query", query)
    with pytest.raises(RuntimeError, match="simulated outbox"):
        store.complete_receipt(original.organization_id, original.operation_id, dispatched.version, "succeeded")
    reopened = stores()
    assert reopened.get_receipt(original.organization_id, original.operation_id) == dispatched
    assert reopened.pending_receipt_audit(original.organization_id) == []


def test_lost_dispatch_commit_ack_does_not_allow_second_dispatch(stores, monkeypatch):
    store = stores()
    original = intent()
    store.prepare_receipt(original)
    real_transaction = store._receipt_transaction
    @contextmanager
    def lost_ack():
        with real_transaction() as conn:
            yield conn
        raise ConnectionError("commit acknowledgement lost")
    monkeypatch.setattr(store, "_receipt_transaction", lost_ack)
    with pytest.raises(ConnectionError):
        store.begin_dispatch(original.organization_id, original.operation_id, 0, "r")
    reopened = stores()
    receipt = reopened.get_receipt(original.organization_id, original.operation_id)
    assert receipt.state == "dispatching"
    with pytest.raises(ReceiptError):
        reopened.begin_dispatch(original.organization_id, original.operation_id, receipt.version, "retry")


def test_memory_store_cannot_claim_durability():
    store = SQLiteStateStore(":memory:")
    try:
        with pytest.raises(ReceiptError, match="RECEIPT_STORE_NOT_DURABLE"):
            store.prepare_receipt(intent())
    finally:
        store.close()


def test_canonical_binding_is_request_independent_but_effect_bound():
    req = ConnectionRequest(requestId="r1", actor={"userId": "u", "agentId": "a", "organizationId": "o"},
                            service={"id": "svc", "name": "Service"}, capability="pay", operation="execute",
                            input={"currency": "ILS", "amount": 5})
    expected = execution_binding(req, "account-1")
    assert expected == execution_binding(req.model_copy(update={"request_id": "retry", "input": {"amount": 5, "currency": "ILS"}}), "account-1")
    assert expected != execution_binding(req, "account-2")
    assert expected != execution_binding(req.model_copy(update={"input": {"amount": 6, "currency": "ILS"}}), "account-1")
    with pytest.raises(ValueError):
        execution_binding(req.model_copy(update={"input": {"amount": float("nan")}}), "account-1")
    with pytest.raises(ValueError):
        execution_binding(req.model_copy(update={"input": {1: "ambiguous"}}), "account-1")


def test_process_crash_after_durable_dispatch_remains_uncertain(tmp_path):
    path = tmp_path / "crash.sqlite3"
    original = intent()
    worker = """
import os, sys
from universal_connection_service.persistence import SQLiteStateStore
from universal_connection_service.receipts import ExecutionIntent
s = SQLiteStateStore(sys.argv[1])
i = ExecutionIntent.model_validate_json(sys.argv[2])
s.prepare_receipt(i)
s.begin_dispatch(i.organization_id, i.operation_id, 0, 'worker-request')
os._exit(42)
"""
    result = subprocess.run([sys.executable, "-c", worker, str(path), original.model_dump_json()], timeout=30)
    assert result.returncode == 42
    with_store = SQLiteStateStore(path)
    try:
        receipt = with_store.get_receipt(original.organization_id, original.operation_id)
        assert receipt.state == "dispatching"
        assert receipt.attempt_count == 1
        with pytest.raises(ReceiptError):
            with_store.begin_dispatch(original.organization_id, original.operation_id, receipt.version, "retry")
    finally:
        with_store.close()
