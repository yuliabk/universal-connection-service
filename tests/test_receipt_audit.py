from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager

import pytest

from test_receipts import stores, intent
from universal_connection_service.receipts import ReceiptError


def completed(store):
    original = intent()
    receipt = store.prepare_receipt(original)
    receipt = store.begin_dispatch(receipt.organization_id, receipt.operation_id, receipt.version, "attempt")
    return store.complete_receipt(receipt.organization_id, receipt.operation_id, receipt.version, "succeeded")


def test_delivery_reopen_concurrency_and_tenant_scope(stores):
    first, second = stores(), stores()
    receipt = completed(first)
    assert second.deliver_receipt_audit("other-org") == 0
    assert receipt.organization_id in first.receipt_audit_organizations()
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda s: s.deliver_receipt_audit(receipt.organization_id), [first, second]))
    reopened = stores()
    events = reopened.list_audit(receipt.organization_id)
    assert len(events) == 1
    assert events[0].audit_id == receipt.audit_id
    assert events[0].status == "success"
    assert reopened.deliver_receipt_audit(receipt.organization_id) == 0
    assert reopened.pending_receipt_audit(receipt.organization_id) == []
    assert reopened.get_receipt(receipt.organization_id, receipt.operation_id) == receipt


def test_ack_failure_rolls_back_audit_projection(stores, monkeypatch):
    store = stores()
    receipt = completed(store)
    query = store._receipt_query
    def fail_ack(conn, sql, args=()):
        if "UPDATE execution_outbox SET delivered" in sql:
            raise RuntimeError("synthetic ack failure")
        return query(conn, sql, args)
    with monkeypatch.context() as patch:
        patch.setattr(store, "_receipt_query", fail_ack)
        with pytest.raises(RuntimeError):
            store.deliver_receipt_audit(receipt.organization_id)
    assert store.list_audit(receipt.organization_id) == []
    assert len(store.pending_receipt_audit(receipt.organization_id)) == 1
    assert store.get_receipt(receipt.organization_id, receipt.operation_id) == receipt
    assert store.deliver_receipt_audit(receipt.organization_id) == 1


def test_lost_delivery_commit_ack_is_idempotent(stores, monkeypatch):
    store = stores()
    receipt = completed(store)
    transaction = store._receipt_transaction
    @contextmanager
    def lost_ack():
        with transaction() as conn:
            yield conn
        raise RuntimeError("synthetic lost commit acknowledgement")
    with monkeypatch.context() as patch:
        patch.setattr(store, "_receipt_transaction", lost_ack)
        with pytest.raises(RuntimeError):
            store.deliver_receipt_audit(receipt.organization_id)
    assert stores().deliver_receipt_audit(receipt.organization_id) == 0
    assert len(store.list_audit(receipt.organization_id)) == 1


def test_conflicting_existing_audit_is_never_acknowledged(stores):
    from universal_connection_service.persistence import AuditEvent
    store = stores()
    receipt = completed(store)
    store.append_audit(AuditEvent(auditId=receipt.audit_id, requestId="unrelated",
        organizationId="other-org", userId="user", agentId="agent", serviceId="records",
        capability="records.write", operation="update", status="failed"))
    with pytest.raises(ReceiptError, match="AUDIT_EVENT_CONFLICT"):
        store.deliver_receipt_audit(receipt.organization_id)
    assert len(store.pending_receipt_audit(receipt.organization_id)) == 1
    assert store.list_audit(receipt.organization_id) == []


def test_discovery_cursor_skips_failing_tenants(stores):
    store = stores()
    receipts = [completed(store), completed(store)]
    organizations = sorted(r.organization_id for r in receipts)
    # PostgreSQL CI may contain other tests' pending events: restrict the cursor.
    found = store.receipt_audit_organizations(after=organizations[0], limit=1000)
    assert organizations[0] not in found
    assert organizations[1] in found


def test_worker_recovers_from_discovery_failure_and_stops_cleanly():
    import asyncio
    from universal_connection_service.receipt_audit import run_receipt_audit_worker
    class Store:
        calls = 0
        delivered = []
        def receipt_audit_organizations(self, *, after):
            self.calls += 1
            if self.calls == 1:
                raise RuntimeError("synthetic unavailable database")
            return ["org"] if not after else []
        def deliver_receipt_audit(self, org):
            self.delivered.append(org)
    async def scenario():
        store = Store()
        stop = asyncio.Event()
        task = asyncio.create_task(run_receipt_audit_worker(store, stop, interval=0.001))
        try:
            async with asyncio.timeout(5):
                while not store.delivered:
                    await asyncio.sleep(0.001)
        finally:
            stop.set()
            await task
        assert store.delivered == ["org"]
    asyncio.run(scenario())
