from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest

from test_receipts import stores
from test_durable_execution import request, approve, build_service, execute
from universal_connection_service.execution import ResultCipher
from universal_connection_service.receipts import ReceiptError, utc_now
from universal_connection_service.receipt_retention import purge_batch


def expired_execution(store, monkeypatch):
    req = request()
    raw = approve(store, req, raw=req.actor.organization_id)
    service, connector = build_service(store, req)
    with monkeypatch.context() as patch:
        patch.setattr("universal_connection_service.execution.utc_now", lambda: utc_now() - timedelta(hours=2))
        result = execute(service, req, raw)
    assert result.status == "success"
    return req, service, connector, result


def scan(store, cipher):
    after = ""
    for _ in range(1000):
        after = purge_batch(store, cipher, after)
        if not after:
            return
    raise AssertionError("retention cursor did not finish")


def test_expired_payload_deleted_but_restart_cannot_repeat_effect(stores, monkeypatch):
    store = stores()
    req, service, connector, result = expired_execution(store, monkeypatch)
    scan(store, service.durable_executor.cipher)
    assert store.get_receipt_result(req.actor.organization_id, req.operation_id) is None
    receipt = store.get_receipt(req.actor.organization_id, req.operation_id)
    assert receipt.result_purged_at is not None
    assert receipt.state == "succeeded"
    assert receipt.audit_id == result.audit_id
    assert len(store.pending_receipt_audit(req.actor.organization_id)) == 1
    reopened, new_connector = build_service(stores(), req)
    retry = execute(reopened, req, approval=None)
    assert retry.error.code == "RESULT_EXPIRED"
    assert retry.execution_state == "succeeded"
    assert retry.receipt_id == result.receipt_id
    assert connector.calls == 1 and new_connector.calls == 0


def test_retention_requires_decryption_key_and_preserves_unexpired_results(stores, monkeypatch):
    store = stores()
    req, service, _, _ = expired_execution(store, monkeypatch)
    before = store.get_receipt_result(req.actor.organization_id, req.operation_id)
    scan(store, ResultCipher({"different-key": b"y" * 32}, "different-key"))
    assert store.get_receipt_result(req.actor.organization_id, req.operation_id) == before
    live = request()
    raw = approve(store, live, raw=live.actor.organization_id)
    live_service, _ = build_service(store, live)
    assert execute(live_service, live, raw).status == "success"
    scan(store, service.durable_executor.cipher)
    assert store.get_receipt_result(live.actor.organization_id, live.operation_id) is not None
    assert store.get_receipt_result(req.actor.organization_id, req.operation_id) is None


def test_purge_is_scoped_atomic_and_idempotent_between_workers(stores, monkeypatch):
    store, second = stores(), stores()
    req, _, _, _ = expired_execution(store, monkeypatch)
    receipt = store.get_receipt(req.actor.organization_id, req.operation_id)
    ciphertext = store.get_receipt_result(req.actor.organization_id, req.operation_id)
    assert not store.purge_receipt_result("other-org", req.operation_id, receipt.version, ciphertext)
    assert not store.purge_receipt_result(req.actor.organization_id, req.operation_id, receipt.version, "wrong-envelope")
    with pytest.raises(ReceiptError, match="RECEIPT_STATE_CONFLICT"):
        store.purge_receipt_result(req.actor.organization_id, req.operation_id, receipt.version - 1, ciphertext)
    assert store.get_receipt_result(req.actor.organization_id, req.operation_id) == ciphertext
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda s: s.purge_receipt_result(req.actor.organization_id,
            req.operation_id, receipt.version, ciphertext), [store, second]))
    assert sorted(results) == [False, True]
    assert stores().get_receipt(req.actor.organization_id, req.operation_id).state == "succeeded"
