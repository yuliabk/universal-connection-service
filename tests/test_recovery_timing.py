from datetime import timedelta
import pytest
from pydantic import ValidationError

from test_receipts import stores
from test_durable_execution import request, approve, make_target, build_service, execute
from test_execution_recovery import Provider, contract, reconcile
from test_execution_replay import DeduplicatingProvider, replay_contract, replay
from universal_connection_service.receipts import utc_now


def test_backoff_is_shared_durable_and_does_not_spend_budget(stores, monkeypatch):
    store = stores()
    req = request()
    recovery = replay_contract().model_copy(update={"recovery_backoff_ms": 1000})
    provider = Provider(recovery)
    provider.outcome = "unknown"
    target = make_target(req).model_copy(update={"recovery": recovery})
    svc, _ = build_service(store, req, connector=provider, target=target)
    raw = approve(store, req, raw=req.actor.organization_id)
    execute(svc, req, raw)
    now = utc_now()
    monkeypatch.setattr("universal_connection_service.receipt_store.utc_now", lambda: now)
    assert reconcile(svc, req).execution_state == "unknown"
    saved = store.get_receipt(req.actor.organization_id, req.operation_id)
    assert saved.recovery_not_before == now + timedelta(seconds=1)
    reopened, _ = build_service(stores(), req, connector=provider, target=target)
    assert reconcile(reopened, req).error.code == "RECOVERY_BACKOFF_REQUIRED"
    assert replay(reopened, req, raw).error.code == "RECOVERY_BACKOFF_REQUIRED"
    assert store.get_receipt(req.actor.organization_id, req.operation_id) == saved
    assert provider.calls == provider.lookups == 1
    now += timedelta(seconds=1)
    provider.outcome = "succeeded"
    assert reconcile(reopened, req).status == "success"
    assert provider.lookups == 2


def test_replay_clock_margin_blocks_before_provider_expiry(stores, tmp_path, monkeypatch):
    store = stores()
    req = request()
    recovery = replay_contract().model_copy(update={"clock_margin_ms": 1000})
    provider = DeduplicatingProvider(tmp_path / "provider.sqlite3", recovery)
    target = make_target(req).model_copy(update={"recovery": recovery})
    svc, _ = build_service(store, req, connector=provider, target=target)
    raw = approve(store, req, raw=req.actor.organization_id)
    execute(svc, req, raw)
    receipt = store.get_receipt(req.actor.organization_id, req.operation_id)
    now = receipt.provider_not_after - timedelta(milliseconds=999)
    monkeypatch.setattr("universal_connection_service.receipt_store.utc_now", lambda: now)
    assert replay(svc, req, raw).error.code == "REPLAY_BUDGET_EXHAUSTED"
    assert provider.counts() == (1, 1)
    assert store.get_receipt(req.actor.organization_id, req.operation_id) == receipt


def test_lost_lookup_commit_ack_preserves_backoff(stores, monkeypatch):
    store = stores()
    req = request()
    recovery = contract().model_copy(update={"recovery_backoff_ms": 1000})
    provider = Provider(recovery)
    target = make_target(req).model_copy(update={"recovery": recovery})
    svc, _ = build_service(store, req, connector=provider, target=target)
    raw = approve(store, req, raw=req.actor.organization_id)
    execute(svc, req, raw)
    now = utc_now()
    monkeypatch.setattr("universal_connection_service.receipt_store.utc_now", lambda: now)
    begin = store.begin_receipt_lookup
    def lost_ack(*args, **kwargs):
        begin(*args, **kwargs)
        raise RuntimeError("synthetic lost acknowledgement")
    monkeypatch.setattr(store, "begin_receipt_lookup", lost_ack)
    assert reconcile(svc, req).error is not None
    reopened, _ = build_service(stores(), req, connector=provider, target=target)
    assert reconcile(reopened, req).error.code == "RECOVERY_BACKOFF_REQUIRED"
    assert provider.lookups == 0
    assert store.get_receipt(req.actor.organization_id, req.operation_id).lookup_count == 1


@pytest.mark.parametrize("field", ["recoveryBackoffMs", "clockMarginMs"])
@pytest.mark.parametrize("value", [0, -1])
def test_recovery_timing_must_be_positive(field, value):
    values = contract().model_dump(by_alias=True)
    values[field] = value
    with pytest.raises(ValidationError):
        type(contract()).model_validate(values)
