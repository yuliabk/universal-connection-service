import asyncio
import pytest

from test_receipts import stores
from test_execution_recovery import setup, ProviderOutcome
from test_durable_execution import build_service, execute
from universal_connection_service.contracts import ConnectorResult, ExecutionContext


@pytest.mark.parametrize("contradictory", [True, False])
@pytest.mark.parametrize("winner_state", ["succeeded", "failed_no_effect"])
def test_live_verified_lookup_conflict_is_quarantined_after_restart(stores, contradictory, winner_state):
    store = stores()
    req, provider, svc, target = setup(store)
    svc2, _ = build_service(stores(), req, connector=provider, target=target)

    async def scenario():
        started, release = asyncio.Event(), asyncio.Event()
        calls = 0
        async def lookup(capability, ctx, key):
            nonlocal calls
            calls += 1
            state = winner_state
            if calls == 1:
                started.set()
                await release.wait()
                if contradictory:
                    state = "failed_no_effect" if winner_state == "succeeded" else "succeeded"
            if state == "failed_no_effect":
                return ProviderOutcome(**key.model_dump(), state=state, lateExecutionPrevented=True,
                    result=ConnectorResult(status="failed", error={"code": "REJECTED", "message": "Synthetic rejection"}))
            return ProviderOutcome(**key.model_dump(), state=state,
                result=ConnectorResult(status="success", data={"current": True}))
        provider.lookup_execution = lookup
        ctx = ExecutionContext(requestId=req.request_id, userId=req.actor.user_id,
            organizationId=req.actor.organization_id, deadlineMs=5000)
        first = asyncio.create_task(svc.execute(req, ctx, allow_dispatch=False, reconcile=True))
        try:
            await asyncio.wait_for(started.wait(), 2)
            await asyncio.sleep(0.002)  # synthetic 1ms backoff
            winner = await svc2.execute(req, ctx, allow_dispatch=False, reconcile=True)
            assert winner.execution_state == winner_state
            encrypted = store.get_receipt_result(req.actor.organization_id, req.operation_id)
            release.set()
            late = await asyncio.wait_for(first, 2)
            expected = "EXECUTION_OUTCOME_CONFLICT" if contradictory else "REJECTED" if winner_state == "failed_no_effect" else None
            assert (late.error.code if late.error else None) == expected
            assert store.get_receipt_result(req.actor.organization_id, req.operation_id) == encrypted
            return winner
        finally:
            release.set()
            if not first.done():
                first.cancel()
                await asyncio.gather(first, return_exceptions=True)

    winner = asyncio.run(scenario())
    receipt = store.get_receipt(req.actor.organization_id, req.operation_id)
    assert receipt.state == winner_state and receipt.outcome_conflicted == contradictory
    reopened, _ = build_service(stores(), req, connector=provider, target=target)
    result = execute(reopened, req, None)
    if contradictory:
        assert result.error.code == "EXECUTION_OUTCOME_CONFLICT" and result.data is None
        assert any(n["code"] == "EXECUTION_OUTCOME_CONFLICT" for n in store.execution_notices(req.actor.organization_id))
    else:
        assert result.execution_state == winner_state
    outbox = store.pending_receipt_audit(req.actor.organization_id)
    assert len(outbox) == 1 and outbox[0].event_id == winner.audit_id
    assert provider.calls == 1


def test_quarantine_and_notice_are_atomic(stores, monkeypatch):
    from test_execution_recovery import reconcile
    store = stores()
    req, _, svc, _ = setup(store)
    assert reconcile(svc, req).status == "success"
    before = store.get_receipt(req.actor.organization_id, req.operation_id)
    def failed_notice(*args):
        raise RuntimeError("synthetic transaction failure")
    with monkeypatch.context() as patch:
        patch.setattr(store, "_record_execution_notice", failed_notice)
        with pytest.raises(RuntimeError):
            store.quarantine_conflicting_outcome(req.actor.organization_id, req.operation_id, "failed_no_effect")
    assert store.get_receipt(req.actor.organization_id, req.operation_id) == before
    conflicted = store.quarantine_conflicting_outcome(req.actor.organization_id, req.operation_id, "failed_no_effect")
    assert conflicted.outcome_conflicted
    assert store.quarantine_conflicting_outcome(req.actor.organization_id, req.operation_id, "failed_no_effect") == conflicted
