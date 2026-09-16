import asyncio
import pytest

from test_receipts import stores
from test_durable_execution import request, approve, build_service, WriteConnector
from test_execution_recovery import setup, ProviderOutcome
from universal_connection_service.contracts import ConnectorResult, ExecutionContext
from universal_connection_service.provider_calls import ProviderCalls
from universal_connection_service.receipts import ReceiptError


class StubbornConnector(WriteConnector):
    def __init__(self):
        super().__init__()
        self.started = asyncio.Event()
        self.cancelled = asyncio.Event()
        self.release = asyncio.Event()
        self.finished = asyncio.Event()

    async def execute(self, capability, input, ctx):
        self.calls += 1
        self.started.set()
        try:
            await self.release.wait()
        except asyncio.CancelledError:
            self.cancelled.set()
            await self.release.wait()
        self.finished.set()
        return ConnectorResult(status="success", data={"late": True})


@pytest.mark.parametrize("cancel_caller", [False, True])
def test_timeout_or_cancellation_never_waits_for_stubborn_connector_or_commits_late_result(stores, cancel_caller):
    store = stores()
    req = request()
    raw = approve(store, req, raw=req.actor.organization_id)
    async def scenario():
        provider = StubbornConnector()
        svc, _ = build_service(store, req, connector=provider)
        ctx = ExecutionContext(requestId=req.request_id, userId=req.actor.user_id,
            organizationId=req.actor.organization_id, approvalId=raw, deadlineMs=5000 if cancel_caller else 20)
        task = asyncio.create_task(svc.execute(req, ctx))
        try:
            await asyncio.wait_for(provider.started.wait(), 2)
            if cancel_caller:
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await asyncio.wait_for(task, 1)
            else:
                result = await asyncio.wait_for(task, 1)
                assert result.error.code == "OUTCOME_UNKNOWN"
            await asyncio.wait_for(provider.cancelled.wait(), 1)
            assert not provider.finished.is_set()
            receipt = store.get_receipt(req.actor.organization_id, req.operation_id)
            assert receipt.state == "dispatching"
            retry = await svc.execute(req, ctx)
            assert retry.error.code == "OUTCOME_UNKNOWN"
            assert provider.calls == 1
            provider.release.set()
            await asyncio.wait_for(provider.finished.wait(), 1)
            await asyncio.sleep(0)
            assert store.get_receipt(req.actor.organization_id, req.operation_id) == receipt
            assert store.pending_receipt_audit(req.actor.organization_id) == []
        finally:
            provider.release.set()
            if not task.done():
                task.cancel()
    asyncio.run(scenario())


def test_late_lookup_cannot_overwrite_another_workers_final_result(stores):
    store = stores()
    req, provider, svc, _ = setup(store)
    async def scenario():
        cancelled, release, finished = asyncio.Event(), asyncio.Event(), asyncio.Event()
        calls = 0
        async def lookup(capability, ctx, key):
            nonlocal calls
            calls += 1
            if calls == 1:
                try:
                    await release.wait()
                except asyncio.CancelledError:
                    cancelled.set()
                    await release.wait()
                finished.set()
                return ProviderOutcome(**key.model_dump(), state="failed_no_effect", lateExecutionPrevented=True,
                    result=ConnectorResult(status="failed", error={"code": "LATE", "message": "late response"}))
            return ProviderOutcome(**key.model_dump(), state="succeeded",
                result=ConnectorResult(status="success", data={"current": True}))
        provider.lookup_execution = lookup
        ctx = ExecutionContext(requestId=req.request_id, userId=req.actor.user_id,
            organizationId=req.actor.organization_id, deadlineMs=20)
        try:
            first = await asyncio.wait_for(svc.execute(req, ctx, allow_dispatch=False, reconcile=True), 1)
            assert first.error.code == "OUTCOME_UNKNOWN"
            await asyncio.wait_for(cancelled.wait(), 1)
            second = await svc.execute(req, ctx, allow_dispatch=False, reconcile=True)
            assert second.status == "success"
            final = store.get_receipt(req.actor.organization_id, req.operation_id)
            release.set()
            await asyncio.wait_for(finished.wait(), 1)
            await asyncio.sleep(0)
            assert store.get_receipt(req.actor.organization_id, req.operation_id) == final
            assert len(store.pending_receipt_audit(req.actor.organization_id)) == 1
        finally:
            release.set()
    asyncio.run(scenario())


def test_orphaned_provider_tasks_have_a_bounded_capacity_and_errors_are_consumed():
    async def scenario():
        calls = ProviderCalls(max_in_flight=1)
        release, cancelled = asyncio.Event(), asyncio.Event()
        async def stuck():
            try:
                await release.wait()
            except asyncio.CancelledError:
                cancelled.set()
                await release.wait()
            raise RuntimeError("synthetic secret in late provider exception")
        with pytest.raises(TimeoutError):
            await calls.run(stuck, 0.01)
        await cancelled.wait()
        invoked = False
        def forbidden():
            nonlocal invoked
            invoked = True
            return stuck()
        with pytest.raises(ReceiptError, match="CAPACITY_EXHAUSTED"):
            await calls.run(forbidden, 1)
        assert not invoked
        release.set()
        for _ in range(5):
            await asyncio.sleep(0)
        assert not calls._tasks
        assert await calls.run(lambda: asyncio.sleep(0, result="available"), 1) == "available"
    asyncio.run(scenario())
