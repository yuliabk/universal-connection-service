import asyncio
import json
import hashlib
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

import pytest
from pydantic import ValidationError

from test_receipts import stores
from test_durable_execution import request, approve, make_target, build_service, execute, WriteConnector
from test_execution_recovery import contract
from universal_connection_service.contracts import ConnectorResult, ExecutionContext
from universal_connection_service.recovery import ReplayPolicy, RecoveryContract
from universal_connection_service.receipts import utc_now


def replay_contract(max_attempts=3):
    return RecoveryContract(**contract().model_dump(exclude={"replay"}), replay=ReplayPolicy(
        deduplicationWindowSeconds=300, maxAttempts=max_attempts,
        providerEnforcesNotAfter=True, concurrentDeduplication=True))


class DeduplicatingProvider(WriteConnector):
    def __init__(self, path, recovery):
        super().__init__()
        self.path, self.recovery = path, recovery
        self.last_key = None
        self.now = utc_now
        with sqlite3.connect(path) as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS effects (id INTEGER PRIMARY KEY, binding TEXT)")
            conn.execute("CREATE TABLE IF NOT EXISTS dedup (key TEXT PRIMARY KEY, binding TEXT, account TEXT)")
            conn.execute("CREATE TABLE IF NOT EXISTS attempts (key TEXT, not_after TEXT)")

    def recovery_contract_digest(self):
        return self.recovery.digest()

    async def lookup_execution(self, capability, ctx, key):
        raise AssertionError("replay must not need lookup to deduplicate")

    async def execute_keyed(self, capability, input, ctx, key):
        self.last_key = key
        self.calls += 1
        assert key.not_after is not None
        # This check is a PROVIDER guarantee, even if its dedup cache was evicted.
        if self.now() >= key.not_after:
            raise TimeoutError("provider rejects expired dispatch")
        with sqlite3.connect(self.path, timeout=10) as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("INSERT INTO attempts VALUES (?, ?)", (key.provider_key, key.not_after.isoformat()))
            old = conn.execute("SELECT binding, account FROM dedup WHERE key = ?", (key.provider_key,)).fetchone()
            if old:
                assert old == (key.binding_digest, key.provider_account_id)
            else:
                conn.execute("INSERT INTO effects (binding) VALUES (?)", (key.binding_digest,))
                conn.execute("INSERT INTO dedup VALUES (?, ?, ?)",
                    (key.provider_key, key.binding_digest, key.provider_account_id))
        if old is None:
            raise TimeoutError("effect committed, first response lost")
        return ConnectorResult(status="success", data={"effect": "original"})

    def counts(self):
        with sqlite3.connect(self.path) as conn:
            return (conn.execute("SELECT count(*) FROM effects").fetchone()[0],
                    conn.execute("SELECT count(*) FROM attempts").fetchone()[0])


def setup(store, path, max_attempts=3):
    req = request()
    recovery = replay_contract(max_attempts)
    provider = DeduplicatingProvider(path, recovery)
    target = make_target(req).model_copy(update={"recovery": recovery})
    svc, _ = build_service(store, req, connector=provider, target=target)
    raw = approve(store, req, raw=req.actor.organization_id, expiresAt=utc_now() + timedelta(hours=1))
    assert execute(svc, req, raw).error.code == "OUTCOME_UNKNOWN"
    return req, provider, target, raw


def replay(svc, req, raw):
    import time
    time.sleep(0.002)  # Explicit synthetic 1ms recovery interval.
    return asyncio.run(svc.execute(req, ExecutionContext(requestId=req.request_id,
        userId=req.actor.user_id, organizationId=req.actor.organization_id, approvalId=raw), replay=True))


def test_restart_replay_uses_same_key_deadline_and_consumed_approval(stores, tmp_path):
    store = stores()
    req, provider, target, raw = setup(store, tmp_path / "provider.sqlite3")
    original = store.get_receipt(req.actor.organization_id, req.operation_id)
    svc, _ = build_service(stores(), req, connector=provider, target=target)
    result = replay(svc, req, raw)
    assert result.status == "success" and result.receipt_id == original.receipt_id
    assert provider.counts() == (1, 2)
    final = store.get_receipt(req.actor.organization_id, req.operation_id)
    assert final.provider_key == original.provider_key
    assert final.provider_not_after == original.provider_not_after
    assert final.attempt_count == 2
    assert replay(svc, req, None).status == "success"
    assert provider.counts() == (1, 2)


@pytest.mark.parametrize("invalid", ["revoked", "expired", "different", "missing"])
def test_replay_requires_original_still_valid_approval(stores, tmp_path, monkeypatch, invalid):
    store = stores()
    req, provider, target, raw = setup(store, tmp_path / "provider.sqlite3")
    from universal_connection_service.approvals import approval_ref_hash
    if invalid == "revoked":
        store.revoke_execution_approval(req.actor.organization_id, approval_ref_hash(raw))
    if invalid == "expired":
        monkeypatch.setattr("universal_connection_service.receipt_store.utc_now", lambda: utc_now() + timedelta(hours=1))
    if invalid == "different":
        raw = approve(store, req, raw=raw + "-replacement")
    if invalid == "missing":
        raw = None
    svc, _ = build_service(stores(), req, connector=provider, target=target)
    assert replay(svc, req, raw).error.code.startswith("APPROVAL_")
    assert provider.counts() == (1, 1)


def test_parallel_replays_cannot_create_a_second_effect(stores, tmp_path):
    store = stores()
    req, provider, target, raw = setup(store, tmp_path / "provider.sqlite3")
    services = [build_service(stores(), req, connector=provider, target=target)[0] for _ in range(2)]
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda svc: replay(svc, req, raw), services))
    assert any(result.status == "success" for result in results)
    assert provider.counts()[0] == 1
    assert provider.counts()[1] <= 3


def test_lost_replay_commit_ack_does_not_send_provider_request(stores, tmp_path, monkeypatch):
    store = stores()
    req, provider, target, raw = setup(store, tmp_path / "provider.sqlite3", max_attempts=2)
    svc, _ = build_service(store, req, connector=provider, target=target)
    begin = store.begin_receipt_replay
    def lost_ack(*args, **kwargs):
        begin(*args, **kwargs)
        raise RuntimeError("lost commit acknowledgement")
    with monkeypatch.context() as patch:
        patch.setattr(store, "begin_receipt_replay", lost_ack)
        assert replay(svc, req, raw).error.code == "OUTCOME_UNKNOWN"
    assert provider.counts() == (1, 1)
    assert replay(svc, req, raw).error.code == "REPLAY_BUDGET_EXHAUSTED"


def test_expired_dispatch_is_rejected_locally_and_by_provider_after_cache_eviction(stores, tmp_path, monkeypatch):
    store = stores()
    req, provider, target, raw = setup(store, tmp_path / "provider.sqlite3")
    original_key = provider.last_key
    svc, _ = build_service(store, req, connector=provider, target=target)
    # Move past dedup expiry but keep the original grant valid for this test.
    with monkeypatch.context() as patch:
        patch.setattr("universal_connection_service.receipt_store.utc_now", lambda: utc_now() + timedelta(seconds=301))
        code = replay(svc, req, raw).error.code
        assert code == "REPLAY_BUDGET_EXHAUSTED"
    with sqlite3.connect(provider.path) as conn:
        conn.execute("DELETE FROM dedup")
    provider.now = lambda: original_key.not_after + timedelta(seconds=1)
    with pytest.raises(TimeoutError):
        asyncio.run(provider.execute_keyed(req.capability, req.input, None, original_key))
    assert provider.counts() == (1, 1)


def test_replay_policy_requires_provider_expiry_and_concurrency_guarantees():
    with pytest.raises(ValidationError):
        ReplayPolicy(deduplicationWindowSeconds=300, maxAttempts=2,
            providerEnforcesNotAfter=False, concurrentDeduplication=True)
    historical = contract().model_copy(update={"recovery_backoff_ms": 1000, "clock_margin_ms": 1000})
    old = historical.model_dump(mode="json", by_alias=True, exclude={"replay", "dispatch_outcomes", "recovery_backoff_ms", "clock_margin_ms"})
    assert historical.digest() == hashlib.sha256(json.dumps(old, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def test_provider_deadline_cannot_outlive_original_approval(stores, tmp_path):
    store = stores()
    req = request()
    recovery = replay_contract()
    provider = DeduplicatingProvider(tmp_path / "provider.sqlite3", recovery)
    target = make_target(req).model_copy(update={"recovery": recovery})
    svc, _ = build_service(store, req, connector=provider, target=target)
    expires = utc_now() + timedelta(seconds=30)
    raw = approve(store, req, raw=req.actor.organization_id, expiresAt=expires)
    assert execute(svc, req, raw).error.code == "OUTCOME_UNKNOWN"
    assert provider.last_key.not_after == expires
    assert store.get_receipt(req.actor.organization_id, req.operation_id).provider_not_after == expires


def test_replay_endpoint_needs_distinct_scope_and_never_starts_new_operation(stores, tmp_path):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from universal_connection_service.control_plane import ControlPlaneCredential, StaticBearerAuthenticator
    from universal_connection_service.execution_api import build_execution_router
    store = stores()
    req, provider, target, raw = setup(store, tmp_path / "provider.sqlite3")
    svc, _ = build_service(store, req, connector=provider, target=target)
    credentials = tuple(ControlPlaneCredential(tokenSha256=hashlib.sha256(token.encode()).hexdigest(),
        subject="operator", tokenId=token, organizations=(req.actor.organization_id,), scopes=(scope,))
        for token, scope in [("reader", "executions:reconcile"), ("replayer", "executions:replay")])
    app = FastAPI()
    app.include_router(build_execution_router(svc, StaticBearerAuthenticator(credentials)))
    body = {"request": req.model_dump(by_alias=True), "context": {"requestId": req.request_id,
        "userId": req.actor.user_id, "organizationId": req.actor.organization_id, "approvalId": raw}}
    with TestClient(app) as http:
        assert http.post("/v1/control-plane/executions/replay", json=body,
            headers={"Authorization": "Bearer reader"}).status_code == 403
        assert provider.counts() == (1, 1)
        response = http.post("/v1/control-plane/executions/replay", json=body,
            headers={"Authorization": "Bearer replayer"})
        assert response.json()["status"] == "success"
        body["request"]["operationId"] = "never-dispatched"
        response = http.post("/v1/control-plane/executions/replay", json=body,
            headers={"Authorization": "Bearer replayer"})
        assert response.json()["error"]["code"] == "RECEIPT_NOT_DISPATCHED"
        assert store.get_receipt(req.actor.organization_id, "never-dispatched") is None
        assert provider.counts() == (1, 2)
