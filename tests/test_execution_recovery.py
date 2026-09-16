import asyncio
import hashlib
import sqlite3
import subprocess
import sys
from pathlib import Path
from datetime import timedelta

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from test_receipts import stores
from test_durable_execution import request, approve, make_target, build_service, execute, WriteConnector
from universal_connection_service.contracts import ConnectorResult, ExecutionContext
from universal_connection_service.recovery import RecoveryContract, ProviderOutcome
from universal_connection_service.execution_api import build_execution_router
from universal_connection_service.control_plane import ControlPlaneCredential, StaticBearerAuthenticator
from universal_connection_service.persistence import SQLiteStateStore
from universal_connection_service.receipts import utc_now


def contract(**updates):
    return RecoveryContract(contractId="synthetic-ledger", revision="1", evidenceSha256="a" * 64,
        approvalReference="synthetic-contract-review", lookupWindowSeconds=3600,
        maxLookups=updates.get("max_lookups", 3), lookupTimeoutMs=500, recoveryBackoffMs=1, clockMarginMs=1)


class Provider(WriteConnector):
    def __init__(self, recovery):
        super().__init__()
        self.recovery = recovery
        self.key = None
        self.lookups = 0
        self.outcome = "succeeded"
        self.mismatch = False

    def recovery_contract_digest(self):
        return self.recovery.digest()

    async def execute_keyed(self, capability, input, ctx, key):
        self.calls += 1
        self.key = key
        raise TimeoutError("synthetic provider committed but response lost")

    async def lookup_execution(self, capability, ctx, key):
        self.lookups += 1
        assert key == self.key
        fields = key.model_dump()
        if self.mismatch:
            fields["provider_account_id"] = "wrong-account"
        return ProviderOutcome(**fields, state=self.outcome,
            result=ConnectorResult(status="success", data={"recovered": True}) if self.outcome == "succeeded" else None)


def setup(store, recovery=None):
    req = request()
    recovery = recovery or contract()
    provider = Provider(recovery)
    target = make_target(req).model_copy(update={"recovery": recovery})
    svc, _ = build_service(store, req, connector=provider, target=target)
    raw = approve(store, req, raw=req.actor.organization_id)
    result = execute(svc, req, raw)
    assert result.error.code == "OUTCOME_UNKNOWN"
    return req, provider, svc, target


def reconcile(svc, req):
    import time
    time.sleep(0.002)  # Explicit synthetic 1ms recovery interval.
    return asyncio.run(svc.execute(req, ExecutionContext(requestId=req.request_id,
        userId=req.actor.user_id, organizationId=req.actor.organization_id), allow_dispatch=False, reconcile=True))


def test_lookup_recovers_after_restart_with_original_key_and_single_effect(stores):
    store = stores()
    req, provider, _, target = setup(store)
    receipt = store.get_receipt(req.actor.organization_id, req.operation_id)
    assert receipt.provider_key == provider.key.provider_key
    assert receipt.recovery_contract_digest == target.recovery.digest()
    reopened, _ = build_service(stores(), req, connector=provider, target=target)
    result = reconcile(reopened, req)
    assert result.status == "success" and result.data == {"recovered": True}
    assert result.receipt_id == receipt.receipt_id
    assert provider.calls == 1 and provider.lookups == 1
    assert reconcile(reopened, req).audit_id == result.audit_id
    assert provider.lookups == 1
    assert store.pending_receipt_audit(req.actor.organization_id)[0].decision == "reconciled"


@pytest.mark.parametrize("state", ["not_found", "pending", "unknown"])
def test_unresolved_lookup_never_reexecutes_and_budget_survives_restart(stores, state):
    store = stores()
    req, provider, svc, target = setup(store, contract(max_lookups=1))
    provider.outcome = state
    result = reconcile(svc, req)
    assert result.execution_state == ("pending" if state == "pending" else "unknown")
    reopened, _ = build_service(stores(), req, connector=provider, target=target)
    assert reconcile(reopened, req).error.code == "RECOVERY_BUDGET_EXHAUSTED"
    assert provider.calls == 1 and provider.lookups == 1


def test_lookup_rejects_provider_account_mismatch(stores):
    req, provider, svc, _ = setup(stores())
    provider.mismatch = True
    assert reconcile(svc, req).error.code == "RECOVERY_OUTCOME_MISMATCH"
    assert provider.calls == 1


def test_legacy_receipt_cannot_gain_recovery_by_configuration_change(stores):
    store = stores()
    req = request()
    svc, _ = build_service(store, req, connector=WriteConnector(fail=True))
    raw = approve(store, req, raw=req.actor.organization_id)
    assert execute(svc, req, raw).error.code == "OUTCOME_UNKNOWN"
    recovery = contract()
    provider = Provider(recovery)
    svc, _ = build_service(store, req, connector=provider,
        target=make_target(req).model_copy(update={"recovery": recovery}))
    assert reconcile(svc, req).error.code == "RECOVERY_CONTRACT_MISMATCH"
    assert provider.calls == 0 and provider.lookups == 0


def test_reconciliation_http_requires_scope_and_organization(stores):
    req, provider, svc, _ = setup(stores())
    def client(org, scopes):
        auth = StaticBearerAuthenticator((ControlPlaneCredential(tokenSha256=hashlib.sha256(b"test-token").hexdigest(),
            subject="operator", tokenId="test", organizations=(org,), scopes=scopes),))
        app = FastAPI()
        app.include_router(build_execution_router(svc, auth))
        return TestClient(app)
    body = {"request": req.model_dump(by_alias=True), "context": {"requestId": req.request_id,
        "userId": req.actor.user_id, "organizationId": req.actor.organization_id}}
    for org, scopes in [("other-org", ("executions:reconcile",)),
                         (req.actor.organization_id, ("connectors:review",))]:
        with client(org, scopes) as http:
            assert http.post("/v1/control-plane/executions/reconcile", json=body,
                headers={"Authorization": "Bearer test-token"}).status_code == 403
    with client(req.actor.organization_id, ("executions:reconcile",)) as http:
        assert http.post("/v1/control-plane/executions/reconcile", json=body).status_code == 401
        response = http.post("/v1/control-plane/executions/reconcile", json=body,
            headers={"Authorization": "Bearer test-token"})
        assert response.status_code == 200 and response.json()["status"] == "success"
    assert provider.calls == 1 and provider.lookups == 1


def test_expired_lookup_window_and_changed_actor_never_contact_provider(stores, monkeypatch):
    store = stores()
    req, provider, svc, _ = setup(store)
    other = req.model_copy(deep=True)
    other.actor.user_id = "other"
    assert reconcile(svc, other).error.code == "EXECUTION_TARGET_DENIED"
    with monkeypatch.context() as patch:
        patch.setattr("universal_connection_service.receipt_store.utc_now", lambda: utc_now() + timedelta(hours=2))
        assert reconcile(svc, req).error.code == "RECOVERY_BUDGET_EXHAUSTED"
    assert provider.lookups == 0


def test_final_no_effect_requires_prevention_of_late_execution(stores):
    from pydantic import ValidationError
    req, provider, svc, _ = setup(stores())
    failure = ConnectorResult(status="failed", error={"code": "PROVIDER_REJECTED", "message": "Rejected"})
    with pytest.raises(ValidationError):
        ProviderOutcome(**provider.key.model_dump(), state="failed_no_effect", result=failure)
    async def final_failure(capability, ctx, key):
        provider.lookups += 1
        return ProviderOutcome(**key.model_dump(), state="failed_no_effect", result=failure,
            lateExecutionPrevented=True)
    provider.lookup_execution = final_failure
    result = reconcile(svc, req)
    assert result.execution_state == "failed_no_effect"
    assert result.error.code == "PROVIDER_REJECTED"
    assert execute(svc, req, approval=None).execution_state == "failed_no_effect"
    assert provider.calls == 1 and provider.lookups == 1


class FileProvider(Provider):
    def __init__(self, recovery, path):
        super().__init__(recovery)
        self.path = path

    async def execute_keyed(self, capability, input, ctx, key):
        import os
        with sqlite3.connect(self.path) as conn:
            conn.execute("CREATE TABLE effects (provider_key TEXT PRIMARY KEY, account TEXT, binding TEXT)")
            conn.execute("INSERT INTO effects VALUES (?, ?, ?)",
                (key.provider_key, key.provider_account_id, key.binding_digest))
        os._exit(42)

    async def lookup_execution(self, capability, ctx, key):
        self.lookups += 1
        with sqlite3.connect(self.path) as conn:
            row = conn.execute("SELECT account, binding FROM effects WHERE provider_key = ?",
                (key.provider_key,)).fetchone()
        assert row == (key.provider_account_id, key.binding_digest)
        return ProviderOutcome(**key.model_dump(), state="succeeded",
            result=ConnectorResult(status="success", data={"recoveredAfterCrash": True}))


def test_process_crash_after_provider_commit_then_keyed_lookup_recovers(tmp_path, stores):
    req = request()
    initial = stores()
    backend = "sqlite" if isinstance(initial, SQLiteStateStore) else "postgres"
    store_path = initial.path if backend == "sqlite" else "postgres"
    witness_path = str(store_path) + ".witness.sqlite3" if backend == "sqlite" else str(initial.test_witness_path)
    provider_path = tmp_path / "provider.sqlite3"
    script = """
import os, sys
sys.path.insert(0, sys.argv[1])
from test_execution_recovery import *
from universal_connection_service.contracts import ConnectionRequest
req = ConnectionRequest.model_validate_json(sys.argv[4])
if sys.argv[5] == "sqlite":
    store = SQLiteStateStore(sys.argv[2])
else:
    from pydantic import SecretStr
    from universal_connection_service.postgres_store import PostgresStateStore, PostgresStoreConfig
    store = PostgresStateStore(PostgresStoreConfig(
        dsn=SecretStr(os.environ["UCS_TEST_POSTGRES_URL"]), sslmode="disable"))
    store.test_witness_path = sys.argv[6]
recovery = contract()
provider = FileProvider(recovery, sys.argv[3])
target = make_target(req).model_copy(update={"recovery": recovery})
svc, _ = build_service(store, req, connector=provider, target=target)
raw = approve(store, req, raw=req.actor.organization_id)
execute(svc, req, raw)
"""
    child = subprocess.run([sys.executable, "-c", script, str(Path(__file__).parent),
        str(store_path), str(provider_path), req.model_dump_json(), backend, witness_path],
        capture_output=True, timeout=30)
    assert child.returncode == 42, child.stderr.decode(errors="replace")
    store = stores()
    provider = FileProvider(contract(), provider_path)
    target = make_target(req).model_copy(update={"recovery": contract()})
    svc, _ = build_service(store, req, connector=provider, target=target)
    result = reconcile(svc, req)
    assert result.status == "success" and result.data == {"recoveredAfterCrash": True}
    with sqlite3.connect(provider_path) as conn:
        assert conn.execute("SELECT count(*) FROM effects").fetchone()[0] == 1
    assert provider.lookups == 1
    store.close()
