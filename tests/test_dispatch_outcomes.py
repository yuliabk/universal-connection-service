import pytest

from test_receipts import stores
from test_durable_execution import request, approve, make_target, build_service, execute
from test_execution_recovery import Provider, contract, reconcile
from test_execution_replay import replay, replay_contract
from universal_connection_service.contracts import ConnectorResult
from universal_connection_service.recovery import ProviderOutcome


class AsyncProvider(Provider):
    state = "pending"
    corrupt = None

    async def execute_keyed(self, capability, input, ctx, key):
        self.calls += 1
        self.key = key
        result = None
        if self.state == "succeeded":
            result = ConnectorResult(status="success", data={"final": True})
        elif self.state == "failed_no_effect":
            result = ConnectorResult(status="failed", error={"code": "REJECTED", "message": "Synthetic rejection"})
        outcome = ProviderOutcome(**key.model_dump(), state=self.state, result=result,
            lateExecutionPrevented=self.state == "failed_no_effect")
        if self.corrupt:
            setattr(outcome, *self.corrupt)
        return outcome


def setup(store, *, structured=True):
    req = request()
    recovery = replay_contract().model_copy(update={"dispatch_outcomes": structured})
    provider = AsyncProvider(recovery)
    target = make_target(req).model_copy(update={"recovery": recovery, "success_is_final": not structured})
    svc, _ = build_service(store, req, connector=provider, target=target)
    raw = approve(store, req, raw=req.actor.organization_id)
    return req, provider, target, svc, raw


def test_pending_survives_restart_and_only_lookup_can_advance(stores):
    store = stores()
    req, provider, target, svc, raw = setup(store)
    result = execute(svc, req, raw)
    assert result.execution_state == "pending" and result.error.code == "EXECUTION_PENDING"
    assert not result.error.retryable
    assert not store.pending_receipt_audit(req.actor.organization_id)
    reopened, _ = build_service(stores(), req, connector=provider, target=target)
    assert execute(reopened, req, None).execution_state == "pending"
    assert replay(reopened, req, raw).execution_state == "pending"
    assert provider.calls == 1
    final = reconcile(reopened, req)
    assert final.status == "success" and final.receipt_id == result.receipt_id
    assert provider.calls == provider.lookups == 1
    assert len(store.pending_receipt_audit(req.actor.organization_id)) == 1


@pytest.mark.parametrize("state", ["succeeded", "failed_no_effect", "unknown", "not_found"])
def test_explicit_dispatch_outcomes_have_correct_finality(stores, state):
    store = stores()
    req, provider, _, svc, raw = setup(store)
    provider.state = state
    result = execute(svc, req, raw)
    expected = "unknown" if state == "not_found" else state
    assert result.execution_state == expected
    assert store.get_receipt(req.actor.organization_id, req.operation_id).state == expected
    assert len(store.pending_receipt_audit(req.actor.organization_id)) == int(state in {"succeeded", "failed_no_effect"})
    execute(svc, req, None)
    assert provider.calls == 1


@pytest.mark.parametrize("corrupt", [("provider_account_id", "wrong"), ("provider_key", "wrong"),
    ("binding_digest", "wrong"), ("contract_digest", "wrong"), ("late_execution_prevented", False)])
def test_unmatched_or_mutated_outcome_cannot_become_final(stores, corrupt):
    store = stores()
    req, provider, _, svc, raw = setup(store)
    provider.state = "failed_no_effect"
    provider.corrupt = corrupt
    result = execute(svc, req, raw)
    assert result.error.code == "OUTCOME_UNKNOWN"
    assert store.get_receipt(req.actor.organization_id, req.operation_id).state == "dispatching"
    assert not store.pending_receipt_audit(req.actor.organization_id)


def test_legacy_contract_cannot_gain_pending_semantics_without_review(stores):
    req, provider, _, svc, raw = setup(stores(), structured=False)
    assert execute(svc, req, raw).execution_state == "unknown"
    assert provider.calls == 1


def test_structured_contract_rejects_unqualified_success(stores):
    req, provider, _, svc, raw = setup(stores())
    async def invalid(*args):
        return ConnectorResult(status="success", data={"accepted": True})
    provider.execute_keyed = invalid
    assert execute(svc, req, raw).error.code == "OUTCOME_UNKNOWN"


def test_dispatch_outcomes_change_pinned_contract_digest():
    original = contract()
    assert original.digest() != original.model_copy(update={"dispatch_outcomes": True}).digest()


def test_process_exit_after_pending_commit_recovers_by_lookup(stores, tmp_path):
    import sqlite3
    import subprocess
    import sys
    from pathlib import Path
    from test_execution_recovery import FileProvider
    from universal_connection_service.persistence import SQLiteStateStore

    initial = stores()
    req = request()
    backend = "sqlite" if isinstance(initial, SQLiteStateStore) else "postgres"
    location = initial.path if backend == "sqlite" else "postgres"
    witness = str(location) + ".witness.sqlite3" if backend == "sqlite" else str(initial.test_witness_path)
    ledger = tmp_path / "provider.sqlite3"
    worker = r'''
import os, sys, sqlite3
sys.path.insert(0, sys.argv[1])
from test_execution_recovery import *
from universal_connection_service.contracts import ConnectionRequest
req = ConnectionRequest.model_validate_json(sys.argv[4])
if sys.argv[5] == 'sqlite':
    store = SQLiteStateStore(sys.argv[2])
else:
    from pydantic import SecretStr
    from universal_connection_service.postgres_store import PostgresStateStore, PostgresStoreConfig
    store = PostgresStateStore(PostgresStoreConfig(
        dsn=SecretStr(os.environ['UCS_TEST_POSTGRES_URL']), sslmode='disable'))
    store.test_witness_path = sys.argv[6]
recovery = contract().model_copy(update={'dispatch_outcomes': True})
class AcceptedProvider(FileProvider):
    async def execute_keyed(self, capability, input, ctx, key):
        with sqlite3.connect(self.path) as conn:
            conn.execute('CREATE TABLE effects (provider_key TEXT PRIMARY KEY, account TEXT, binding TEXT)')
            conn.execute('INSERT INTO effects VALUES (?, ?, ?)',
                (key.provider_key, key.provider_account_id, key.binding_digest))
        return ProviderOutcome(**key.model_dump(), state='pending')
provider = AcceptedProvider(recovery, sys.argv[3])
target = make_target(req).model_copy(update={'recovery': recovery, 'success_is_final': False})
svc, _ = build_service(store, req, connector=provider, target=target)
raw = approve(store, req, raw=req.actor.organization_id)
assert execute(svc, req, raw).execution_state == 'pending'
os._exit(42)
'''
    child = subprocess.run([sys.executable, "-c", worker, str(Path(__file__).parent),
        str(location), str(ledger), req.model_dump_json(), backend, witness],
        capture_output=True, timeout=30)
    assert child.returncode == 42, child.stderr.decode(errors="replace")
    reopened = stores()
    assert reopened.get_receipt(req.actor.organization_id, req.operation_id).state == "pending"
    recovery = contract().model_copy(update={"dispatch_outcomes": True})
    provider = FileProvider(recovery, ledger)
    target = make_target(req).model_copy(update={"recovery": recovery, "success_is_final": False})
    svc, _ = build_service(reopened, req, connector=provider, target=target)
    assert execute(svc, req, None).execution_state == "pending"
    result = reconcile(svc, req)
    assert result.status == "success" and result.data == {"recoveredAfterCrash": True}
    assert provider.calls == 0 and provider.lookups == 1
    with sqlite3.connect(ledger) as conn:
        assert conn.execute("SELECT count(*) FROM effects").fetchone()[0] == 1
    assert len(reopened.pending_receipt_audit(req.actor.organization_id)) == 1
