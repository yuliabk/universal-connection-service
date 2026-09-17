"""Real process exits at the remaining durable execution boundaries."""
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

from test_receipts import stores
from test_durable_execution import request, build_service, execute, WriteConnector
from universal_connection_service.contracts import ConnectorResult
from universal_connection_service.persistence import SQLiteStateStore


class LedgerProvider(WriteConnector):
    def __init__(self, path):
        super().__init__()
        self.path = path
        with sqlite3.connect(path) as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS effects (id INTEGER PRIMARY KEY)")

    async def execute(self, capability, input, ctx):
        self.calls += 1
        with sqlite3.connect(self.path) as conn:
            conn.execute("INSERT INTO effects DEFAULT VALUES")
        return ConnectorResult(status="success", data={"committed": True})


WORKER = r'''
import os, sys
sys.path.insert(0, sys.argv[1])
from test_execution_crash_matrix import *
from test_durable_execution import approve
from universal_connection_service.contracts import ConnectionRequest
req = ConnectionRequest.model_validate_json(sys.argv[4])
from process_store_helpers import open_process_store
store = open_process_store(sys.argv[2], sys.argv[5], sys.argv[6])
phase = sys.argv[7]
method = {'before_intent': 'prepare_receipt', 'after_intent': 'prepare_receipt',
          'after_dispatch': 'begin_dispatch', 'after_result': 'complete_receipt'}.get(phase)
if method:
    original = getattr(store, method)
    def crash(*args, **kwargs):
        if phase != 'before_intent':
            original(*args, **kwargs)
        os._exit(42)
    setattr(store, method, crash)
raw = approve(store, req, raw=req.actor.organization_id)
svc, _ = build_service(store, req, connector=LedgerProvider(sys.argv[3]))
if phase == 'after_witness':
    record = svc.durable_executor.witness.record_dispatch
    def witness_crash(*args):
        record(*args)
        os._exit(42)
    svc.durable_executor.witness.record_dispatch = witness_crash
assert execute(svc, req, raw).status == 'success'
assert phase == 'after_audit_ack'
store.deliver_receipt_audit(req.actor.organization_id)
os._exit(42)
'''


@pytest.mark.parametrize("phase", ["before_intent", "after_intent", "after_dispatch", "after_witness", "after_result", "after_audit_ack"])
def test_crash_boundary_never_duplicates_provider_effect(stores, tmp_path, phase):
    initial = stores()
    req = request()
    backend = "postgres" if hasattr(initial, "config") else "sqlite"
    location = initial.path if backend == "sqlite" else "postgres"
    witness = str(location) + ".witness.sqlite3" if backend == "sqlite" else str(initial.test_witness_path)
    ledger = tmp_path / "provider.sqlite3"
    child = subprocess.run([sys.executable, "-c", WORKER, str(Path(__file__).parent), str(location),
        str(ledger), req.model_dump_json(), backend, witness, phase], capture_output=True, timeout=30)
    assert child.returncode == 42, child.stderr.decode(errors="replace")
    reopened = stores()
    provider = LedgerProvider(ledger)
    svc, _ = build_service(reopened, req, connector=provider)
    result = execute(svc, req, req.actor.organization_id)
    if phase in {"after_dispatch", "after_witness"}:
        # Witness was not committed: restore quarantine safely blocks this gap.
        assert result.status == "failed"
        assert result.error.code == ("EXECUTION_RESTORE_QUARANTINED" if phase == "after_dispatch" else "OUTCOME_UNKNOWN")
        assert provider.calls == 0
    else:
        assert result.status == "success"
        assert provider.calls == int(phase in {"before_intent", "after_intent"})
        reopened.deliver_receipt_audit(req.actor.organization_id)
        reopened.deliver_receipt_audit(req.actor.organization_id)
        assert len(reopened.list_audit(req.actor.organization_id)) == 1
    with sqlite3.connect(ledger) as conn:
        assert conn.execute("SELECT count(*) FROM effects").fetchone()[0] == int(phase not in {"after_dispatch", "after_witness"})
