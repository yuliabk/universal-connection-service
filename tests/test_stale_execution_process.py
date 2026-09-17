"""A live old process must neither duplicate effects nor overwrite recovery."""
import json
import queue
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from test_receipts import stores
from test_durable_execution import request, approve, make_target, build_service
from test_execution_replay import DeduplicatingProvider, replay_contract, replay
from universal_connection_service.persistence import SQLiteStateStore


WORKER = r"""
import os, sys
sys.path.insert(0, sys.argv[1])
from test_execution_replay import *
from universal_connection_service.contracts import ConnectionRequest
from universal_connection_service.persistence import SQLiteStateStore
req = ConnectionRequest.model_validate_json(sys.argv[4])
from process_store_helpers import open_process_store
store = open_process_store(sys.argv[2], sys.argv[5], sys.argv[6])
recovery = replay_contract()
class SuspendedProvider(DeduplicatingProvider):
    async def execute_keyed(self, capability, input, ctx, key):
        if sys.argv[7] == 'after_effect':
            try:
                await super().execute_keyed(capability, input, ctx, key)
            except TimeoutError:
                pass
        print('READY', flush=True)
        assert (await asyncio.to_thread(sys.stdin.readline)).strip() == 'release'
        if sys.argv[7] == 'before_effect':
            await super().execute_keyed(capability, input, ctx, key)
        # Deliberately distinguish this obsolete completion from the winner.
        return ConnectorResult(status='success', data={'effect': 'late-stale-result'})
provider = SuspendedProvider(sys.argv[3], recovery)
target = make_target(req).model_copy(update={'recovery': recovery})
svc, _ = build_service(store, req, connector=provider, target=target)
result = execute(svc, req, req.actor.organization_id, deadlineMs=60000)
print(result.model_dump_json(), flush=True)
store.close()
"""


@pytest.mark.parametrize("pause", ["before_effect", "after_effect"])
def test_live_old_process_cannot_overwrite_replay_or_duplicate_effect(stores, tmp_path, pause):
    initial = stores()
    req = request()
    raw = approve(initial, req, raw=req.actor.organization_id)
    backend = "postgres" if hasattr(initial, "config") else "sqlite"
    location = initial.path if backend == "sqlite" else "postgres"
    witness = str(location) + ".witness.sqlite3" if backend == "sqlite" else str(initial.test_witness_path)
    provider_path = tmp_path / "provider.sqlite3"
    provider = DeduplicatingProvider(provider_path, replay_contract())
    child = subprocess.Popen([sys.executable, "-c", WORKER, str(Path(__file__).parent),
        str(location), str(provider_path), req.model_dump_json(), backend, witness, pause],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    messages = queue.Queue()
    reader = threading.Thread(target=lambda: messages.put(child.stdout.readline()), daemon=True)
    reader.start()
    try:
        assert messages.get(timeout=20).strip() == "READY"
        assert child.poll() is None  # Recovery overlaps an actual live old worker.
        receipt = initial.get_receipt(req.actor.organization_id, req.operation_id)
        assert receipt.state == "dispatching" and receipt.attempt_count == 1
        target = make_target(req).model_copy(update={"recovery": replay_contract()})
        service, _ = build_service(stores(), req, connector=provider, target=target)
        winner = replay(service, req, raw)
        if pause == "before_effect":
            assert winner.error.code == "OUTCOME_UNKNOWN"  # First provider response is lost.
            winner = replay(service, req, raw)
        assert winner.status == "success" and winner.data == {"effect": "original"}
        final = initial.get_receipt(req.actor.organization_id, req.operation_id)
        stdout, stderr = child.communicate(input="release\n", timeout=20)
        assert child.returncode == 0, stderr
        assert json.loads(stdout)["data"] != {"effect": "late-stale-result"}
        assert initial.get_receipt(req.actor.organization_id, req.operation_id) == final
        assert provider.counts() == (1, 3 if pause == "before_effect" else 2)
        assert len(initial.pending_receipt_audit(req.actor.organization_id)) == 1
    finally:
        if child.poll() is None:
            child.kill()
            child.communicate(timeout=10)
        reader.join(timeout=1)
