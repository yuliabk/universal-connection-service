"""Explicit synthetic witness provisioning; production never auto-provisions."""
from pathlib import Path
from universal_connection_service.persistence import SQLiteStateStore
from universal_connection_service.dispatch_witness import DispatchWitness


def witness_for(store):
    if hasattr(store, "_test_witness"):
        return store._test_witness
    path = getattr(store, "test_witness_path", None)
    if path is None:
        path = store.path + ".witness.sqlite3"
    exists = Path(path).exists()
    backing = SQLiteStateStore(path)
    if not exists:
        DispatchWitness.initialize(backing, "synthetic-witness")
    witness = DispatchWitness(backing, "synthetic-witness")
    store._test_witness = witness
    close = store.close
    def close_both():
        witness.close()
        close()
    store.close = close_both
    return witness
