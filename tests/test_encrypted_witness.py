import pytest

from test_encrypted_receipt_store import encrypted_stores, repositories, stores
from test_durable_execution import request, approve, build_service, execute
from test_dispatch_witness import test_witness_failure_or_lost_ack_prevents_provider_io as witness_failure_case
from test_metadata_storage import cipher
from universal_connection_service.dispatch_witness import DispatchWitness
from universal_connection_service.encrypted_witness import EncryptedDispatchWitness
from universal_connection_service.encrypted_receipt_store import EncryptedStateStore
from universal_connection_service.metadata_storage import MetadataRepository
from universal_connection_service.persistence import SQLiteStateStore
from universal_connection_service.receipts import ReceiptError


@pytest.mark.parametrize("restore", ["missing", "prepared"])
def test_encrypted_witness_quarantines_primary_data_loss(encrypted_stores, restore):
    store = encrypted_stores()
    req = request()
    raw = approve(store, req, raw=req.actor.organization_id)
    svc, provider = build_service(store, req)
    assert execute(svc, req, raw).status == "success"
    final = store.get_receipt(req.actor.organization_id, req.operation_id)
    with store.repository.transaction() as conn:
        document = store.repository.get(conn, "receipt", req.actor.organization_id, (req.operation_id,))
        if restore == "missing":
            assert store.repository.delete(conn, "receipt", req.actor.organization_id, (req.operation_id,), document.revision)
        else:
            old = final.model_copy(update={"state": "prepared", "version": 0, "attempt_count": 0,
                                          "attempt_id": None, "audit_id": None, "approval_ref_hash": None})
            assert store.repository.compare_and_swap(conn, "receipt", req.actor.organization_id, (req.operation_id,),
                document.revision, old.model_dump_json().encode())
    replacement = approve(store, req, raw=raw + "-replacement")
    reopened, new_provider = build_service(encrypted_stores(), req)
    assert execute(reopened, req, replacement).error.code == "EXECUTION_RESTORE_QUARANTINED"
    assert provider.calls == 1 and new_provider.calls == 0
    witness = reopened.durable_executor.witness
    with witness.repository.transaction() as conn:
        rows = witness.store._receipt_query(conn, "SELECT * FROM metadata_document").fetchall()
    assert req.actor.organization_id not in repr([dict(row) for row in rows])
    assert final.provider_key not in repr([dict(row) for row in rows])


@pytest.mark.parametrize("committed", [False, True])
def test_encrypted_witness_failure_blocks_io(encrypted_stores, monkeypatch, committed):
    witness_failure_case(encrypted_stores, monkeypatch, committed)


def test_encrypted_witness_cannot_be_reset_or_share_primary_database(encrypted_stores):
    primary = encrypted_stores()
    witness = primary._test_witness
    witness.assert_independent(primary)
    with pytest.raises(ReceiptError, match="IDENTITY_MISMATCH"):
        EncryptedDispatchWitness(witness.repository, "wrong-identity")
    with pytest.raises(ReceiptError, match="NOT_EMPTY"):
        EncryptedDispatchWitness.initialize(witness.repository, "replacement")
    with pytest.raises(ValueError, match="separate"):
        witness.assert_independent(EncryptedStateStore(witness.repository))


def test_encrypted_provisioning_does_not_reset_a_legacy_witness(tmp_path):
    store = SQLiteStateStore(tmp_path / "existing-witness.sqlite3")
    try:
        DispatchWitness.initialize(store, "existing-identity")
        MetadataRepository.provision(store, cipher(), "new-encrypted-area")
        repository = MetadataRepository(store, cipher(), "new-encrypted-area")
        with pytest.raises(ReceiptError, match="NOT_EMPTY"):
            EncryptedDispatchWitness.initialize(repository, "must-not-reset")
        DispatchWitness(store, "existing-identity")
    finally:
        store.close()
