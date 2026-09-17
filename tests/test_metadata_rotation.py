from types import SimpleNamespace

import pytest

from test_metadata_storage import repositories, cipher
from test_encrypted_receipt_store import encrypted_stores
from test_durable_execution import request, approve, build_service, execute
from universal_connection_service.metadata_storage import MetadataRepository
from universal_connection_service.metadata_rotation import rotate_metadata_batch
from universal_connection_service.metadata_crypto import MetadataCryptoError
from universal_connection_service.encrypted_receipt_store import EncryptedStateStore
from universal_connection_service.encrypted_witness import EncryptedDispatchWitness


@pytest.fixture(params=["sqlite", "postgres"])
def stores(request, tmp_path):
    # Rotation changes a whole profile, so tenant-level fixture isolation is
    # insufficient. Never rotate the shared PostgreSQL regression database.
    import os
    from uuid import uuid4
    from universal_connection_service.persistence import SQLiteStateStore
    opened = []
    postgres = request.param == "postgres"
    if postgres:
        dsn = os.getenv("UCS_TEST_POSTGRES_URL")
        if not dsn:
            pytest.skip("PostgreSQL not configured")
        import psycopg
        from psycopg import sql
        from psycopg.conninfo import make_conninfo
        from pydantic import SecretStr
        from universal_connection_service.postgres_store import PostgresStateStore, PostgresStoreConfig
        database = "ucs_rotation_test_" + uuid4().hex
        with psycopg.connect(dsn, autocommit=True) as admin:
            admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(database)))
        isolated_dsn = make_conninfo(dsn, dbname=database)
    def factory():
        store = (PostgresStateStore(PostgresStoreConfig(dsn=SecretStr(isolated_dsn), sslmode="disable", autoMigrate=True))
                 if postgres else SQLiteStateStore(tmp_path / "rotation.sqlite3"))
        opened.append(store)
        return store
    try:
        yield factory
    finally:
        for store in opened:
            store.close()
        if postgres:
            with psycopg.connect(dsn, autocommit=True) as admin:
                admin.execute(sql.SQL("DROP DATABASE {}").format(sql.Identifier(database)))


def new_cipher(*, retire=False):
    return cipher(keys={"new": b"n" * 32} if retire else {"initial": b"d" * 32, "new": b"n" * 32}, active_key="new")


def pass_all(repo, *, verify_only=False, limit=1):
    cursor = None
    batches = []
    while True:
        batch = rotate_metadata_batch(repo, cursor=cursor, limit=limit, verify_only=verify_only)
        assert batch.scanned <= limit
        batches.append(batch)
        cursor = batch.cursor
        if cursor is None:
            return batches


def test_rotation_preserves_receipt_witness_and_retry(encrypted_stores):
    store = encrypted_stores()
    req = request()
    raw = approve(store, req, raw=req.actor.organization_id)
    service, provider = build_service(store, req)
    first = execute(service, req, raw)
    assert first.status == "success"
    original = store.get_receipt(req.actor.organization_id, req.operation_id)
    witness = store._test_witness
    primary_repo = MetadataRepository(store.repository.store, new_cipher(), store.repository.profile_id)
    witness_repo = MetadataRepository(witness.store, new_cipher(), witness.repository.profile_id)
    for repo in (primary_repo, witness_repo):
        batches = pass_all(repo)
        assert sum(batch.changed for batch in batches) > 0
        assert all(set(batch.key_counts) <= {"new"} for batch in batches)
        assert all(batch.changed == 0 for batch in pass_all(repo, verify_only=True))
    reopened = EncryptedStateStore(MetadataRepository(primary_repo.store, new_cipher(retire=True), primary_repo.profile_id))
    reopened._test_witness = EncryptedDispatchWitness(
        MetadataRepository(witness_repo.store, new_cipher(retire=True), witness_repo.profile_id), witness.witness_id)
    assert reopened.get_receipt(req.actor.organization_id, req.operation_id) == original
    recovered, unused = build_service(reopened, req)
    result = execute(recovered, req, raw)
    assert result.status == "success" and result.receipt_id == first.receipt_id
    assert provider.calls == 1 and unused.calls == 0
    assert reopened.deliver_receipt_audit(req.actor.organization_id) == 1


def test_partial_rotation_resumes_and_missing_old_key_fails_closed(repositories):
    repo = repositories()
    with repo.transaction() as conn:
        for op in ("a", "b", "c"):
            assert repo.insert(conn, "receipt", "org", (op,), op.encode())
    rotated = repositories(new_cipher())
    first = rotate_metadata_batch(rotated, limit=1)
    assert first.scanned == first.changed == 1
    with pytest.raises(MetadataCryptoError):
        repositories(new_cipher(retire=True))
    reopened = repositories(new_cipher())
    cursor = first.cursor
    while cursor is not None:
        cursor = rotate_metadata_batch(reopened, cursor=cursor, limit=1).cursor
    final = repositories(new_cipher(retire=True))
    with final.transaction() as conn:
        for op in ("a", "b", "c"):
            assert final.get(conn, "receipt", "org", (op,)).body == op.encode()
    assert all(batch.changed == 0 for batch in pass_all(final))


def test_verify_only_counts_old_keys_without_modifying(repositories):
    repo = repositories()
    with repo.transaction() as conn:
        repo.insert(conn, "receipt", "org", ("op",), b"body")
    batches = pass_all(repositories(new_cipher()), verify_only=True)
    assert sum(batch.scanned for batch in batches) == 3
    assert sum(batch.changed for batch in batches) == 0
    assert all(set(batch.key_counts) <= {"initial"} for batch in batches)
    with repositories().transaction() as conn:
        assert repo.get(conn, "receipt", "org", ("op",)).body == b"body"


@pytest.mark.parametrize("failure", ["cas", "corrupt"])
def test_rotation_failure_rolls_back_entire_batch(repositories, monkeypatch, failure):
    repo = repositories()
    with repo.transaction() as conn:
        for op in ("a", "b"):
            repo.insert(conn, "receipt", "org", (op,), op.encode())
        rows = repo.store._receipt_query(conn, "SELECT * FROM metadata_document ORDER BY record_index").fetchall()
        if failure == "corrupt":
            repo.store._receipt_query(conn, "UPDATE metadata_document SET envelope = ? WHERE record_index = ?",
                                      ("invalid", rows[-1]["record_index"]))
    rotated = repositories(new_cipher())
    original = rotated.store._receipt_query
    updates = 0
    def conflict(conn, sql, args=()):
        nonlocal updates
        if "UPDATE metadata_document SET revision" in sql:
            updates += 1
            if updates == 2:
                return SimpleNamespace(rowcount=0)
        return original(conn, sql, args)
    if failure == "cas":
        monkeypatch.setattr(rotated.store, "_receipt_query", conflict)
    with pytest.raises(MetadataCryptoError):
        rotate_metadata_batch(rotated)
    with repo.transaction() as conn:
        preserved = repo.store._receipt_query(conn, "SELECT * FROM metadata_document WHERE record_index = ?",
                                            (rows[0]["record_index"],)).fetchone()
    assert dict(preserved) == dict(rows[0])
