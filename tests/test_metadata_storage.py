from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import pytest

from test_receipts import stores
from universal_connection_service.metadata_crypto import MetadataCipher, MetadataCryptoError
from universal_connection_service.metadata_storage import MetadataRepository


PROFILE = "synthetic-encrypted-storage-tests"


def cipher(**updates):
    return MetadataCipher(**(dict(keys={"initial": b"d" * 32}, active_key="initial", index_key=b"i" * 32) | updates))


@pytest.fixture
def repositories(stores):
    store = stores()
    with store._receipt_transaction() as conn:
        exists = store._receipt_query(conn, "SELECT 1 FROM metadata_profile WHERE singleton = 1").fetchone()
    if not exists:
        MetadataRepository.provision(store, cipher(), PROFILE)
    return lambda crypto=None: MetadataRepository(stores(), crypto or cipher(), PROFILE)


def test_restart_preserves_private_metadata_and_duplicate_identity(repositories):
    repo = repositories()
    org = "private-org-" + uuid4().hex
    identity = ("private-operation",)
    body = b'{"actor":"private-user","account":"private-account","amount":1234}'
    with repo.transaction() as conn:
        assert repo.insert(conn, "receipt", org, identity, body)
    reopened = repositories()
    with reopened.transaction() as conn:
        assert not reopened.insert(conn, "receipt", org, identity, b"must-not-overwrite")
        doc = reopened.get(conn, "receipt", org, identity)
        assert doc.revision == 0 and doc.body == body
        assert reopened.get(conn, "receipt", org + "-other", identity) is None
        rows = reopened.store._receipt_query(conn, "SELECT * FROM metadata_document").fetchall()
        tenants = reopened.store._receipt_query(conn, "SELECT * FROM metadata_tenant").fetchall()
    physical = repr([dict(row) for row in rows + tenants])
    assert all(secret not in physical for secret in (org, "private-operation", "private-user", "private-account"))


def test_wrong_keys_and_profile_fail_before_existing_identity_can_look_absent(repositories):
    repo = repositories()
    org = uuid4().hex
    with repo.transaction() as conn:
        repo.insert(conn, "receipt", org, ("op",), b"original")
    for wrong in (cipher(index_key=b"j" * 32), cipher(keys={"initial": b"x" * 32})):
        with pytest.raises(MetadataCryptoError):
            repositories(wrong)
    with pytest.raises(MetadataCryptoError, match="METADATA_PROFILE_MISMATCH"):
        MetadataRepository(repo.store, cipher(), "other-profile")
    with repo.transaction() as conn:
        assert repo.get(conn, "receipt", org, ("op",)).body == b"original"


def test_transaction_rolls_back_approval_and_receipt_together(repositories):
    repo = repositories()
    org = uuid4().hex
    with repo.transaction() as conn:
        repo.insert(conn, "approval", org, ("grant",), b"unconsumed")
        repo.insert(conn, "receipt", org, ("op",), b"prepared")
    with pytest.raises(RuntimeError, match="lost-before-commit"):
        with repo.transaction() as conn:
            assert repo.compare_and_swap(conn, "approval", org, ("grant",), 0, b"consumed")
            assert repo.compare_and_swap(conn, "receipt", org, ("op",), 0, b"dispatching")
            raise RuntimeError("lost-before-commit")
    with repositories().transaction() as conn:
        assert repo.get(conn, "approval", org, ("grant",)).body == b"unconsumed"
        assert repo.get(conn, "receipt", org, ("op",)).body == b"prepared"


def test_cas_has_one_winner_between_instances(repositories):
    first, second = repositories(), repositories()
    org = uuid4().hex
    with first.transaction() as conn:
        assert first.insert(conn, "receipt", org, ("op",), b"prepared")
    def claim(repo):
        with repo.transaction() as conn:
            return repo.compare_and_swap(conn, "receipt", org, ("op",), 0, b"dispatching")
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(claim, (first, second))) == [False, True]
    with first.transaction() as conn:
        assert first.get(conn, "receipt", org, ("op",)).revision == 1


def test_encrypted_tenant_directory_and_bounded_record_pagination(repositories):
    repo = repositories()
    org = uuid4().hex
    with repo.transaction() as conn:
        for n in range(5):
            repo.insert(conn, "receipt", org, (str(n),), str(n).encode())
    with repositories().transaction() as conn:
        cursor, bodies = "", []
        while page := repo.page(conn, "receipt", org, after=cursor, limit=2):
            bodies.extend(row.body for row in page)
            cursor = page[-1].cursor
        assert set(bodies) == {str(n).encode() for n in range(5)} and len(bodies) == 5
        cursor, found = "", []
        while page := repo.tenant_page(conn, after=cursor, limit=2):
            found.extend(organization for _, organization in page)
            cursor = page[-1][0]
        assert found.count(org) == 1


@pytest.mark.parametrize("damage", ["revision", "transplant"])
def test_revision_tamper_and_ciphertext_transplant_are_rejected(repositories, damage):
    repo = repositories()
    org = uuid4().hex
    with repo.transaction() as conn:
        repo.insert(conn, "receipt", org, ("op",), b"private")
        doc = repo.get(conn, "receipt", org, ("op",))
        if damage == "revision":
            repo.store._receipt_query(conn, "UPDATE metadata_document SET revision = revision + 1 WHERE record_index = ?", (doc.cursor,))
        else:
            repo.insert(conn, "receipt", org, ("another-op",), b"unrelated")
            other = repo.get(conn, "receipt", org, ("another-op",))
            row = repo.store._receipt_query(conn, "SELECT envelope FROM metadata_document WHERE record_index = ?", (other.cursor,)).fetchone()
            repo.store._receipt_query(conn, "UPDATE metadata_document SET envelope = ? WHERE record_index = ?", (row["envelope"], doc.cursor))
    with pytest.raises(MetadataCryptoError, match="METADATA_UNAVAILABLE"):
        with repo.transaction() as conn:
            repo.get(conn, "receipt", org, ("op",))


def test_key_rotation_reads_old_rows_and_keeps_cas_identity(repositories):
    repo = repositories()
    org = uuid4().hex
    with repo.transaction() as conn:
        repo.insert(conn, "receipt", org, ("op",), b"old")
    rotated = repositories(cipher(keys={"initial": b"d" * 32, "rotated": b"n" * 32}, active_key="rotated"))
    with rotated.transaction() as conn:
        assert rotated.get(conn, "receipt", org, ("op",)).body == b"old"
        assert rotated.compare_and_swap(conn, "receipt", org, ("op",), 0, b"new")
    with pytest.raises(MetadataCryptoError, match="METADATA_UNAVAILABLE"):
        with repo.transaction() as conn:
            repo.get(conn, "receipt", org, ("op",))
    with rotated.transaction() as conn:
        assert rotated.get(conn, "receipt", org, ("op",)).body == b"new"


def test_provisioning_cannot_replace_a_live_profile(repositories):
    repo = repositories()
    org = uuid4().hex
    with repo.transaction() as conn:
        repo.insert(conn, "receipt", org, ("op",), b"retained")
    with pytest.raises(MetadataCryptoError, match="METADATA_PROFILE_NOT_EMPTY"):
        MetadataRepository.provision(repo.store, cipher(index_key=b"j" * 32), "replacement")
    with repo.transaction() as conn:
        assert repo.get(conn, "receipt", org, ("op",)).body == b"retained"


def test_index_key_tag_is_authenticated_by_profile_probe(repositories):
    repo = repositories()
    wrong = cipher(index_key=b"j" * 32)
    with repo.store._receipt_transaction() as conn:
        repo.store._receipt_query(conn, "UPDATE metadata_profile SET index_key_tag = ? WHERE singleton = 1", (wrong.configuration_tag(),))
    try:
        # A database edit cannot authorize a new index key with the old probe.
        with pytest.raises(MetadataCryptoError, match="METADATA_PROFILE_MISMATCH"):
            repositories(wrong)
    finally:
        with repo.store._receipt_transaction() as conn:
            repo.store._receipt_query(conn, "UPDATE metadata_profile SET index_key_tag = ? WHERE singleton = 1", (cipher().configuration_tag(),))
