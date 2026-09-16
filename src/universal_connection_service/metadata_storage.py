"""Transactional encrypted document storage shared by SQLite and PostgreSQL.

This is a persistence building block, not an encrypted StateStore implementation.
Callers own domain transitions and must use one transaction for related writes.
"""
from __future__ import annotations

import json
from contextlib import contextmanager
from dataclasses import dataclass

from .metadata_crypto import MetadataCipher, MetadataCryptoError


def metadata_schema(prefix: str = "") -> tuple[str, ...]:
    return (
        f"""CREATE TABLE IF NOT EXISTS {prefix}metadata_profile (
            singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
            profile_id TEXT NOT NULL,
            index_key_tag TEXT NOT NULL,
            key_probe TEXT NOT NULL
        )""",
        f"""CREATE TABLE IF NOT EXISTS {prefix}metadata_tenant (
            tenant_index TEXT PRIMARY KEY,
            envelope TEXT NOT NULL
        )""",
        f"""CREATE TABLE IF NOT EXISTS {prefix}metadata_document (
            domain TEXT NOT NULL,
            tenant_index TEXT NOT NULL,
            record_index TEXT NOT NULL,
            revision INTEGER NOT NULL CHECK (revision >= 0),
            envelope TEXT NOT NULL,
            PRIMARY KEY (domain, tenant_index, record_index),
            FOREIGN KEY (tenant_index) REFERENCES {prefix}metadata_tenant (tenant_index)
        )""",
    )


@dataclass(frozen=True)
class MetadataDocument:
    cursor: str
    revision: int
    body: bytes


class MetadataRepository:
    """AEAD documents with opaque tenant/record indexes and atomic CAS.

    Every transaction authenticates the provisioned profile before accessing
    records. Data-key rotation retains older keys until all envelopes, including
    the profile probe and tenant directory, have been re-encrypted.
    """

    def __init__(self, store, cipher: MetadataCipher, profile_id: str):
        if not store.receipts_durable or not isinstance(profile_id, str) or not 1 <= len(profile_id) <= 200:
            raise MetadataCryptoError("METADATA_PROFILE_INVALID")
        self.store, self.cipher, self.profile_id = store, cipher, profile_id
        with self.transaction():
            pass

    @staticmethod
    def provision(store, cipher: MetadataCipher, profile_id: str) -> None:
        """Explicit initialization; never invoked as fallback by the constructor.

        This reserves a new encrypted area. Legacy plaintext is not migrated or
        removed here; activation of an encrypted runtime needs a separate gate.
        """
        if not store.receipts_durable or not isinstance(profile_id, str) or not 1 <= len(profile_id) <= 200:
            raise MetadataCryptoError("METADATA_PROFILE_INVALID")
        probe = cipher.seal("profile", profile_id, ("key-probe",),
                            MetadataRepository._probe_body(cipher.configuration_tag()))
        with store._receipt_transaction() as conn:
            # A missing profile with surviving records is damaged state, not new.
            for table in ("metadata_tenant", "metadata_document"):
                if store._receipt_query(conn, f"SELECT 1 FROM {table} LIMIT 1").fetchone():
                    raise MetadataCryptoError("METADATA_PROFILE_NOT_EMPTY")
            store._receipt_query(conn, """INSERT INTO metadata_profile
                (singleton, profile_id, index_key_tag, key_probe) VALUES (1, ?, ?, ?)""",
                (profile_id, cipher.configuration_tag(), probe))

    @staticmethod
    def _probe_body(index_key_tag):
        return json.dumps(["ucs-metadata-profile-v1", index_key_tag], separators=(",", ":")).encode("ascii")

    def _verify(self, conn):
        row = self.store._receipt_query(conn, "SELECT * FROM metadata_profile WHERE singleton = 1").fetchone()
        if row is None or row["profile_id"] != self.profile_id:
            raise MetadataCryptoError("METADATA_PROFILE_MISMATCH")
        self.cipher.verify_configuration(row["index_key_tag"])
        if self.cipher.open("profile", self.profile_id, ("key-probe",), row["key_probe"]) != self._probe_body(row["index_key_tag"]):
            raise MetadataCryptoError("METADATA_PROFILE_MISMATCH")

    @contextmanager
    def transaction(self):
        with self.store._receipt_transaction() as conn:
            self._verify(conn)
            yield conn

    def _tenant_index(self, organization_id):
        return self.cipher.index("tenant", organization_id, self.profile_id)

    def _record_index(self, domain, organization_id, identity):
        if not isinstance(identity, tuple) or not identity:
            raise MetadataCryptoError("METADATA_SCOPE_INVALID")
        return self.cipher.index(domain, organization_id, self.profile_id, *identity)

    def _register_tenant(self, conn, organization_id, tenant_index):
        envelope = self.cipher.seal("tenant-directory", self.profile_id, (tenant_index,),
                                    organization_id.encode("utf-8"))
        self.store._receipt_query(conn, """INSERT INTO metadata_tenant (tenant_index, envelope)
            VALUES (?, ?) ON CONFLICT (tenant_index) DO NOTHING""", (tenant_index, envelope))
        row = self.store._receipt_query(conn, "SELECT envelope FROM metadata_tenant WHERE tenant_index = ?", (tenant_index,)).fetchone()
        if (row is None or self.cipher.open("tenant-directory", self.profile_id, (tenant_index,), row["envelope"])
            != organization_id.encode("utf-8")):
            raise MetadataCryptoError("METADATA_TENANT_MISMATCH")

    def _open_document(self, domain, organization_id, row):
        body = self.cipher.open(domain, organization_id,
            (self.profile_id, row["record_index"], str(row["revision"])), row["envelope"])
        return MetadataDocument(row["record_index"], row["revision"], body)

    def get(self, conn, domain: str, organization_id: str, identity: tuple[str, ...], *, lock: bool = False) -> MetadataDocument | None:
        tenant_index = self._tenant_index(organization_id)
        record_index = self._record_index(domain, organization_id, identity)
        if lock:
            # Portable row lock: PostgreSQL serializes contenders until commit;
            # SQLite already holds BEGIN IMMEDIATE. Do not advance the revision.
            self.store._receipt_query(conn, """UPDATE metadata_document SET revision = revision
                WHERE domain = ? AND tenant_index = ? AND record_index = ?""",
                (domain, tenant_index, record_index))
        row = self.store._receipt_query(conn, """SELECT record_index, revision, envelope FROM metadata_document
            WHERE domain = ? AND tenant_index = ? AND record_index = ?""",
            (domain, tenant_index, record_index)).fetchone()
        return self._open_document(domain, organization_id, row) if row else None

    def insert(self, conn, domain: str, organization_id: str, identity: tuple[str, ...], body: bytes) -> bool:
        tenant_index = self._tenant_index(organization_id)
        record_index = self._record_index(domain, organization_id, identity)
        envelope = self.cipher.seal(domain, organization_id, (self.profile_id, record_index, "0"), body)
        self._register_tenant(conn, organization_id, tenant_index)
        return self.store._receipt_query(conn, """INSERT INTO metadata_document
            (domain, tenant_index, record_index, revision, envelope) VALUES (?, ?, ?, 0, ?)
            ON CONFLICT (domain, tenant_index, record_index) DO NOTHING""",
            (domain, tenant_index, record_index, envelope)).rowcount == 1

    def compare_and_swap(self, conn, domain: str, organization_id: str, identity: tuple[str, ...],
                         expected_revision: int, body: bytes) -> bool:
        if type(expected_revision) is not int or expected_revision < 0:
            raise ValueError("nonnegative revision required")
        tenant_index = self._tenant_index(organization_id)
        record_index = self._record_index(domain, organization_id, identity)
        revision = expected_revision + 1
        envelope = self.cipher.seal(domain, organization_id, (self.profile_id, record_index, str(revision)), body)
        return self.store._receipt_query(conn, """UPDATE metadata_document SET revision = ?, envelope = ?
            WHERE domain = ? AND tenant_index = ? AND record_index = ? AND revision = ?""",
            (revision, envelope, domain, tenant_index, record_index, expected_revision)).rowcount == 1

    def page(self, conn, domain: str, organization_id: str, *, after: str = "", limit: int = 100) -> list[MetadataDocument]:
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("limit must be between 1 and 100")
        rows = self.store._receipt_query(conn, """SELECT record_index, revision, envelope FROM metadata_document
            WHERE domain = ? AND tenant_index = ? AND record_index > ? ORDER BY record_index LIMIT ?""",
            (domain, self._tenant_index(organization_id), after, limit)).fetchall()
        return [self._open_document(domain, organization_id, row) for row in rows]

    def tenant_page(self, conn, *, after: str = "", limit: int = 100) -> list[tuple[str, str]]:
        """Host maintenance only; not an API for tenants to enumerate each other."""
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("limit must be between 1 and 100")
        rows = self.store._receipt_query(conn, """SELECT tenant_index, envelope FROM metadata_tenant
            WHERE tenant_index > ? ORDER BY tenant_index LIMIT ?""", (after, limit)).fetchall()
        result = []
        for row in rows:
            organization_id = self.cipher.open("tenant-directory", self.profile_id,
                (row["tenant_index"],), row["envelope"]).decode("utf-8")
            if self._tenant_index(organization_id) != row["tenant_index"]:
                raise MetadataCryptoError("METADATA_TENANT_MISMATCH")
            result.append((row["tenant_index"], organization_id))
        return result
