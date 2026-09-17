"""Bounded authenticated metadata re-encryption; never changes business identity.

All writers must use the new active key before retiring any old data key.
This maintenance API does not rotate inner execution-result encryption keys.
"""
from collections import Counter
from dataclasses import dataclass
import json

from .metadata_crypto import MetadataCryptoError


@dataclass(frozen=True)
class RotationCursor:
    phase: str = "documents"
    domain: str = ""
    tenant: str = ""
    record: str = ""


@dataclass(frozen=True)
class RotationBatch:
    cursor: RotationCursor | None
    scanned: int
    changed: int
    key_counts: dict[str, int]


def rotate_metadata_batch(repository, *, cursor=None, limit=100, verify_only=False):
    """Process at most limit selected records and return a resumable opaque cursor.

    Document batches also authenticate their tenant directory and the profile.

    key_counts describes the keys of authenticated envelopes AFTER this batch.
    None cursor means this pass reached its end, not proof against stale writers
    or old backups. Run a complete verify-only pass from the beginning after
    switching every writer, retaining all old keys until it succeeds.
    """
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError("limit must be between 1 and 100")
    cursor = cursor or RotationCursor()
    if not isinstance(cursor, RotationCursor) or cursor.phase not in {"documents", "tenants", "profile"}:
        raise ValueError("invalid rotation cursor")
    repo = repository
    query = repo.store._receipt_query
    counts = Counter()
    changed = 0
    with repo.transaction() as conn:
        if cursor.phase == "documents":
            rows = query(conn, """SELECT d.domain, d.tenant_index, d.record_index, d.revision,
                d.envelope, t.envelope AS tenant_envelope FROM metadata_document d
                LEFT JOIN metadata_tenant t ON d.tenant_index = t.tenant_index
                WHERE (d.domain, d.tenant_index, d.record_index) > (?, ?, ?)
                ORDER BY d.domain, d.tenant_index, d.record_index LIMIT ?""",
                (cursor.domain, cursor.tenant, cursor.record, limit)).fetchall()
            for row in rows:
                org = repo.cipher.open("tenant-directory", repo.profile_id,
                    (row["tenant_index"],), row["tenant_envelope"]).decode("utf-8")
                if repo._tenant_index(org) != row["tenant_index"]:
                    raise MetadataCryptoError("METADATA_TENANT_MISMATCH")
                document = repo._open_document(row["domain"], org, row)
                key = json.loads(row["envelope"])["keyId"]
                if key != repo.cipher.active_key and not verify_only:
                    revision = row["revision"] + 1
                    envelope = repo.cipher.seal(row["domain"], org,
                        (repo.profile_id, row["record_index"], str(revision)), document.body)
                    updated = query(conn, """UPDATE metadata_document SET revision = ?, envelope = ?
                        WHERE domain = ? AND tenant_index = ? AND record_index = ?
                        AND revision = ? AND envelope = ?""", (revision, envelope, row["domain"],
                        row["tenant_index"], row["record_index"], row["revision"], row["envelope"])).rowcount
                    if updated != 1:
                        raise MetadataCryptoError("METADATA_ROTATION_CONFLICT")
                    key, changed = repo.cipher.active_key, changed + 1
                counts[key] += 1
            next_cursor = (RotationCursor("documents", rows[-1]["domain"], rows[-1]["tenant_index"], rows[-1]["record_index"])
                           if len(rows) == limit else RotationCursor("tenants"))
        elif cursor.phase == "tenants":
            rows = query(conn, """SELECT tenant_index, envelope FROM metadata_tenant
                WHERE tenant_index > ? ORDER BY tenant_index LIMIT ?""", (cursor.tenant, limit)).fetchall()
            for row in rows:
                identity = (row["tenant_index"],)
                body = repo.cipher.open("tenant-directory", repo.profile_id, identity, row["envelope"])
                if repo._tenant_index(body.decode("utf-8")) != row["tenant_index"]:
                    raise MetadataCryptoError("METADATA_TENANT_MISMATCH")
                key = json.loads(row["envelope"])["keyId"]
                if key != repo.cipher.active_key and not verify_only:
                    envelope = repo.cipher.seal("tenant-directory", repo.profile_id, identity, body)
                    if query(conn, """UPDATE metadata_tenant SET envelope = ?
                        WHERE tenant_index = ? AND envelope = ?""",
                        (envelope, row["tenant_index"], row["envelope"])).rowcount != 1:
                        raise MetadataCryptoError("METADATA_ROTATION_CONFLICT")
                    key, changed = repo.cipher.active_key, changed + 1
                counts[key] += 1
            next_cursor = RotationCursor("tenants", tenant=rows[-1]["tenant_index"]) if len(rows) == limit else RotationCursor("profile")
        else:
            row = query(conn, "SELECT key_probe FROM metadata_profile WHERE singleton = 1").fetchone()
            # repo.transaction has already authenticated the probe and index key.
            key = json.loads(row["key_probe"])["keyId"]
            if key != repo.cipher.active_key and not verify_only:
                envelope = repo.cipher.seal("profile", repo.profile_id, ("key-probe",),
                    repo._probe_body(repo.cipher.configuration_tag()))
                if query(conn, """UPDATE metadata_profile SET key_probe = ?
                    WHERE singleton = 1 AND key_probe = ?""", (envelope, row["key_probe"])).rowcount != 1:
                    raise MetadataCryptoError("METADATA_ROTATION_CONFLICT")
                key, changed = repo.cipher.active_key, 1
            counts[key] += 1
            rows, next_cursor = [row], None
    return RotationBatch(next_cursor, len(rows), changed, dict(counts))
