"""Offline legacy-to-encrypted copy. Never dispatches, resets or deletes sources."""
from collections import Counter
from contextlib import ExitStack
from dataclasses import dataclass
from itertools import combinations
import json
from types import SimpleNamespace
from uuid import uuid4

from .approvals import ApprovalRecord
from .contracts import ConnectorManifest, ConnectorResult
from .dispatch_witness import DispatchWitness
from .encrypted_control_store import _body, _DIRECTORY
from .encrypted_receipt_store import _json
from .encrypted_witness import _WITNESS
from .metadata_crypto import MetadataCryptoError
from .metadata_storage import MetadataRepository
from .persistence import ConnectorStateRecord, EvidenceRecord, AuditEvent, ConnectionWorkflowRecord
from .receipts import ExecutionReceipt, ReceiptAudit
from .storage_runtime import assert_legacy_empty


_TABLE_KEYS = {
    "connector_state": ("organization_id", "connector_id", "version"),
    "evidence": ("evidence_id",), "audit_event": ("audit_id",),
    "approval_grant": ("approval_ref_hash",), "connection_workflow": ("workflow_id",),
    "execution_receipt": ("organization_id", "operation_id"),
    "execution_attempt": ("organization_id", "attempt_id"),
    "execution_outbox": ("organization_id", "event_id"),
    "execution_result": ("organization_id", "operation_id"),
    "execution_notice": ("organization_id", "receipt_id", "code"),
    "dispatch_witness_attempt": ("organization_id", "operation_id", "attempt_count"),
}


@dataclass(frozen=True)
class MigrationTarget:
    store: object
    cipher: object
    profile_id: str


class _PendingRepository(MetadataRepository):
    def __init__(self, target, migration_id):
        self.migration_id = migration_id
        super().__init__(target.store, target.cipher, target.profile_id)

    def _probe_body(self, tag):
        return _json(["ucs-metadata-migration-pending-v1", tag, self.migration_id])

    @classmethod
    def create(cls, target, migration_id):
        if not isinstance(target.profile_id, str) or not 1 <= len(target.profile_id) <= 200:
            raise ValueError("invalid target profile")
        body = _json(["ucs-metadata-migration-pending-v1", target.cipher.configuration_tag(), migration_id])
        probe = target.cipher.seal("profile", target.profile_id, ("key-probe",), body)
        with target.store._receipt_transaction() as conn:
            assert_legacy_empty(target.store, conn)
            for table in ("metadata_profile", "metadata_tenant", "metadata_document"):
                if target.store._receipt_query(conn, f"SELECT 1 FROM {table} LIMIT 1").fetchone():
                    raise ValueError("migration requires an unprovisioned empty target")
            target.store._receipt_query(conn, """INSERT INTO metadata_profile
                (singleton, profile_id, index_key_tag, key_probe) VALUES (1, ?, ?, ?)""",
                (target.profile_id, target.cipher.configuration_tag(), probe))
        return cls(target, migration_id)

    def _activate(self):
        # Only the coordinator calls this after both complete verification passes.
        with self.transaction() as conn:
            probe = self.cipher.seal("profile", self.profile_id, ("key-probe",),
                MetadataRepository._probe_body(self.cipher.configuration_tag()))
            self.store._receipt_query(conn, "UPDATE metadata_profile SET key_probe = ? WHERE singleton = 1", (probe,))


def _table(store, table):
    return ("ucs_internal." if hasattr(store, "config") else "") + table


def _query(store, conn, sql, args=()):
    return conn.execute(sql.replace("?", "%s") if hasattr(store, "config") else sql, args)


def _rows(store, conn, table):
    columns = _TABLE_KEYS[table]
    after = None
    while True:
        names = ", ".join(columns)
        condition = "" if after is None else f" WHERE ({names}) > ({', '.join('?' for _ in columns)})"
        rows = _query(store, conn, f"SELECT * FROM {_table(store, table)}{condition} ORDER BY {names} LIMIT 100", after or ()).fetchall()
        for row in rows:
            yield dict(row)
        if len(rows) < 100:
            return
        after = tuple(rows[-1][key] for key in columns)


def _decoded(value):
    return json.loads(value) if isinstance(value, str) else value


def _receipt(store, conn, org, op):
    row = _query(store, conn, f"SELECT * FROM {_table(store, 'execution_receipt')} WHERE organization_id = ? AND operation_id = ?", (org, op)).fetchone()
    if row is None:
        raise ValueError("orphan execution record")
    receipt = ExecutionReceipt.model_validate(_decoded(row["receipt_json"]))
    if any(row[key] != getattr(receipt, key) for key in ("organization_id", "operation_id", "receipt_id", "state", "version")):
        raise ValueError("receipt index mismatch")
    return receipt


def _unique(domain, org, record_id, body):
    yield "locator-" + domain, _DIRECTORY, (record_id,), org.encode()
    yield domain, org, (record_id,), body


def _primary_entries(source, conn, result_cipher):
    for table, keys in _TABLE_KEYS.items():
        if table == "dispatch_witness_attempt":
            continue
        for row in _rows(source, conn, table):
            org = row["organization_id"]
            if table == "connector_state":
                manifest = ConnectorManifest.model_validate(_decoded(row["manifest_json"]))
                if (manifest.connector_id, manifest.version, manifest.service_id) != (row["connector_id"], row["version"], row["service_id"]):
                    raise ValueError("connector index mismatch")
                record = ConnectorStateRecord(organizationId=org, manifest=manifest, status=row["status"], approvalId=row["approval_id"], updatedAt=row["updated_at"])
                yield "connector", org, (manifest.connector_id, manifest.version), _body(record)
            elif table == "evidence":
                row["payload"] = _decoded(row.pop("payload_json"))
                record = EvidenceRecord.model_validate(row)
                yield from _unique("evidence", org, record.evidence_id, _body(record))
            elif table in {"audit_event", "approval_grant", "connection_workflow"}:
                model, domain, key = {"audit_event": (AuditEvent, "audit", "audit_id"),
                    "approval_grant": (ApprovalRecord, "approval", "approval_ref_hash"),
                    "connection_workflow": (ConnectionWorkflowRecord, "workflow", "workflow_id")}[table]
                record = model.model_validate(row)
                yield from _unique(domain, org, row[key], _body(record))
                if table == "connection_workflow":
                    yield "workflow-request", org, (record.request_id,), record.workflow_id.encode()
            elif table == "execution_receipt":
                record = _receipt(source, conn, org, row["operation_id"])
                yield "locator-receipt", _DIRECTORY, (record.receipt_id,), org.encode()
                yield "receipt", org, (record.operation_id,), _body(record)
                yield "receipt-id", org, (record.receipt_id,), record.operation_id.encode()
            elif table == "execution_attempt":
                receipt = _receipt(source, conn, org, row["operation_id"])
                if row["receipt_version"] > receipt.version:
                    raise ValueError("attempt is ahead of primary")
                body = dict(organizationId=org, operationId=row["operation_id"], attemptId=row["attempt_id"],
                    requestId=row["request_id"], receiptVersion=row["receipt_version"],
                    createdAt=row["created_at"].isoformat() if hasattr(row["created_at"], "isoformat") else row["created_at"])
                yield "attempt", org, (row["attempt_id"],), _json(body)
            elif table == "execution_outbox":
                event = ReceiptAudit.model_validate(_decoded(row["event_json"]))
                receipt = _receipt(source, conn, org, row["operation_id"])
                if (event.organization_id, event.operation_id, event.event_id, event.receipt_id) != (org, row["operation_id"], row["event_id"], receipt.receipt_id):
                    raise ValueError("outbox index mismatch")
                yield "outbox", org, (event.event_id,), _body(event)
                if not row["delivered"]:
                    yield "pending-outbox", org, (event.event_id,), _body(event)
            elif table == "execution_result":
                receipt = _receipt(source, conn, org, row["operation_id"])
                # Authenticate expired payloads too; do not extend their deadline.
                result_cipher.expires_at(receipt, row["ciphertext"])
                ConnectorResult.model_validate(result_cipher._decode(receipt, row["ciphertext"])["result"])
                yield "result", org, (receipt.operation_id,), row["ciphertext"].encode()
                yield "result-scan", _DIRECTORY, (receipt.receipt_id,), _json(dict(organizationId=org, operationId=receipt.operation_id, receiptId=receipt.receipt_id))
            else:
                row.pop("organization_id")
                from .execution_observability import NOTICE_CODES
                if row["code"] not in NOTICE_CODES or row["observations"] < 1:
                    raise ValueError("invalid notice")
                receipt = _query(source, conn, f"SELECT receipt_id FROM {_table(source, 'execution_receipt')} WHERE organization_id = ? AND receipt_id = ?", (org, row["receipt_id"])).fetchone()
                if receipt is None:
                    raise ValueError("orphan notice")
                yield "notice", org, (row["receipt_id"], row["code"]), _json(row)


def _witness_entries(source, conn, target, witness_id):
    yield "witness-identity", _WITNESS, ("identity",), witness_id.encode()
    for row in _rows(source, conn, "dispatch_witness_attempt"):
        receipt = ExecutionReceipt.model_validate(_decoded(row["receipt_json"]))
        if (receipt.organization_id, receipt.operation_id, receipt.attempt_count) != (row["organization_id"], row["operation_id"], row["attempt_count"]):
            raise ValueError("witness index mismatch")
        domain = target.cipher.index("witness-operation", receipt.organization_id, target.profile_id, receipt.operation_id)
        yield domain, receipt.organization_id, (str(receipt.attempt_count),), receipt.model_dump_json().encode()


def _transfer(repository, entries, *, verify=False):
    counts = Counter()
    # Each row commits independently under the pending profile. A crash leaves
    # a blocked target, never an apparently empty replacement operation space.
    for domain, org, identity, body in entries:
        with repository.transaction() as conn:
            if verify:
                doc = repository.get(conn, domain, org, identity)
                if doc is None or doc.body != body:
                    raise MetadataCryptoError("METADATA_MIGRATION_MISMATCH")
            elif not repository.insert(conn, domain, org, identity, body):
                raise MetadataCryptoError("METADATA_MIGRATION_DUPLICATE")
        counts[domain] += 1
    if verify:
        with repository.transaction() as conn:
            actual = repository.store._receipt_query(conn, "SELECT count(*) AS n FROM metadata_document").fetchone()["n"]
            if actual != sum(counts.values()):
                raise MetadataCryptoError("METADATA_MIGRATION_MISMATCH")
            tenants = repository.store._receipt_query(conn, "SELECT count(DISTINCT tenant_index) AS n FROM metadata_document").fetchone()["n"]
            cursor, seen = "", 0
            while page := repository.tenant_page(conn, after=cursor):
                seen += len(page)
                cursor = page[-1][0]
            if seen != tenants:
                raise MetadataCryptoError("METADATA_MIGRATION_MISMATCH")
    return dict(counts)


def migrate_legacy_pair(primary, witness, primary_target, witness_target, *, result_cipher, writers_stopped=False):
    """Copy a drained, frozen legacy pair into NEW, unprovisioned targets.

    Source stores must already be on the supported schema. The caller owns
    stopping all writers and in-flight provider calls and preserving backups.
    Failure leaves targets blocked; retry requires new targets, never a reset.
    """
    if writers_stopped is not True:
        raise ValueError("stop and drain writers before migration")
    sources = (primary, witness.store)
    for source in sources:
        if hasattr(source, "require_current_schema"):
            source.require_current_schema()
    for left, right in combinations((*sources, primary_target.store, witness_target.store), 2):
        DispatchWitness.assert_independent(SimpleNamespace(store=left), right)
    migration_id = str(uuid4())
    with ExitStack() as stack:
        pc, wc = (stack.enter_context(store._receipt_transaction()) for store in sources)
        for store, conn, tables in ((primary, pc, tuple(_TABLE_KEYS)[:-1]),
                                   (witness.store, wc, ("dispatch_witness_identity", "dispatch_witness_attempt"))):
            if hasattr(store, "config"):
                conn.execute("LOCK TABLE " + ", ".join(_table(store, table) for table in (*tables, "metadata_profile", "metadata_tenant", "metadata_document")) + " IN SHARE MODE")
            for table in ("metadata_tenant", "metadata_document"):
                if store._receipt_query(conn, f"SELECT 1 FROM {table} LIMIT 1").fetchone():
                    raise ValueError("source contains encrypted records")
        primary_witness = (pc.execute("SELECT to_regclass('ucs_internal.dispatch_witness_identity') AS existing").fetchone()["existing"]
                           if hasattr(primary, "config") else pc.execute("SELECT 1 FROM sqlite_master WHERE name = 'dispatch_witness_identity'").fetchone())
        if primary_witness:
            raise ValueError("source primary contains witness identity")
        for table in tuple(_TABLE_KEYS)[:-1]:
            if _query(witness.store, wc, f"SELECT 1 FROM {_table(witness.store, table)} LIMIT 1").fetchone():
                raise ValueError("source witness contains primary data")
        witness._identity(wc)
        # Compare both directions: no surviving witness may disappear merely
        # because a restored primary no longer enumerates its operation.
        previous_operation, previous_count = None, 0
        for row in _rows(witness.store, wc, "dispatch_witness_attempt"):
            operation = (row["organization_id"], row["operation_id"])
            if operation != previous_operation:
                previous_operation, previous_count = operation, 0
            if row["attempt_count"] != previous_count + 1:
                raise ValueError("source witness history is incomplete")
            previous_count = row["attempt_count"]
            receipt = _receipt(primary, pc, row["organization_id"], row["operation_id"])
            previous = ExecutionReceipt.model_validate(_decoded(row["receipt_json"]))
            if not witness._matches(receipt, previous) or receipt.attempt_count < previous.attempt_count:
                raise ValueError("source witness is ahead of primary")
        for row in _rows(primary, pc, "execution_receipt"):
            receipt = _receipt(primary, pc, row["organization_id"], row["operation_id"])
            previous = witness._latest(wc, receipt.organization_id, receipt.operation_id)
            if receipt.attempt_count and (previous is None or previous.attempt_count != receipt.attempt_count or previous.attempt_id != receipt.attempt_id):
                raise ValueError("source dispatch is not witnessed")
        pr = _PendingRepository.create(primary_target, migration_id)
        wr = _PendingRepository.create(witness_target, migration_id)
        primary_count = _transfer(pr, _primary_entries(primary, pc, result_cipher))
        witness_count = _transfer(wr, _witness_entries(witness.store, wc, witness_target, witness.witness_id))
        if (_transfer(pr, _primary_entries(primary, pc, result_cipher), verify=True) != primary_count
            or _transfer(wr, _witness_entries(witness.store, wc, witness_target, witness.witness_id), verify=True) != witness_count):
            raise MetadataCryptoError("METADATA_MIGRATION_MISMATCH")
        wr._activate()
        pr._activate()
    return {"migrationId": migration_id, "primaryDocuments": sum(primary_count.values()),
            "witnessDocuments": sum(witness_count.values())}


def main():
    """Secrets and locations are supplied by the host, never command arguments."""
    import argparse
    import base64
    import os
    from pathlib import Path
    from .execution import ResultCipher
    from .storage_runtime import metadata_configuration, _unique_object
    parser = argparse.ArgumentParser(description="Offline copy of a drained legacy primary/witness pair into fresh encrypted storage")
    parser.add_argument("--confirm-writers-stopped-and-drained", action="store_true", required=True)
    args = parser.parse_args()
    opened = []
    try:
        pc, pp = metadata_configuration("UCS_METADATA")
        wc, wp = metadata_configuration("UCS_WITNESS_METADATA")
        packet = json.loads(os.environ["UCS_RECEIPT_KEYRING_JSON"], object_pairs_hook=_unique_object)
        if set(packet) != {"activeKey", "keys"}:
            raise ValueError("invalid result keys")
        result_cipher = ResultCipher({k: base64.b64decode(v, validate=True) for k, v in packet["keys"].items()}, packet["activeKey"])
        witness_id = os.environ["UCS_EXECUTION_WITNESS_ID"]
        locations = []
        for role in ("SOURCE_PRIMARY", "SOURCE_WITNESS", "TARGET_PRIMARY", "TARGET_WITNESS"):
            location = json.loads(os.environ["UCS_MIGRATION_" + role + "_JSON"], object_pairs_hook=_unique_object)
            if not isinstance(location, dict) or set(location) not in ({"sqlitePath"}, {"postgresUrl"}):
                raise ValueError("one backend required")
            if not all(isinstance(value, str) and value for value in location.values()):
                raise ValueError("nonempty location required")
            locations.append(location)
        for number, location in enumerate(locations):
            target = number >= 2
            if "sqlitePath" in location:
                from .persistence import SQLiteStateStore
                if target:
                    with Path(location["sqlitePath"]).open("xb"):
                        pass
                physical = SQLiteStateStore(location["sqlitePath"], must_exist=True)
            else:
                from pydantic import SecretStr
                from .postgres_store import PostgresStateStore, PostgresStoreConfig
                physical = PostgresStateStore(PostgresStoreConfig(dsn=SecretStr(location["postgresUrl"]), autoMigrate=target))
            opened.append(physical)
        report = migrate_legacy_pair(opened[0], DispatchWitness(opened[1], witness_id),
            MigrationTarget(opened[2], pc, pp), MigrationTarget(opened[3], wc, wp),
            result_cipher=result_cipher, writers_stopped=args.confirm_writers_stopped_and_drained)
        print(json.dumps(report, separators=(",", ":")))
    except Exception:
        parser.exit(1, "Metadata migration failed; sources were not reset. Do not activate unverified targets.\n")
    finally:
        for physical in reversed(opened):
            physical.close()


if __name__ == "__main__":
    main()
