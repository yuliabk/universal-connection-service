from __future__ import annotations

import argparse
import json
import os
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from pydantic import Field, SecretStr, field_validator
from .receipt_store import SQLReceiptStore, receipt_schema, receipt_result_schema
from .execution_observability import execution_notice_schema

from .approvals import ApprovalRecord, ApprovalStore
from .contracts import ConnectorManifest, Lifecycle, Model
from .persistence import (
    AuditEvent,
    AuditStore,
    ConnectionWorkflowRecord,
    ConnectorStateRecord,
    ConnectorStateStore,
    EvidenceKind,
    EvidenceRecord,
    EvidenceStore,
    WorkflowStore,
)

try:  # optional production dependency
    from psycopg.conninfo import conninfo_to_dict
    from psycopg.rows import dict_row
    from psycopg_pool import ConnectionPool
except ImportError:  # pragma: no cover - exercised when postgres extra is absent
    ConnectionPool = None  # type: ignore[assignment]
    conninfo_to_dict = None  # type: ignore[assignment]
    dict_row = None  # type: ignore[assignment]


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    statements: tuple[str, ...]


_BOOTSTRAP = (
    "CREATE SCHEMA IF NOT EXISTS ucs_internal",
    "REVOKE ALL ON SCHEMA ucs_internal FROM PUBLIC",
    """
    CREATE TABLE IF NOT EXISTS ucs_internal.schema_migration (
        version INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )
    """,
)

_MIGRATIONS = (
    Migration(
        1,
        "state_evidence_audit",
        (
            """
            CREATE TABLE IF NOT EXISTS ucs_internal.connector_state (
                organization_id TEXT NOT NULL,
                connector_id TEXT NOT NULL,
                version TEXT NOT NULL,
                service_id TEXT NOT NULL,
                status TEXT NOT NULL,
                approval_id TEXT,
                manifest_json JSONB NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL,
                PRIMARY KEY (organization_id, connector_id, version)
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_ucs_connector_org_service ON ucs_internal.connector_state (organization_id, service_id, status)",
            """
            CREATE TABLE IF NOT EXISTS ucs_internal.evidence (
                evidence_id TEXT PRIMARY KEY,
                organization_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                phase TEXT NOT NULL,
                request_id TEXT,
                connector_id TEXT,
                payload_json JSONB NOT NULL,
                created_at TIMESTAMPTZ NOT NULL
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_ucs_evidence_org_request ON ucs_internal.evidence (organization_id, request_id, created_at)",
            "CREATE INDEX IF NOT EXISTS idx_ucs_evidence_org_kind ON ucs_internal.evidence (organization_id, kind, created_at)",
            """
            CREATE TABLE IF NOT EXISTS ucs_internal.audit_event (
                audit_id TEXT PRIMARY KEY,
                request_id TEXT NOT NULL,
                organization_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                service_id TEXT NOT NULL,
                capability TEXT NOT NULL,
                operation TEXT NOT NULL,
                status TEXT NOT NULL,
                connector_id TEXT,
                policy_decision TEXT,
                error_code TEXT,
                approval_ref_hash TEXT,
                created_at TIMESTAMPTZ NOT NULL
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_ucs_audit_org_created ON ucs_internal.audit_event (organization_id, created_at)",
            "CREATE INDEX IF NOT EXISTS idx_ucs_audit_org_request ON ucs_internal.audit_event (organization_id, request_id, created_at)",
            "REVOKE ALL ON ALL TABLES IN SCHEMA ucs_internal FROM PUBLIC",
        ),
    ),
    Migration(
        2,
        "persistent_approvals",
        (
            """
            CREATE TABLE IF NOT EXISTS ucs_internal.approval_grant (
                approval_ref_hash TEXT PRIMARY KEY,
                request_id TEXT NOT NULL,
                organization_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                service_id TEXT NOT NULL,
                capability TEXT NOT NULL,
                operation TEXT NOT NULL,
                expires_at TIMESTAMPTZ NOT NULL,
                consumed_at TIMESTAMPTZ,
                created_at TIMESTAMPTZ NOT NULL
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_ucs_approval_org_request ON ucs_internal.approval_grant (organization_id, request_id, expires_at)",
            "REVOKE ALL ON ALL TABLES IN SCHEMA ucs_internal FROM PUBLIC",
        ),
    ),
    Migration(
        3,
        "resumable_connection_workflows",
        (
            """
            CREATE TABLE IF NOT EXISTS ucs_internal.connection_workflow (
                workflow_id TEXT PRIMARY KEY,
                request_id TEXT NOT NULL,
                organization_id TEXT NOT NULL,
                request_fingerprint TEXT NOT NULL,
                service_id TEXT NOT NULL,
                capability TEXT NOT NULL,
                operation TEXT NOT NULL,
                stage TEXT NOT NULL,
                selected_candidate_id TEXT,
                selected_tool TEXT,
                connector_id TEXT,
                connector_version TEXT,
                promotion_id TEXT,
                last_code TEXT,
                result_audit_id TEXT,
                revision INTEGER NOT NULL DEFAULT 0,
                lease_token TEXT,
                lease_expires_at TIMESTAMPTZ,
                created_at TIMESTAMPTZ NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL,
                UNIQUE (organization_id, request_id)
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_ucs_workflow_org_stage ON ucs_internal.connection_workflow (organization_id, stage, updated_at)",
            "REVOKE ALL ON ALL TABLES IN SCHEMA ucs_internal FROM PUBLIC",
        ),
    ),
)

_MIGRATIONS += (
    Migration(4, "durable_execution_receipts", receipt_schema("ucs_internal.") + (
        "REVOKE ALL ON ALL TABLES IN SCHEMA ucs_internal FROM PUBLIC",
    )),
    Migration(5, "execution_approval_binding_and_encrypted_results", (
        "ALTER TABLE ucs_internal.approval_grant ADD COLUMN operation_id TEXT",
        "ALTER TABLE ucs_internal.approval_grant ADD COLUMN binding_digest TEXT",
        "ALTER TABLE ucs_internal.approval_grant ADD COLUMN revoked_at TIMESTAMPTZ",
        receipt_result_schema("ucs_internal."),
        "REVOKE ALL ON ALL TABLES IN SCHEMA ucs_internal FROM PUBLIC",
    )),
)

_MIGRATIONS += (Migration(6, "execution_operational_notices", (
    execution_notice_schema("ucs_internal."),
    "REVOKE ALL ON ALL TABLES IN SCHEMA ucs_internal FROM PUBLIC",
)),)

LATEST_SCHEMA_VERSION = _MIGRATIONS[-1].version
_MIGRATION_LOCK_KEY = 814434035


class PostgresStoreConfig(Model):
    dsn: SecretStr
    min_size: int = Field(alias="minSize", default=1, ge=1, le=32)
    max_size: int = Field(alias="maxSize", default=1, ge=1, le=64)
    timeout_seconds: float = Field(alias="timeoutSeconds", default=10.0, gt=0, le=60)
    sslmode: str | None = None
    auto_migrate: bool = Field(alias="autoMigrate", default=False)

    @field_validator("sslmode")
    @classmethod
    def validate_sslmode(cls, value: str | None) -> str | None:
        if value is None:
            return value
        allowed = {"disable", "allow", "prefer", "require", "verify-ca", "verify-full"}
        if value not in allowed:
            raise ValueError("unsupported PostgreSQL sslmode")
        return value

    @field_validator("max_size")
    @classmethod
    def validate_pool_sizes(cls, value: int, info):
        min_size = info.data.get("min_size", 1)
        if value < min_size:
            raise ValueError("maxSize must be greater than or equal to minSize")
        return value


class PostgresStateStore(SQLReceiptStore, ConnectorStateStore, EvidenceStore, AuditStore, ApprovalStore, WorkflowStore):
    """PostgreSQL/Supabase implementation of UCS persistent control-plane state."""

    def __init__(self, config: PostgresStoreConfig) -> None:
        if ConnectionPool is None or conninfo_to_dict is None or dict_row is None:
            raise RuntimeError("PostgreSQL support is not installed; install universal-connection-service[postgres]")
        self.config = config
        dsn = config.dsn.get_secret_value()
        conninfo = conninfo_to_dict(dsn)
        host = str(conninfo.get("host") or "").split(",", 1)[0].strip("[]").lower()
        local = host in {"localhost", "127.0.0.1", "::1"}
        sslmode = config.sslmode or conninfo.get("sslmode") or ("disable" if local else "require")
        if not local and sslmode not in {"require", "verify-ca", "verify-full"}:
            raise ValueError("remote PostgreSQL connections must require SSL")

        self._pool = ConnectionPool(
            conninfo=dsn,
            min_size=config.min_size,
            max_size=config.max_size,
            timeout=config.timeout_seconds,
            kwargs={
                "row_factory": dict_row,
                "prepare_threshold": None,
                "connect_timeout": max(1, int(config.timeout_seconds)),
                "sslmode": sslmode,
            },
            open=True,
        )
        self._pool.wait(timeout=config.timeout_seconds)
        if config.auto_migrate:
            self.migrate()
        else:
            self.require_current_schema()

    def close(self) -> None:
        self._pool.close()

    @property
    def receipts_durable(self) -> bool:
        return True

    def _receipt_sql(self, sql: str) -> str:
        sql = sql.replace("execution_notice", "ucs_internal.execution_notice")
        for table in ("execution_receipt", "execution_attempt", "execution_outbox", "execution_result", "approval_grant", "audit_event", "dispatch_witness_identity", "dispatch_witness_attempt"):
            sql = sql.replace(table, "ucs_internal." + table)
        return sql.replace("?", "%s")

    _receipt_created_expression = "(receipt_json::jsonb ->> 'createdAt')"

    def _receipt_time(self, value):
        return value

    @contextmanager
    def _receipt_transaction(self):
        with self._pool.connection() as conn, conn.transaction():
            conn.execute("SET LOCAL synchronous_commit = on")
            yield conn

    def _migration_versions(self) -> set[int]:
        with self._pool.connection() as conn:
            try:
                rows = conn.execute(
                    "SELECT version FROM ucs_internal.schema_migration ORDER BY version"
                ).fetchall()
            except Exception:
                return set()
        return {int(row["version"]) for row in rows}

    def schema_version(self) -> int:
        versions = self._migration_versions()
        return max(versions) if versions else 0

    def require_current_schema(self) -> None:
        current = self.schema_version()
        if current != LATEST_SCHEMA_VERSION:
            raise RuntimeError(
                f"UCS PostgreSQL schema is at version {current}; run `ucs-db migrate` for version {LATEST_SCHEMA_VERSION}"
            )

    def migrate(self) -> int:
        with self._pool.connection() as conn:
            with conn.transaction():
                conn.execute("SELECT pg_advisory_xact_lock(%s)", (_MIGRATION_LOCK_KEY,))
                for statement in _BOOTSTRAP:
                    conn.execute(statement)
                applied = {
                    int(row["version"])
                    for row in conn.execute(
                        "SELECT version FROM ucs_internal.schema_migration"
                    ).fetchall()
                }
                for migration in _MIGRATIONS:
                    if migration.version in applied:
                        continue
                    for statement in migration.statements:
                        conn.execute(statement)
                    conn.execute(
                        "INSERT INTO ucs_internal.schema_migration (version, name) VALUES (%s, %s)",
                        (migration.version, migration.name),
                    )
        return self.schema_version()

    @staticmethod
    def _json(value: Any) -> str:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    @staticmethod
    def _dt(value: datetime | str | None) -> datetime | None:
        if value is None or isinstance(value, datetime):
            return value
        return datetime.fromisoformat(value)

    @classmethod
    def _workflow_from_row(cls, row: dict[str, Any]) -> ConnectionWorkflowRecord:
        return ConnectionWorkflowRecord(
            workflowId=row["workflow_id"],
            requestId=row["request_id"],
            organizationId=row["organization_id"],
            requestFingerprint=row["request_fingerprint"],
            serviceId=row["service_id"],
            capability=row["capability"],
            operation=row["operation"],
            stage=row["stage"],
            selectedCandidateId=row["selected_candidate_id"],
            selectedTool=row["selected_tool"],
            connectorId=row["connector_id"],
            connectorVersion=row["connector_version"],
            promotionId=row["promotion_id"],
            lastCode=row["last_code"],
            resultAuditId=row["result_audit_id"],
            revision=row["revision"],
            leaseToken=row["lease_token"],
            leaseExpiresAt=cls._dt(row["lease_expires_at"]),
            createdAt=cls._dt(row["created_at"]),
            updatedAt=cls._dt(row["updated_at"]),
        )

    def upsert_connector(self, record: ConnectorStateRecord) -> None:
        manifest_json = self._json(record.manifest.model_dump(by_alias=True, mode="json"))
        with self._pool.connection() as conn:
            conn.execute(
                """
                INSERT INTO ucs_internal.connector_state (
                    organization_id, connector_id, version, service_id, status,
                    approval_id, manifest_json, updated_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s)
                ON CONFLICT (organization_id, connector_id, version) DO UPDATE SET
                    service_id = excluded.service_id,
                    status = excluded.status,
                    approval_id = excluded.approval_id,
                    manifest_json = excluded.manifest_json,
                    updated_at = excluded.updated_at
                """,
                (
                    record.organization_id,
                    record.manifest.connector_id,
                    record.manifest.version,
                    record.manifest.service_id,
                    record.status,
                    record.approval_id,
                    manifest_json,
                    record.updated_at,
                ),
            )

    def update_connector_status(
        self,
        organization_id: str,
        connector_id: str,
        version: str,
        status: Lifecycle,
        approval_id: str | None = None,
    ) -> None:
        with self._pool.connection() as conn:
            cursor = conn.execute(
                """
                UPDATE ucs_internal.connector_state
                SET status = %s, approval_id = %s, updated_at = now()
                WHERE organization_id = %s AND connector_id = %s AND version = %s
                """,
                (status, approval_id, organization_id, connector_id, version),
            )
            if cursor.rowcount != 1:
                raise KeyError("connector metadata is not registered")

    def list_connectors(self, organization_id: str | None = None) -> list[ConnectorStateRecord]:
        query = "SELECT * FROM ucs_internal.connector_state"
        params: tuple[Any, ...] = ()
        if organization_id is not None:
            query += " WHERE organization_id = %s"
            params = (organization_id,)
        query += " ORDER BY organization_id, connector_id, version"
        with self._pool.connection() as conn:
            rows = conn.execute(query, params).fetchall()
        return [
            ConnectorStateRecord(
                organizationId=row["organization_id"],
                manifest=ConnectorManifest.model_validate(row["manifest_json"]),
                status=row["status"],
                approvalId=row["approval_id"],
                updatedAt=self._dt(row["updated_at"]),
            )
            for row in rows
        ]

    def append_evidence(self, record: EvidenceRecord) -> None:
        with self._pool.connection() as conn:
            conn.execute(
                """
                INSERT INTO ucs_internal.evidence (
                    evidence_id, organization_id, kind, phase, request_id,
                    connector_id, payload_json, created_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s)
                """,
                (
                    record.evidence_id,
                    record.organization_id,
                    record.kind,
                    record.phase,
                    record.request_id,
                    record.connector_id,
                    self._json(record.payload),
                    record.created_at,
                ),
            )

    def list_evidence(
        self,
        organization_id: str,
        *,
        request_id: str | None = None,
        kind: EvidenceKind | None = None,
    ) -> list[EvidenceRecord]:
        clauses = ["organization_id = %s"]
        params: list[Any] = [organization_id]
        if request_id is not None:
            clauses.append("request_id = %s")
            params.append(request_id)
        if kind is not None:
            clauses.append("kind = %s")
            params.append(kind)
        query = "SELECT * FROM ucs_internal.evidence WHERE " + " AND ".join(clauses)
        query += " ORDER BY created_at, evidence_id"
        with self._pool.connection() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()
        return [
            EvidenceRecord(
                evidenceId=row["evidence_id"],
                organizationId=row["organization_id"],
                kind=row["kind"],
                phase=row["phase"],
                requestId=row["request_id"],
                connectorId=row["connector_id"],
                payload=row["payload_json"],
                createdAt=self._dt(row["created_at"]),
            )
            for row in rows
        ]

    def append_audit(self, event: AuditEvent) -> None:
        with self._pool.connection() as conn:
            conn.execute(
                """
                INSERT INTO ucs_internal.audit_event (
                    audit_id, request_id, organization_id, user_id, agent_id,
                    service_id, capability, operation, status, connector_id,
                    policy_decision, error_code, approval_ref_hash, created_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    event.audit_id,
                    event.request_id,
                    event.organization_id,
                    event.user_id,
                    event.agent_id,
                    event.service_id,
                    event.capability,
                    event.operation,
                    event.status,
                    event.connector_id,
                    event.policy_decision,
                    event.error_code,
                    event.approval_ref_hash,
                    event.created_at,
                ),
            )

    def list_audit(self, organization_id: str, *, request_id: str | None = None) -> list[AuditEvent]:
        query = "SELECT * FROM ucs_internal.audit_event WHERE organization_id = %s"
        params: list[Any] = [organization_id]
        if request_id is not None:
            query += " AND request_id = %s"
            params.append(request_id)
        query += " ORDER BY created_at, audit_id"
        with self._pool.connection() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()
        return [
            AuditEvent(
                auditId=row["audit_id"],
                requestId=row["request_id"],
                organizationId=row["organization_id"],
                userId=row["user_id"],
                agentId=row["agent_id"],
                serviceId=row["service_id"],
                capability=row["capability"],
                operation=row["operation"],
                status=row["status"],
                connectorId=row["connector_id"],
                policyDecision=row["policy_decision"],
                errorCode=row["error_code"],
                approvalRefHash=row["approval_ref_hash"],
                createdAt=self._dt(row["created_at"]),
            )
            for row in rows
        ]

    def put_approval(self, record: ApprovalRecord) -> None:
        with self._pool.connection() as conn:
            conn.execute(
                """
                INSERT INTO ucs_internal.approval_grant (
                    approval_ref_hash, request_id, organization_id, user_id,
                    agent_id, service_id, capability, operation, expires_at,
                    consumed_at, created_at, operation_id, binding_digest, revoked_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (approval_ref_hash) DO NOTHING
                """,
                (
                    record.approval_ref_hash,
                    record.request_id,
                    record.organization_id,
                    record.user_id,
                    record.agent_id,
                    record.service_id,
                    record.capability,
                    record.operation,
                    record.expires_at,
                    record.consumed_at,
                    record.created_at,
                    record.operation_id,
                    record.binding_digest,
                    record.revoked_at,
                ),
            )

    def get_approval(self, approval_ref_hash: str) -> ApprovalRecord | None:
        with self._pool.connection() as conn:
            row = conn.execute(
                "SELECT * FROM ucs_internal.approval_grant WHERE approval_ref_hash = %s",
                (approval_ref_hash,),
            ).fetchone()
        if row is None:
            return None
        return ApprovalRecord(
            approvalRefHash=row["approval_ref_hash"],
            requestId=row["request_id"],
            organizationId=row["organization_id"],
            userId=row["user_id"],
            agentId=row["agent_id"],
            serviceId=row["service_id"],
            capability=row["capability"],
            operation=row["operation"],
            expiresAt=self._dt(row["expires_at"]),
            consumedAt=self._dt(row["consumed_at"]),
            createdAt=self._dt(row["created_at"]),
            operationId=row["operation_id"],
            bindingDigest=row["binding_digest"],
            revokedAt=row["revoked_at"],
        )

    def consume_approval(self, approval_ref_hash: str, consumed_at: datetime) -> bool:
        with self._pool.connection() as conn:
            cursor = conn.execute(
                """
                UPDATE ucs_internal.approval_grant
                SET consumed_at = %s
                WHERE approval_ref_hash = %s
                  AND consumed_at IS NULL
                  AND revoked_at IS NULL
                  AND expires_at > %s
                """,
                (consumed_at, approval_ref_hash, consumed_at),
            )
            return cursor.rowcount == 1

    def create_workflow(self, record: ConnectionWorkflowRecord) -> ConnectionWorkflowRecord:
        with self._pool.connection() as conn:
            conn.execute(
                """
                INSERT INTO ucs_internal.connection_workflow (
                    workflow_id, request_id, organization_id, request_fingerprint,
                    service_id, capability, operation, stage, selected_candidate_id,
                    selected_tool, connector_id, connector_version, promotion_id,
                    last_code, result_audit_id, revision, lease_token,
                    lease_expires_at, created_at, updated_at
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NULL, NULL, %s, %s)
                """,
                (
                    record.workflow_id,
                    record.request_id,
                    record.organization_id,
                    record.request_fingerprint,
                    record.service_id,
                    record.capability,
                    record.operation,
                    record.stage,
                    record.selected_candidate_id,
                    record.selected_tool,
                    record.connector_id,
                    record.connector_version,
                    record.promotion_id,
                    record.last_code,
                    record.result_audit_id,
                    record.revision,
                    record.created_at,
                    record.updated_at,
                ),
            )
        created = self.get_workflow(record.organization_id, record.workflow_id)
        assert created is not None
        return created

    def get_workflow(self, organization_id: str, workflow_id: str) -> ConnectionWorkflowRecord | None:
        with self._pool.connection() as conn:
            row = conn.execute(
                "SELECT * FROM ucs_internal.connection_workflow WHERE organization_id = %s AND workflow_id = %s",
                (organization_id, workflow_id),
            ).fetchone()
        return self._workflow_from_row(row) if row is not None else None

    def get_workflow_by_request(self, organization_id: str, request_id: str) -> ConnectionWorkflowRecord | None:
        with self._pool.connection() as conn:
            row = conn.execute(
                "SELECT * FROM ucs_internal.connection_workflow WHERE organization_id = %s AND request_id = %s",
                (organization_id, request_id),
            ).fetchone()
        return self._workflow_from_row(row) if row is not None else None

    def claim_workflow(
        self,
        organization_id: str,
        workflow_id: str,
        lease_token: str,
        lease_expires_at: datetime,
        now: datetime,
    ) -> bool:
        with self._pool.connection() as conn:
            cursor = conn.execute(
                """
                UPDATE ucs_internal.connection_workflow
                SET lease_token = %s, lease_expires_at = %s
                WHERE organization_id = %s AND workflow_id = %s
                  AND (lease_token IS NULL OR lease_expires_at IS NULL OR lease_expires_at <= %s)
                """,
                (lease_token, lease_expires_at, organization_id, workflow_id, now),
            )
            return cursor.rowcount == 1

    def update_claimed_workflow(
        self,
        record: ConnectionWorkflowRecord,
        *,
        expected_revision: int,
        lease_token: str,
    ) -> bool:
        with self._pool.connection() as conn:
            cursor = conn.execute(
                """
                UPDATE ucs_internal.connection_workflow
                SET stage = %s, selected_candidate_id = %s, selected_tool = %s,
                    connector_id = %s, connector_version = %s, promotion_id = %s,
                    last_code = %s, result_audit_id = %s, revision = revision + 1,
                    lease_token = NULL, lease_expires_at = NULL, updated_at = now()
                WHERE organization_id = %s AND workflow_id = %s
                  AND revision = %s AND lease_token = %s
                """,
                (
                    record.stage,
                    record.selected_candidate_id,
                    record.selected_tool,
                    record.connector_id,
                    record.connector_version,
                    record.promotion_id,
                    record.last_code,
                    record.result_audit_id,
                    record.organization_id,
                    record.workflow_id,
                    expected_revision,
                    lease_token,
                ),
            )
            return cursor.rowcount == 1

    def release_workflow(self, organization_id: str, workflow_id: str, lease_token: str) -> None:
        with self._pool.connection() as conn:
            conn.execute(
                """
                UPDATE ucs_internal.connection_workflow
                SET lease_token = NULL, lease_expires_at = NULL
                WHERE organization_id = %s AND workflow_id = %s AND lease_token = %s
                """,
                (organization_id, workflow_id, lease_token),
            )


def config_from_env(*, auto_migrate: bool | None = None) -> PostgresStoreConfig:
    dsn = os.getenv("UCS_DATABASE_URL")
    if not dsn:
        raise RuntimeError("UCS_DATABASE_URL is required")
    env_auto = os.getenv("UCS_POSTGRES_AUTO_MIGRATE", "false").strip().lower() in {"1", "true", "yes"}
    return PostgresStoreConfig(
        dsn=SecretStr(dsn),
        minSize=int(os.getenv("UCS_POSTGRES_POOL_MIN", "1")),
        maxSize=int(os.getenv("UCS_POSTGRES_POOL_MAX", "1")),
        timeoutSeconds=float(os.getenv("UCS_POSTGRES_TIMEOUT_SECONDS", "10")),
        sslmode=os.getenv("UCS_POSTGRES_SSLMODE") or None,
        autoMigrate=env_auto if auto_migrate is None else auto_migrate,
    )


def main() -> None:
    parser = argparse.ArgumentParser(prog="ucs-db", description="UCS PostgreSQL schema management")
    parser.add_argument("command", choices=("migrate", "status"))
    args = parser.parse_args()

    config = config_from_env(auto_migrate=args.command == "migrate")
    store = PostgresStateStore(config)
    try:
        if args.command == "migrate":
            print(f"UCS PostgreSQL schema migrated to version {store.schema_version()}")
        else:
            print(f"UCS PostgreSQL schema version {store.schema_version()}/{LATEST_SCHEMA_VERSION}")
    finally:
        store.close()


if __name__ == "__main__":  # pragma: no cover
    main()
