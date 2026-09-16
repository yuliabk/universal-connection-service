from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from typing import Any, Literal, Protocol, runtime_checkable

from pydantic import Field
from .receipt_store import SQLReceiptStore, receipt_schema, receipt_result_schema
from .receipts import ReceiptStore

from .contracts import (
    ConnectorManifest,
    Lifecycle,
    Model,
    Operation,
    PolicyDecision,
    Status,
)


EvidenceKind = Literal["policy_decision", "approval_verification", "validation"]
EvidencePhase = Literal["plan", "execution", "validation"]
WorkflowStage = Literal[
    "planning",
    "awaiting_candidate_selection",
    "awaiting_build",
    "awaiting_credentials",
    "awaiting_tool_selection",
    "awaiting_promotion_approval",
    "awaiting_promotion",
    "awaiting_execution_approval",
    "ready_to_execute",
    "awaiting_reconciliation",
    "awaiting_effect_classification",
    "completed",
    "failed",
]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ConnectorStateRecord(Model):
    organization_id: str = Field(alias="organizationId", min_length=1)
    manifest: ConnectorManifest
    status: Lifecycle
    approval_id: str | None = Field(alias="approvalId", default=None)
    updated_at: datetime = Field(alias="updatedAt", default_factory=utc_now)


class EvidenceRecord(Model):
    evidence_id: str = Field(alias="evidenceId", min_length=1)
    organization_id: str = Field(alias="organizationId", min_length=1)
    kind: EvidenceKind
    phase: EvidencePhase
    request_id: str | None = Field(alias="requestId", default=None)
    connector_id: str | None = Field(alias="connectorId", default=None)
    payload: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(alias="createdAt", default_factory=utc_now)


class AuditEvent(Model):
    audit_id: str = Field(alias="auditId", min_length=1)
    request_id: str = Field(alias="requestId", min_length=1)
    organization_id: str = Field(alias="organizationId", min_length=1)
    user_id: str = Field(alias="userId", min_length=1)
    agent_id: str = Field(alias="agentId", min_length=1)
    service_id: str = Field(alias="serviceId", min_length=1)
    capability: str = Field(min_length=1)
    operation: Operation
    status: Status
    connector_id: str | None = Field(alias="connectorId", default=None)
    policy_decision: PolicyDecision | None = Field(alias="policyDecision", default=None)
    error_code: str | None = Field(alias="errorCode", default=None)
    approval_ref_hash: str | None = Field(alias="approvalRefHash", default=None)
    created_at: datetime = Field(alias="createdAt", default_factory=utc_now)


class ConnectionWorkflowRecord(Model):
    workflow_id: str = Field(alias="workflowId", min_length=1)
    request_id: str = Field(alias="requestId", min_length=1)
    organization_id: str = Field(alias="organizationId", min_length=1)
    request_fingerprint: str = Field(alias="requestFingerprint", min_length=64, max_length=64)
    service_id: str = Field(alias="serviceId", min_length=1)
    capability: str = Field(min_length=1)
    operation: Operation
    stage: WorkflowStage = "planning"
    selected_candidate_id: str | None = Field(alias="selectedCandidateId", default=None)
    selected_tool: str | None = Field(alias="selectedTool", default=None)
    connector_id: str | None = Field(alias="connectorId", default=None)
    connector_version: str | None = Field(alias="connectorVersion", default=None)
    promotion_id: str | None = Field(alias="promotionId", default=None)
    last_code: str | None = Field(alias="lastCode", default=None)
    result_audit_id: str | None = Field(alias="resultAuditId", default=None)
    revision: int = Field(default=0, ge=0)
    lease_token: str | None = Field(alias="leaseToken", default=None, exclude=True)
    lease_expires_at: datetime | None = Field(alias="leaseExpiresAt", default=None, exclude=True)
    created_at: datetime = Field(alias="createdAt", default_factory=utc_now)
    updated_at: datetime = Field(alias="updatedAt", default_factory=utc_now)


@runtime_checkable
class ConnectorStateStore(Protocol):
    def upsert_connector(self, record: ConnectorStateRecord) -> None: ...

    def update_connector_status(
        self,
        organization_id: str,
        connector_id: str,
        version: str,
        status: Lifecycle,
        approval_id: str | None = None,
    ) -> None: ...

    def list_connectors(self, organization_id: str | None = None) -> list[ConnectorStateRecord]: ...


@runtime_checkable
class EvidenceStore(Protocol):
    def append_evidence(self, record: EvidenceRecord) -> None: ...

    def list_evidence(
        self,
        organization_id: str,
        *,
        request_id: str | None = None,
        kind: EvidenceKind | None = None,
    ) -> list[EvidenceRecord]: ...


@runtime_checkable
class AuditStore(Protocol):
    def append_audit(self, event: AuditEvent) -> None: ...

    def list_audit(
        self,
        organization_id: str,
        *,
        request_id: str | None = None,
    ) -> list[AuditEvent]: ...


@runtime_checkable
class WorkflowStore(Protocol):
    def create_workflow(self, record: ConnectionWorkflowRecord) -> ConnectionWorkflowRecord: ...

    def get_workflow(self, organization_id: str, workflow_id: str) -> ConnectionWorkflowRecord | None: ...

    def get_workflow_by_request(self, organization_id: str, request_id: str) -> ConnectionWorkflowRecord | None: ...

    def claim_workflow(
        self,
        organization_id: str,
        workflow_id: str,
        lease_token: str,
        lease_expires_at: datetime,
        now: datetime,
    ) -> bool: ...

    def update_claimed_workflow(
        self,
        record: ConnectionWorkflowRecord,
        *,
        expected_revision: int,
        lease_token: str,
    ) -> bool: ...

    def release_workflow(self, organization_id: str, workflow_id: str, lease_token: str) -> None: ...


@runtime_checkable
class StateStore(ConnectorStateStore, EvidenceStore, AuditStore, WorkflowStore, ReceiptStore, Protocol):
    pass


class SQLiteStateStore(SQLReceiptStore):
    """SQLite reference store for UCS control-plane state."""

    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        self._lock = RLock()
        self._connection = sqlite3.connect(self.path, check_same_thread=False)
        self._connection.row_factory = sqlite3.Row
        with self._lock:
            self._connection.execute("PRAGMA foreign_keys = ON")
            if self.path != ":memory:":
                self._connection.execute("PRAGMA journal_mode = WAL")
            self._connection.execute("PRAGMA synchronous = FULL")
            self._create_schema()
            with self._connection:
                self._connection.execute("BEGIN IMMEDIATE")
                for statement in receipt_schema():
                    self._connection.execute(statement)
                self._connection.execute(receipt_result_schema())
                columns = {row["name"] for row in self._connection.execute("PRAGMA table_info(approval_grant)")}
                for column in ("operation_id", "binding_digest", "revoked_at"):
                    if column not in columns:
                        self._connection.execute(f"ALTER TABLE approval_grant ADD COLUMN {column} TEXT")

    @property
    def receipts_durable(self) -> bool:
        return self.path not in {":memory:", ""}

    @contextmanager
    def _receipt_transaction(self):
        # BEGIN IMMEDIATE serializes read/CAS/attempt transactions across processes.
        with self._lock, self._connection:
            self._connection.execute("BEGIN IMMEDIATE")
            yield self._connection

    def close(self) -> None:
        with self._lock:
            self._connection.close()

    def _create_schema(self) -> None:
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS connector_state (
                organization_id TEXT NOT NULL,
                connector_id TEXT NOT NULL,
                version TEXT NOT NULL,
                service_id TEXT NOT NULL,
                status TEXT NOT NULL,
                approval_id TEXT,
                manifest_json TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                PRIMARY KEY (organization_id, connector_id, version)
            );

            CREATE INDEX IF NOT EXISTS idx_connector_state_org_service
                ON connector_state (organization_id, service_id, status);

            CREATE TABLE IF NOT EXISTS evidence (
                evidence_id TEXT PRIMARY KEY,
                organization_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                phase TEXT NOT NULL,
                request_id TEXT,
                connector_id TEXT,
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_evidence_org_request
                ON evidence (organization_id, request_id, created_at);
            CREATE INDEX IF NOT EXISTS idx_evidence_org_kind
                ON evidence (organization_id, kind, created_at);

            CREATE TABLE IF NOT EXISTS audit_event (
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
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_audit_org_created
                ON audit_event (organization_id, created_at);
            CREATE INDEX IF NOT EXISTS idx_audit_org_request
                ON audit_event (organization_id, request_id, created_at);

            CREATE TABLE IF NOT EXISTS approval_grant (
                approval_ref_hash TEXT PRIMARY KEY,
                request_id TEXT NOT NULL,
                organization_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                service_id TEXT NOT NULL,
                capability TEXT NOT NULL,
                operation TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                consumed_at TEXT,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_approval_org_request
                ON approval_grant (organization_id, request_id, expires_at);

            CREATE TABLE IF NOT EXISTS connection_workflow (
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
                revision INTEGER NOT NULL,
                lease_token TEXT,
                lease_expires_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE (organization_id, request_id)
            );

            CREATE INDEX IF NOT EXISTS idx_workflow_org_stage
                ON connection_workflow (organization_id, stage, updated_at);
            """
        )
        self._connection.commit()

    @staticmethod
    def _json(value: Any) -> str:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    @staticmethod
    def _workflow_from_row(row: sqlite3.Row) -> ConnectionWorkflowRecord:
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
            leaseExpiresAt=datetime.fromisoformat(row["lease_expires_at"]) if row["lease_expires_at"] else None,
            createdAt=datetime.fromisoformat(row["created_at"]),
            updatedAt=datetime.fromisoformat(row["updated_at"]),
        )

    def upsert_connector(self, record: ConnectorStateRecord) -> None:
        manifest_json = self._json(record.manifest.model_dump(by_alias=True, mode="json"))
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT INTO connector_state (
                    organization_id, connector_id, version, service_id, status,
                    approval_id, manifest_json, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
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
                    record.updated_at.isoformat(),
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
        with self._lock, self._connection:
            cursor = self._connection.execute(
                """
                UPDATE connector_state
                SET status = ?, approval_id = ?, updated_at = ?
                WHERE organization_id = ? AND connector_id = ? AND version = ?
                """,
                (
                    status,
                    approval_id,
                    utc_now().isoformat(),
                    organization_id,
                    connector_id,
                    version,
                ),
            )
            if cursor.rowcount != 1:
                raise KeyError("connector metadata is not registered")

    def list_connectors(self, organization_id: str | None = None) -> list[ConnectorStateRecord]:
        query = "SELECT * FROM connector_state"
        params: tuple[Any, ...] = ()
        if organization_id is not None:
            query += " WHERE organization_id = ?"
            params = (organization_id,)
        query += " ORDER BY organization_id, connector_id, version"
        with self._lock:
            rows = self._connection.execute(query, params).fetchall()
        return [
            ConnectorStateRecord(
                organizationId=row["organization_id"],
                manifest=ConnectorManifest.model_validate(json.loads(row["manifest_json"])),
                status=row["status"],
                approvalId=row["approval_id"],
                updatedAt=datetime.fromisoformat(row["updated_at"]),
            )
            for row in rows
        ]

    def append_evidence(self, record: EvidenceRecord) -> None:
        payload_json = self._json(record.payload)
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT INTO evidence (
                    evidence_id, organization_id, kind, phase, request_id,
                    connector_id, payload_json, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.evidence_id,
                    record.organization_id,
                    record.kind,
                    record.phase,
                    record.request_id,
                    record.connector_id,
                    payload_json,
                    record.created_at.isoformat(),
                ),
            )

    def list_evidence(
        self,
        organization_id: str,
        *,
        request_id: str | None = None,
        kind: EvidenceKind | None = None,
    ) -> list[EvidenceRecord]:
        clauses = ["organization_id = ?"]
        params: list[Any] = [organization_id]
        if request_id is not None:
            clauses.append("request_id = ?")
            params.append(request_id)
        if kind is not None:
            clauses.append("kind = ?")
            params.append(kind)
        query = "SELECT * FROM evidence WHERE " + " AND ".join(clauses) + " ORDER BY created_at, evidence_id"
        with self._lock:
            rows = self._connection.execute(query, tuple(params)).fetchall()
        return [
            EvidenceRecord(
                evidenceId=row["evidence_id"],
                organizationId=row["organization_id"],
                kind=row["kind"],
                phase=row["phase"],
                requestId=row["request_id"],
                connectorId=row["connector_id"],
                payload=json.loads(row["payload_json"]),
                createdAt=datetime.fromisoformat(row["created_at"]),
            )
            for row in rows
        ]

    def append_audit(self, event: AuditEvent) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT INTO audit_event (
                    audit_id, request_id, organization_id, user_id, agent_id,
                    service_id, capability, operation, status, connector_id,
                    policy_decision, error_code, approval_ref_hash, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    event.created_at.isoformat(),
                ),
            )

    def list_audit(
        self,
        organization_id: str,
        *,
        request_id: str | None = None,
    ) -> list[AuditEvent]:
        query = "SELECT * FROM audit_event WHERE organization_id = ?"
        params: list[Any] = [organization_id]
        if request_id is not None:
            query += " AND request_id = ?"
            params.append(request_id)
        query += " ORDER BY created_at, audit_id"
        with self._lock:
            rows = self._connection.execute(query, tuple(params)).fetchall()
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
                createdAt=datetime.fromisoformat(row["created_at"]),
            )
            for row in rows
        ]

    def put_approval(self, record) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT INTO approval_grant (
                    approval_ref_hash, request_id, organization_id, user_id,
                    agent_id, service_id, capability, operation, expires_at,
                    consumed_at, created_at, operation_id, binding_digest, revoked_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    record.expires_at.isoformat(),
                    record.consumed_at.isoformat() if record.consumed_at else None,
                    record.created_at.isoformat(),
                    record.operation_id,
                    record.binding_digest,
                    record.revoked_at.isoformat() if record.revoked_at else None,
                ),
            )

    def get_approval(self, approval_ref_hash: str):
        from .approvals import ApprovalRecord

        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM approval_grant WHERE approval_ref_hash = ?",
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
            expiresAt=datetime.fromisoformat(row["expires_at"]),
            consumedAt=datetime.fromisoformat(row["consumed_at"]) if row["consumed_at"] else None,
            createdAt=datetime.fromisoformat(row["created_at"]),
            operationId=row["operation_id"],
            bindingDigest=row["binding_digest"],
            revokedAt=row["revoked_at"],
        )

    def consume_approval(self, approval_ref_hash: str, consumed_at: datetime) -> bool:
        timestamp = consumed_at.isoformat()
        with self._lock, self._connection:
            cursor = self._connection.execute(
                """
                UPDATE approval_grant
                SET consumed_at = ?
                WHERE approval_ref_hash = ?
                  AND consumed_at IS NULL
                  AND revoked_at IS NULL
                  AND expires_at > ?
                """,
                (timestamp, approval_ref_hash, timestamp),
            )
            return cursor.rowcount == 1

    def create_workflow(self, record: ConnectionWorkflowRecord) -> ConnectionWorkflowRecord:
        with self._lock, self._connection:
            self._connection.execute(
                """
                INSERT INTO connection_workflow (
                    workflow_id, request_id, organization_id, request_fingerprint,
                    service_id, capability, operation, stage, selected_candidate_id,
                    selected_tool, connector_id, connector_version, promotion_id,
                    last_code, result_audit_id, revision, lease_token,
                    lease_expires_at, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    None,
                    None,
                    record.created_at.isoformat(),
                    record.updated_at.isoformat(),
                ),
            )
        created = self.get_workflow(record.organization_id, record.workflow_id)
        assert created is not None
        return created

    def get_workflow(self, organization_id: str, workflow_id: str) -> ConnectionWorkflowRecord | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM connection_workflow WHERE organization_id = ? AND workflow_id = ?",
                (organization_id, workflow_id),
            ).fetchone()
        return self._workflow_from_row(row) if row is not None else None

    def get_workflow_by_request(self, organization_id: str, request_id: str) -> ConnectionWorkflowRecord | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM connection_workflow WHERE organization_id = ? AND request_id = ?",
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
        with self._lock, self._connection:
            cursor = self._connection.execute(
                """
                UPDATE connection_workflow
                SET lease_token = ?, lease_expires_at = ?
                WHERE organization_id = ? AND workflow_id = ?
                  AND (lease_token IS NULL OR lease_expires_at IS NULL OR lease_expires_at <= ?)
                """,
                (
                    lease_token,
                    lease_expires_at.isoformat(),
                    organization_id,
                    workflow_id,
                    now.isoformat(),
                ),
            )
            return cursor.rowcount == 1

    def update_claimed_workflow(
        self,
        record: ConnectionWorkflowRecord,
        *,
        expected_revision: int,
        lease_token: str,
    ) -> bool:
        updated_at = utc_now()
        with self._lock, self._connection:
            cursor = self._connection.execute(
                """
                UPDATE connection_workflow
                SET stage = ?, selected_candidate_id = ?, selected_tool = ?,
                    connector_id = ?, connector_version = ?, promotion_id = ?,
                    last_code = ?, result_audit_id = ?, revision = revision + 1,
                    lease_token = NULL, lease_expires_at = NULL, updated_at = ?
                WHERE organization_id = ? AND workflow_id = ?
                  AND revision = ? AND lease_token = ?
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
                    updated_at.isoformat(),
                    record.organization_id,
                    record.workflow_id,
                    expected_revision,
                    lease_token,
                ),
            )
            return cursor.rowcount == 1

    def release_workflow(self, organization_id: str, workflow_id: str, lease_token: str) -> None:
        with self._lock, self._connection:
            self._connection.execute(
                """
                UPDATE connection_workflow
                SET lease_token = NULL, lease_expires_at = NULL
                WHERE organization_id = ? AND workflow_id = ? AND lease_token = ?
                """,
                (organization_id, workflow_id, lease_token),
            )
