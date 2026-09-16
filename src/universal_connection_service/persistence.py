from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from threading import RLock
from typing import Any, Literal, Protocol, runtime_checkable

from pydantic import Field

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
class StateStore(ConnectorStateStore, EvidenceStore, AuditStore, Protocol):
    pass


class SQLiteStateStore:
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
            self._create_schema()

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
            """
        )
        self._connection.commit()

    @staticmethod
    def _json(value: Any) -> str:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

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
                    consumed_at, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                  AND expires_at > ?
                """,
                (timestamp, approval_ref_hash, timestamp),
            )
            return cursor.rowcount == 1
