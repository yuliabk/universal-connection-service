"""Shared transactional receipt operations for SQLite and PostgreSQL.

Only fixed internal table identifiers pass through _receipt_sql. No caller SQL.
Transaction ownership is supplied by the backend, never by a connector.
"""
from __future__ import annotations

from typing import Literal
from uuid import uuid4

from .receipts import ExecutionIntent, ExecutionReceipt, ReceiptAudit, ReceiptError, utc_now


def receipt_schema(prefix: str = "") -> tuple[str, ...]:
    return (
        f"""CREATE TABLE IF NOT EXISTS {prefix}execution_receipt (
            organization_id TEXT NOT NULL,
            operation_id TEXT NOT NULL,
            receipt_id TEXT NOT NULL UNIQUE,
            state TEXT NOT NULL CHECK (state IN ('prepared','dispatching','pending','unknown','succeeded','failed_no_effect')),
            version INTEGER NOT NULL CHECK (version >= 0),
            receipt_json TEXT NOT NULL,
            PRIMARY KEY (organization_id, operation_id)
        )""",
        f"""CREATE TABLE IF NOT EXISTS {prefix}execution_attempt (
            organization_id TEXT NOT NULL,
            operation_id TEXT NOT NULL,
            attempt_id TEXT NOT NULL,
            request_id TEXT NOT NULL,
            receipt_version INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (organization_id, attempt_id),
            FOREIGN KEY (organization_id, operation_id)
                REFERENCES {prefix}execution_receipt (organization_id, operation_id)
        )""",
        f"""CREATE TABLE IF NOT EXISTS {prefix}execution_outbox (
            organization_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            operation_id TEXT NOT NULL,
            event_json TEXT NOT NULL,
            delivered INTEGER NOT NULL DEFAULT 0 CHECK (delivered IN (0,1)),
            PRIMARY KEY (organization_id, event_id),
            UNIQUE (organization_id, operation_id),
            FOREIGN KEY (organization_id, operation_id)
                REFERENCES {prefix}execution_receipt (organization_id, operation_id)
        )""",
        f"CREATE INDEX IF NOT EXISTS idx_execution_outbox_pending ON {prefix}execution_outbox (organization_id, delivered)",
    )


class SQLReceiptStore:
    def _receipt_sql(self, sql: str) -> str:
        return sql

    def _receipt_transaction(self):
        raise NotImplementedError

    def _receipt_query(self, conn, sql, args=()):
        return conn.execute(self._receipt_sql(sql), args)

    def _load_receipt(self, conn, organization_id: str, operation_id: str) -> ExecutionReceipt | None:
        row = self._receipt_query(conn,
            "SELECT receipt_json FROM execution_receipt WHERE organization_id = ? AND operation_id = ?",
            (organization_id, operation_id),
        ).fetchone()
        return ExecutionReceipt.model_validate_json(row["receipt_json"]) if row else None

    def get_receipt(self, organization_id: str, operation_id: str) -> ExecutionReceipt | None:
        with self._receipt_transaction() as conn:
            return self._load_receipt(conn, organization_id, operation_id)

    def prepare_receipt(self, intent: ExecutionIntent) -> ExecutionReceipt:
        if not self.receipts_durable:
            raise ReceiptError("RECEIPT_STORE_NOT_DURABLE")
        receipt = ExecutionReceipt(**intent.model_dump())
        with self._receipt_transaction() as conn:
            self._receipt_query(conn, """
                INSERT INTO execution_receipt (organization_id, operation_id, receipt_id, state, version, receipt_json)
                VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (organization_id, operation_id) DO NOTHING
                """, (receipt.organization_id, receipt.operation_id, receipt.receipt_id, receipt.state, receipt.version, receipt.model_dump_json()))
            existing = self._load_receipt(conn, intent.organization_id, intent.operation_id)
            # requestId is per attempt; connector upgrades cannot mint a new operation.
            fields = ("binding_digest", "user_id", "agent_id", "service_id", "provider_account_id", "capability", "operation")
            if existing is None or any(getattr(existing, key) != getattr(intent, key) for key in fields):
                raise ReceiptError("IDEMPOTENCY_CONFLICT")
            return existing

    def _expected(self, conn, organization_id, operation_id, expected_version, allowed_states):
        receipt = self._load_receipt(conn, organization_id, operation_id)
        if receipt is None:
            raise ReceiptError("RECEIPT_NOT_FOUND")
        if receipt.version != expected_version or receipt.state not in allowed_states:
            raise ReceiptError("RECEIPT_STATE_CONFLICT")
        return receipt

    def _save(self, conn, receipt: ExecutionReceipt, expected_version: int):
        receipt.version = expected_version + 1
        receipt.updated_at = utc_now()
        cursor = self._receipt_query(conn, """
            UPDATE execution_receipt SET state = ?, version = ?, receipt_json = ?
            WHERE organization_id = ? AND operation_id = ? AND version = ?
            """, (receipt.state, receipt.version, receipt.model_dump_json(), receipt.organization_id, receipt.operation_id, expected_version))
        if cursor.rowcount != 1:
            raise ReceiptError("RECEIPT_STATE_CONFLICT")

    def begin_dispatch(self, organization_id: str, operation_id: str, expected_version: int, request_id: str) -> ExecutionReceipt:
        if not request_id:
            raise ValueError("request_id is required")
        with self._receipt_transaction() as conn:
            receipt = self._expected(conn, organization_id, operation_id, expected_version, {"prepared"})
            receipt.state = "dispatching"
            receipt.attempt_id = str(uuid4())
            receipt.attempt_count += 1
            self._save(conn, receipt, expected_version)
            self._receipt_query(conn, """
                INSERT INTO execution_attempt (organization_id, operation_id, attempt_id, request_id, receipt_version, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """, (organization_id, operation_id, receipt.attempt_id, request_id, receipt.version, receipt.updated_at.isoformat()))
            return receipt

    def mark_unresolved(self, organization_id: str, operation_id: str, expected_version: int, state: Literal["unknown", "pending"]) -> ExecutionReceipt:
        if state not in {"unknown", "pending"}:
            raise ValueError("not an unresolved state")
        with self._receipt_transaction() as conn:
            receipt = self._expected(conn, organization_id, operation_id, expected_version, {"dispatching", "unknown", "pending"})
            receipt.state = state
            self._save(conn, receipt, expected_version)
            return receipt

    def complete_receipt(self, organization_id: str, operation_id: str, expected_version: int, state: Literal["succeeded", "failed_no_effect"], *, result_ref: str | None = None, provider_reference: str | None = None) -> ExecutionReceipt:
        """Called only with authoritative outcome evidence by the trusted coordinator.

        References are opaque handles, never payloads. Unknown must not be classified
        as failed_no_effect by catching an exception or inspecting HTTP status alone.
        """
        if state not in {"succeeded", "failed_no_effect"}:
            raise ValueError("not a terminal state")
        with self._receipt_transaction() as conn:
            receipt = self._expected(conn, organization_id, operation_id, expected_version, {"dispatching", "unknown", "pending"})
            decision = "execution_completed" if receipt.state == "dispatching" else "reconciled"
            receipt.state = state
            receipt.result_ref = result_ref
            receipt.provider_reference = provider_reference
            event = ReceiptAudit(
                organizationId=organization_id, receiptId=receipt.receipt_id,
                operationId=operation_id, requestId=receipt.request_id,
                userId=receipt.user_id, agentId=receipt.agent_id, serviceId=receipt.service_id,
                capability=receipt.capability, operation=receipt.operation,
                connectorId=receipt.connector_id, connectorVersion=receipt.connector_version,
                state=state, decision=decision,
            )
            receipt.audit_id = event.event_id
            self._save(conn, receipt, expected_version)
            self._receipt_query(conn, """
                INSERT INTO execution_outbox (organization_id, event_id, operation_id, event_json)
                VALUES (?, ?, ?, ?)
                """, (organization_id, event.event_id, operation_id, event.model_dump_json()))
            return receipt

    def pending_receipt_audit(self, organization_id: str, limit: int = 100) -> list[ReceiptAudit]:
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        with self._receipt_transaction() as conn:
            rows = self._receipt_query(conn, """
                SELECT event_json FROM execution_outbox
                WHERE organization_id = ? AND delivered = 0 ORDER BY event_id LIMIT ?
                """, (organization_id, limit)).fetchall()
            return [ReceiptAudit.model_validate_json(row["event_json"]) for row in rows]

    def acknowledge_receipt_audit(self, organization_id: str, event_id: str) -> bool:
        with self._receipt_transaction() as conn:
            cursor = self._receipt_query(conn, """
                UPDATE execution_outbox SET delivered = 1 WHERE organization_id = ? AND event_id = ?
                """, (organization_id, event_id))
            return cursor.rowcount == 1
