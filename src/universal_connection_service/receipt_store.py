"""Shared transactional receipt operations for SQLite and PostgreSQL.

Only fixed internal table identifiers pass through _receipt_sql. No caller SQL.
Transaction ownership is supplied by the backend, never by a connector.
"""
from __future__ import annotations

from typing import Literal
from datetime import datetime, timezone, timedelta
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

    def _receipt_time(self, value):
        return value.isoformat()

    def _validate_execution_approval(self, conn, receipt, *, allow_consumed=False):
        row = self._receipt_query(conn, "SELECT * FROM approval_grant WHERE approval_ref_hash = ?", (receipt.approval_ref_hash,)).fetchone()
        if not row:
            raise ReceiptError("APPROVAL_INVALID")
        if row["revoked_at"] is not None:
            raise ReceiptError("APPROVAL_REVOKED")
        expires = row["expires_at"]
        if isinstance(expires, str):
            expires = datetime.fromisoformat(expires)
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        if expires <= utc_now():
            raise ReceiptError("APPROVAL_EXPIRED")
        fields = ("organization_id", "user_id", "agent_id", "service_id", "capability", "operation", "operation_id", "binding_digest")
        if any(row[name] != getattr(receipt, name) for name in fields):
            raise ReceiptError("APPROVAL_SCOPE_MISMATCH")
        if row["consumed_at"] is not None and not allow_consumed:
            raise ReceiptError("APPROVAL_ALREADY_USED")
        return expires

    def revoke_execution_approval(self, organization_id: str, ref_hash: str) -> bool:
        with self._receipt_transaction() as conn:
            return self._receipt_query(conn, """UPDATE approval_grant SET revoked_at = ?
                WHERE organization_id = ? AND approval_ref_hash = ? AND revoked_at IS NULL""",
                (self._receipt_time(utc_now()), organization_id, ref_hash)).rowcount == 1

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

    def begin_dispatch(self, organization_id: str, operation_id: str, expected_version: int, request_id: str, *, require_approval: bool = False, approval_ref_hash: str | None = None, replay_window_seconds: int | None = None) -> ExecutionReceipt:
        if not request_id:
            raise ValueError("request_id is required")
        with self._receipt_transaction() as conn:
            receipt = self._expected(conn, organization_id, operation_id, expected_version, {"prepared"})
            approval_expires = None
            if require_approval:
                if approval_ref_hash is not None:
                    receipt.approval_ref_hash = approval_ref_hash
                self._validate_execution_approval(conn, receipt)
                timestamp = self._receipt_time(utc_now())
                consumed = self._receipt_query(conn, """UPDATE approval_grant SET consumed_at = ?
                    WHERE approval_ref_hash = ? AND organization_id = ? AND consumed_at IS NULL
                    AND revoked_at IS NULL AND expires_at > ?""",
                    (timestamp, receipt.approval_ref_hash, organization_id, timestamp))
                if consumed.rowcount != 1:
                    raise ReceiptError("APPROVAL_UNAVAILABLE")
                approval_expires = self._validate_execution_approval(conn, receipt, allow_consumed=True)
            receipt.state = "dispatching"
            if replay_window_seconds is not None:
                if type(replay_window_seconds) is not int or replay_window_seconds <= 0:
                    raise ValueError("replay window must be positive")
                receipt.provider_not_after = utc_now() + timedelta(seconds=replay_window_seconds)
                if approval_expires is not None:
                    receipt.provider_not_after = min(receipt.provider_not_after, approval_expires)
            receipt.attempt_id = str(uuid4())
            receipt.attempt_count += 1
            self._save(conn, receipt, expected_version)
            self._receipt_query(conn, """
                INSERT INTO execution_attempt (organization_id, operation_id, attempt_id, request_id, receipt_version, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """, (organization_id, operation_id, receipt.attempt_id, request_id, receipt.version, receipt.updated_at.isoformat()))
            return receipt

    def begin_receipt_replay(self, organization_id: str, operation_id: str, expected_version: int,
                            request_id: str, contract_digest: str, max_attempts: int, approval_ref_hash: str) -> ExecutionReceipt:
        with self._receipt_transaction() as conn:
            receipt = self._expected(conn, organization_id, operation_id, expected_version, {"dispatching", "unknown", "pending"})
            if not contract_digest or receipt.recovery_contract_digest != contract_digest:
                raise ReceiptError("RECOVERY_CONTRACT_MISMATCH")
            if not approval_ref_hash or receipt.approval_ref_hash != approval_ref_hash:
                raise ReceiptError("APPROVAL_SCOPE_MISMATCH")
            self._validate_execution_approval(conn, receipt, allow_consumed=True)
            # Serialize authorization with concurrent revocation, without minting
            # a second grant or altering its original consumption timestamp.
            locked = self._receipt_query(conn, """UPDATE approval_grant SET consumed_at = consumed_at
                WHERE approval_ref_hash = ? AND organization_id = ? AND consumed_at IS NOT NULL
                AND revoked_at IS NULL""", (approval_ref_hash, organization_id)).rowcount
            if locked != 1:
                raise ReceiptError("APPROVAL_UNAVAILABLE")
            self._validate_execution_approval(conn, receipt, allow_consumed=True)
            if (receipt.provider_not_after is None or utc_now() >= receipt.provider_not_after
                or receipt.attempt_count >= max_attempts):
                raise ReceiptError("REPLAY_BUDGET_EXHAUSTED")
            receipt.state = "dispatching"
            receipt.attempt_count += 1
            receipt.attempt_id = str(uuid4())
            self._save(conn, receipt, expected_version)
            self._receipt_query(conn, """INSERT INTO execution_attempt
                (organization_id, operation_id, attempt_id, request_id, receipt_version, created_at)
                VALUES (?, ?, ?, ?, ?, ?)""", (organization_id, operation_id, receipt.attempt_id,
                    request_id, receipt.version, receipt.updated_at.isoformat()))
            return receipt

    def mark_unresolved(self, organization_id: str, operation_id: str, expected_version: int, state: Literal["unknown", "pending"]) -> ExecutionReceipt:
        if state not in {"unknown", "pending"}:
            raise ValueError("not an unresolved state")
        with self._receipt_transaction() as conn:
            receipt = self._expected(conn, organization_id, operation_id, expected_version, {"dispatching", "unknown", "pending"})
            receipt.state = state
            self._save(conn, receipt, expected_version)
            return receipt

    def begin_receipt_lookup(self, organization_id: str, operation_id: str, expected_version: int,
                             contract_digest: str, max_lookups: int, deadline: datetime) -> ExecutionReceipt:
        with self._receipt_transaction() as conn:
            receipt = self._expected(conn, organization_id, operation_id, expected_version, {"dispatching", "unknown", "pending"})
            if not contract_digest or receipt.recovery_contract_digest != contract_digest:
                raise ReceiptError("RECOVERY_CONTRACT_MISMATCH")
            if utc_now() >= deadline or receipt.lookup_count >= max_lookups:
                raise ReceiptError("RECOVERY_BUDGET_EXHAUSTED")
            receipt.lookup_count += 1
            # Fence a late execution response; lookup completion uses this version.
            if receipt.state == "dispatching":
                receipt.state = "unknown"
            self._save(conn, receipt, expected_version)
            return receipt

    def complete_receipt(self, organization_id: str, operation_id: str, expected_version: int, state: Literal["succeeded", "failed_no_effect"], *, result_ref: str | None = None, provider_reference: str | None = None, result_ciphertext: str | None = None) -> ExecutionReceipt:
        """Called only with authoritative outcome evidence by the trusted coordinator.

        References are opaque handles, never payloads. Unknown must not be classified
        as failed_no_effect by catching an exception or inspecting HTTP status alone.
        """
        if state not in {"succeeded", "failed_no_effect"}:
            raise ValueError("not a terminal state")
        with self._receipt_transaction() as conn:
            receipt = self._expected(conn, organization_id, operation_id, expected_version, {"dispatching", "unknown", "pending"})
            decision = "execution_completed" if receipt.state == "dispatching" and receipt.attempt_count == 1 else "reconciled"
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
            if result_ciphertext is not None:
                if len(result_ciphertext) > 2_000_000:
                    raise ReceiptError("RESULT_TOO_LARGE")
                self._receipt_query(conn, """INSERT INTO execution_result (organization_id, operation_id, ciphertext)
                    VALUES (?, ?, ?)""", (organization_id, operation_id, result_ciphertext))
            self._receipt_query(conn, """
                INSERT INTO execution_outbox (organization_id, event_id, operation_id, event_json)
                VALUES (?, ?, ?, ?)
                """, (organization_id, event.event_id, operation_id, event.model_dump_json()))
            return receipt

    def get_receipt_result(self, organization_id: str, operation_id: str) -> str | None:
        with self._receipt_transaction() as conn:
            row = self._receipt_query(conn, """SELECT ciphertext FROM execution_result
                WHERE organization_id = ? AND operation_id = ?""", (organization_id, operation_id)).fetchone()
            return row["ciphertext"] if row else None
    def pending_receipt_audit(self, organization_id: str, limit: int = 100) -> list[ReceiptAudit]:
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        with self._receipt_transaction() as conn:
            rows = self._receipt_query(conn, """
                SELECT event_json FROM execution_outbox
                WHERE organization_id = ? AND delivered = 0 ORDER BY event_id LIMIT ?
                """, (organization_id, limit)).fetchall()
            return [ReceiptAudit.model_validate_json(row["event_json"]) for row in rows]

    def receipt_result_page(self, after: str = "", limit: int = 10) -> list[tuple[ExecutionReceipt, str]]:
        """Host-only bounded scan, including legacy G2 encrypted envelopes."""
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("limit must be between 1 and 100")
        with self._receipt_transaction() as conn:
            rows = self._receipt_query(conn, """SELECT r.receipt_json, p.ciphertext
                FROM execution_receipt r JOIN execution_result p
                ON r.organization_id = p.organization_id AND r.operation_id = p.operation_id
                WHERE r.receipt_id > ? AND r.state IN ('succeeded', 'failed_no_effect')
                ORDER BY r.receipt_id LIMIT ?""", (after, limit)).fetchall()
            return [(ExecutionReceipt.model_validate_json(row["receipt_json"]), row["ciphertext"]) for row in rows]

    def purge_receipt_result(self, organization_id: str, operation_id: str, expected_version: int, ciphertext: str) -> bool:
        """Trusted retention worker calls only after authenticating envelope expiry.

        Delete the exact observed payload; preserve the operation tombstone forever.
        """
        with self._receipt_transaction() as conn:
            deleted = self._receipt_query(conn, """DELETE FROM execution_result
                WHERE organization_id = ? AND operation_id = ? AND ciphertext = ?""",
                (organization_id, operation_id, ciphertext)).rowcount
            if not deleted:
                return False
            receipt = self._expected(conn, organization_id, operation_id, expected_version, {"succeeded", "failed_no_effect"})
            receipt.result_purged_at = utc_now()
            self._save(conn, receipt, expected_version)
            return True

    def acknowledge_receipt_audit(self, organization_id: str, event_id: str) -> bool:
        with self._receipt_transaction() as conn:
            cursor = self._receipt_query(conn, """
                UPDATE execution_outbox SET delivered = 1 WHERE organization_id = ? AND event_id = ?
                """, (organization_id, event_id))
            return cursor.rowcount == 1

    def receipt_audit_organizations(self, limit: int = 100, *, after: str = "") -> list[str]:
        """Host worker discovery only; never exposed as a tenant API."""
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        with self._receipt_transaction() as conn:
            rows = self._receipt_query(conn, """SELECT DISTINCT organization_id
                FROM execution_outbox WHERE delivered = 0 AND organization_id > ?
                ORDER BY organization_id LIMIT ?""", (after, limit)).fetchall()
            return [row["organization_id"] for row in rows]

    def deliver_receipt_audit(self, organization_id: str, limit: int = 100) -> int:
        """Atomically project the outbox into the colocated audit store and ack.

        A commit acknowledgement can be lost safely: replay uses the same audit ID.
        No connector or receipt state transition participates in delivery.
        """
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        with self._receipt_transaction() as conn:
            rows = self._receipt_query(conn, """SELECT event_json FROM execution_outbox
                WHERE organization_id = ? AND delivered = 0 ORDER BY event_id LIMIT ?""",
                (organization_id, limit)).fetchall()
            for row in rows:
                event = ReceiptAudit.model_validate_json(row["event_json"])
                receipt = self._load_receipt(conn, organization_id, event.operation_id)
                if (event.organization_id != organization_id or receipt is None
                    or receipt.audit_id != event.event_id or receipt.receipt_id != event.receipt_id
                    or receipt.state != event.state):
                    raise ReceiptError("AUDIT_OUTBOX_CONFLICT")
                values = dict(audit_id=event.event_id, request_id=event.request_id,
                    organization_id=organization_id, user_id=event.user_id, agent_id=event.agent_id,
                    service_id=event.service_id, capability=event.capability, operation=event.operation,
                    status="success" if event.state == "succeeded" else "failed",
                    connector_id=event.connector_id, policy_decision=None,
                    error_code=None if event.state == "succeeded" else "EXECUTION_FAILED_NO_EFFECT",
                    approval_ref_hash=receipt.approval_ref_hash,
                    created_at=self._receipt_time(event.created_at))
                self._receipt_query(conn, """INSERT INTO audit_event
                    (audit_id, request_id, organization_id, user_id, agent_id, service_id,
                     capability, operation, status, connector_id, policy_decision, error_code,
                     approval_ref_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT (audit_id) DO NOTHING""", tuple(values.values()))
                existing = self._receipt_query(conn, "SELECT * FROM audit_event WHERE audit_id = ?",
                    (event.event_id,)).fetchone()
                if existing is None or any(existing[key] != value for key, value in values.items()):
                    raise ReceiptError("AUDIT_EVENT_CONFLICT")
                self._receipt_query(conn, """UPDATE execution_outbox SET delivered = 1
                    WHERE organization_id = ? AND event_id = ?""", (organization_id, event.event_id))
            return len(rows)


def receipt_result_schema(prefix: str = "") -> str:
    return f"""CREATE TABLE IF NOT EXISTS {prefix}execution_result (
        organization_id TEXT NOT NULL,
        operation_id TEXT NOT NULL,
        ciphertext TEXT NOT NULL,
        PRIMARY KEY (organization_id, operation_id),
        FOREIGN KEY (organization_id, operation_id)
            REFERENCES {prefix}execution_receipt (organization_id, operation_id)
    )"""
