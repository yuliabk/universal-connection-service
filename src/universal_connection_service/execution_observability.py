"""Tenant-scoped operational notices and aggregate execution health."""
from datetime import datetime
from uuid import uuid4

from .receipts import utc_now

NOTICE_CODES = frozenset({
    "OUTCOME_UNKNOWN", "EXECUTION_PENDING", "IDEMPOTENCY_CONFLICT",
    "RECOVERY_BUDGET_EXHAUSTED", "REPLAY_BUDGET_EXHAUSTED", "RECOVERY_BACKOFF_REQUIRED",
    "RECOVERY_CONTRACT_MISMATCH", "RECOVERY_OUTCOME_MISMATCH", "REPLAY_NOT_CONFIGURED",
    "APPROVAL_REVOKED", "APPROVAL_EXPIRED", "EXECUTION_RESTORE_QUARANTINED",
    "EXECUTION_OUTCOME_CONFLICT",
})


def execution_notice_schema(prefix=""):
    return f"""CREATE TABLE IF NOT EXISTS {prefix}execution_notice (
        organization_id TEXT NOT NULL,
        receipt_id TEXT NOT NULL,
        code TEXT NOT NULL,
        notice_id TEXT NOT NULL UNIQUE,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        observations INTEGER NOT NULL CHECK (observations >= 1),
        PRIMARY KEY (organization_id, receipt_id, code)
    )"""


class ExecutionObservabilityStore:
    _receipt_created_expression = "json_extract(receipt_json, '$.createdAt')"

    def record_execution_notice(self, organization_id, receipt_id, code):
        with self._receipt_transaction() as conn:
            self._record_execution_notice(conn, organization_id, receipt_id, code)

    def _record_execution_notice(self, conn, organization_id, receipt_id, code):
        if code not in NOTICE_CODES:
            raise ValueError("unsupported execution notice")
        now = utc_now().isoformat()
        # Do not create an orphan or accept a receipt from another tenant.
        self._receipt_query(conn, """INSERT INTO execution_notice
                (organization_id, receipt_id, code, notice_id, first_seen, last_seen, observations)
                SELECT organization_id, receipt_id, ?, ?, ?, ?, 1 FROM execution_receipt
                WHERE organization_id = ? AND receipt_id = ?
                ON CONFLICT (organization_id, receipt_id, code) DO UPDATE SET
                    last_seen = excluded.last_seen, observations = execution_notice.observations + 1
                """, (code, str(uuid4()), now, now, organization_id, receipt_id))

    def execution_notices(self, organization_id, *, after="", limit=100):
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("limit must be between 1 and 100")
        with self._receipt_transaction() as conn:
            rows = self._receipt_query(conn, """SELECT notice_id, receipt_id, code,
                first_seen, last_seen, observations FROM execution_notice
                WHERE organization_id = ? AND notice_id > ? ORDER BY notice_id LIMIT ?
                """, (organization_id, after, limit)).fetchall()
            return [dict(row) for row in rows]

    def execution_metrics(self, organization_id):
        with self._receipt_transaction() as conn:
            states = self._receipt_query(conn, """SELECT state, count(*) AS count
                FROM execution_receipt WHERE organization_id = ? GROUP BY state""", (organization_id,)).fetchall()
            observations = self._receipt_query(conn, """SELECT code, sum(observations) AS count
                FROM execution_notice WHERE organization_id = ? GROUP BY code""", (organization_id,)).fetchall()
            backlog = self._receipt_query(conn, """SELECT count(*) AS count FROM execution_outbox
                WHERE organization_id = ? AND delivered = 0""", (organization_id,)).fetchone()["count"]
            oldest = self._receipt_query(conn, f"""SELECT min({self._receipt_created_expression}) AS oldest
                FROM execution_receipt WHERE organization_id = ?
                AND state IN ('dispatching', 'unknown', 'pending')""", (organization_id,)).fetchone()["oldest"]
        counts = {row["state"]: row["count"] for row in states}
        return {"receiptStates": counts,
            "unknownReceipts": counts.get("unknown", 0) + counts.get("dispatching", 0),
            "outboxBacklog": backlog,
            "oldestUnresolvedAgeSeconds": max(0, (utc_now() - datetime.fromisoformat(oldest)).total_seconds()) if oldest else 0,
            "noticeObservations": {row["code"]: row["count"] for row in observations}}
