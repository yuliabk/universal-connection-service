"""Durable run budget.

`InMemoryRunBudget` is correct for one process. Two uvicorn workers each keep
their own counter, so an agent gets twice its allowance. This implementation puts
the counter in SQLite and consumes it inside a single immediate transaction, so
concurrent workers cannot both read the same value and both allow a call.

For Postgres, the same shape works with
`INSERT ... ON CONFLICT DO UPDATE ... WHERE used < limit RETURNING used`; that is
one method, not a redesign, which is the point of keeping `RunBudgetStore` a
protocol.
"""

from __future__ import annotations

import sqlite3
import threading
from datetime import timedelta

from .persistence import utc_now
from .run_budget import BudgetDecision

_SCHEMA = """
CREATE TABLE IF NOT EXISTS tool_run_budget (
    organization_id TEXT NOT NULL,
    agent_id        TEXT NOT NULL,
    run_id          TEXT NOT NULL,
    used            INTEGER NOT NULL,
    updated_at      TEXT NOT NULL,
    PRIMARY KEY (organization_id, agent_id, run_id)
);
CREATE INDEX IF NOT EXISTS tool_run_budget_updated_at ON tool_run_budget (updated_at);
"""


class SQLiteRunBudget:
    def __init__(self, path: str, *, ttl: timedelta = timedelta(hours=6)) -> None:
        self._ttl = ttl
        self._lock = threading.Lock()
        self._connection = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.executescript(_SCHEMA)

    def consume(self, organization_id: str, agent_id: str, run_id: str, limit: int) -> BudgetDecision:
        now = utc_now()
        cutoff = (now - self._ttl).isoformat()
        key = (organization_id, agent_id, run_id)
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                self._connection.execute("DELETE FROM tool_run_budget WHERE updated_at < ?", (cutoff,))
                row = self._connection.execute(
                    "SELECT used FROM tool_run_budget WHERE organization_id = ? AND agent_id = ? AND run_id = ?",
                    key,
                ).fetchone()
                used = int(row[0]) if row else 0
                if used >= limit:
                    self._connection.execute("COMMIT")
                    return BudgetDecision(allowed=False, used=used, limit=limit)
                self._connection.execute(
                    """
                    INSERT INTO tool_run_budget (organization_id, agent_id, run_id, used, updated_at)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT (organization_id, agent_id, run_id)
                    DO UPDATE SET used = used + 1, updated_at = excluded.updated_at
                    """,
                    (*key, 1, now.isoformat()),
                )
                self._connection.execute("COMMIT")
            except Exception:
                self._connection.execute("ROLLBACK")
                raise
        return BudgetDecision(allowed=True, used=used + 1, limit=limit)

    def usage(self, organization_id: str, agent_id: str, run_id: str) -> int:
        with self._lock:
            row = self._connection.execute(
                "SELECT used FROM tool_run_budget WHERE organization_id = ? AND agent_id = ? AND run_id = ?",
                (organization_id, agent_id, run_id),
            ).fetchone()
        return int(row[0]) if row else 0

    def close(self) -> None:
        with self._lock:
            self._connection.close()
