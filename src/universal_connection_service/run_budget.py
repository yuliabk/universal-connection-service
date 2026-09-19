"""Per-run tool call budgets.

`AgentToolPolicy.max_calls_per_run` was stored but not enforced, because nothing
in the service counted calls that belong to the same agent run: every tool call
carries its own `requestId`, and the audit store has no run identifier to group
them by.

This module adds the missing counter. A caller passes a `runId` for all tool
calls that belong to one agent turn, and the budget is consumed per
(organization, agent, run).

The in-memory implementation is correct for a single process. A multi-process or
multi-instance deployment needs a shared implementation of `RunBudgetStore`
backed by the same database as the audit store; the protocol exists so that
swap requires no change at the call site.
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol

from .persistence import utc_now


@dataclass(frozen=True)
class BudgetDecision:
    allowed: bool
    used: int
    limit: int

    @property
    def remaining(self) -> int:
        return max(self.limit - self.used, 0)


class RunBudgetStore(Protocol):
    def consume(self, organization_id: str, agent_id: str, run_id: str, limit: int) -> BudgetDecision: ...


class InMemoryRunBudget:
    """Bounded, expiring counter for one process.

    Bounded on purpose: an unbounded dictionary keyed by a caller-supplied run
    identifier is a memory-exhaustion path. Oldest runs are evicted first, and a
    run that has been idle beyond the TTL is discarded.
    """

    def __init__(self, *, max_runs: int = 10000, ttl: timedelta = timedelta(hours=6)) -> None:
        if max_runs < 1:
            raise ValueError("max_runs must be positive")
        self._max_runs = max_runs
        self._ttl = ttl
        self._lock = threading.Lock()
        self._runs: OrderedDict[tuple[str, str, str], tuple[int, datetime]] = OrderedDict()

    def _evict(self, now: datetime) -> None:
        expired = [key for key, (_, seen) in self._runs.items() if now - seen > self._ttl]
        for key in expired:
            self._runs.pop(key, None)
        while len(self._runs) > self._max_runs:
            self._runs.popitem(last=False)

    def consume(self, organization_id: str, agent_id: str, run_id: str, limit: int) -> BudgetDecision:
        key = (organization_id, agent_id, run_id)
        now = utc_now()
        with self._lock:
            self._evict(now)
            used, _ = self._runs.get(key, (0, now))
            if used >= limit:
                # Refused calls do not consume budget: the counter tracks work
                # that was actually dispatched.
                return BudgetDecision(allowed=False, used=used, limit=limit)
            self._runs[key] = (used + 1, now)
            self._runs.move_to_end(key)
            self._evict(now)  # trim after insertion so the table never exceeds max_runs
            return BudgetDecision(allowed=True, used=used + 1, limit=limit)

    def usage(self, organization_id: str, agent_id: str, run_id: str) -> int:
        with self._lock:
            used, _ = self._runs.get((organization_id, agent_id, run_id), (0, utc_now()))
            return used
