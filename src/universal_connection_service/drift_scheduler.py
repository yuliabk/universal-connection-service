"""Periodic schema drift verification.

The drift endpoint answers "has this connector's contract changed?" on demand.
Nothing calls it on its own, which means drift is only found when somebody
remembers to look.

This scheduler closes that gap without becoming a job framework: one asyncio task
per process, one pass at a fixed interval over trusted MCP connectors, with a
stagger between connectors so a pass does not burst a listing at every server at
once.

Off by default. A deployment that runs several instances should enable it on one
of them, or accept that each instance verifies independently.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field

from .registry import ConnectorRegistry
from .schema_drift import MCPSchemaDriftVerifier

logger = logging.getLogger(__name__)


@dataclass
class DriftSweepResult:
    checked: int = 0
    drifted: int = 0
    demoted: int = 0
    skipped: int = 0
    failures: int = 0
    codes: dict[str, int] = field(default_factory=dict)

    def record(self, code: str) -> None:
        self.codes[code] = self.codes.get(code, 0) + 1


class SchemaDriftScheduler:
    def __init__(
        self,
        registry: ConnectorRegistry,
        verifier: MCPSchemaDriftVerifier,
        *,
        interval_seconds: float = 3600.0,
        stagger_seconds: float = 0.5,
        deadline_ms: int = 10000,
    ) -> None:
        if interval_seconds <= 0:
            raise ValueError("interval_seconds must be positive")
        self.registry = registry
        self.verifier = verifier
        self.interval_seconds = interval_seconds
        self.stagger_seconds = stagger_seconds
        self.deadline_ms = deadline_ms
        self._task: asyncio.Task | None = None
        self.last_result: DriftSweepResult | None = None

    async def sweep(self) -> DriftSweepResult:
        """One pass over trusted connectors. Never raises."""
        result = DriftSweepResult()
        for registration in self.registry.registrations():
            if registration.status != "trusted":
                result.skipped += 1
                continue
            manifest = registration.manifest
            try:
                report = await self.verifier.verify(
                    registration.organization_id,
                    manifest.connector_id,
                    manifest.version,
                    deadline_ms=self.deadline_ms,
                )
            except Exception:
                # A single bad connector must not end the sweep.
                result.failures += 1
                logger.warning("drift verification failed for %s", manifest.connector_id, exc_info=False)
                continue

            result.record(report.code)
            if not report.checked:
                result.skipped += 1
            else:
                result.checked += 1
                if report.drifted:
                    result.drifted += 1
                if report.demoted:
                    result.demoted += 1
            if self.stagger_seconds:
                await asyncio.sleep(self.stagger_seconds)

        self.last_result = result
        return result

    async def _loop(self) -> None:
        while True:
            try:
                await asyncio.sleep(self.interval_seconds)
                await self.sweep()
            except asyncio.CancelledError:
                raise
            except Exception:  # pragma: no cover - defensive, sweep already swallows
                logger.exception("drift sweep loop error")

    def start(self) -> None:
        if self._task is not None and not self._task.done():
            return
        self._task = asyncio.create_task(self._loop(), name="schema-drift-sweep")

    async def stop(self) -> None:
        task = self._task
        self._task = None
        if task is None or task.done():
            return
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()
