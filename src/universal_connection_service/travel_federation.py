from __future__ import annotations

import asyncio
import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any, Iterable

from pydantic import Field

from .contracts import ConnectionError, ExecutionContext, Model
from .registry import ConnectorRegistry


class TravelSource(Model):
    service_id: str = Field(alias="serviceId", min_length=1)
    capability: str = Field(min_length=1)
    priority: int = Field(default=100, ge=0)


class SourceEvidence(Model):
    service_id: str = Field(alias="serviceId")
    capability: str
    connector_id: str | None = Field(alias="connectorId", default=None)
    status: str
    latency_ms: int = Field(alias="latencyMs", ge=0)
    item_count: int = Field(alias="itemCount", ge=0)
    error: ConnectionError | None = None


class FederatedTravelResult(Model):
    status: str
    items: tuple[dict[str, Any], ...] = ()
    sources: tuple[SourceEvidence, ...] = ()
    incomplete: bool = False


@dataclass(frozen=True)
class _Run:
    source: TravelSource
    evidence: SourceEvidence
    items: tuple[dict[str, Any], ...]


def _extract_items(data: Any) -> tuple[dict[str, Any], ...]:
    if isinstance(data, list):
        values = data
    elif isinstance(data, dict):
        values = next((data[key] for key in ("items", "options", "results") if isinstance(data.get(key), list)), [])
    else:
        values = []
    return tuple(value for value in values if isinstance(value, dict))


def _stable_key(item: dict[str, Any]) -> str:
    explicit = item.get("providerReference") or item.get("provider_reference") or item.get("id")
    if explicit:
        return f"ref:{explicit}"
    selected = {
        key: item.get(key)
        for key in (
            "type", "origin", "destination", "departureAt", "arrivalAt",
            "checkIn", "checkOut", "propertyName", "currency", "totalPrice",
        )
        if item.get(key) is not None
    }
    payload = json.dumps(selected or item, sort_keys=True, separators=(",", ":"), default=str)
    return "sha256:" + hashlib.sha256(payload.encode()).hexdigest()


class FederatedTravelExecutor:
    """Run an explicit, auditable set of trusted read connectors."""

    def __init__(self, registry: ConnectorRegistry) -> None:
        self.registry = registry

    async def _run_one(
        self,
        source: TravelSource,
        payload: dict[str, Any],
        ctx: ExecutionContext,
    ) -> _Run:
        started = time.perf_counter()
        registration = self.registry.trusted(
            source.service_id, source.capability, ctx.organization_id
        )
        if registration is None:
            evidence = SourceEvidence(
                serviceId=source.service_id,
                capability=source.capability,
                status="unavailable",
                latencyMs=int((time.perf_counter() - started) * 1000),
                itemCount=0,
                error=ConnectionError(
                    code="CONNECTION_UNAVAILABLE",
                    message="No trusted connector is available for this source",
                ),
            )
            return _Run(source, evidence, ())

        if not await registration.connector.health_check(ctx):
            evidence = SourceEvidence(
                serviceId=source.service_id,
                capability=source.capability,
                connectorId=registration.manifest.connector_id,
                status="unavailable",
                latencyMs=int((time.perf_counter() - started) * 1000),
                itemCount=0,
                error=ConnectionError(
                    code="CONNECTOR_UNHEALTHY",
                    message="Trusted connector failed its health check",
                    retryable=True,
                ),
            )
            return _Run(source, evidence, ())

        result = await registration.connector.execute(source.capability, payload, ctx)
        items = _extract_items(result.data) if result.status != "failed" else ()
        evidence = SourceEvidence(
            serviceId=source.service_id,
            capability=source.capability,
            connectorId=registration.manifest.connector_id,
            status=result.status,
            latencyMs=int((time.perf_counter() - started) * 1000),
            itemCount=len(items),
            error=result.error,
        )
        enriched = tuple(
            {
                **item,
                "_source": {
                    "serviceId": source.service_id,
                    "connectorId": registration.manifest.connector_id,
                    "capability": source.capability,
                },
            }
            for item in items
        )
        return _Run(source, evidence, enriched)

    async def execute(
        self,
        sources: Iterable[TravelSource],
        payload: dict[str, Any],
        ctx: ExecutionContext,
    ) -> FederatedTravelResult:
        ordered = sorted(tuple(sources), key=lambda source: source.priority)
        if not ordered:
            return FederatedTravelResult(status="failed", incomplete=True)

        runs = await asyncio.gather(
            *(self._run_one(source, payload, ctx) for source in ordered)
        )
        unique: dict[str, dict[str, Any]] = {}
        for run in runs:
            for item in run.items:
                unique.setdefault(_stable_key(item), item)

        successes = sum(run.evidence.status == "success" for run in runs)
        incomplete = successes != len(runs)
        status = "success" if successes == len(runs) else ("partial" if successes else "failed")
        return FederatedTravelResult(
            status=status,
            items=tuple(unique.values()),
            sources=tuple(run.evidence for run in runs),
            incomplete=incomplete,
        )
