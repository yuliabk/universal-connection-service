from __future__ import annotations

import asyncio

from universal_connection_service.contracts import (
    AuthRequirement, ConnectorManifest, ConnectorResult, ExecutionContext,
)
from universal_connection_service.registry import ConnectorRegistry, Registration
from universal_connection_service.travel_federation import (
    FederatedTravelExecutor, TravelSource,
)


class FakeConnector:
    def __init__(self, connector_id, service_id, items=(), healthy=True, fail=False):
        self.connector_id = connector_id
        self.service_id = service_id
        self.items = list(items)
        self.healthy = healthy
        self.fail = fail

    def manifest(self):
        return ConnectorManifest(
            connectorId=self.connector_id,
            serviceId=self.service_id,
            name=self.connector_id,
            version="1.0.0",
            strategy="mcp",
            capabilities=("travel.flight.search@1",),
            auth=AuthRequirement(),
        )

    async def health_check(self, ctx):
        return self.healthy

    async def execute(self, capability, input, ctx):
        if self.fail:
            from universal_connection_service.contracts import ConnectionError
            return ConnectorResult(
                status="failed",
                error=ConnectionError(code="UPSTREAM_FAILED", message="upstream failed"),
            )
        return ConnectorResult(status="success", data={"items": self.items})


def ctx(org="tenant-a"):
    return ExecutionContext(
        requestId="req-1", userId="user-1", organizationId=org, deadlineMs=1000
    )


def test_federates_and_deduplicates_stable_references():
    registry = ConnectorRegistry()
    registry.register(Registration(
        FakeConnector("a", "sabre", [{"id": "same", "price": 100}]),
        status="trusted",
    ))
    registry.register(Registration(
        FakeConnector("b", "expedia", [{"id": "same", "price": 101}, {"id": "new"}]),
        status="trusted",
    ))
    result = asyncio.run(FederatedTravelExecutor(registry).execute(
        [
            TravelSource(serviceId="sabre", capability="travel.flight.search@1", priority=1),
            TravelSource(serviceId="expedia", capability="travel.flight.search@1", priority=2),
        ],
        {"origin": "TLV", "destination": "ATH"},
        ctx(),
    ))
    assert result.status == "success"
    assert result.incomplete is False
    assert [item["id"] for item in result.items] == ["same", "new"]
    assert result.items[0]["_source"]["serviceId"] == "sabre"


def test_partial_failure_is_explicit():
    registry = ConnectorRegistry()
    registry.register(Registration(
        FakeConnector("a", "sabre", [{"id": "ok"}]), status="trusted"
    ))
    registry.register(Registration(
        FakeConnector("b", "expedia", fail=True), status="trusted"
    ))
    result = asyncio.run(FederatedTravelExecutor(registry).execute(
        [
            TravelSource(serviceId="sabre", capability="travel.flight.search@1"),
            TravelSource(serviceId="expedia", capability="travel.flight.search@1"),
        ],
        {},
        ctx(),
    ))
    assert result.status == "partial"
    assert result.incomplete is True
    assert result.sources[1].error.code == "UPSTREAM_FAILED"


def test_tenant_connector_is_not_visible_to_another_tenant():
    registry = ConnectorRegistry()
    registry.register(Registration(
        FakeConnector("private", "expedia", [{"id": "secret"}]),
        status="trusted",
        organization_id="tenant-a",
    ))
    result = asyncio.run(FederatedTravelExecutor(registry).execute(
        [TravelSource(serviceId="expedia", capability="travel.flight.search@1")],
        {},
        ctx("tenant-b"),
    ))
    assert result.status == "failed"
    assert result.items == ()
    assert result.sources[0].error.code == "CONNECTION_UNAVAILABLE"
