import asyncio
from contextlib import asynccontextmanager
from datetime import timedelta

import pytest

from universal_connection_service.capability_schemas import CapabilitySchema
from universal_connection_service.mcp_adapter import (
    MCPConnectorAdapter,
    MCPConnectorConfig,
    MCPHTTPConfig,
    MCPToolBinding,
)
from universal_connection_service.registry import ConnectorRegistry, Registration
from universal_connection_service.run_budget import InMemoryRunBudget
from universal_connection_service.schema_drift import MCPSchemaDriftVerifier, SchemaDriftError

ORG = "org-1"
AGENT = "travel-proposal"
TOOL_SCHEMA = {"type": "object", "properties": {"flyFrom": {"type": "string"}}, "required": ["flyFrom"]}


# --- run budget ---------------------------------------------------------


def test_budget_allows_up_to_the_limit_then_refuses():
    budget = InMemoryRunBudget()
    decisions = [budget.consume(ORG, AGENT, "run-1", 2) for _ in range(3)]
    assert [d.allowed for d in decisions] == [True, True, False]
    assert decisions[1].remaining == 0
    assert decisions[2].used == 2  # a refused call does not consume budget


def test_budget_is_scoped_per_run_agent_and_organization():
    budget = InMemoryRunBudget()
    assert budget.consume(ORG, AGENT, "run-1", 1).allowed is True
    assert budget.consume(ORG, AGENT, "run-2", 1).allowed is True
    assert budget.consume(ORG, "other-agent", "run-1", 1).allowed is True
    assert budget.consume("org-2", AGENT, "run-1", 1).allowed is True
    assert budget.consume(ORG, AGENT, "run-1", 1).allowed is False


def test_zero_limit_blocks_every_call():
    budget = InMemoryRunBudget()
    assert budget.consume(ORG, AGENT, "run-1", 0).allowed is False


def test_expired_runs_are_discarded():
    budget = InMemoryRunBudget(ttl=timedelta(seconds=-1))
    assert budget.consume(ORG, AGENT, "run-1", 1).allowed is True
    assert budget.consume(ORG, AGENT, "run-1", 1).allowed is True  # previous entry expired


def test_run_table_stays_bounded():
    budget = InMemoryRunBudget(max_runs=5)
    for index in range(50):
        budget.consume(ORG, AGENT, f"run-{index}", 10)
    assert len(budget._runs) <= 5


# --- schema drift -------------------------------------------------------


class FakeTool:
    def __init__(self, name: str, schema: dict) -> None:
        self.name = name
        self.schema = schema

    def model_dump(self, **kwargs):
        return {"name": self.name, "inputSchema": self.schema, "annotations": {"readOnlyHint": True}}


class FakePage:
    def __init__(self, tools) -> None:
        self.tools = tools
        self.next_cursor = None


class FakeClient:
    def __init__(self, tools) -> None:
        self._tools = tools

    async def list_tools(self, cursor=None):
        return FakePage(self._tools)


def client_factory(tools):
    @asynccontextmanager
    async def factory():
        yield FakeClient(tools)

    return lambda: factory()


def build_registry(schema: dict = TOOL_SCHEMA, status: str = "trusted"):
    config = MCPConnectorConfig(
        connectorId="mcp-1",
        serviceId="kiwi",
        name="Kiwi",
        version="1.0.0",
        bindings=(
            MCPToolBinding(
                capability="flights.search",
                tool="search_flights",
                capabilitySchema=CapabilitySchema(capability="flights.search", inputSchema=schema),
            ),
        ),
        endpoint=MCPHTTPConfig(url="https://mcp.example.com/mcp"),
    )
    registry = ConnectorRegistry()
    registration = Registration(
        connector=MCPConnectorAdapter(config, client_factory=lambda: None),
        status=status,
        organization_id=ORG,
    )
    registry.register(registration)
    return registry, registration


def verify(registry, tools):
    verifier = MCPSchemaDriftVerifier(registry, client_factory=client_factory(tools))
    return asyncio.run(verifier.verify(ORG, "mcp-1", "1.0.0"))


def test_matching_schema_reports_stable():
    registry, registration = build_registry()
    report = verify(registry, [FakeTool("search_flights", TOOL_SCHEMA)])
    assert report.code == "SCHEMA_STABLE"
    assert report.drifted is False
    assert report.findings[0].status == "unchanged"
    assert registration.status == "trusted"


def test_changed_schema_drifts_and_demotes_the_connector():
    registry, registration = build_registry()
    changed = {"type": "object", "properties": {"origin": {"type": "string"}}, "required": ["origin"]}
    report = verify(registry, [FakeTool("search_flights", changed)])
    assert report.drifted is True
    assert report.code == "DRIFT_DETECTED"
    assert report.findings[0].status == "drifted"
    assert report.demoted is True
    assert registration.status == "degraded"


def test_removed_tool_counts_as_drift():
    registry, _ = build_registry()
    report = verify(registry, [FakeTool("something_else", TOOL_SCHEMA)])
    assert report.findings[0].status == "missing_tool"
    assert report.drifted is True


def test_unreachable_server_is_not_treated_as_drift():
    registry, registration = build_registry()

    def failing_factory():
        raise RuntimeError("connection refused")

    verifier = MCPSchemaDriftVerifier(registry, client_factory=failing_factory)
    report = asyncio.run(verifier.verify(ORG, "mcp-1", "1.0.0"))
    assert report.checked is False
    assert report.drifted is False
    assert report.code == "DRIFT_INTROSPECTION_FAILED"
    assert registration.status == "trusted"


def test_demotion_can_be_disabled():
    registry, registration = build_registry()
    verifier = MCPSchemaDriftVerifier(
        registry,
        client_factory=client_factory([FakeTool("search_flights", {"type": "object"})]),
        demote_on_drift=False,
    )
    report = asyncio.run(verifier.verify(ORG, "mcp-1", "1.0.0"))
    assert report.drifted is True
    assert report.demoted is False
    assert registration.status == "trusted"


def test_unknown_connector_fails_closed():
    registry, _ = build_registry()
    verifier = MCPSchemaDriftVerifier(registry, client_factory=client_factory([]))
    with pytest.raises(SchemaDriftError) as excinfo:
        asyncio.run(verifier.verify(ORG, "missing", "1.0.0"))
    assert excinfo.value.code == "CONNECTOR_NOT_FOUND"


def test_non_mcp_connector_is_reported_as_not_applicable():
    from universal_connection_service.contracts import ConnectorManifest, ConnectorResult

    class ApiConnector:
        def manifest(self):
            return ConnectorManifest(
                connectorId="api-1",
                serviceId="flights",
                name="Flights",
                version="1.0.0",
                strategy="api",
                capabilities=("flights.search",),
            )

        async def health_check(self, ctx):
            return True

        async def execute(self, capability, input, ctx):
            return ConnectorResult(status="success", data={})

    registry = ConnectorRegistry()
    registry.register(Registration(connector=ApiConnector(), status="trusted", organization_id=ORG))
    verifier = MCPSchemaDriftVerifier(registry, client_factory=client_factory([]))
    report = asyncio.run(verifier.verify(ORG, "api-1", "1.0.0"))
    assert report.checked is False
    assert report.code == "DRIFT_CHECK_NOT_APPLICABLE"
