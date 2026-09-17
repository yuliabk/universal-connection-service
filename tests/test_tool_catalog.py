import asyncio

import pytest

from universal_connection_service.capability_schemas import CapabilitySchema, SchemaAnnotatedConnector
from universal_connection_service.contracts import ConnectorManifest, ConnectorResult
from universal_connection_service.registry import ConnectorRegistry, Registration
from universal_connection_service.service import ConnectionService
from universal_connection_service.tool_catalog import (
    AgentToolPolicy,
    InMemoryAgentToolPolicyStore,
    ToolCatalog,
    ToolCatalogError,
    to_gemini_declarations,
    to_mcp_tools,
    validate_tool_input,
)

ORG = "org-1"
AGENT = "travel-proposal"

SEARCH_SCHEMA = CapabilitySchema(
    capability="flights.search",
    description="Search flight offers",
    operation="read",
    readOnly=True,
    inputSchema={
        "type": "object",
        "properties": {
            "query": {
                "type": "object",
                "properties": {"origin": {"type": "string"}, "destination": {"type": "string"}},
                "required": ["origin", "destination"],
                "additionalProperties": False,
            }
        },
        "required": ["query"],
        "additionalProperties": False,
    },
)


class FlightsConnector:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    def manifest(self) -> ConnectorManifest:
        return ConnectorManifest(
            connectorId="flights-1",
            serviceId="flights",
            name="Flights",
            version="1.0.0",
            strategy="api",
            capabilities=("flights.search",),
        )

    async def health_check(self, ctx) -> bool:
        return True

    async def execute(self, capability, input, ctx) -> ConnectorResult:
        self.calls.append((capability, input))
        return ConnectorResult(status="success", data={"offers": 2})


def build(status: str = "trusted", tools: tuple[str, ...] = ("flights__flights_search",)):
    connector = SchemaAnnotatedConnector(FlightsConnector(), (SEARCH_SCHEMA,))
    registry = ConnectorRegistry()
    registry.register(Registration(connector=connector, status=status, organization_id=ORG))
    policies = InMemoryAgentToolPolicyStore(
        (AgentToolPolicy(organizationId=ORG, agentId=AGENT, tools=tools),)
    )
    return registry, ToolCatalog(registry, policies), connector


def test_trusted_and_allowlisted_capability_becomes_a_tool():
    _, catalog, _ = build()
    tools = catalog.tools(ORG, AGENT)
    assert [tool.name for tool in tools] == ["flights__flights_search"]
    assert tools[0].connector_version == "1.0.0"


def test_tool_name_is_sanitized_for_function_calling():
    from universal_connection_service.tool_catalog import tool_name

    assert tool_name("flights", "flights.search") == "flights__flights_search"


def test_untrusted_connector_is_not_listed():
    _, catalog, _ = build(status="awaiting_approval", tools=("flights__flights_search",))
    assert catalog.tools(ORG, AGENT) == ()


def test_agent_without_policy_sees_nothing():
    _, catalog, _ = build(tools=("flights__flights_search",))
    assert catalog.tools(ORG, "unknown-agent") == ()


def test_tool_outside_the_allowlist_is_refused():
    _, catalog, _ = build(tools=())
    with pytest.raises(ToolCatalogError) as excinfo:
        catalog.resolve(ORG, AGENT, "flights__flights_search")
    assert excinfo.value.code == "TOOL_NOT_ALLOWED"


def test_unknown_tool_fails_closed():
    _, catalog, _ = build(tools=("maps__geocode",))
    with pytest.raises(ToolCatalogError) as excinfo:
        catalog.resolve(ORG, AGENT, "maps__geocode")
    assert excinfo.value.code == "TOOL_UNAVAILABLE"


def test_input_validation_rejects_missing_required_section():
    _, catalog, _ = build(tools=("flights__flights_search",))
    definition = catalog.resolve(ORG, AGENT, "flights__flights_search")
    assert validate_tool_input(definition, {}) is not None
    assert validate_tool_input(definition, {"query": {"origin": "TLV", "destination": "ATH"}}) is None


def test_rendering_for_mcp_and_gemini():
    _, catalog, _ = build(tools=("flights__flights_search",))
    tools = catalog.tools(ORG, AGENT)
    mcp = to_mcp_tools(tools)
    assert mcp[0]["inputSchema"]["required"] == ["query"]
    assert mcp[0]["annotations"]["readOnlyHint"] is True

    gemini = to_gemini_declarations(tools)
    assert "additionalProperties" not in gemini[0]["parameters"]
    assert "additionalProperties" not in gemini[0]["parameters"]["properties"]["query"]


def test_call_routes_through_the_connection_service():
    registry, catalog, connector = build(tools=("flights__flights_search",))
    service = ConnectionService(registry)
    definition = catalog.resolve(ORG, AGENT, "flights__flights_search")

    from universal_connection_service.contracts import (
        ActorRef,
        ConnectionRequest,
        ExecutionContext,
        ServiceRef,
    )

    request = ConnectionRequest(
        requestId="r-1",
        actor=ActorRef(userId="u-1", organizationId=ORG, agentId=AGENT),
        service=ServiceRef(id=definition.service_id, name=definition.service_id),
        capability=definition.capability,
        operation=definition.operation,
        input={"query": {"origin": "TLV", "destination": "ATH"}},
        readOnly=definition.read_only,
    )
    context = ExecutionContext(requestId="r-1", userId="u-1", organizationId=ORG)
    result = asyncio.run(service.execute(request, context))

    assert result.status == "success"
    assert result.audit_id
    assert connector.inner.calls[0][0] == "flights.search"


def test_validation_degrades_structurally_without_jsonschema(monkeypatch):
    """If jsonschema is unavailable, argument checking must weaken, not vanish."""
    import universal_connection_service.tool_catalog as module

    monkeypatch.setattr(module, "Draft202012Validator", None)
    _, catalog, _ = build(tools=("flights__flights_search",))
    definition = catalog.resolve(ORG, AGENT, "flights__flights_search")

    assert validate_tool_input(definition, {}) is not None  # required section still checked
    assert validate_tool_input(definition, {"unexpected": {}}) is not None  # unknown section rejected
    assert validate_tool_input(definition, {"query": {"origin": "TLV", "destination": "ATH"}}) is None
