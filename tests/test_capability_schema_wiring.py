import pytest

from universal_connection_service.capability_schemas import CapabilitySchema, capability_schemas_of
from universal_connection_service.mcp_adapter import (
    MCPConnectorAdapter,
    MCPConnectorConfig,
    MCPHTTPConfig,
    MCPToolBinding,
)
from universal_connection_service.mcp_validation import MCPToolSnapshot, _capability_schema_for, _snapshot_tool
from universal_connection_service.openapi_adapter import OpenAPIConnectorConfig, compile_openapi_connector
from universal_connection_service.registry import ConnectorRegistry, Registration
from universal_connection_service.tool_catalog import (
    AgentToolPolicy,
    InMemoryAgentToolPolicyStore,
    ToolCatalog,
)

pytest.importorskip("openapi_spec_validator")

SPEC = {
    "openapi": "3.0.3",
    "info": {"title": "Flights", "version": "1.0.0"},
    "paths": {
        "/offers": {
            "get": {
                "operationId": "searchOffers",
                "summary": "Search flight offers",
                "parameters": [
                    {"name": "origin", "in": "query", "required": True, "schema": {"type": "string"}},
                    {"name": "adults", "in": "query", "schema": {"type": "integer"}},
                ],
                "responses": {"200": {"description": "ok"}},
            }
        }
    },
}


def compiled_connector():
    return compile_openapi_connector(
        SPEC,
        connector_id="flights-1",
        service_id="flights",
        name="Flights",
        version="1.0.0",
        base_url="https://api.example.com",
    ).connector


def test_compiled_openapi_connector_publishes_the_spec_contract():
    connector = compiled_connector()
    schemas = {schema.capability: schema for schema in connector.capability_schemas()}
    query = schemas["searchOffers"].input_schema["properties"]["query"]
    assert query["required"] == ["origin"]
    assert set(query["properties"]) == {"origin", "adults"}
    assert schemas["searchOffers"].read_only is True


def test_published_schema_survives_a_package_round_trip():
    connector = compiled_connector()
    restored = OpenAPIConnectorConfig.model_validate_json(
        connector.config.model_dump_json(by_alias=True)
    )
    assert restored.bindings[0].capability_schema is not None
    assert restored.bindings[0].capability_schema.input_schema == (
        connector.config.bindings[0].capability_schema.input_schema
    )


def test_binding_without_a_schema_degrades_to_the_permissive_envelope():
    connector = compiled_connector()
    config = connector.config.model_copy(
        update={"bindings": (connector.config.bindings[0].model_copy(update={"capability_schema": None}),)}
    )
    degraded = type(connector)(config)
    schema = degraded.capability_schemas()[0]
    assert set(schema.input_schema["properties"]) == {"path", "query", "body"}


def mcp_adapter(binding: MCPToolBinding):
    return MCPConnectorAdapter(
        MCPConnectorConfig(
            connectorId="mcp-1",
            serviceId="kiwi",
            name="Kiwi",
            version="1.0.0",
            bindings=(binding,),
            endpoint=MCPHTTPConfig(url="https://mcp.example.com/mcp"),
        ),
        client_factory=lambda: None,
    )


def test_mcp_binding_publishes_the_tool_schema_without_an_envelope():
    tool_schema = {
        "type": "object",
        "properties": {"flyFrom": {"type": "string"}},
        "required": ["flyFrom"],
    }
    adapter = mcp_adapter(
        MCPToolBinding(
            capability="flights.search",
            tool="search_flights",
            capabilitySchema=CapabilitySchema(capability="flights.search", inputSchema=tool_schema),
        )
    )
    published = adapter.capability_schemas()[0]
    assert published.input_schema == tool_schema
    assert "query" not in published.input_schema["properties"]


def test_mcp_binding_without_a_schema_claims_nothing():
    adapter = mcp_adapter(MCPToolBinding(capability="flights.search", tool="search_flights"))
    assert adapter.capability_schemas()[0].input_schema == {"type": "object"}


def test_snapshot_keeps_both_the_digest_and_the_schema():
    snapshot = _snapshot_tool(
        {
            "name": "search_flights",
            "description": "Search flights",
            "inputSchema": {"type": "object", "properties": {"flyFrom": {"type": "string"}}, "required": ["flyFrom"]},
            "annotations": {"readOnlyHint": True},
        }
    )
    assert len(snapshot.input_schema_sha256) == 64
    assert snapshot.input_schema["required"] == ["flyFrom"]
    assert snapshot.required_inputs == ("flyFrom",)


def test_capability_schema_from_snapshot_uses_hints_conservatively():
    tools = (
        MCPToolSnapshot(
            name="delete_booking",
            description="Delete a booking",
            inputSchemaSha256="a" * 64,
            inputSchema={"type": "object"},
            destructiveHint=True,
        ),
        MCPToolSnapshot(name="other", inputSchemaSha256="b" * 64, inputSchema={"type": "object"}),
    )
    schema = _capability_schema_for("bookings.delete", tools, "delete_booking")
    assert schema.risk_hints.destructive is True
    assert schema.read_only is False  # no readOnlyHint means not read-only
    assert schema.operation == "execute"


def test_capability_schema_is_absent_when_the_server_reported_no_schema():
    tools = (MCPToolSnapshot(name="x", inputSchemaSha256="c" * 64),)
    assert _capability_schema_for("cap", tools, "x") is None
    assert _capability_schema_for("cap", tools, "missing-tool") is None


def test_catalog_uses_adapter_schemas_without_manual_annotation():
    connector = compiled_connector()
    registry = ConnectorRegistry()
    registry.register(Registration(connector=connector, status="trusted", organization_id="org-1"))
    catalog = ToolCatalog(
        registry,
        InMemoryAgentToolPolicyStore(
            (AgentToolPolicy(organizationId="org-1", agentId="a1", tools=("flights__searchOffers",)),)
        ),
    )
    tools = catalog.tools("org-1", "a1")
    assert tools[0].description == "Search flight offers"
    assert tools[0].input_schema["properties"]["query"]["required"] == ["origin"]
    assert capability_schemas_of(connector)[0].capability == "searchOffers"
