import asyncio

from mcp import Client
from mcp.server.mcpserver import MCPServer
from pydantic import BaseModel

from universal_connection_service.contracts import (
    ActorRef,
    AuthRequirement,
    ConnectionRequest,
    DiscoveryCandidateRef,
    ServiceRef,
)
from universal_connection_service.mcp_validation import MCPValidationService
from universal_connection_service.persistence import SQLiteStateStore
from universal_connection_service.registry import ConnectorRegistry


class WeatherResult(BaseModel):
    temperature: int


auto_server = MCPServer("Weather Validation", version="1.0.0")


@auto_server.tool()
def get_weather(city: str) -> WeatherResult:
    return WeatherResult(temperature=20)


ambiguous_server = MCPServer("Ambiguous Weather", version="1.0.0")


@ambiguous_server.tool()
def get_weather(city: str) -> WeatherResult:
    return WeatherResult(temperature=20)


@ambiguous_server.tool()
def list_weather(city: str) -> WeatherResult:
    return WeatherResult(temperature=20)


destructive_server = MCPServer("Destructive Weather", version="1.0.0")


@destructive_server.tool()
def delete_weather(city: str) -> str:
    return city


def request(*, request_id="r1") -> ConnectionRequest:
    return ConnectionRequest(
        requestId=request_id,
        actor=ActorRef(userId="u1", organizationId="o1", agentId="a1"),
        service=ServiceRef(id="weather", name="Weather"),
        capability="weather.read",
        operation="read",
    )


def candidate(*, auth="none", actionable=True) -> DiscoveryCandidateRef:
    return DiscoveryCandidateRef(
        candidateId="mcp-weather-1",
        source="mcp_registry",
        name="Weather MCP",
        version="1.0.0",
        strategy="mcp",
        transport="streamable-http",
        endpoint="https://weather.example/mcp",
        authRequirement=AuthRequirement(type=auth),
        confidence=100,
        actionable=actionable,
        requiresBuild=False,
    )


def test_candidate_introspection_auto_maps_and_promotes_only_to_validated():
    store = SQLiteStateStore(":memory:")
    registry = ConnectorRegistry(state_store=store)
    service = MCPValidationService(
        registry,
        evidence_store=store,
        client_factory=lambda: Client(auto_server),
    )

    report = asyncio.run(service.validate(candidate(), request()))

    assert report.passed is True
    assert report.code == "MCP_CANDIDATE_VALIDATED"
    assert report.selected_tool == "get_weather"
    assert report.selection_mode == "automatic"
    assert report.lifecycle == "validated"
    assert report.tool_count == 1
    assert report.tools[0].input_schema_sha256
    assert report.tools[0].required_inputs == ("city",)
    assert registry.trusted("weather", "weather.read", "o1") is None
    persisted = store.list_connectors("o1")
    assert len(persisted) == 1
    assert persisted[0].status == "validated"
    store.close()


def test_ambiguous_tool_mapping_requires_explicit_selection_and_registers_nothing():
    registry = ConnectorRegistry()
    service = MCPValidationService(
        registry,
        client_factory=lambda: Client(ambiguous_server),
    )

    report = asyncio.run(service.validate(candidate(), request()))

    assert report.passed is False
    assert report.code == "MCP_TOOL_SELECTION_REQUIRED"
    assert report.requires_selection is True
    assert {match.tool_name for match in report.matches[:2]} == {"get_weather", "list_weather"}
    assert registry.manifests("o1") == []


def test_explicit_tool_selection_resolves_ambiguity():
    registry = ConnectorRegistry()
    service = MCPValidationService(
        registry,
        client_factory=lambda: Client(ambiguous_server),
    )

    report = asyncio.run(
        service.validate(
            candidate(),
            request(),
            selected_tool="list_weather",
        )
    )

    assert report.passed is True
    assert report.selected_tool == "list_weather"
    assert report.selection_mode == "explicit"
    assert report.lifecycle == "validated"


def test_non_actionable_candidate_is_rejected_before_any_client_is_opened():
    calls = 0

    def factory():
        nonlocal calls
        calls += 1
        return Client(auto_server)

    report = asyncio.run(
        MCPValidationService(ConnectorRegistry(), client_factory=factory).validate(
            candidate(actionable=False),
            request(),
        )
    )

    assert report.passed is False
    assert report.code == "MCP_CANDIDATE_NOT_ACTIONABLE"
    assert calls == 0


def test_authenticated_candidate_without_brokered_handle_fails_before_network():
    report = asyncio.run(
        MCPValidationService(ConnectorRegistry()).validate(
            candidate(auth="api_key"),
            request(),
        )
    )

    assert report.passed is False
    assert report.code == "CREDENTIAL_HANDLE_REQUIRED"


def test_destructive_named_tool_is_not_auto_mapped_to_read_capability():
    report = asyncio.run(
        MCPValidationService(
            ConnectorRegistry(),
            client_factory=lambda: Client(destructive_server),
        ).validate(candidate(), request())
    )

    assert report.passed is False
    assert report.code == "MCP_TOOL_SELECTION_REQUIRED"
    assert report.requires_selection is True


def test_validation_evidence_uses_endpoint_hash_and_not_raw_url():
    store = SQLiteStateStore(":memory:")
    registry = ConnectorRegistry(state_store=store)
    report = asyncio.run(
        MCPValidationService(
            registry,
            evidence_store=store,
            client_factory=lambda: Client(auto_server),
        ).validate(candidate(), request(request_id="evidence-1"))
    )
    assert report.passed is True

    evidence = store.list_evidence("o1", request_id="evidence-1", kind="validation")
    validation = [item for item in evidence if item.payload.get("type") == "mcp_candidate_validation"]
    assert len(validation) == 1
    assert validation[0].payload["endpointHash"]
    assert "https://weather.example/mcp" not in str(validation[0].payload)
    store.close()
