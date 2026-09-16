import httpx

from universal_connection_service.compiler import ConnectionCompiler
from universal_connection_service.contracts import (
    ActorRef,
    AuthRequirement,
    ConnectionRequest,
    ConnectorManifest,
    ConnectorResult,
    DiscoveryCandidateRef,
    ServiceRef,
)
from universal_connection_service.discovery import (
    DiscoveryEngine,
    DiscoveryQuery,
    MCPRegistryConfig,
    MCPRegistryDiscoveryProvider,
)
from universal_connection_service.persistence import SQLiteStateStore
from universal_connection_service.registry import ConnectorRegistry, Registration


class StubConnector:
    def manifest(self):
        return ConnectorManifest(
            connectorId="trusted-weather",
            serviceId="weather",
            name="Trusted Weather",
            version="1.0.0",
            strategy="api",
            capabilities=("weather.read",),
            auth=AuthRequirement(type="none"),
        )

    async def health_check(self, ctx):
        return True

    async def execute(self, capability, input, ctx):
        return ConnectorResult(status="success", data={"ok": True})


class StaticProvider:
    def __init__(self, candidates=(), *, fail=False):
        self.candidates = tuple(candidates)
        self.fail = fail
        self.calls = 0

    def discover(self, query):
        self.calls += 1
        if self.fail:
            raise RuntimeError("registry unavailable")
        return self.candidates


def query():
    return DiscoveryQuery(serviceId="weather", serviceName="Weather", capability="weather.read")


def request():
    return ConnectionRequest(
        requestId="r1",
        actor=ActorRef(userId="u1", organizationId="o1", agentId="a1"),
        service=ServiceRef(id="weather", name="Weather"),
        capability="weather.read",
        operation="read",
    )


def remote_candidate(candidate_id="remote-1", *, confidence=100, endpoint="https://weather.example/mcp"):
    return DiscoveryCandidateRef(
        candidateId=candidate_id,
        source="mcp_registry",
        name="Weather MCP",
        version="1.0.0",
        strategy="mcp",
        transport="streamable-http",
        endpoint=endpoint,
        authRequirement=AuthRequirement(type="none"),
        confidence=confidence,
        actionable=True,
        requiresBuild=False,
    )


def test_mcp_registry_parses_current_wrapped_remote_server():
    def handler(req):
        assert req.url.path == "/v0.1/servers"
        assert req.url.params["search"] == "Weather"
        assert req.url.params["version"] == "latest"
        return httpx.Response(
            200,
            json={
                "servers": [
                    {
                        "server": {
                            "name": "io.github.acme/weather",
                            "title": "Weather",
                            "version": "1.2.0",
                            "remotes": [
                                {"type": "streamable-http", "url": "https://weather.example/mcp"}
                            ],
                        }
                    }
                ],
                "metadata": {"count": 1},
            },
        )

    provider = MCPRegistryDiscoveryProvider(
        MCPRegistryConfig(baseUrl="https://registry.example"),
        client_factory=lambda: httpx.Client(
            transport=httpx.MockTransport(handler),
            base_url="https://registry.example",
        ),
    )
    candidates = provider.discover(query())
    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.strategy == "mcp"
    assert candidate.transport == "streamable-http"
    assert candidate.endpoint == "https://weather.example/mcp"
    assert candidate.actionable is True
    assert candidate.requires_build is False
    assert candidate.confidence == 100


def test_registry_pagination_uses_opaque_cursor_and_cache_avoids_repeat_calls():
    calls = []

    def handler(req):
        calls.append(str(req.url))
        cursor = req.url.params.get("cursor")
        if cursor is None:
            return httpx.Response(
                200,
                json={
                    "servers": [],
                    "metadata": {"nextCursor": "opaque/a+b=="},
                },
            )
        assert cursor == "opaque/a+b=="
        return httpx.Response(
            200,
            json={
                "servers": [
                    {
                        "server": {
                            "name": "io.github.acme/weather",
                            "version": "1.0.0",
                            "remotes": [
                                {"type": "streamable-http", "url": "https://weather.example/mcp"}
                            ],
                        }
                    }
                ],
                "metadata": {},
            },
        )

    provider = MCPRegistryDiscoveryProvider(
        MCPRegistryConfig(baseUrl="https://registry.example", maxPages=2, cacheTtlSeconds=3600),
        client_factory=lambda: httpx.Client(
            transport=httpx.MockTransport(handler),
            base_url="https://registry.example",
        ),
    )
    assert len(provider.discover(query())) == 1
    assert len(calls) == 2
    assert len(provider.discover(query())) == 1
    assert len(calls) == 2


def test_unsafe_remote_is_rejected_and_package_is_discovery_only():
    def handler(req):
        return httpx.Response(
            200,
            json={
                "servers": [
                    {
                        "server": {
                            "name": "io.github.acme/weather",
                            "version": "2.0.0",
                            "remotes": [
                                {"type": "streamable-http", "url": "http://weather.example/mcp"},
                                {"type": "sse", "url": "https://weather.example/sse"},
                            ],
                            "packages": [
                                {
                                    "registryType": "npm",
                                    "identifier": "@acme/weather-mcp",
                                    "version": "2.0.0",
                                    "transport": {"type": "stdio"},
                                    "fileSha256": "a" * 64,
                                }
                            ],
                        }
                    }
                ],
                "metadata": {},
            },
        )

    provider = MCPRegistryDiscoveryProvider(
        MCPRegistryConfig(baseUrl="https://registry.example"),
        client_factory=lambda: httpx.Client(
            transport=httpx.MockTransport(handler),
            base_url="https://registry.example",
        ),
    )
    candidates = provider.discover(query())
    assert len(candidates) == 2
    assert all(candidate.endpoint != "http://weather.example/mcp" for candidate in candidates)
    sse = next(candidate for candidate in candidates if candidate.transport == "sse")
    assert sse.actionable is False
    package = next(candidate for candidate in candidates if candidate.package_identifier)
    assert package.package_registry == "npm"
    assert package.package_identifier == "@acme/weather-mcp"
    assert package.package_sha256 == "a" * 64
    assert package.actionable is False
    assert package.requires_build is True


def test_trusted_connector_wins_without_discovery_call():
    provider = StaticProvider((remote_candidate(),))
    registry = ConnectorRegistry()
    registry.register(Registration(connector=StubConnector(), status="trusted"))
    compiler = ConnectionCompiler(registry, discovery_engine=DiscoveryEngine((provider,)))
    plan = compiler.compile(request())
    assert plan.strategy == "trusted_connector"
    assert plan.connector_id == "trusted-weather"
    assert plan.discovery_candidates == ()
    assert provider.calls == 0


def test_single_remote_candidate_becomes_reviewable_mcp_plan():
    provider = StaticProvider((remote_candidate(),))
    compiler = ConnectionCompiler(ConnectorRegistry(), discovery_engine=DiscoveryEngine((provider,)))
    plan = compiler.compile(request())
    assert plan.strategy == "mcp"
    assert plan.connector_id is None
    assert plan.requires_build is False
    assert plan.requires_validation is True
    assert plan.policy_decision == "REQUIRE_APPROVAL"
    assert plan.selected_discovery_candidate_id == "remote-1"
    assert plan.requires_selection is False
    assert len(plan.discovery_candidates) == 1


def test_ambiguous_candidates_require_selection_instead_of_guessing():
    provider = StaticProvider(
        (
            remote_candidate("remote-1", confidence=100, endpoint="https://one.example/mcp"),
            remote_candidate("remote-2", confidence=100, endpoint="https://two.example/mcp"),
        )
    )
    compiler = ConnectionCompiler(ConnectorRegistry(), discovery_engine=DiscoveryEngine((provider,)))
    plan = compiler.compile(request())
    assert plan.strategy == "mcp"
    assert plan.selected_discovery_candidate_id is None
    assert plan.requires_selection is True
    assert len(plan.discovery_candidates) == 2


def test_discovery_failure_falls_back_to_existing_generation_path():
    provider = StaticProvider(fail=True)
    compiler = ConnectionCompiler(ConnectorRegistry(), discovery_engine=DiscoveryEngine((provider,)))
    plan = compiler.compile(request())
    assert plan.strategy == "generated_api_adapter"
    assert plan.requires_build is True
    assert plan.discovery_candidates == ()
    assert provider.calls == 1


def test_execution_phase_never_calls_external_discovery():
    provider = StaticProvider((remote_candidate(),))
    compiler = ConnectionCompiler(ConnectorRegistry(), discovery_engine=DiscoveryEngine((provider,)))
    plan = compiler.compile(request(), phase="execution")
    assert plan.strategy == "generated_api_adapter"
    assert plan.discovery_candidates == ()
    assert provider.calls == 0


def test_discovery_evidence_contains_only_candidate_metadata():
    store = SQLiteStateStore(":memory:")
    provider = StaticProvider((remote_candidate(),))
    compiler = ConnectionCompiler(
        ConnectorRegistry(),
        evidence_store=store,
        discovery_engine=DiscoveryEngine((provider,)),
    )
    plan = compiler.compile(request())
    assert plan.selected_discovery_candidate_id == "remote-1"
    evidence = store.list_evidence("o1", request_id="r1", kind="validation")
    discovery = [item for item in evidence if item.payload.get("type") == "discovery"]
    assert len(discovery) == 1
    assert discovery[0].payload["candidateIds"] == ["remote-1"]
    assert "https://weather.example/mcp" not in str(discovery[0].payload)
    store.close()
