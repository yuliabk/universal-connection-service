import asyncio

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from universal_connection_service.capability_schemas import CapabilitySchema, SchemaAnnotatedConnector
from universal_connection_service.contracts import ConnectorManifest, ConnectorResult
from universal_connection_service.drift_scheduler import SchemaDriftScheduler
from universal_connection_service.mcp_server import build_mcp_server_router
from universal_connection_service.registry import ConnectorRegistry, Registration
from universal_connection_service.run_budget_sqlite import SQLiteRunBudget
from universal_connection_service.service import ConnectionService
from universal_connection_service.tool_catalog import (
    AgentToolPolicy,
    InMemoryAgentToolPolicyStore,
    ToolCatalog,
    ToolExecutor,
)

ORG = "org-1"
AGENT = "travel-proposal"
TOOL = "flights__flights_search"

SCHEMA = CapabilitySchema(
    capability="flights.search",
    description="Search flight offers",
    inputSchema={
        "type": "object",
        "properties": {
            "query": {
                "type": "object",
                "properties": {"origin": {"type": "string"}},
                "required": ["origin"],
                "additionalProperties": False,
            }
        },
        "required": ["query"],
        "additionalProperties": False,
    },
)


class Flights:
    def __init__(self, fail: bool = False) -> None:
        self.fail = fail

    def manifest(self):
        return ConnectorManifest(
            connectorId="flights-1",
            serviceId="flights",
            name="Flights",
            version="1.0.0",
            strategy="api",
            capabilities=("flights.search",),
        )

    async def health_check(self, ctx):
        return True

    async def execute(self, capability, input, ctx):
        if self.fail:
            from universal_connection_service.contracts import ConnectionError

            return ConnectorResult(status="failed", error=ConnectionError(code="API_HTTP_ERROR", message="upstream"))
        return ConnectorResult(status="success", data={"offers": [{"price": 412}]})


class AllowAll:
    def authenticate(self, authorization):
        return object() if authorization == "Bearer ok" else None


def build_client(*, tools=(TOOL,), max_calls=10, fail=False, budget=None):
    registry = ConnectorRegistry()
    registry.register(
        Registration(
            connector=SchemaAnnotatedConnector(Flights(fail=fail), (SCHEMA,)),
            status="trusted",
            organization_id=ORG,
        )
    )
    catalog = ToolCatalog(
        registry,
        InMemoryAgentToolPolicyStore(
            (AgentToolPolicy(organizationId=ORG, agentId=AGENT, tools=tools, maxCallsPerRun=max_calls),)
        ),
    )
    executor = ToolExecutor(catalog, ConnectionService(registry), run_budget=budget)
    app = FastAPI()
    app.include_router(build_mcp_server_router(catalog, executor, AllowAll()))
    return TestClient(app)


HEADERS = {
    "Authorization": "Bearer ok",
    "x-ucs-user-id": "u-1",
    "x-ucs-organization-id": ORG,
}


def rpc(client, method, params=None, request_id=1, headers=None):
    body = {"jsonrpc": "2.0", "method": method}
    if request_id is not None:
        body["id"] = request_id
    if params is not None:
        body["params"] = params
    return client.post(f"/v1/agents/{AGENT}/mcp", json=body, headers=headers or HEADERS)


def test_initialize_reports_only_tools_capability():
    client = build_client()
    result = rpc(client, "initialize", {"protocolVersion": "2025-06-18"}).json()["result"]
    assert result["protocolVersion"] == "2025-06-18"
    assert set(result["capabilities"]) == {"tools"}


def test_unknown_protocol_version_falls_back_to_the_server_version():
    client = build_client()
    result = rpc(client, "initialize", {"protocolVersion": "1999-01-01"}).json()["result"]
    assert result["protocolVersion"] == "2025-06-18"


def test_tools_list_returns_the_allowlisted_tool_with_its_schema():
    client = build_client()
    tools = rpc(client, "tools/list").json()["result"]["tools"]
    assert [tool["name"] for tool in tools] == [TOOL]
    assert tools[0]["inputSchema"]["required"] == ["query"]


def test_tools_call_succeeds_and_returns_the_audit_id():
    client = build_client()
    result = rpc(client, "tools/call", {"name": TOOL, "arguments": {"query": {"origin": "TLV"}}}).json()["result"]
    assert result["isError"] is False
    assert result["structuredContent"]["offers"][0]["price"] == 412
    assert result["_meta"]["auditId"]


def test_refused_tool_is_an_error_result_not_a_protocol_error():
    client = build_client(tools=())
    body = rpc(client, "tools/call", {"name": TOOL, "arguments": {"query": {"origin": "TLV"}}}).json()
    assert "error" not in body
    assert body["result"]["isError"] is True
    assert "TOOL_NOT_ALLOWED" in body["result"]["content"][0]["text"]


def test_invalid_arguments_are_reported_to_the_model():
    client = build_client()
    result = rpc(client, "tools/call", {"name": TOOL, "arguments": {"query": {}}}).json()["result"]
    assert result["isError"] is True
    assert "INVALID_TOOL_INPUT" in result["content"][0]["text"]


def test_upstream_failure_is_an_error_result_with_the_audit_id():
    client = build_client(fail=True)
    result = rpc(client, "tools/call", {"name": TOOL, "arguments": {"query": {"origin": "TLV"}}}).json()["result"]
    assert result["isError"] is True
    assert result["_meta"]["auditId"]


def test_run_budget_applies_on_the_mcp_surface():
    client = build_client(max_calls=1, budget=SQLiteRunBudget(":memory:"))
    headers = {**HEADERS, "x-ucs-run-id": "turn-1"}
    first = rpc(client, "tools/call", {"name": TOOL, "arguments": {"query": {"origin": "TLV"}}}, headers=headers)
    second = rpc(client, "tools/call", {"name": TOOL, "arguments": {"query": {"origin": "TLV"}}}, headers=headers)
    assert first.json()["result"]["isError"] is False
    assert "TOOL_RUN_BUDGET_EXCEEDED" in second.json()["result"]["content"][0]["text"]


def test_identity_comes_from_headers_not_from_the_payload():
    client = build_client()
    response = client.post(
        f"/v1/agents/{AGENT}/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={"Authorization": "Bearer ok"},
    )
    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "AGENT_MCP_IDENTITY_REQUIRED"


def test_unauthenticated_call_is_rejected():
    client = build_client()
    response = client.post(
        f"/v1/agents/{AGENT}/mcp",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
        headers={**HEADERS, "Authorization": "Bearer nope"},
    )
    assert response.status_code == 401


def test_unimplemented_methods_say_so():
    client = build_client()
    body = rpc(client, "resources/list").json()
    assert body["error"]["code"] == -32601


def test_notifications_produce_no_response_body():
    client = build_client()
    body = rpc(client, "notifications/initialized", request_id=None).json()
    assert body == {}


def test_batch_drops_notifications_and_keeps_results():
    client = build_client()
    response = client.post(
        f"/v1/agents/{AGENT}/mcp",
        json=[
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 7, "method": "tools/list"},
        ],
        headers=HEADERS,
    )
    payload = response.json()
    assert len(payload) == 1
    assert payload[0]["id"] == 7


def test_malformed_message_is_an_invalid_request():
    client = build_client()
    response = client.post(f"/v1/agents/{AGENT}/mcp", json={"method": "tools/list"}, headers=HEADERS)
    assert response.json()["error"]["code"] == -32600


# --- durable budget -----------------------------------------------------


def test_sqlite_budget_enforces_the_limit_across_instances(tmp_path):
    path = str(tmp_path / "budget.db")
    first = SQLiteRunBudget(path)
    second = SQLiteRunBudget(path)  # a second worker sharing the same file
    assert first.consume(ORG, AGENT, "run-1", 2).allowed is True
    assert second.consume(ORG, AGENT, "run-1", 2).allowed is True
    assert first.consume(ORG, AGENT, "run-1", 2).allowed is False
    assert second.usage(ORG, AGENT, "run-1") == 2
    first.close()
    second.close()


def test_sqlite_budget_is_scoped_per_run(tmp_path):
    budget = SQLiteRunBudget(str(tmp_path / "budget.db"))
    assert budget.consume(ORG, AGENT, "run-1", 1).allowed is True
    assert budget.consume(ORG, AGENT, "run-2", 1).allowed is True
    assert budget.consume(ORG, AGENT, "run-1", 1).allowed is False
    budget.close()


# --- drift scheduler ----------------------------------------------------


class StubVerifier:
    def __init__(self, reports) -> None:
        self.reports = reports
        self.seen = []

    async def verify(self, organization_id, connector_id, version, *, ctx=None, deadline_ms=10000):
        self.seen.append(connector_id)
        outcome = self.reports.get(connector_id)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class Report:
    def __init__(self, code, checked=True, drifted=False, demoted=False) -> None:
        self.code = code
        self.checked = checked
        self.drifted = drifted
        self.demoted = demoted


def registry_with(statuses):
    registry = ConnectorRegistry()
    for index, status in enumerate(statuses):
        class Connector:
            def __init__(self, i):
                self.i = i

            def manifest(self):
                return ConnectorManifest(
                    connectorId=f"c-{self.i}",
                    serviceId=f"svc-{self.i}",
                    name="C",
                    version="1.0.0",
                    strategy="mcp",
                    capabilities=("cap",),
                )

            async def health_check(self, ctx):
                return True

            async def execute(self, capability, input, ctx):
                return ConnectorResult(status="success", data={})

        registry.register(Registration(connector=Connector(index), status=status, organization_id=ORG))
    return registry


def test_sweep_skips_untrusted_connectors():
    registry = registry_with(["trusted", "awaiting_approval"])
    verifier = StubVerifier({"c-0": Report("SCHEMA_STABLE")})
    scheduler = SchemaDriftScheduler(registry, verifier, stagger_seconds=0)
    result = asyncio.run(scheduler.sweep())
    assert verifier.seen == ["c-0"]
    assert result.checked == 1
    assert result.skipped == 1


def test_sweep_counts_drift_and_demotion():
    registry = registry_with(["trusted"])
    verifier = StubVerifier({"c-0": Report("DRIFT_DETECTED", drifted=True, demoted=True)})
    scheduler = SchemaDriftScheduler(registry, verifier, stagger_seconds=0)
    result = asyncio.run(scheduler.sweep())
    assert (result.drifted, result.demoted) == (1, 1)
    assert result.codes["DRIFT_DETECTED"] == 1


def test_one_failing_connector_does_not_end_the_sweep():
    registry = registry_with(["trusted", "trusted"])
    verifier = StubVerifier({"c-0": RuntimeError("boom"), "c-1": Report("SCHEMA_STABLE")})
    scheduler = SchemaDriftScheduler(registry, verifier, stagger_seconds=0)
    result = asyncio.run(scheduler.sweep())
    assert result.failures == 1
    assert result.checked == 1
    assert verifier.seen == ["c-0", "c-1"]


def test_scheduler_start_and_stop_are_idempotent():
    registry = registry_with(["trusted"])
    verifier = StubVerifier({"c-0": Report("SCHEMA_STABLE")})
    scheduler = SchemaDriftScheduler(registry, verifier, interval_seconds=3600, stagger_seconds=0)

    async def run():
        scheduler.start()
        scheduler.start()
        assert scheduler.running is True
        await scheduler.stop()
        await scheduler.stop()
        assert scheduler.running is False

    asyncio.run(run())


def test_non_positive_interval_is_rejected():
    with pytest.raises(ValueError):
        SchemaDriftScheduler(registry_with([]), StubVerifier({}), interval_seconds=0)
