from effect_helpers import approve_read
import asyncio

from mcp import Client
from mcp.server.mcpserver import MCPServer
from pydantic import BaseModel

from universal_connection_service.contracts import ActorRef, ConnectionRequest, ExecutionContext, ServiceRef
from universal_connection_service.mcp_adapter import (
    MCPConnectorAdapter,
    MCPConnectorConfig,
    MCPHTTPConfig,
    MCPToolBinding,
)
from universal_connection_service.registry import ConnectorRegistry, Registration
from universal_connection_service.service import ConnectionService


class EchoResult(BaseModel):
    value: str


mcp = MCPServer("Synthetic UCS MCP", version="1.0.0")


@mcp.tool()
def echo(value: str) -> EchoResult:
    return EchoResult(value=value)


@mcp.tool()
def explode() -> str:
    raise ValueError("synthetic failure")


def context(deadline_ms: int = 1000) -> ExecutionContext:
    return ExecutionContext(
        requestId="r1",
        userId="u1",
        organizationId="o1",
        deadlineMs=deadline_ms,
    )


def adapter(*, tool: str = "echo", capability: str = "records.read") -> MCPConnectorAdapter:
    return MCPConnectorAdapter(
        MCPConnectorConfig(
            connectorId="synthetic-mcp",
            serviceId="synthetic",
            name="Synthetic MCP",
            version="1.0.0",
            bindings=(MCPToolBinding(capability=capability, tool=tool),),
        ),
        client_factory=lambda: Client(mcp),
    )


def test_http_config_rejects_remote_plain_http_and_url_secrets():
    for url in (
        "http://example.com/mcp",
        "https://token@example.com/mcp",
        "https://example.com/mcp?token=secret",
    ):
        try:
            MCPHTTPConfig(url=url)
            assert False, f"expected validation error for {url}"
        except ValueError:
            pass

    assert MCPHTTPConfig(url="http://127.0.0.1:8000/mcp").url.startswith("http://")
    assert MCPHTTPConfig(url="https://example.com/mcp").url.startswith("https://")


def test_health_check_validates_bound_tools():
    assert asyncio.run(adapter().health_check(context())) is True
    assert asyncio.run(adapter(tool="missing_tool").health_check(context())) is False


def test_execute_returns_structured_content():
    result = asyncio.run(adapter().execute("records.read", {"value": "hello"}, context()))
    assert result.status == "success"
    assert result.data == {"value": "hello"}


def test_execute_fails_closed_for_unbound_capability():
    result = asyncio.run(adapter().execute("records.write", {}, context()))
    assert result.status == "failed"
    assert result.error is not None
    assert result.error.code == "CAPABILITY_UNAVAILABLE"


def test_mcp_tool_error_is_normalized():
    result = asyncio.run(adapter(tool="explode").execute("records.read", {}, context()))
    assert result.status == "failed"
    assert result.error is not None
    assert result.error.code == "MCP_TOOL_ERROR"
    assert "synthetic failure" not in result.error.message


def test_trusted_mcp_connector_executes_through_connection_service():
    registry = ConnectorRegistry()
    registry.register(Registration(connector=adapter(), status="trusted"))
    service = ConnectionService(registry)

    request = ConnectionRequest(
        requestId="r1",
        actor=ActorRef(userId="u1", organizationId="o1", agentId="a1"),
        service=ServiceRef(id="synthetic", name="Synthetic"),
        capability="records.read",
        operation="read",
        input={"value": "through-core"},
    )

    approve_read(service, request)
    result = asyncio.run(service.execute(request, context()))
    assert result.status == "success"
    assert result.connector_id == "synthetic-mcp"
    assert result.data == {"value": "through-core"}
    assert result.audit_id
