import asyncio
from contextlib import asynccontextmanager
from copy import deepcopy

import httpx
from mcp import Client
from mcp.server.mcpserver import MCPServer
from pydantic import BaseModel, SecretStr

from universal_connection_service.contracts import AuthRequirement, ExecutionContext
from universal_connection_service.credentials import (
    AgentVaultCredentialBinding,
    AgentVaultCredentialResolver,
    AgentVaultCredentialResolverConfig,
    CredentialResolutionError,
    CredentialTarget,
)
from universal_connection_service.mcp_adapter import (
    MCPConnectorAdapter,
    MCPConnectorConfig,
    MCPHTTPConfig,
    MCPToolBinding,
)
from universal_connection_service.openapi_adapter import compile_openapi_connector


def context(*, organization_id="org-1", handle="cred-handle") -> ExecutionContext:
    return ExecutionContext(
        requestId="r1",
        userId="u1",
        organizationId=organization_id,
        credentialHandle=SecretStr(handle) if handle is not None else None,
        deadlineMs=2000,
    )


AUTH_SCHEMA = {
    "openapi": "3.1.0",
    "info": {"title": "Brokered API", "version": "1.0.0"},
    "components": {
        "securitySchemes": {
            "ApiKeyAuth": {"type": "apiKey", "in": "header", "name": "X-API-Key"}
        }
    },
    "paths": {
        "/records/{record_id}": {
            "get": {
                "operationId": "getRecord",
                "x-ucs-capability": "records.read",
                "security": [{"ApiKeyAuth": []}],
                "parameters": [
                    {
                        "name": "record_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Record",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["id"],
                                    "properties": {"id": {"type": "string"}},
                                }
                            }
                        },
                    }
                },
            }
        }
    },
}


class FakeResolver:
    def __init__(self, *, http_handler=None, mcp_server=None):
        self.http_handler = http_handler
        self.mcp_server = mcp_server
        self.http_targets = []
        self.mcp_targets = []

    @asynccontextmanager
    async def http_client(self, target, ctx):
        self.http_targets.append((target, ctx.organization_id))
        transport = httpx.MockTransport(self.http_handler)
        async with httpx.AsyncClient(transport=transport, base_url=target.url) as client:
            yield client

    @asynccontextmanager
    async def mcp_client(self, target, ctx):
        self.mcp_targets.append((target, ctx.organization_id))
        async with Client(self.mcp_server) as client:
            yield client


def test_openapi_authenticated_operation_uses_resolver_without_raw_credentials():
    async def handler(request):
        assert "authorization" not in request.headers
        assert "x-api-key" not in request.headers
        return httpx.Response(200, json={"id": "42"})

    resolver = FakeResolver(http_handler=handler)
    connector = compile_openapi_connector(
        deepcopy(AUTH_SCHEMA),
        connector_id="brokered-openapi",
        service_id="records",
        name="Brokered OpenAPI",
        version="1.0.0",
        base_url="https://api.example.test",
        credential_resolver=resolver,
    ).connector

    result = asyncio.run(
        connector.execute(
            "records.read",
            {"path": {"record_id": "42"}},
            context(),
        )
    )
    assert result.status == "success"
    assert result.data == {"statusCode": 200, "body": {"id": "42"}}
    assert len(resolver.http_targets) == 1
    target, organization_id = resolver.http_targets[0]
    assert target.service_id == "records"
    assert target.auth.type == "api_key"
    assert organization_id == "org-1"


def test_openapi_authenticated_operation_requires_handle_when_resolver_exists():
    resolver = FakeResolver(http_handler=lambda request: httpx.Response(200, json={}))
    connector = compile_openapi_connector(
        deepcopy(AUTH_SCHEMA),
        connector_id="brokered-openapi",
        service_id="records",
        name="Brokered OpenAPI",
        version="1.0.0",
        base_url="https://api.example.test",
        credential_resolver=resolver,
    ).connector

    result = asyncio.run(
        connector.execute(
            "records.read",
            {"path": {"record_id": "42"}},
            context(handle=None),
        )
    )
    assert result.status == "failed"
    assert result.error is not None
    assert result.error.code == "CREDENTIAL_HANDLE_REQUIRED"


class EchoResult(BaseModel):
    value: str


mcp_server = MCPServer("Credential MCP", version="1.0.0")


@mcp_server.tool()
def echo(value: str) -> EchoResult:
    return EchoResult(value=value)


def test_mcp_authenticated_operation_uses_resolver():
    resolver = FakeResolver(mcp_server=mcp_server)
    connector = MCPConnectorAdapter(
        MCPConnectorConfig(
            connectorId="brokered-mcp",
            serviceId="mcp-service",
            name="Brokered MCP",
            version="1.0.0",
            endpoint=MCPHTTPConfig(url="https://mcp.example.test/mcp"),
            bindings=(MCPToolBinding(capability="records.read", tool="echo"),),
            auth=AuthRequirement(type="api_key"),
        ),
        credential_resolver=resolver,
    )

    result = asyncio.run(
        connector.execute("records.read", {"value": "hello"}, context())
    )
    assert result.status == "success"
    assert result.data == {"value": "hello"}
    assert len(resolver.mcp_targets) == 1
    target, organization_id = resolver.mcp_targets[0]
    assert target.transport == "mcp"
    assert target.service_id == "mcp-service"
    assert organization_id == "org-1"


def agent_vault_config():
    return AgentVaultCredentialResolverConfig(
        address="http://127.0.0.1:14321",
        agentToken=SecretStr("agent-control-token"),
        bindings=(
            AgentVaultCredentialBinding(
                handle=SecretStr("cred-handle"),
                organizationId="org-1",
                serviceId="records",
                vault="team-vault",
                allowedHosts=("api.example.test",),
            ),
        ),
        sessionTtlSeconds=300,
    )


def test_agent_vault_sensitive_values_are_masked_in_model_repr():
    config = agent_vault_config()
    rendered = repr(config)
    assert "agent-control-token" not in rendered
    assert "cred-handle" not in rendered
    assert "**********" in rendered


def test_agent_vault_scope_checks_tenant_service_and_host_before_network():
    resolver = AgentVaultCredentialResolver(agent_vault_config())
    target = CredentialTarget(
        transport="http",
        serviceId="records",
        url="https://api.example.test",
        auth=AuthRequirement(type="api_key"),
    )

    try:
        resolver._binding(target, context(organization_id="other-org"))
        assert False, "tenant mismatch must fail"
    except CredentialResolutionError as exc:
        assert exc.code == "CREDENTIAL_HANDLE_INVALID"

    wrong_service = CredentialTarget(
        transport="http",
        serviceId="billing",
        url="https://api.example.test",
        auth=AuthRequirement(type="api_key"),
    )
    try:
        resolver._binding(wrong_service, context())
        assert False, "service mismatch must fail"
    except CredentialResolutionError as exc:
        assert exc.code == "CREDENTIAL_SCOPE_DENIED"

    wrong_host = CredentialTarget(
        transport="http",
        serviceId="records",
        url="https://evil.example.test",
        auth=AuthRequirement(type="api_key"),
    )
    try:
        resolver._binding(wrong_host, context())
        assert False, "host mismatch must fail"
    except CredentialResolutionError as exc:
        assert exc.code == "CREDENTIAL_TARGET_DENIED"


def test_agent_vault_mints_short_lived_proxy_session_without_exposing_upstream_secret(monkeypatch):
    control_plane_calls = []
    builder_capture = {}

    async def management_handler(request):
        control_plane_calls.append(request)
        assert request.headers["authorization"] == "Bearer agent-control-token"
        if request.url.path == "/v1/sessions":
            payload = request.content.decode()
            assert "team-vault" in payload
            assert "300" in payload
            return httpx.Response(200, json={"token": "short-lived-session"})
        if request.url.path == "/v1/mitm/ca.pem":
            return httpx.Response(
                200,
                text="-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----",
                headers={"X-MITM-Port": "14322"},
            )
        return httpx.Response(404)

    def management_factory():
        return httpx.AsyncClient(
            transport=httpx.MockTransport(management_handler),
            base_url="http://127.0.0.1:14321",
        )

    async def upstream_handler(request):
        return httpx.Response(200, json={"ok": True})

    def outbound_builder(target_url, proxy_url, ssl_context):
        builder_capture["target"] = target_url
        builder_capture["proxy"] = proxy_url
        builder_capture["ssl"] = ssl_context
        return httpx.AsyncClient(
            transport=httpx.MockTransport(upstream_handler),
            base_url=target_url,
        )

    monkeypatch.setattr(
        "universal_connection_service.credentials.ssl.create_default_context",
        lambda cadata=None: object(),
    )

    resolver = AgentVaultCredentialResolver(
        agent_vault_config(),
        management_client_factory=management_factory,
        http_client_builder=outbound_builder,
    )
    target = CredentialTarget(
        transport="http",
        serviceId="records",
        url="https://api.example.test",
        auth=AuthRequirement(type="api_key"),
    )

    async def run():
        async with resolver.http_client(target, context()) as client:
            response = await client.get("/ping")
            return response.json()

    assert asyncio.run(run()) == {"ok": True}
    assert len(control_plane_calls) == 2
    assert builder_capture["target"] == "https://api.example.test"
    assert "short-lived-session" in builder_capture["proxy"]
    assert "team-vault" in builder_capture["proxy"]
    assert "agent-control-token" not in builder_capture["proxy"]
    assert "cred-handle" not in builder_capture["proxy"]
