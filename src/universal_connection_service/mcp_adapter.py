from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

from pydantic import Field, field_validator, model_validator

from .contracts import (
    AuthRequirement,
    ConnectionError,
    ConnectorManifest,
    ConnectorResult,
    ExecutionContext,
    Model,
)

try:
    from mcp import Client
except ImportError:  # pragma: no cover - exercised only when optional extra is absent
    Client = None  # type: ignore[assignment]


class MCPToolBinding(Model):
    capability: str = Field(min_length=1)
    tool: str = Field(min_length=1)


class MCPHTTPConfig(Model):
    url: str = Field(min_length=1)

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("MCP endpoint must be an absolute HTTP(S) URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("MCP endpoint URL must not contain credentials, query parameters or fragments")
        local_hosts = {"localhost", "127.0.0.1", "::1"}
        if parsed.scheme == "http" and parsed.hostname not in local_hosts:
            raise ValueError("remote MCP endpoints must use HTTPS")
        return value


class MCPConnectorConfig(Model):
    connector_id: str = Field(alias="connectorId", min_length=1)
    service_id: str = Field(alias="serviceId", min_length=1)
    name: str = Field(min_length=1)
    version: str = Field(min_length=1)
    bindings: tuple[MCPToolBinding, ...] = Field(min_length=1)
    endpoint: MCPHTTPConfig | None = None
    auth: AuthRequirement = AuthRequirement()

    @model_validator(mode="after")
    def unique_capabilities(self):
        capabilities = [binding.capability for binding in self.bindings]
        if len(capabilities) != len(set(capabilities)):
            raise ValueError("MCP capability bindings must be unique")
        return self


class MCPConnectorAdapter:
    """MCP implementation of ConnectorContract.

    The adapter maps UCS capabilities to MCP tool names and deliberately keeps
    credentials outside the transport configuration. Authenticated transports
    are deferred to a CredentialResolver-backed client factory.
    """

    def __init__(
        self,
        config: MCPConnectorConfig,
        *,
        client_factory: Callable[[], Any] | None = None,
    ) -> None:
        if config.endpoint is None and client_factory is None:
            raise ValueError("MCP connector requires an endpoint or an injected client factory")
        self.config = config
        self._client_factory = client_factory
        self._bindings = {binding.capability: binding.tool for binding in config.bindings}

    def manifest(self) -> ConnectorManifest:
        return ConnectorManifest(
            connectorId=self.config.connector_id,
            serviceId=self.config.service_id,
            name=self.config.name,
            version=self.config.version,
            strategy="mcp",
            capabilities=tuple(self._bindings),
            auth=self.config.auth,
        )

    def _client(self):
        if self._client_factory is not None:
            return self._client_factory()
        if Client is None:
            raise RuntimeError("MCP SDK is not installed; install universal-connection-service[mcp]")
        assert self.config.endpoint is not None
        return Client(self.config.endpoint.url)

    async def _tool_names(self, client: Any) -> set[str]:
        names: set[str] = set()
        cursor: str | None = None
        while True:
            page = await client.list_tools(cursor=cursor) if cursor else await client.list_tools()
            names.update(tool.name for tool in page.tools)
            cursor = page.next_cursor
            if cursor is None:
                return names

    async def health_check(self, ctx: ExecutionContext) -> bool:
        try:
            async with asyncio.timeout(ctx.deadline_ms / 1000):
                async with self._client() as client:
                    available = await self._tool_names(client)
            return set(self._bindings.values()).issubset(available)
        except Exception:
            return False

    async def execute(
        self,
        capability: str,
        input: dict[str, Any],
        ctx: ExecutionContext,
    ) -> ConnectorResult:
        tool = self._bindings.get(capability)
        if tool is None:
            return ConnectorResult(
                status="failed",
                error=ConnectionError(
                    code="CAPABILITY_UNAVAILABLE",
                    message="Connector does not expose the requested capability",
                ),
            )

        if self.config.auth.type != "none" and self._client_factory is None:
            return ConnectorResult(
                status="failed",
                error=ConnectionError(
                    code="CREDENTIAL_RESOLUTION_UNAVAILABLE",
                    message="Authenticated MCP transport requires a credential resolver",
                    userActionRequired=True,
                ),
            )

        try:
            async with asyncio.timeout(ctx.deadline_ms / 1000):
                async with self._client() as client:
                    result = await client.call_tool(tool, input)

            if result.is_error:
                return ConnectorResult(
                    status="failed",
                    error=ConnectionError(
                        code="MCP_TOOL_ERROR",
                        message="MCP tool reported an error",
                    ),
                )

            data: Any = result.structured_content
            if data is None:
                data = {
                    "content": [
                        block.model_dump(by_alias=True, mode="json", exclude_none=True)
                        for block in result.content
                    ]
                }
            return ConnectorResult(status="success", data=data)
        except TimeoutError:
            return ConnectorResult(
                status="failed",
                error=ConnectionError(
                    code="CONNECTION_TIMEOUT",
                    message="MCP connector exceeded the execution deadline",
                    retryable=True,
                ),
            )
        except Exception:
            return ConnectorResult(
                status="failed",
                error=ConnectionError(
                    code="MCP_TRANSPORT_ERROR",
                    message="MCP connector execution failed",
                    retryable=True,
                ),
            )
