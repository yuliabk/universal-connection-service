from __future__ import annotations

import asyncio
from collections.abc import Callable
from contextlib import asynccontextmanager
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
from .credentials import (
    CredentialResolutionError,
    CredentialResolver,
    CredentialTarget,
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
    """MCP implementation of ConnectorContract with brokered auth support."""

    def __init__(
        self,
        config: MCPConnectorConfig,
        *,
        client_factory: Callable[[], Any] | None = None,
        credential_resolver: CredentialResolver | None = None,
    ) -> None:
        if config.endpoint is None and client_factory is None:
            raise ValueError("MCP connector requires an endpoint or an injected client factory")
        self.config = config
        self._client_factory = client_factory
        self._credential_resolver = credential_resolver
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

    @asynccontextmanager
    async def _client(self, ctx: ExecutionContext):
        if self._client_factory is not None:
            async with self._client_factory() as client:
                yield client
            return

        if Client is None:
            raise RuntimeError("MCP SDK is not installed; install universal-connection-service[mcp]")
        assert self.config.endpoint is not None

        if self.config.auth.type == "none":
            async with Client(self.config.endpoint.url) as client:
                yield client
            return

        if self._credential_resolver is None:
            raise CredentialResolutionError(
                "CREDENTIAL_RESOLUTION_UNAVAILABLE",
                "Authenticated MCP transport requires a credential resolver",
                user_action_required=True,
            )
        if ctx.credential_handle is None:
            raise CredentialResolutionError(
                "CREDENTIAL_HANDLE_REQUIRED",
                "Authenticated connection requires a credential handle",
                user_action_required=True,
            )

        target = CredentialTarget(
            transport="mcp",
            serviceId=self.config.service_id,
            url=self.config.endpoint.url,
            auth=self.config.auth,
        )
        async with self._credential_resolver.mcp_client(target, ctx) as client:
            yield client

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
                async with self._client(ctx) as client:
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

        try:
            async with asyncio.timeout(ctx.deadline_ms / 1000):
                async with self._client(ctx) as client:
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
        except CredentialResolutionError as exc:
            return ConnectorResult(
                status="failed",
                error=ConnectionError(
                    code=exc.code,
                    message=exc.safe_message,
                    userActionRequired=exc.user_action_required,
                ),
            )
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
