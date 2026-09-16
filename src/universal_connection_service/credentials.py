from __future__ import annotations

import ssl
from collections.abc import Callable
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from typing import Any, Literal, Protocol, runtime_checkable
from urllib.parse import quote, urlsplit

import httpx
from pydantic import Field, SecretStr, field_validator, model_validator

from .contracts import AuthRequirement, ExecutionContext, Model


class CredentialTarget(Model):
    transport: Literal["http", "mcp"]
    service_id: str = Field(alias="serviceId", min_length=1)
    url: str = Field(min_length=1)
    auth: AuthRequirement

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("credential target must be an absolute HTTP(S) URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("credential target URL must not contain credentials, query parameters or fragments")
        return value


class CredentialResolutionError(RuntimeError):
    def __init__(self, code: str, message: str, *, user_action_required: bool = False):
        super().__init__(message)
        self.code = code
        self.safe_message = message
        self.user_action_required = user_action_required


@runtime_checkable
class CredentialResolver(Protocol):
    """Resolve opaque credential handles into outbound transports, never secret values."""

    def http_client(
        self,
        target: CredentialTarget,
        ctx: ExecutionContext,
    ) -> AbstractAsyncContextManager[httpx.AsyncClient]: ...

    def mcp_client(
        self,
        target: CredentialTarget,
        ctx: ExecutionContext,
    ) -> AbstractAsyncContextManager[Any]: ...


class AgentVaultCredentialBinding(Model):
    handle: SecretStr
    organization_id: str = Field(alias="organizationId", min_length=1)
    service_id: str = Field(alias="serviceId", min_length=1)
    vault: str = Field(min_length=1)
    allowed_hosts: tuple[str, ...] = Field(alias="allowedHosts", min_length=1)

    @field_validator("allowed_hosts")
    @classmethod
    def normalize_hosts(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(host.strip().lower().rstrip(".") for host in value if host.strip())
        if not normalized:
            raise ValueError("Agent Vault binding requires at least one allowed host")
        if len(normalized) != len(set(normalized)):
            raise ValueError("Agent Vault allowed hosts must be unique")
        return normalized


class AgentVaultCredentialResolverConfig(Model):
    address: str = Field(min_length=1)
    agent_token: SecretStr = Field(alias="agentToken")
    bindings: tuple[AgentVaultCredentialBinding, ...] = Field(min_length=1)
    session_ttl_seconds: int = Field(alias="sessionTtlSeconds", default=300, ge=300, le=604800)

    @field_validator("address")
    @classmethod
    def validate_address(cls, value: str) -> str:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("Agent Vault address must be an absolute HTTP(S) URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("Agent Vault address must not contain credentials, query parameters or fragments")
        local_hosts = {"localhost", "127.0.0.1", "::1"}
        if parsed.scheme == "http" and parsed.hostname not in local_hosts:
            raise ValueError("remote Agent Vault management endpoints must use HTTPS")
        return value.rstrip("/")

    @model_validator(mode="after")
    def unique_binding_handles_per_tenant(self):
        keys = [
            (binding.organization_id, binding.handle.get_secret_value())
            for binding in self.bindings
        ]
        if len(keys) != len(set(keys)):
            raise ValueError("Agent Vault credential handles must be unique within an organization")
        return self


class _AgentVaultSession(Model):
    proxy_url: SecretStr = Field(alias="proxyUrl")
    ca_certificate: str = Field(alias="caCertificate", min_length=1)


ManagementClientFactory = Callable[[], httpx.AsyncClient]
HTTPClientBuilder = Callable[[str, str, ssl.SSLContext], httpx.AsyncClient]
MCPClientBuilder = Callable[[str, str, ssl.SSLContext], AbstractAsyncContextManager[Any]]


class AgentVaultCredentialResolver:
    """Credential broker backed by an Agent Vault MITM proxy session.

    The upstream credential never enters UCS. The only sensitive material UCS
    handles is the short-lived Agent Vault proxy session token used to route the
    outbound connection through the broker.
    """

    def __init__(
        self,
        config: AgentVaultCredentialResolverConfig,
        *,
        management_client_factory: ManagementClientFactory | None = None,
        http_client_builder: HTTPClientBuilder | None = None,
        mcp_client_builder: MCPClientBuilder | None = None,
    ) -> None:
        self.config = config
        self._management_client_factory = management_client_factory
        self._http_client_builder = http_client_builder or self._default_http_client
        self._mcp_client_builder = mcp_client_builder or self._default_mcp_client

    def _binding(self, target: CredentialTarget, ctx: ExecutionContext) -> AgentVaultCredentialBinding:
        if ctx.credential_handle is None:
            raise CredentialResolutionError(
                "CREDENTIAL_HANDLE_REQUIRED",
                "Authenticated connection requires a credential handle",
                user_action_required=True,
            )
        handle = ctx.credential_handle.get_secret_value()
        candidates = [
            binding
            for binding in self.config.bindings
            if binding.organization_id == ctx.organization_id
            and binding.handle.get_secret_value() == handle
        ]
        if len(candidates) != 1:
            raise CredentialResolutionError(
                "CREDENTIAL_HANDLE_INVALID",
                "Credential handle is not available for this organization",
                user_action_required=True,
            )
        binding = candidates[0]
        if binding.service_id != target.service_id:
            raise CredentialResolutionError(
                "CREDENTIAL_SCOPE_DENIED",
                "Credential handle is not authorized for this service",
                user_action_required=True,
            )
        hostname = (urlsplit(target.url).hostname or "").lower().rstrip(".")
        if hostname not in binding.allowed_hosts:
            raise CredentialResolutionError(
                "CREDENTIAL_TARGET_DENIED",
                "Credential handle is not authorized for this target host",
                user_action_required=True,
            )
        return binding

    def _management_client(self) -> httpx.AsyncClient:
        authorization = f"Bearer {self.config.agent_token.get_secret_value()}"
        if self._management_client_factory is not None:
            client = self._management_client_factory()
            client.headers["Authorization"] = authorization
            return client
        return httpx.AsyncClient(
            base_url=self.config.address,
            headers={"Authorization": authorization},
            follow_redirects=False,
            trust_env=False,
            timeout=15.0,
        )

    async def _mint_session(self, binding: AgentVaultCredentialBinding) -> _AgentVaultSession:
        try:
            async with self._management_client() as client:
                session_response = await client.post(
                    "/v1/sessions",
                    json={
                        "vault": binding.vault,
                        "ttl_seconds": self.config.session_ttl_seconds,
                    },
                )
                if session_response.status_code >= 400:
                    raise CredentialResolutionError(
                        "CREDENTIAL_BROKER_UNAVAILABLE",
                        "Credential broker could not mint a session",
                        user_action_required=session_response.status_code in {401, 403},
                    )
                try:
                    session_payload = session_response.json()
                    token = str(session_payload["token"])
                except (ValueError, KeyError, TypeError):
                    raise CredentialResolutionError(
                        "CREDENTIAL_BROKER_INVALID_RESPONSE",
                        "Credential broker returned an invalid session response",
                    ) from None

                ca_response = await client.get("/v1/mitm/ca.pem")
                if ca_response.status_code >= 400 or not ca_response.text.strip():
                    raise CredentialResolutionError(
                        "CREDENTIAL_BROKER_UNAVAILABLE",
                        "Credential broker MITM proxy is unavailable",
                    )
                ca_certificate = ca_response.text
                try:
                    proxy_port = int(ca_response.headers.get("X-MITM-Port", "14322"))
                except ValueError:
                    raise CredentialResolutionError(
                        "CREDENTIAL_BROKER_INVALID_RESPONSE",
                        "Credential broker returned invalid proxy metadata",
                    ) from None
                if proxy_port <= 0 or proxy_port > 65535:
                    raise CredentialResolutionError(
                        "CREDENTIAL_BROKER_INVALID_RESPONSE",
                        "Credential broker returned invalid proxy metadata",
                    )
        except CredentialResolutionError:
            raise
        except Exception:
            raise CredentialResolutionError(
                "CREDENTIAL_BROKER_UNAVAILABLE",
                "Credential broker request failed",
            ) from None

        broker_host = urlsplit(self.config.address).hostname or "127.0.0.1"
        proxy_url = (
            f"http://{quote(token, safe='')}:{quote(binding.vault, safe='')}"
            f"@{broker_host}:{proxy_port}"
        )
        return _AgentVaultSession(proxyUrl=SecretStr(proxy_url), caCertificate=ca_certificate)

    @staticmethod
    def _ssl_context(ca_certificate: str) -> ssl.SSLContext:
        try:
            return ssl.create_default_context(cadata=ca_certificate)
        except Exception:
            raise CredentialResolutionError(
                "CREDENTIAL_BROKER_INVALID_RESPONSE",
                "Credential broker returned an invalid CA certificate",
            ) from None

    @staticmethod
    def _default_http_client(target_url: str, proxy_url: str, ssl_context: ssl.SSLContext) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=target_url,
            proxy=proxy_url,
            verify=ssl_context,
            follow_redirects=False,
            trust_env=False,
        )

    @staticmethod
    @asynccontextmanager
    async def _default_mcp_client(
        target_url: str,
        proxy_url: str,
        ssl_context: ssl.SSLContext,
    ):
        try:
            import httpx2
            from mcp import Client
            from mcp.client.streamable_http import streamable_http_client
        except ImportError:
            raise CredentialResolutionError(
                "CREDENTIAL_TRANSPORT_UNAVAILABLE",
                "MCP credential transport support is not installed",
            ) from None

        async with httpx2.AsyncClient(
            proxy=proxy_url,
            verify=ssl_context,
            trust_env=False,
            timeout=httpx2.Timeout(30.0, read=300.0),
        ) as http_client:
            transport = streamable_http_client(target_url, http_client=http_client)
            async with Client(transport) as client:
                yield client

    @asynccontextmanager
    async def http_client(self, target: CredentialTarget, ctx: ExecutionContext):
        binding = self._binding(target, ctx)
        session = await self._mint_session(binding)
        ssl_context = self._ssl_context(session.ca_certificate)
        async with self._http_client_builder(
            target.url,
            session.proxy_url.get_secret_value(),
            ssl_context,
        ) as client:
            yield client

    @asynccontextmanager
    async def mcp_client(self, target: CredentialTarget, ctx: ExecutionContext):
        binding = self._binding(target, ctx)
        session = await self._mint_session(binding)
        ssl_context = self._ssl_context(session.ca_certificate)
        async with self._mcp_client_builder(
            target.url,
            session.proxy_url.get_secret_value(),
            ssl_context,
        ) as client:
            yield client
