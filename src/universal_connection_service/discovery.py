from __future__ import annotations

import hashlib
import time
from typing import Any, Protocol, runtime_checkable
from urllib.parse import urlsplit

import httpx
from pydantic import Field, field_validator

from .contracts import AuthRequirement, DiscoveryCandidateRef, Model
from .mcp_adapter import MCPHTTPConfig


OFFICIAL_MCP_REGISTRY = "https://registry.modelcontextprotocol.io"


class DiscoveryQuery(Model):
    service_id: str = Field(alias="serviceId", min_length=1)
    service_name: str = Field(alias="serviceName", min_length=1)
    capability: str = Field(min_length=1)


@runtime_checkable
class DiscoveryProvider(Protocol):
    def discover(self, query: DiscoveryQuery) -> tuple[DiscoveryCandidateRef, ...]: ...


class MCPRegistryConfig(Model):
    base_url: str = Field(alias="baseUrl", default=OFFICIAL_MCP_REGISTRY)
    timeout_seconds: float = Field(alias="timeoutSeconds", default=4.0, gt=0, le=30)
    page_size: int = Field(alias="pageSize", default=20, ge=1, le=100)
    max_pages: int = Field(alias="maxPages", default=2, ge=1, le=5)
    cache_ttl_seconds: int = Field(alias="cacheTtlSeconds", default=3600, ge=60, le=86400)

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, value: str) -> str:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("registry base URL must be an absolute HTTP(S) URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("registry base URL must not contain credentials, query parameters or fragments")
        if parsed.scheme == "http" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise ValueError("remote registries must use HTTPS")
        return value.rstrip("/")


class MCPRegistryDiscoveryProvider:
    """Read-only MCP Registry consumer with bounded search and a small TTL cache.

    Registry metadata is treated as untrusted discovery data. This provider
    never installs packages, never marks a connector trusted, and never
    executes a discovered server.
    """

    def __init__(self, config: MCPRegistryConfig | None = None, *, client_factory=None) -> None:
        self.config = config or MCPRegistryConfig()
        self._client_factory = client_factory
        self._cache: dict[str, tuple[float, tuple[DiscoveryCandidateRef, ...]]] = {}

    def _client(self) -> httpx.Client:
        if self._client_factory is not None:
            return self._client_factory()
        return httpx.Client(
            base_url=self.config.base_url,
            timeout=self.config.timeout_seconds,
            follow_redirects=False,
            trust_env=False,
        )

    @staticmethod
    def _normalized(value: str) -> str:
        return "".join(ch.lower() for ch in value if ch.isalnum())

    @classmethod
    def _confidence(cls, query: DiscoveryQuery, server_name: str, title: str | None) -> int:
        wanted = cls._normalized(query.service_name)
        service_id = cls._normalized(query.service_id)
        leaf = cls._normalized(server_name.rsplit("/", 1)[-1])
        full = cls._normalized(server_name)
        display = cls._normalized(title or "")
        if wanted and leaf == wanted:
            return 100
        if service_id and leaf == service_id:
            return 100
        if wanted and wanted in leaf:
            return 90
        if service_id and service_id in leaf:
            return 90
        if wanted and (wanted in full or wanted in display):
            return 80
        if service_id and (service_id in full or service_id in display):
            return 80
        return 60

    @staticmethod
    def _candidate_id(*parts: str) -> str:
        material = "\x1f".join(parts).encode("utf-8")
        return "mcp-registry:" + hashlib.sha256(material).hexdigest()[:24]

    @staticmethod
    def _server_payload(item: Any) -> dict[str, Any] | None:
        if not isinstance(item, dict):
            return None
        wrapped = item.get("server")
        if isinstance(wrapped, dict):
            return wrapped
        return item

    @staticmethod
    def _auth_for_remote(remote: dict[str, Any]) -> AuthRequirement:
        headers = remote.get("headers")
        variables = remote.get("variables")
        if isinstance(headers, list) and headers:
            return AuthRequirement(type="other")
        if isinstance(variables, dict) and variables:
            return AuthRequirement(type="other")
        return AuthRequirement(type="none")

    def _remote_candidates(
        self,
        query: DiscoveryQuery,
        server: dict[str, Any],
    ) -> list[DiscoveryCandidateRef]:
        name = server.get("name")
        version = server.get("version")
        if not isinstance(name, str) or not name or not isinstance(version, str) or not version:
            return []
        title = server.get("title") if isinstance(server.get("title"), str) else None
        candidates: list[DiscoveryCandidateRef] = []
        remotes = server.get("remotes")
        if not isinstance(remotes, list):
            return candidates
        for remote in remotes:
            if not isinstance(remote, dict):
                continue
            transport = remote.get("type")
            url = remote.get("url")
            if transport not in {"streamable-http", "sse"} or not isinstance(url, str):
                continue
            # URL templates require unresolved external variables and are not
            # safe for automatic selection in this foundation.
            if "{" in url or "}" in url:
                continue
            try:
                endpoint = MCPHTTPConfig(url=url).url
            except ValueError:
                continue
            actionable = transport == "streamable-http"
            candidates.append(
                DiscoveryCandidateRef(
                    candidateId=self._candidate_id(name, version, transport, endpoint),
                    source="mcp_registry",
                    name=title or name,
                    version=version,
                    strategy="mcp",
                    transport=transport,
                    endpoint=endpoint,
                    authRequirement=self._auth_for_remote(remote),
                    confidence=self._confidence(query, name, title),
                    actionable=actionable,
                    requiresBuild=False,
                )
            )
        return candidates

    def _package_candidates(
        self,
        query: DiscoveryQuery,
        server: dict[str, Any],
    ) -> list[DiscoveryCandidateRef]:
        name = server.get("name")
        version = server.get("version")
        if not isinstance(name, str) or not name or not isinstance(version, str) or not version:
            return []
        title = server.get("title") if isinstance(server.get("title"), str) else None
        packages = server.get("packages")
        if not isinstance(packages, list):
            return []
        candidates: list[DiscoveryCandidateRef] = []
        for package in packages:
            if not isinstance(package, dict):
                continue
            registry_type = package.get("registryType")
            identifier = package.get("identifier")
            package_version = package.get("version")
            transport_obj = package.get("transport")
            transport = transport_obj.get("type") if isinstance(transport_obj, dict) else None
            if not all(isinstance(value, str) and value for value in (registry_type, identifier, package_version)):
                continue
            file_sha256 = package.get("fileSha256")
            if file_sha256 is not None and (
                not isinstance(file_sha256, str)
                or len(file_sha256) != 64
                or any(ch not in "0123456789abcdef" for ch in file_sha256)
            ):
                file_sha256 = None
            candidates.append(
                DiscoveryCandidateRef(
                    candidateId=self._candidate_id(name, version, registry_type, identifier, package_version),
                    source="mcp_registry",
                    name=title or name,
                    version=version,
                    strategy="mcp",
                    transport=transport if isinstance(transport, str) else None,
                    packageRegistry=registry_type,
                    packageIdentifier=identifier,
                    packageVersion=package_version,
                    packageSha256=file_sha256,
                    authRequirement=AuthRequirement(type="other") if package.get("environmentVariables") else AuthRequirement(type="none"),
                    confidence=self._confidence(query, name, title),
                    actionable=False,
                    requiresBuild=True,
                )
            )
        return candidates

    def _parse_page(self, query: DiscoveryQuery, payload: Any) -> tuple[list[DiscoveryCandidateRef], str | None]:
        if not isinstance(payload, dict):
            return [], None
        servers = payload.get("servers")
        candidates: list[DiscoveryCandidateRef] = []
        if isinstance(servers, list):
            for item in servers:
                server = self._server_payload(item)
                if server is None:
                    continue
                candidates.extend(self._remote_candidates(query, server))
                candidates.extend(self._package_candidates(query, server))
        metadata = payload.get("metadata")
        cursor = metadata.get("nextCursor") if isinstance(metadata, dict) else None
        return candidates, cursor if isinstance(cursor, str) and cursor else None

    def discover(self, query: DiscoveryQuery) -> tuple[DiscoveryCandidateRef, ...]:
        cache_key = self._normalized(query.service_name) or self._normalized(query.service_id)
        now = time.monotonic()
        cached = self._cache.get(cache_key)
        if cached is not None and now - cached[0] < self.config.cache_ttl_seconds:
            return cached[1]

        search = query.service_name.strip() or query.service_id.strip()
        cursor: str | None = None
        all_candidates: list[DiscoveryCandidateRef] = []
        seen: set[str] = set()
        with self._client() as client:
            for _ in range(self.config.max_pages):
                params: dict[str, Any] = {
                    "search": search,
                    "version": "latest",
                    "limit": self.config.page_size,
                }
                if cursor is not None:
                    params["cursor"] = cursor
                response = client.get("/v0.1/servers", params=params)
                response.raise_for_status()
                page, cursor = self._parse_page(query, response.json())
                for candidate in page:
                    if candidate.candidate_id in seen:
                        continue
                    seen.add(candidate.candidate_id)
                    all_candidates.append(candidate)
                if cursor is None:
                    break

        all_candidates.sort(key=lambda item: (-item.confidence, not item.actionable, item.name, item.candidate_id))
        result = tuple(all_candidates[: self.config.page_size])
        self._cache[cache_key] = (now, result)
        return result


class DiscoveryEngine:
    """Aggregates providers without allowing discovery failures to open execution."""

    def __init__(self, providers: tuple[DiscoveryProvider, ...] = ()) -> None:
        self.providers = providers

    def discover(self, query: DiscoveryQuery, *, limit: int = 10) -> tuple[DiscoveryCandidateRef, ...]:
        merged: list[DiscoveryCandidateRef] = []
        seen: set[str] = set()
        for provider in self.providers:
            try:
                candidates = provider.discover(query)
            except Exception:
                continue
            for candidate in candidates:
                if candidate.candidate_id in seen:
                    continue
                seen.add(candidate.candidate_id)
                merged.append(candidate)
        merged.sort(key=lambda item: (-item.confidence, not item.actionable, item.name, item.candidate_id))
        return tuple(merged[:limit])

    @staticmethod
    def select(candidates: tuple[DiscoveryCandidateRef, ...]) -> tuple[DiscoveryCandidateRef | None, bool]:
        actionable = [candidate for candidate in candidates if candidate.actionable]
        if len(actionable) == 1:
            return actionable[0], False
        if len(actionable) > 1:
            top = actionable[0]
            equally_good = [candidate for candidate in actionable if candidate.confidence == top.confidence]
            if len(equally_good) == 1 and top.confidence >= 90:
                return top, False
            return None, True

        buildable = [candidate for candidate in candidates if candidate.requires_build]
        if len(buildable) == 1:
            return buildable[0], False
        if len(buildable) > 1:
            return None, True
        return None, False
