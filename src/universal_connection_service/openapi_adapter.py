from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import quote, urlsplit

import httpx
from pydantic import Field, field_validator, model_validator

from .capability_schemas import CapabilitySchema, permissive_envelope, schemas_from_openapi
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
    from openapi_spec_validator import validate as validate_openapi_spec
except ImportError:  # pragma: no cover - exercised only when optional extra is absent
    validate_openapi_spec = None  # type: ignore[assignment]


HTTPMethod = Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
_SUPPORTED_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}
_PATH_PARAMETER = re.compile(r"\{([^{}]+)\}")


class OpenAPIEndpoint(Model):
    base_url: str = Field(alias="baseUrl", min_length=1)

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, value: str) -> str:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("OpenAPI base URL must be an absolute HTTP(S) URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("OpenAPI base URL must not contain credentials, query parameters or fragments")
        local_hosts = {"localhost", "127.0.0.1", "::1"}
        if parsed.scheme == "http" and parsed.hostname not in local_hosts:
            raise ValueError("remote OpenAPI endpoints must use HTTPS")
        return value.rstrip("/")


class OpenAPIOperationBinding(Model):
    capability: str = Field(min_length=1)
    operation_id: str = Field(alias="operationId", min_length=1)
    method: HTTPMethod
    path: str = Field(min_length=1)
    accepts_json_body: bool = Field(alias="acceptsJsonBody", default=False)
    auth: AuthRequirement = AuthRequirement()
    # Published argument contract for agent-facing callers. Optional so that
    # connector packages written before the tool catalog still load.
    capability_schema: CapabilitySchema | None = Field(alias="capabilitySchema", default=None)


class OpenAPIConnectorConfig(Model):
    connector_id: str = Field(alias="connectorId", min_length=1)
    service_id: str = Field(alias="serviceId", min_length=1)
    name: str = Field(min_length=1)
    version: str = Field(min_length=1)
    endpoint: OpenAPIEndpoint
    bindings: tuple[OpenAPIOperationBinding, ...] = Field(min_length=1)
    auth: AuthRequirement = AuthRequirement()
    max_response_bytes: int = Field(alias="maxResponseBytes", default=1_048_576, ge=1024, le=33_554_432)

    @model_validator(mode="after")
    def unique_capabilities(self):
        capabilities = [binding.capability for binding in self.bindings]
        if len(capabilities) != len(set(capabilities)):
            raise ValueError("OpenAPI capability bindings must be unique")
        return self


@dataclass(frozen=True)
class OpenAPICompileResult:
    connector: "OpenAPIConnectorAdapter"
    skipped_operations: tuple[str, ...]


class OpenAPIConnectorAdapter:
    """Generated REST/OpenAPI implementation of ConnectorContract with brokered auth."""

    def __init__(
        self,
        config: OpenAPIConnectorConfig,
        *,
        client_factory: Callable[[], httpx.AsyncClient] | None = None,
        credential_resolver: CredentialResolver | None = None,
    ) -> None:
        self.config = config
        self._client_factory = client_factory
        self._credential_resolver = credential_resolver
        self._bindings = {binding.capability: binding for binding in config.bindings}

    def manifest(self) -> ConnectorManifest:
        return ConnectorManifest(
            connectorId=self.config.connector_id,
            serviceId=self.config.service_id,
            name=self.config.name,
            version=self.config.version,
            strategy="api",
            capabilities=tuple(self._bindings),
            auth=self.config.auth,
        )

    def capability_schemas(self) -> tuple[CapabilitySchema, ...]:
        """Argument contracts for the capabilities this connector exposes.

        A binding compiled before the tool catalog carries no schema, so it
        degrades to the permissive envelope rather than disappearing.
        """
        schemas: list[CapabilitySchema] = []
        for capability, binding in self._bindings.items():
            if binding.capability_schema is not None:
                schemas.append(binding.capability_schema)
                continue
            schemas.append(
                CapabilitySchema(
                    capability=capability,
                    description=f"{self.config.name}: {binding.operation_id}",
                    operation="read" if binding.method in {"GET", "HEAD", "OPTIONS"} else "execute",
                    readOnly=binding.method in {"GET", "HEAD", "OPTIONS"},
                    inputSchema=permissive_envelope(),
                )
            )
        return tuple(schemas)

    async def health_check(self, ctx: ExecutionContext) -> bool:
        # Generated connectors deliberately avoid probing arbitrary operations:
        # even GET-like endpoints may have cost or side effects. Dynamic health
        # evidence belongs to validation against an explicit sandbox.
        return bool(self._bindings) and ctx.deadline_ms > 0

    def _direct_client(self) -> httpx.AsyncClient:
        if self._client_factory is not None:
            return self._client_factory()
        return httpx.AsyncClient(
            base_url=self.config.endpoint.base_url,
            follow_redirects=False,
            trust_env=False,
        )

    @asynccontextmanager
    async def _client(self, binding: OpenAPIOperationBinding, ctx: ExecutionContext):
        if self._client_factory is not None or binding.auth.type == "none":
            async with self._direct_client() as client:
                yield client
            return

        if self._credential_resolver is None:
            raise CredentialResolutionError(
                "CREDENTIAL_RESOLUTION_UNAVAILABLE",
                "Authenticated OpenAPI transport requires a credential resolver",
                user_action_required=True,
            )
        if ctx.credential_handle is None:
            raise CredentialResolutionError(
                "CREDENTIAL_HANDLE_REQUIRED",
                "Authenticated connection requires a credential handle",
                user_action_required=True,
            )

        target = CredentialTarget(
            transport="http",
            serviceId=self.config.service_id,
            url=self.config.endpoint.base_url,
            auth=binding.auth,
        )
        async with self._credential_resolver.http_client(target, ctx) as client:
            yield client

    @staticmethod
    def _render_path(template: str, values: dict[str, Any]) -> tuple[str | None, str | None]:
        required = set(_PATH_PARAMETER.findall(template))
        missing = sorted(required - set(values))
        if missing:
            return None, f"Missing path parameters: {', '.join(missing)}"
        extra = sorted(set(values) - required)
        if extra:
            return None, f"Unknown path parameters: {', '.join(extra)}"
        rendered = template
        for name in required:
            rendered = rendered.replace("{" + name + "}", quote(str(values[name]), safe=""))
        return rendered, None

    async def execute(
        self,
        capability: str,
        input: dict[str, Any],
        ctx: ExecutionContext,
    ) -> ConnectorResult:
        binding = self._bindings.get(capability)
        if binding is None:
            return ConnectorResult(
                status="failed",
                error=ConnectionError(
                    code="CAPABILITY_UNAVAILABLE",
                    message="Connector does not expose the requested capability",
                ),
            )

        allowed_keys = {"path", "query", "body"}
        unknown_keys = sorted(set(input) - allowed_keys)
        if unknown_keys:
            return ConnectorResult(
                status="failed",
                error=ConnectionError(
                    code="INVALID_INPUT",
                    message="OpenAPI connector input contains unsupported fields",
                ),
            )

        path_values = input.get("path", {})
        query = input.get("query", {})
        body = input.get("body")
        if not isinstance(path_values, dict) or not isinstance(query, dict):
            return ConnectorResult(
                status="failed",
                error=ConnectionError(code="INVALID_INPUT", message="path and query inputs must be objects"),
            )
        if body is not None and not binding.accepts_json_body:
            return ConnectorResult(
                status="failed",
                error=ConnectionError(
                    code="UNSUPPORTED_REQUEST_BODY",
                    message="This generated operation does not accept an application/json body",
                ),
            )

        rendered_path, path_error = self._render_path(binding.path, path_values)
        if path_error:
            return ConnectorResult(
                status="failed",
                error=ConnectionError(code="INVALID_INPUT", message=path_error),
            )
        assert rendered_path is not None

        oversized = False
        try:
            async with asyncio.timeout(ctx.deadline_ms / 1000):
                async with self._client(binding, ctx) as client:
                    # Streamed and capped: reading an unbounded body into memory
                    # lets one upstream response take the process down.
                    async with client.stream(
                        binding.method,
                        rendered_path,
                        params=query or None,
                        json=body if body is not None else None,
                    ) as response:
                        chunks: list[bytes] = []
                        total = 0
                        async for chunk in response.aiter_bytes():
                            total += len(chunk)
                            if total > self.config.max_response_bytes:
                                oversized = True
                                break
                            chunks.append(chunk)
                        raw = b"".join(chunks)
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
                    message="OpenAPI connector exceeded the execution deadline",
                    retryable=True,
                ),
            )
        except Exception:
            return ConnectorResult(
                status="failed",
                error=ConnectionError(
                    code="API_TRANSPORT_ERROR",
                    message="OpenAPI connector execution failed",
                    retryable=True,
                ),
            )

        if oversized:
            return ConnectorResult(
                status="failed",
                error=ConnectionError(
                    code="UPSTREAM_RESPONSE_TOO_LARGE",
                    message="Upstream response exceeded the allowed size",
                ),
            )

        if response.status_code >= 400:
            return ConnectorResult(
                status="failed",
                error=ConnectionError(
                    code="API_HTTP_ERROR",
                    message="Upstream API returned an error response",
                    retryable=response.status_code >= 500,
                ),
            )

        content_type = response.headers.get("content-type", "").lower()
        text = raw.decode(response.encoding or "utf-8", errors="replace")
        if "json" in content_type:
            try:
                payload: Any = json.loads(text)
            except ValueError:
                return ConnectorResult(
                    status="failed",
                    error=ConnectionError(
                        code="INVALID_UPSTREAM_RESPONSE",
                        message="Upstream declared JSON but returned invalid JSON",
                    ),
                )
        else:
            payload = text

        return ConnectorResult(
            status="success",
            data={"statusCode": response.status_code, "body": payload},
        )


def _reject_remote_refs(value: Any) -> None:
    if isinstance(value, dict):
        ref = value.get("$ref")
        if isinstance(ref, str) and urlsplit(ref).scheme in {"http", "https"}:
            raise ValueError("Remote OpenAPI $ref values are not allowed in UCS-03")
        for child in value.values():
            _reject_remote_refs(child)
    elif isinstance(value, list):
        for child in value:
            _reject_remote_refs(child)


def _security_auth(spec: dict[str, Any], operation: dict[str, Any]) -> AuthRequirement:
    security = operation.get("security", spec.get("security"))
    if not security:
        return AuthRequirement(type="none")

    schemes = spec.get("components", {}).get("securitySchemes", {})
    discovered: set[str] = set()
    scopes: set[str] = set()
    for requirement in security:
        if not isinstance(requirement, dict):
            continue
        for scheme_name, required_scopes in requirement.items():
            scheme = schemes.get(scheme_name, {})
            scheme_type = scheme.get("type")
            if scheme_type == "apiKey":
                discovered.add("api_key")
            elif scheme_type in {"oauth2", "openIdConnect"}:
                discovered.add("oauth2")
            elif scheme_type == "mutualTLS":
                discovered.add("certificate")
            else:
                discovered.add("other")
            if isinstance(required_scopes, list):
                scopes.update(str(item) for item in required_scopes)

    if not discovered:
        return AuthRequirement(type="other")
    auth_type = discovered.pop() if len(discovered) == 1 else "other"
    return AuthRequirement(type=auth_type, scopes=tuple(sorted(scopes)))


def _aggregate_auth(bindings: list[OpenAPIOperationBinding]) -> AuthRequirement:
    auth_types = {binding.auth.type for binding in bindings}
    all_scopes = {scope for binding in bindings for scope in binding.auth.scopes}
    if auth_types == {"none"}:
        return AuthRequirement(type="none")
    non_none = auth_types - {"none"}
    auth_type = non_none.pop() if len(non_none) == 1 and "none" not in auth_types else "other"
    return AuthRequirement(type=auth_type, scopes=tuple(sorted(all_scopes)))


def compile_openapi_connector(
    schema: dict[str, Any],
    *,
    connector_id: str,
    service_id: str,
    name: str,
    version: str,
    base_url: str,
    client_factory: Callable[[], httpx.AsyncClient] | None = None,
    credential_resolver: CredentialResolver | None = None,
) -> OpenAPICompileResult:
    """Validate an OpenAPI document and compile supported operations into a candidate connector."""
    if validate_openapi_spec is None:
        raise RuntimeError("OpenAPI validation support is not installed; install universal-connection-service[openapi]")

    _reject_remote_refs(schema)
    validate_openapi_spec(schema)

    # Derived once for the whole document so every binding can publish the
    # argument contract the spec declares instead of discarding it.
    derived_schemas = {item.capability: item for item in schemas_from_openapi(schema)}

    bindings: list[OpenAPIOperationBinding] = []
    skipped: list[str] = []
    for path, path_item in schema.get("paths", {}).items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method.lower() not in _SUPPORTED_METHODS or not isinstance(operation, dict):
                continue
            operation_id = operation.get("operationId")
            capability = operation.get("x-ucs-capability") or operation_id
            operation_label = f"{method.upper()} {path}"
            if not isinstance(operation_id, str) or not operation_id.strip():
                skipped.append(operation_label + " (missing operationId)")
                continue
            if not isinstance(capability, str) or not capability.strip():
                skipped.append(operation_label + " (missing capability)")
                continue

            request_body = operation.get("requestBody", {})
            content = request_body.get("content", {}) if isinstance(request_body, dict) else {}
            accepts_json = "application/json" in content
            bindings.append(
                OpenAPIOperationBinding(
                    capability=capability,
                    operationId=operation_id,
                    method=method.upper(),
                    path=path,
                    acceptsJsonBody=accepts_json,
                    auth=_security_auth(schema, operation),
                    capabilitySchema=derived_schemas.get(capability),
                )
            )

    if not bindings:
        raise ValueError("OpenAPI schema contains no operations with operationId/capability bindings")

    config = OpenAPIConnectorConfig(
        connectorId=connector_id,
        serviceId=service_id,
        name=name,
        version=version,
        endpoint=OpenAPIEndpoint(baseUrl=base_url),
        bindings=tuple(bindings),
        auth=_aggregate_auth(bindings),
    )
    return OpenAPICompileResult(
        connector=OpenAPIConnectorAdapter(
            config,
            client_factory=client_factory,
            credential_resolver=credential_resolver,
        ),
        skipped_operations=tuple(skipped),
    )
