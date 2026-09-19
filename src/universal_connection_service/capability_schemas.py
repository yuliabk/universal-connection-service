"""Machine-readable input contracts for capabilities.

A ConnectorManifest lists capability names only. That is enough for a caller who
already knows the API, and not enough for a model-driven agent, which has to be
told what arguments a capability accepts before it can call it.

This module adds that layer without changing existing contracts:

- `CapabilitySchema` describes one capability as JSON Schema over the execution
  envelope the adapters already use: {"path": {...}, "query": {...}, "body": ...}.
- `schemas_from_openapi` derives those schemas from an OpenAPI document, so a
  generated connector publishes the same contract the spec declares.
- `SchemaAnnotatedConnector` wraps any existing ConnectorContract and adds
  `capability_schemas()` to it, leaving manifest/health_check/execute untouched.

Nothing here performs a call or relaxes a policy. It only publishes a contract.
"""

from __future__ import annotations

import re
from typing import Any, Protocol, runtime_checkable

from pydantic import Field

from .contracts import (
    ConnectorContract,
    ConnectorManifest,
    ConnectorResult,
    ExecutionContext,
    Model,
    Operation,
    RiskHints,
)

_SUPPORTED_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}
_PATH_PARAMETER = re.compile(r"\{([^{}]+)\}")
_MAX_REF_DEPTH = 12

_OPERATION_BY_METHOD: dict[str, Operation] = {
    "get": "read",
    "head": "read",
    "options": "read",
    "post": "create",
    "put": "update",
    "patch": "update",
    "delete": "delete",
}


def permissive_envelope() -> dict[str, Any]:
    """Fallback contract for a connector that publishes no schema of its own."""
    return {
        "type": "object",
        "properties": {
            "path": {"type": "object", "description": "Path parameter values"},
            "query": {"type": "object", "description": "Query parameter values"},
            "body": {"description": "JSON request body when the operation accepts one"},
        },
        "additionalProperties": False,
    }


class CapabilitySchema(Model):
    capability: str = Field(min_length=1)
    description: str = ""
    operation: Operation = "read"
    read_only: bool = Field(alias="readOnly", default=True)
    risk_hints: RiskHints = Field(alias="riskHints", default_factory=RiskHints)
    # True when operation/readOnly/riskHints are the connector's own claim about
    # this capability. False means the source said nothing, which is not the
    # same as saying the call is safe: policy then falls back to the caller.
    risk_declared: bool = Field(alias="riskDeclared", default=True)
    input_schema: dict[str, Any] = Field(alias="inputSchema", default_factory=permissive_envelope)


@runtime_checkable
class CapabilitySchemaProvider(Protocol):
    def capability_schemas(self) -> tuple[CapabilitySchema, ...]: ...


class SchemaAnnotatedConnector:
    """Delegating wrapper that adds capability schemas to an existing connector."""

    def __init__(self, connector: ConnectorContract, schemas: tuple[CapabilitySchema, ...]) -> None:
        declared = set(connector.manifest().capabilities)
        unknown = sorted({schema.capability for schema in schemas} - declared)
        if unknown:
            raise ValueError(f"schemas reference capabilities the connector does not expose: {unknown}")
        duplicates = len(schemas) != len({schema.capability for schema in schemas})
        if duplicates:
            raise ValueError("capability schemas must be unique")
        self._connector = connector
        self._schemas = schemas

    @property
    def inner(self) -> ConnectorContract:
        return self._connector

    def manifest(self) -> ConnectorManifest:
        return self._connector.manifest()

    def capability_schemas(self) -> tuple[CapabilitySchema, ...]:
        return self._schemas

    async def health_check(self, ctx: ExecutionContext) -> bool:
        return await self._connector.health_check(ctx)

    async def execute(self, capability: str, input: dict[str, Any], ctx: ExecutionContext) -> ConnectorResult:
        return await self._connector.execute(capability, input, ctx)


def capability_schemas_of(connector: Any) -> tuple[CapabilitySchema, ...]:
    """Return published schemas, or a permissive envelope per declared capability."""
    provider = getattr(connector, "capability_schemas", None)
    if callable(provider):
        return tuple(provider())
    manifest = connector.manifest()
    return tuple(CapabilitySchema(capability=capability) for capability in manifest.capabilities)


def schemas_from_openapi(schema: dict[str, Any]) -> tuple[CapabilitySchema, ...]:
    """Derive capability schemas from an OpenAPI document.

    Mirrors the binding rules of `compile_openapi_connector`: an operation is only
    usable when it declares an operationId, and `x-ucs-capability` overrides the
    capability name. Remote $ref values are rejected the same way, and a recursive
    local $ref collapses into an untyped object instead of expanding forever.
    """
    results: list[CapabilitySchema] = []
    for path, path_item in (schema.get("paths") or {}).items():
        if not isinstance(path_item, dict):
            continue
        shared_parameters = path_item.get("parameters") or []
        for method, operation in path_item.items():
            if method.lower() not in _SUPPORTED_METHODS or not isinstance(operation, dict):
                continue
            operation_id = operation.get("operationId")
            capability = operation.get("x-ucs-capability") or operation_id
            if not isinstance(operation_id, str) or not operation_id.strip():
                continue
            if not isinstance(capability, str) or not capability.strip():
                continue

            parameters = [
                _resolve(schema, item)
                for item in [*shared_parameters, *(operation.get("parameters") or [])]
            ]
            path_properties: dict[str, Any] = {}
            path_required: list[str] = []
            query_properties: dict[str, Any] = {}
            query_required: list[str] = []

            for parameter in parameters:
                if not isinstance(parameter, dict) or not parameter.get("name"):
                    continue
                name = str(parameter["name"])
                location = parameter.get("in", "query")
                if location not in {"path", "query"}:
                    continue  # header and cookie parameters are not part of the envelope
                property_schema = _expand(schema, parameter.get("schema") or {"type": "string"})
                if parameter.get("description"):
                    property_schema = {**property_schema, "description": str(parameter["description"])}
                if location == "path":
                    path_properties[name] = property_schema
                    path_required.append(name)  # a path parameter is always required
                else:
                    query_properties[name] = property_schema
                    if parameter.get("required"):
                        query_required.append(name)

            for declared in _PATH_PARAMETER.findall(path):
                path_properties.setdefault(declared, {"type": "string"})
                if declared not in path_required:
                    path_required.append(declared)

            request_body = operation.get("requestBody")
            body_schema = None
            body_required = False
            if isinstance(request_body, dict):
                request_body = _resolve(schema, request_body)
                content = request_body.get("content") or {}
                json_content = content.get("application/json")
                if isinstance(json_content, dict):
                    body_schema = _expand(schema, json_content.get("schema") or {})
                    body_required = bool(request_body.get("required"))

            method_key = method.lower()
            results.append(
                CapabilitySchema(
                    capability=capability,
                    description=str(operation.get("summary") or operation.get("description") or capability),
                    operation=_OPERATION_BY_METHOD.get(method_key, "execute"),
                    readOnly=method_key in {"get", "head", "options"},
                    riskHints=RiskHints(destructive=method_key == "delete"),
                    inputSchema=_envelope(
                        path_properties,
                        path_required,
                        query_properties,
                        query_required,
                        body_schema,
                        body_required,
                    ),
                )
            )

    if not results:
        raise ValueError("OpenAPI document contains no operations with an operationId")

    seen: set[str] = set()
    unique: list[CapabilitySchema] = []
    for item in results:
        if item.capability in seen:
            continue
        seen.add(item.capability)
        unique.append(item)
    return tuple(unique)


def _envelope(
    path_properties: dict[str, Any],
    path_required: list[str],
    query_properties: dict[str, Any],
    query_required: list[str],
    body_schema: dict[str, Any] | None,
    body_required: bool,
) -> dict[str, Any]:
    properties: dict[str, Any] = {}
    required: list[str] = []

    if path_properties:
        properties["path"] = {
            "type": "object",
            "properties": path_properties,
            "required": sorted(path_required),
            "additionalProperties": False,
        }
        required.append("path")
    if query_properties:
        properties["query"] = {
            "type": "object",
            "properties": query_properties,
            "required": sorted(query_required),
            "additionalProperties": False,
        }
        if query_required:
            required.append("query")
    if body_schema is not None:
        properties["body"] = body_schema
        if body_required:
            required.append("body")

    envelope: dict[str, Any] = {"type": "object", "properties": properties, "additionalProperties": False}
    if required:
        envelope["required"] = sorted(required)
    return envelope


def _resolve(document: dict[str, Any], node: Any, depth: int = 0) -> Any:
    if not isinstance(node, dict) or "$ref" not in node:
        return node
    if depth >= _MAX_REF_DEPTH:
        return {"type": "object"}
    reference = node["$ref"]
    if not isinstance(reference, str) or not reference.startswith("#/"):
        raise ValueError("only local OpenAPI $ref values are supported")
    target: Any = document
    for part in reference[2:].split("/"):
        key = part.replace("~1", "/").replace("~0", "~")
        if not isinstance(target, dict) or key not in target:
            raise ValueError(f"unresolved OpenAPI $ref: {reference}")
        target = target[key]
    return _resolve(document, target, depth + 1)


def _expand(document: dict[str, Any], node: Any, depth: int = 0, seen: frozenset[str] = frozenset()) -> Any:
    if isinstance(node, list):
        return [_expand(document, item, depth + 1, seen) for item in node]
    if not isinstance(node, dict):
        return node
    if "$ref" in node:
        reference = node["$ref"]
        if isinstance(reference, str) and (reference in seen or depth >= _MAX_REF_DEPTH):
            return {"type": "object", "description": "recursive schema omitted"}
        resolved = _resolve(document, node, depth)
        return _expand(document, resolved, depth + 1, seen | {reference} if isinstance(reference, str) else seen)
    return {key: _expand(document, value, depth + 1, seen) for key, value in node.items()}
