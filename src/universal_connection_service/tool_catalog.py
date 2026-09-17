"""Agent-facing tool catalog.

`/v1/connections/execute` is the right contract for a caller that already knows
which service and capability it wants. A model-driven agent does not: it needs a
list of callable tools with argument schemas, and one call endpoint.

This module adds that surface on top of what already exists, without a second
execution path:

- only `trusted` connectors are ever listed;
- an agent sees a tool only if an explicit allowlist names it (fail closed);
- a tool call is translated into a normal ConnectionRequest/ExecutionContext and
  handed to ConnectionService, so policy, approval, credential brokering and the
  audit identifier behave exactly as they do for a direct call.

Naming: a tool is `<serviceId>__<capability>`, sanitized to [A-Za-z0-9_], which is
accepted by both the MCP tool contract and provider function-calling APIs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Protocol
from uuid import uuid4

from fastapi import APIRouter, Header, HTTPException, Query
from pydantic import Field

from .capability_schemas import CapabilitySchema, capability_schemas_of
from .contracts import (
    ActorRef,
    ConnectionRequest,
    ConnectionResult,
    ExecutionContext,
    Model,
    Operation,
    RiskHints,
    ServiceRef,
)
from .registry import ConnectorRegistry
from .run_budget import RunBudgetStore
from .schema_drift import MCPSchemaDriftVerifier, SchemaDriftError, SchemaDriftReport
from .service import ConnectionService

try:
    from jsonschema import Draft202012Validator
except ImportError:  # pragma: no cover - jsonschema is a declared dependency
    # Kept as a guard rather than removed: if the import ever fails, argument
    # checking degrades to a structural check instead of disappearing.
    Draft202012Validator = None  # type: ignore[assignment]

_UNSAFE = re.compile(r"[^A-Za-z0-9_]")
_GEMINI_UNSUPPORTED = {"$schema", "$ref", "$id", "additionalProperties", "examples", "const", "default", "nullable"}


def tool_name(service_id: str, capability: str) -> str:
    return f"{_UNSAFE.sub('_', service_id)}__{_UNSAFE.sub('_', capability)}"


@dataclass(frozen=True)
class ToolDefinition:
    name: str
    service_id: str
    capability: str
    connector_id: str
    connector_version: str
    description: str
    operation: Operation
    read_only: bool
    risk_hints: RiskHints
    input_schema: dict[str, Any]


class AgentToolPolicy(Model):
    organization_id: str = Field(alias="organizationId", min_length=1)
    agent_id: str = Field(alias="agentId", min_length=1)
    tools: tuple[str, ...] = ()
    max_calls_per_run: int = Field(alias="maxCallsPerRun", default=10, ge=0)


class AgentToolPolicyStore(Protocol):
    def policy(self, organization_id: str, agent_id: str) -> AgentToolPolicy | None: ...


class InMemoryAgentToolPolicyStore:
    """Development store. Production should read the same shape from persistence."""

    def __init__(self, policies: tuple[AgentToolPolicy, ...] = ()) -> None:
        self._items: dict[tuple[str, str], AgentToolPolicy] = {
            (item.organization_id, item.agent_id): item for item in policies
        }

    def put(self, policy: AgentToolPolicy) -> None:
        self._items[(policy.organization_id, policy.agent_id)] = policy

    def policy(self, organization_id: str, agent_id: str) -> AgentToolPolicy | None:
        return self._items.get((organization_id, agent_id))


class ToolCatalogError(Exception):
    def __init__(self, status_code: int, code: str, safe_message: str) -> None:
        super().__init__(code)
        self.status_code = status_code
        self.code = code
        self.safe_message = safe_message


class ToolCatalog:
    def __init__(self, registry: ConnectorRegistry, policy_store: AgentToolPolicyStore) -> None:
        self.registry = registry
        self.policy_store = policy_store

    def _available(self, organization_id: str) -> dict[str, ToolDefinition]:
        """Every trusted (service, capability) pair visible to this organization."""
        found: dict[str, ToolDefinition] = {}
        for manifest in self.registry.manifests(organization_id):
            for capability in manifest.capabilities:
                registration = self.registry.trusted(manifest.service_id, capability, organization_id)
                if registration is None:
                    continue  # not trusted yet: discovered, sandboxed or awaiting approval
                name = tool_name(manifest.service_id, capability)
                if name in found:
                    continue
                schema = _schema_for(registration.connector, capability)
                found[name] = ToolDefinition(
                    name=name,
                    service_id=registration.manifest.service_id,
                    capability=capability,
                    connector_id=registration.manifest.connector_id,
                    connector_version=registration.manifest.version,
                    description=schema.description or f"{registration.manifest.name}: {capability}",
                    operation=schema.operation,
                    read_only=schema.read_only,
                    risk_hints=schema.risk_hints,
                    input_schema=schema.input_schema,
                )
        return found

    def tools(self, organization_id: str, agent_id: str) -> tuple[ToolDefinition, ...]:
        policy = self.policy_store.policy(organization_id, agent_id)
        if policy is None:
            return ()
        available = self._available(organization_id)
        return tuple(available[name] for name in policy.tools if name in available)

    def resolve(self, organization_id: str, agent_id: str, name: str) -> ToolDefinition:
        policy = self.policy_store.policy(organization_id, agent_id)
        if policy is None:
            raise ToolCatalogError(403, "AGENT_TOOL_POLICY_MISSING", "No tool policy is configured for this agent")
        if name not in policy.tools:
            raise ToolCatalogError(403, "TOOL_NOT_ALLOWED", "This agent may not call the requested tool")
        available = self._available(organization_id)
        definition = available.get(name)
        if definition is None:
            raise ToolCatalogError(404, "TOOL_UNAVAILABLE", "No trusted connector currently provides this tool")
        return definition


def _schema_for(connector: Any, capability: str) -> CapabilitySchema:
    for schema in capability_schemas_of(connector):
        if schema.capability == capability:
            return schema
    return CapabilitySchema(capability=capability)


def to_mcp_tools(tools: tuple[ToolDefinition, ...]) -> list[dict[str, Any]]:
    return [
        {
            "name": tool.name,
            "description": tool.description,
            "inputSchema": tool.input_schema,
            "annotations": {
                "readOnlyHint": tool.read_only,
                "destructiveHint": tool.risk_hints.destructive,
            },
        }
        for tool in tools
    ]


def to_gemini_declarations(tools: tuple[ToolDefinition, ...]) -> list[dict[str, Any]]:
    return [
        {
            "name": tool.name,
            "description": tool.description,
            "parameters": _strip_unsupported(tool.input_schema),
        }
        for tool in tools
    ]


def _strip_unsupported(node: Any) -> Any:
    if isinstance(node, list):
        return [_strip_unsupported(item) for item in node]
    if isinstance(node, dict):
        return {key: _strip_unsupported(value) for key, value in node.items() if key not in _GEMINI_UNSUPPORTED}
    return node


def validate_tool_input(definition: ToolDefinition, value: dict[str, Any]) -> str | None:
    """Return an error message when the input does not satisfy the tool schema."""
    if not isinstance(value, dict):
        return "tool input must be an object"
    if Draft202012Validator is not None:
        errors = sorted(Draft202012Validator(definition.input_schema).iter_errors(value), key=lambda e: list(e.path))
        if errors:
            first = errors[0]
            location = "/".join(str(part) for part in first.path) or "input"
            return f"{location}: {first.message}"
        return None
    # Structural fallback when jsonschema is not installed.
    allowed = set(definition.input_schema.get("properties", {}))
    unknown = sorted(set(value) - allowed)
    if unknown:
        return f"unknown input sections: {unknown}"
    missing = sorted(set(definition.input_schema.get("required", [])) - set(value))
    if missing:
        return f"missing required input sections: {missing}"
    return None


class ToolExecutor:
    """One place where a tool call becomes a ConnectionRequest.

    Both the REST endpoint and the MCP endpoint go through this, so allowlist,
    argument validation, run budget and audit behave identically on either
    surface instead of drifting apart.
    """

    def __init__(
        self,
        catalog: ToolCatalog,
        service: ConnectionService,
        *,
        run_budget: RunBudgetStore | None = None,
    ) -> None:
        self.catalog = catalog
        self.service = service
        self.run_budget = run_budget

    async def call(
        self,
        agent_id: str,
        actor: ActorRef,
        tool: str,
        tool_input: dict[str, Any],
        *,
        run_id: str | None = None,
        request_id: str | None = None,
        approval_id: str | None = None,
        deadline_ms: int = 15000,
    ) -> ConnectionResult:
        if actor.agent_id != agent_id:
            raise ToolCatalogError(400, "AGENT_MISMATCH", "Actor agent does not match the requested agent")

        definition = self.catalog.resolve(actor.organization_id, agent_id, tool)

        error = validate_tool_input(definition, tool_input)
        if error:
            raise ToolCatalogError(422, "INVALID_TOOL_INPUT", error)

        resolved_request_id = request_id or str(uuid4())
        policy = self.catalog.policy_store.policy(actor.organization_id, agent_id)
        if self.run_budget is not None and policy is not None:
            decision = self.run_budget.consume(
                actor.organization_id,
                agent_id,
                run_id or resolved_request_id,
                policy.max_calls_per_run,
            )
            if not decision.allowed:
                raise ToolCatalogError(
                    429,
                    "TOOL_RUN_BUDGET_EXCEEDED",
                    f"This agent run has used its {decision.limit} allowed tool calls",
                )

        request = ConnectionRequest(
            requestId=resolved_request_id,
            actor=actor,
            service=ServiceRef(id=definition.service_id, name=definition.service_id),
            capability=definition.capability,
            operation=definition.operation,
            input=tool_input,
            readOnly=definition.read_only,
            riskHints=definition.risk_hints,
        )
        context = ExecutionContext(
            requestId=resolved_request_id,
            userId=actor.user_id,
            organizationId=actor.organization_id,
            approvalId=approval_id,
            deadlineMs=deadline_ms,
        )
        return await self.service.execute(request, context)


class ToolCallCommand(Model):
    actor: ActorRef
    tool: str = Field(min_length=1)
    input: dict[str, Any] = Field(default_factory=dict)
    request_id: str | None = Field(alias="requestId", default=None)
    # All tool calls in one agent turn should carry the same runId; that is what
    # maxCallsPerRun is counted against. Omitting it means every call is its own
    # run, so the budget stops aggregating rather than silently disappearing.
    run_id: str | None = Field(alias="runId", default=None)
    approval_id: str | None = Field(alias="approvalId", default=None)
    deadline_ms: int = Field(alias="deadlineMs", default=15000, ge=1)


def build_tool_catalog_router(
    catalog: ToolCatalog,
    service: ConnectionService,
    authenticator: Any | None,
    *,
    run_budget: RunBudgetStore | None = None,
    drift_verifier: MCPSchemaDriftVerifier | None = None,
) -> APIRouter:
    router = APIRouter(prefix="/v1/agents", tags=["agent-tools"])
    executor = ToolExecutor(catalog, service, run_budget=run_budget)

    def principal(authorization: str | None):
        if authenticator is None:
            raise HTTPException(
                status_code=503,
                detail={"code": "AGENT_TOOLS_DISABLED", "message": "Agent tool catalog is not configured"},
            )
        value = authenticator.authenticate(authorization)
        if value is None:
            raise HTTPException(
                status_code=401,
                detail={"code": "AGENT_TOOLS_UNAUTHENTICATED", "message": "Valid bearer token required"},
                headers={"WWW-Authenticate": "Bearer"},
            )
        return value

    def fail(exc: ToolCatalogError):
        raise HTTPException(status_code=exc.status_code, detail={"code": exc.code, "message": exc.safe_message})

    @router.get("/{agent_id}/tools")
    def list_tools(
        agent_id: str,
        organization_id: str = Query(alias="organizationId"),
        format: str = Query(default="mcp", pattern="^(mcp|gemini)$"),
        authorization: str | None = Header(default=None),
    ):
        principal(authorization)
        tools = catalog.tools(organization_id, agent_id)
        payload = to_gemini_declarations(tools) if format == "gemini" else to_mcp_tools(tools)
        return {"agentId": agent_id, "organizationId": organization_id, "format": format, "tools": payload}

    @router.post("/{agent_id}/tools/call", response_model=ConnectionResult)
    async def call_tool(
        agent_id: str,
        command: ToolCallCommand,
        authorization: str | None = Header(default=None),
    ):
        principal(authorization)
        try:
            return await executor.call(
                agent_id,
                command.actor,
                command.tool,
                command.input,
                run_id=command.run_id,
                request_id=command.request_id,
                approval_id=command.approval_id,
                deadline_ms=command.deadline_ms,
            )
        except ToolCatalogError as exc:
            fail(exc)

    @router.post("/connectors/{connector_id}/schema-drift", response_model=SchemaDriftReport)
    async def check_schema_drift(
        connector_id: str,
        organization_id: str = Query(alias="organizationId"),
        version: str = Query(...),
        authorization: str | None = Header(default=None),
    ):
        principal(authorization)
        if drift_verifier is None:
            raise HTTPException(
                status_code=503,
                detail={"code": "DRIFT_CHECK_DISABLED", "message": "Schema drift verification is not configured"},
            )
        try:
            return await drift_verifier.verify(organization_id, connector_id, version)
        except SchemaDriftError as exc:
            raise HTTPException(status_code=exc.status_code, detail={"code": exc.code, "message": exc.safe_message})

    return router
