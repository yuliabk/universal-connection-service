from __future__ import annotations

import asyncio
import hashlib
import json
import re
from contextlib import asynccontextmanager
from typing import Any, Callable
from uuid import uuid4

from pydantic import Field

from .capability_schemas import CapabilitySchema
from .contracts import (
    ConnectionRequest,
    DiscoveryCandidateRef,
    ExecutionContext,
    Model,
    Operation,
    RiskHints,
)
from .credentials import CredentialResolutionError, CredentialResolver, CredentialTarget
from .mcp_adapter import MCPConnectorAdapter, MCPConnectorConfig, MCPHTTPConfig, MCPToolBinding
from .persistence import EvidenceRecord, EvidenceStore
from .registry import ConnectorRegistry, Registration

try:
    from mcp import Client
except ImportError:  # pragma: no cover
    Client = None  # type: ignore[assignment]


MAX_INTROSPECTION_TOOLS = 100
MAX_LIST_PAGES = 10
MAX_TOOL_METADATA_BYTES = 64 * 1024
MAX_DESCRIPTION_CHARS = 1000
UCS_CAPABILITY_META_KEYS = (
    "io.universal-connection-service/capability",
    "io.universal-connection-service/capabilities",
    "ucs/capability",
    "ucs/capabilities",
)


class MCPToolSnapshot(Model):
    name: str = Field(min_length=1)
    title: str | None = None
    description: str | None = None
    input_schema_sha256: str = Field(alias="inputSchemaSha256", min_length=64, max_length=64)
    # Kept alongside the digest: the digest detects drift, the schema itself is
    # what an agent needs in order to call the tool. Already size-bounded by
    # MAX_TOOL_METADATA_BYTES in _snapshot_tool.
    input_schema: dict[str, Any] | None = Field(alias="inputSchema", default=None)
    output_schema_sha256: str | None = Field(alias="outputSchemaSha256", default=None)
    required_inputs: tuple[str, ...] = Field(alias="requiredInputs", default=())
    read_only_hint: bool | None = Field(alias="readOnlyHint", default=None)
    destructive_hint: bool | None = Field(alias="destructiveHint", default=None)
    idempotent_hint: bool | None = Field(alias="idempotentHint", default=None)
    explicit_capabilities: tuple[str, ...] = Field(alias="explicitCapabilities", default=())


class MCPToolMatch(Model):
    tool_name: str = Field(alias="toolName", min_length=1)
    score: int = Field(ge=0, le=1000)
    reasons: tuple[str, ...] = ()
    safety_unknown: bool = Field(alias="safetyUnknown", default=False)


class MCPValidationReport(Model):
    passed: bool
    code: str
    candidate_id: str = Field(alias="candidateId")
    connector_id: str | None = Field(alias="connectorId", default=None)
    tool_count: int = Field(alias="toolCount", default=0, ge=0)
    tools: tuple[MCPToolSnapshot, ...] = ()
    matches: tuple[MCPToolMatch, ...] = ()
    selected_tool: str | None = Field(alias="selectedTool", default=None)
    selection_mode: str | None = Field(alias="selectionMode", default=None)
    requires_selection: bool = Field(alias="requiresSelection", default=False)
    lifecycle: str | None = None
    issues: tuple[str, ...] = ()


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _schema_digest(value: Any) -> str:
    return hashlib.sha256(_canonical_json(value)).hexdigest()


def _normalized(value: str) -> str:
    return "".join(ch.lower() for ch in value if ch.isalnum())


def _tokens(value: str) -> tuple[str, ...]:
    return tuple(part.lower() for part in re.split(r"[^a-zA-Z0-9]+", value) if part)


def _singular(value: str) -> str:
    if value.endswith("ies") and len(value) > 3:
        return value[:-3] + "y"
    if value.endswith("s") and len(value) > 3:
        return value[:-1]
    return value


def _operation_words(operation: Operation) -> set[str]:
    return {
        "read": {"read", "get", "list", "fetch", "find", "search", "lookup", "query", "show", "retrieve"},
        "create": {"create", "add", "new", "insert", "post", "make"},
        "update": {"update", "edit", "set", "patch", "change", "modify", "write"},
        "delete": {"delete", "remove", "destroy", "revoke", "drop"},
        "execute": {"execute", "run", "call", "trigger", "send", "perform"},
    }[operation]


def _mutating_words() -> set[str]:
    return _operation_words("create") | _operation_words("update") | _operation_words("delete")


def _extract_explicit_capabilities(meta: Any) -> tuple[str, ...]:
    if not isinstance(meta, dict):
        return ()
    values: list[str] = []
    for key in UCS_CAPABILITY_META_KEYS:
        value = meta.get(key)
        if isinstance(value, str) and value.strip():
            values.append(value.strip())
        elif isinstance(value, list):
            values.extend(item.strip() for item in value if isinstance(item, str) and item.strip())
    return tuple(dict.fromkeys(values))


def _clip(value: Any, limit: int) -> str | None:
    if not isinstance(value, str):
        return None
    return value if len(value) <= limit else value[:limit]


def _snapshot_tool(tool: Any) -> MCPToolSnapshot:
    if hasattr(tool, "model_dump"):
        payload = tool.model_dump(by_alias=True, mode="json", exclude_none=True)
    elif isinstance(tool, dict):
        payload = dict(tool)
    else:
        raise ValueError("MCP tool metadata is not serializable")
    if not isinstance(payload, dict):
        raise ValueError("MCP tool metadata is malformed")
    if len(_canonical_json(payload)) > MAX_TOOL_METADATA_BYTES:
        raise ValueError("MCP tool metadata exceeds the validation size limit")

    name = payload.get("name")
    if not isinstance(name, str) or not name:
        raise ValueError("MCP tool is missing a valid name")

    input_schema = payload.get("inputSchema")
    if not isinstance(input_schema, (dict, bool)):
        input_schema = {"type": "object"}
    output_schema = payload.get("outputSchema")
    if output_schema is not None and not isinstance(output_schema, (dict, bool)):
        output_schema = None

    required: Any = input_schema.get("required") if isinstance(input_schema, dict) else None
    required_inputs = tuple(sorted(item for item in required if isinstance(item, str))) if isinstance(required, list) else ()
    annotations = payload.get("annotations") if isinstance(payload.get("annotations"), dict) else {}
    meta = payload.get("_meta") if isinstance(payload.get("_meta"), dict) else {}

    def optional_bool(key: str) -> bool | None:
        value = annotations.get(key)
        return value if isinstance(value, bool) else None

    return MCPToolSnapshot(
        name=name,
        title=_clip(payload.get("title"), 256),
        description=_clip(payload.get("description"), MAX_DESCRIPTION_CHARS),
        inputSchemaSha256=_schema_digest(input_schema),
        inputSchema=input_schema if isinstance(input_schema, dict) else None,
        outputSchemaSha256=_schema_digest(output_schema) if output_schema is not None else None,
        requiredInputs=required_inputs,
        readOnlyHint=optional_bool("readOnlyHint"),
        destructiveHint=optional_bool("destructiveHint"),
        idempotentHint=optional_bool("idempotentHint"),
        explicitCapabilities=_extract_explicit_capabilities(meta),
    )


class MCPToolMapper:
    """Conservative deterministic mapper from MCP tool metadata to a requested capability."""

    @staticmethod
    def _unsafe_for_operation(request: ConnectionRequest, tool: MCPToolSnapshot) -> bool:
        if request.operation != "read":
            return False
        if tool.destructive_hint is True or tool.read_only_hint is False:
            return True
        words = set(_tokens(tool.name)) | set(_tokens(tool.title or ""))
        return bool(words & _mutating_words())

    @classmethod
    def _score(cls, request: ConnectionRequest, tool: MCPToolSnapshot) -> MCPToolMatch:
        if cls._unsafe_for_operation(request, tool):
            return MCPToolMatch(
                toolName=tool.name,
                score=0,
                reasons=("tool metadata conflicts with requested read operation",),
                safetyUnknown=False,
            )
        if request.capability in tool.explicit_capabilities:
            return MCPToolMatch(toolName=tool.name, score=1000, reasons=("explicit UCS capability metadata",))

        reasons: list[str] = []
        capability_norm = _normalized(request.capability)
        leaf_norm = _normalized(request.capability.rsplit(".", 1)[-1])
        tool_norm = _normalized(tool.name)
        title_norm = _normalized(tool.title or "")
        score = 0

        if tool_norm == capability_norm:
            score = 500
            reasons.append("tool name exactly matches capability")
        elif leaf_norm and tool_norm == leaf_norm:
            score = 480
            reasons.append("tool name exactly matches capability leaf")

        service_tokens = {_singular(token) for token in _tokens(request.service.name)}
        service_tokens.update(_singular(token) for token in _tokens(request.service.id or ""))
        service_tokens.discard("")
        tool_tokens = {_singular(token) for token in _tokens(tool.name)}
        title_tokens = {_singular(token) for token in _tokens(tool.title or "")}
        combined = tool_tokens | title_tokens

        service_match = bool(service_tokens & combined)
        operation_match = bool(_operation_words(request.operation) & combined)
        if service_match and operation_match and score < 420:
            score = 420
            reasons.append("tool name/title matches service and operation")
        elif service_match and score < 320:
            score = 320
            reasons.append("tool name/title matches service")
        if leaf_norm and (leaf_norm in tool_norm or leaf_norm in title_norm) and score < 360:
            score = 360
            reasons.append("tool name/title contains capability leaf")

        return MCPToolMatch(
            toolName=tool.name,
            score=score,
            reasons=tuple(reasons),
            safetyUnknown=request.operation == "read" and tool.read_only_hint is None,
        )

    def map(
        self,
        request: ConnectionRequest,
        tools: tuple[MCPToolSnapshot, ...],
        *,
        selected_tool: str | None = None,
    ) -> tuple[tuple[MCPToolMatch, ...], str | None, str | None, bool]:
        matches = tuple(sorted((self._score(request, tool) for tool in tools), key=lambda item: (-item.score, item.tool_name)))
        by_name = {tool.name: tool for tool in tools}
        if selected_tool is not None:
            tool = by_name.get(selected_tool)
            if tool is None or self._unsafe_for_operation(request, tool):
                return matches, None, None, True
            return matches, selected_tool, "explicit", False

        eligible = [match for match in matches if match.score >= 320]
        if not eligible:
            return matches, None, None, True
        top = eligible[0]
        if sum(match.score == top.score for match in eligible) != 1:
            return matches, None, None, True
        return matches, top.tool_name, "automatic", False


class MCPToolIntrospector:
    """List MCP tools without invoking any tool or changing connector trust."""

    def __init__(
        self,
        candidate: DiscoveryCandidateRef,
        *,
        service_id: str,
        credential_resolver: CredentialResolver | None = None,
        client_factory: Callable[[], Any] | None = None,
    ) -> None:
        if candidate.strategy != "mcp" or candidate.transport != "streamable-http":
            raise ValueError("MCP validation requires a streamable-http discovery candidate")
        if not candidate.actionable or not candidate.endpoint:
            raise ValueError("MCP validation requires an actionable endpoint candidate")
        MCPHTTPConfig(url=candidate.endpoint)
        self.candidate = candidate
        self.service_id = service_id
        self.credential_resolver = credential_resolver
        self.client_factory = client_factory

    @asynccontextmanager
    async def _client(self, ctx: ExecutionContext | None):
        if self.client_factory is not None:
            async with self.client_factory() as client:
                yield client
            return
        if Client is None:
            raise RuntimeError("MCP SDK is not installed; install universal-connection-service[mcp]")
        assert self.candidate.endpoint is not None
        if self.candidate.auth_requirement.type == "none":
            async with Client(self.candidate.endpoint) as client:
                yield client
            return
        if self.credential_resolver is None or ctx is None or ctx.credential_handle is None:
            raise CredentialResolutionError(
                "CREDENTIAL_HANDLE_REQUIRED",
                "Authenticated MCP validation requires a credential handle",
                user_action_required=True,
            )
        target = CredentialTarget(
            transport="mcp",
            serviceId=self.service_id,
            url=self.candidate.endpoint,
            auth=self.candidate.auth_requirement,
        )
        async with self.credential_resolver.mcp_client(target, ctx) as client:
            yield client

    async def inspect(self, *, ctx: ExecutionContext | None = None, deadline_ms: int = 10000) -> tuple[MCPToolSnapshot, ...]:
        tools: list[MCPToolSnapshot] = []
        cursor: str | None = None
        async with asyncio.timeout(deadline_ms / 1000):
            async with self._client(ctx) as client:
                for _ in range(MAX_LIST_PAGES):
                    page = await client.list_tools(cursor=cursor) if cursor else await client.list_tools()
                    for tool in page.tools:
                        tools.append(_snapshot_tool(tool))
                        if len(tools) > MAX_INTROSPECTION_TOOLS:
                            raise ValueError("MCP server exposes more tools than the validation limit")
                    cursor = page.next_cursor
                    if cursor is None:
                        break
                else:
                    if cursor is not None:
                        raise ValueError("MCP tool pagination exceeds the validation page limit")
        return tuple(tools)


def _capability_schema_for(
    capability: str,
    tools: tuple[MCPToolSnapshot, ...],
    chosen: str,
) -> CapabilitySchema | None:
    """Turn the selected tool's introspected metadata into a published contract.

    Hints are advisory: a server that says nothing about read-only or
    destructive behaviour is treated as not read-only and not destructive here,
    because risk classification stays with the policy engine.
    """
    snapshot = next((item for item in tools if item.name == chosen), None)
    if snapshot is None or snapshot.input_schema is None:
        return None
    declared = snapshot.read_only_hint is not None or snapshot.destructive_hint is not None
    return CapabilitySchema(
        capability=capability,
        description=snapshot.description or snapshot.title or chosen,
        operation="read" if snapshot.read_only_hint else "execute",
        readOnly=bool(snapshot.read_only_hint),
        riskHints=RiskHints(destructive=bool(snapshot.destructive_hint)),
        # Tool annotations are optional in MCP and most servers omit them.
        # Treating silence as "not read-only" would send every unannotated tool
        # to human approval; treating it as "read-only" would hide a delete.
        # It is recorded as undeclared instead.
        riskDeclared=declared,
        inputSchema=snapshot.input_schema,
    )


class MCPValidationService:
    """Validate a discovered MCP endpoint and produce a non-trusted validated connector."""

    def __init__(
        self,
        registry: ConnectorRegistry,
        *,
        evidence_store: EvidenceStore | None = None,
        credential_resolver: CredentialResolver | None = None,
        client_factory: Callable[[], Any] | None = None,
        mapper: MCPToolMapper | None = None,
    ) -> None:
        self.registry = registry
        self.evidence_store = evidence_store
        self.credential_resolver = credential_resolver
        self.client_factory = client_factory
        self.mapper = mapper or MCPToolMapper()

    @staticmethod
    def _service_id(request: ConnectionRequest) -> str:
        return request.service.id or request.service.name.lower().replace(" ", "-")

    @staticmethod
    def _connector_id(candidate: DiscoveryCandidateRef, request: ConnectionRequest, tool_name: str) -> str:
        material = "\x1f".join((candidate.candidate_id, request.capability, tool_name)).encode("utf-8")
        return "mcp-discovered-" + hashlib.sha256(material).hexdigest()[:24]

    @staticmethod
    def _endpoint_hash(candidate: DiscoveryCandidateRef) -> str | None:
        return hashlib.sha256(candidate.endpoint.encode("utf-8")).hexdigest() if candidate.endpoint else None

    def _evidence(self, candidate: DiscoveryCandidateRef, request: ConnectionRequest, report: MCPValidationReport) -> None:
        if self.evidence_store is None:
            return
        self.evidence_store.append_evidence(
            EvidenceRecord(
                evidenceId=str(uuid4()),
                organizationId=request.actor.organization_id,
                kind="validation",
                phase="validation",
                requestId=request.request_id,
                connectorId=report.connector_id,
                payload={
                    "type": "mcp_candidate_validation",
                    "candidateId": report.candidate_id,
                    "endpointHash": self._endpoint_hash(candidate),
                    "toolCount": report.tool_count,
                    "selectedTool": report.selected_tool,
                    "selectionMode": report.selection_mode,
                    "requiresSelection": report.requires_selection,
                    "passed": report.passed,
                    "code": report.code,
                    "lifecycle": report.lifecycle,
                },
            )
        )

    async def validate(
        self,
        candidate: DiscoveryCandidateRef,
        request: ConnectionRequest,
        *,
        ctx: ExecutionContext | None = None,
        selected_tool: str | None = None,
        deadline_ms: int = 10000,
    ) -> MCPValidationReport:
        if candidate.strategy != "mcp" or candidate.transport != "streamable-http" or not candidate.actionable:
            report = MCPValidationReport(
                passed=False,
                code="MCP_CANDIDATE_NOT_ACTIONABLE",
                candidateId=candidate.candidate_id,
                issues=("Candidate is not an actionable Streamable HTTP MCP endpoint",),
            )
            self._evidence(candidate, request, report)
            return report

        try:
            tools = await MCPToolIntrospector(
                candidate,
                service_id=self._service_id(request),
                credential_resolver=self.credential_resolver,
                client_factory=self.client_factory,
            ).inspect(ctx=ctx, deadline_ms=deadline_ms)
        except CredentialResolutionError as exc:
            report = MCPValidationReport(passed=False, code=exc.code, candidateId=candidate.candidate_id, issues=(exc.safe_message,))
            self._evidence(candidate, request, report)
            return report
        except TimeoutError:
            report = MCPValidationReport(
                passed=False,
                code="MCP_VALIDATION_TIMEOUT",
                candidateId=candidate.candidate_id,
                issues=("MCP candidate validation exceeded its deadline",),
            )
            self._evidence(candidate, request, report)
            return report
        except Exception:
            report = MCPValidationReport(
                passed=False,
                code="MCP_INTROSPECTION_FAILED",
                candidateId=candidate.candidate_id,
                issues=("MCP candidate tool introspection failed",),
            )
            self._evidence(candidate, request, report)
            return report

        matches, chosen, selection_mode, requires_selection = self.mapper.map(request, tools, selected_tool=selected_tool)
        if chosen is None:
            report = MCPValidationReport(
                passed=False,
                code="MCP_TOOL_SELECTION_REQUIRED",
                candidateId=candidate.candidate_id,
                toolCount=len(tools),
                tools=tools,
                matches=matches,
                requiresSelection=True,
                issues=("No single MCP tool can be selected safely for the requested capability",),
            )
            self._evidence(candidate, request, report)
            return report

        connector_id = self._connector_id(candidate, request, chosen)
        config = MCPConnectorConfig(
            connectorId=connector_id,
            serviceId=self._service_id(request),
            name=candidate.name,
            version=candidate.version,
            bindings=(
                MCPToolBinding(
                    capability=request.capability,
                    tool=chosen,
                    capabilitySchema=_capability_schema_for(request.capability, tools, chosen),
                ),
            ),
            endpoint=MCPHTTPConfig(url=candidate.endpoint),
            auth=candidate.auth_requirement,
        )
        connector = MCPConnectorAdapter(
            config,
            client_factory=self.client_factory,
            credential_resolver=self.credential_resolver,
        )
        registration = Registration(
            connector=connector,
            status="sandboxed",
            organization_id=request.actor.organization_id,
        )
        try:
            self.registry.register(registration)
        except ValueError:
            report = MCPValidationReport(
                passed=False,
                code="MCP_CONNECTOR_ALREADY_REGISTERED",
                candidateId=candidate.candidate_id,
                connectorId=connector_id,
                toolCount=len(tools),
                tools=tools,
                matches=matches,
                selectedTool=chosen,
                selectionMode=selection_mode,
                lifecycle="sandboxed",
                issues=("Connector version is already registered for this organization",),
            )
            self._evidence(candidate, request, report)
            return report

        health_ctx = ctx or ExecutionContext(
            requestId=request.request_id,
            userId=request.actor.user_id,
            organizationId=request.actor.organization_id,
            deadlineMs=deadline_ms,
        )
        if not await connector.health_check(health_ctx):
            report = MCPValidationReport(
                passed=False,
                code="MCP_HEALTH_CHECK_FAILED",
                candidateId=candidate.candidate_id,
                connectorId=connector_id,
                toolCount=len(tools),
                tools=tools,
                matches=matches,
                selectedTool=chosen,
                selectionMode=selection_mode,
                lifecycle="sandboxed",
                issues=("MCP candidate failed the post-binding health check",),
            )
            self._evidence(candidate, request, report)
            return report

        registration.set_status("validated")
        report = MCPValidationReport(
            passed=True,
            code="MCP_CANDIDATE_VALIDATED",
            candidateId=candidate.candidate_id,
            connectorId=connector_id,
            toolCount=len(tools),
            tools=tools,
            matches=matches,
            selectedTool=chosen,
            selectionMode=selection_mode,
            requiresSelection=requires_selection,
            lifecycle="validated",
        )
        self._evidence(candidate, request, report)
        return report
