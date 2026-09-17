"""Native MCP endpoint over the agent tool catalog.

Until now the catalog rendered MCP-shaped tool definitions over a bespoke REST
API, which means every client had to be taught that API. This module serves the
same catalog as an actual MCP server, so any MCP client can point at
`/v1/agents/{agentId}/mcp` and see the tools that agent is allowed to use.

Scope, stated plainly:

- JSON-RPC 2.0 over HTTP POST, single response per request. No SSE, no session
  resumption, no server-initiated messages. That is the request/response subset
  of Streamable HTTP, which is what a tool-calling client needs.
- `initialize`, `notifications/initialized`, `ping`, `tools/list`, `tools/call`.
  Resources, prompts, sampling and completion are not implemented and return
  method-not-found rather than an empty success, so a client is not told a
  capability exists when it does not.
- Identity is not taken from the MCP payload. The bearer token authenticates the
  caller, and the acting user and organization arrive as headers. An MCP client
  cannot promote itself to another tenant by editing a JSON-RPC parameter.

Every call goes through the same `ToolExecutor` as the REST surface, so the
allowlist, argument validation, run budget, policy, approval and audit behave
identically here.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Header, HTTPException, Request

from .contracts import ActorRef
from .tool_catalog import ToolCatalog, ToolCatalogError, ToolExecutor, to_mcp_tools

PROTOCOL_VERSION = "2025-06-18"
SUPPORTED_PROTOCOL_VERSIONS = {"2025-06-18", "2025-03-26", "2024-11-05"}

PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603


def _result(request_id: Any, payload: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": payload}


def _error(request_id: Any, code: int, message: str, data: dict[str, Any] | None = None) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if data:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": error}


def _tool_error(request_id: Any, exc: ToolCatalogError) -> dict[str, Any]:
    """Refusals are surfaced as tool errors, not transport errors.

    A model that asked for a tool it may not use should see that as a failed tool
    result it can react to, while a malformed request stays a protocol error.
    """
    if exc.code in {"AGENT_MISMATCH"}:
        return _error(request_id, INVALID_PARAMS, exc.safe_message, {"code": exc.code})
    return _result(
        request_id,
        {
            "content": [{"type": "text", "text": f"{exc.code}: {exc.safe_message}"}],
            "isError": True,
        },
    )


def build_mcp_server_router(
    catalog: ToolCatalog,
    executor: ToolExecutor,
    authenticator: Any | None,
) -> APIRouter:
    router = APIRouter(prefix="/v1/agents", tags=["agent-mcp"])

    def principal(authorization: str | None):
        if authenticator is None:
            raise HTTPException(
                status_code=503,
                detail={"code": "AGENT_MCP_DISABLED", "message": "Agent MCP endpoint is not configured"},
            )
        value = authenticator.authenticate(authorization)
        if value is None:
            raise HTTPException(
                status_code=401,
                detail={"code": "AGENT_MCP_UNAUTHENTICATED", "message": "Valid bearer token required"},
                headers={"WWW-Authenticate": "Bearer"},
            )
        return value

    @router.post("/{agent_id}/mcp")
    async def mcp_endpoint(
        agent_id: str,
        request: Request,
        authorization: str | None = Header(default=None),
        x_ucs_user_id: str | None = Header(default=None),
        x_ucs_organization_id: str | None = Header(default=None),
        x_ucs_run_id: str | None = Header(default=None),
    ):
        principal(authorization)
        if not x_ucs_user_id or not x_ucs_organization_id:
            raise HTTPException(
                status_code=400,
                detail={
                    "code": "AGENT_MCP_IDENTITY_REQUIRED",
                    "message": "x-ucs-user-id and x-ucs-organization-id headers are required",
                },
            )
        actor = ActorRef(
            userId=x_ucs_user_id,
            organizationId=x_ucs_organization_id,
            agentId=agent_id,
        )

        try:
            payload = await request.json()
        except Exception:
            return _error(None, PARSE_ERROR, "Request body is not valid JSON")

        if isinstance(payload, list):
            # Batches are accepted; notifications inside them produce no entry.
            responses = [await _dispatch(item, agent_id, actor, x_ucs_run_id) for item in payload]
            return [item for item in responses if item is not None]

        response = await _dispatch(payload, agent_id, actor, x_ucs_run_id)
        if response is None:
            return {}  # notification: nothing to return
        return response

    async def _dispatch(
        message: Any,
        agent_id: str,
        actor: ActorRef,
        run_id: str | None,
    ) -> dict[str, Any] | None:
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            return _error(None, INVALID_REQUEST, "Expected a JSON-RPC 2.0 message")

        method = message.get("method")
        request_id = message.get("id")
        params = message.get("params") or {}
        if not isinstance(method, str):
            return _error(request_id, INVALID_REQUEST, "Missing method")
        if not isinstance(params, dict):
            return _error(request_id, INVALID_PARAMS, "params must be an object")

        is_notification = "id" not in message

        if method == "notifications/initialized":
            return None
        if method.startswith("notifications/"):
            return None

        if method == "initialize":
            requested = params.get("protocolVersion")
            version = requested if requested in SUPPORTED_PROTOCOL_VERSIONS else PROTOCOL_VERSION
            return _result(
                request_id,
                {
                    "protocolVersion": version,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": f"ucs-agent-{agent_id}", "version": "0.1.0"},
                    "instructions": (
                        "Tools are scoped to this agent's allowlist. Arguments must match each "
                        "tool's inputSchema; refused or invalid calls return isError results."
                    ),
                },
            )

        if method == "ping":
            return _result(request_id, {})

        if method == "tools/list":
            tools = catalog.tools(actor.organization_id, agent_id)
            return _result(request_id, {"tools": to_mcp_tools(tools)})

        if method == "tools/call":
            if is_notification:
                return None  # a tool call as a notification has nowhere to return a result
            name = params.get("name")
            arguments = params.get("arguments") or {}
            if not isinstance(name, str) or not name:
                return _error(request_id, INVALID_PARAMS, "tools/call requires a tool name")
            if not isinstance(arguments, dict):
                return _error(request_id, INVALID_PARAMS, "arguments must be an object")
            try:
                result = await executor.call(
                    agent_id,
                    actor,
                    name,
                    arguments,
                    run_id=run_id,
                )
            except ToolCatalogError as exc:
                return _tool_error(request_id, exc)
            except Exception:
                return _error(request_id, INTERNAL_ERROR, "Tool execution failed")

            if result.status == "failed":
                message_text = result.error.message if result.error else "Tool call failed"
                code = result.error.code if result.error else "CONNECTION_FAILED"
                return _result(
                    request_id,
                    {
                        "content": [{"type": "text", "text": f"{code}: {message_text}"}],
                        "isError": True,
                        "_meta": {"auditId": result.audit_id},
                    },
                )

            structured = result.data if isinstance(result.data, dict) else {"result": result.data}
            return _result(
                request_id,
                {
                    "content": [{"type": "text", "text": _as_text(result.data)}],
                    "structuredContent": structured,
                    "isError": False,
                    "_meta": {"auditId": result.audit_id, "connectorId": result.connector_id},
                },
            )

        return _error(request_id, METHOD_NOT_FOUND, f"Method not supported: {method}")

    return router


def _as_text(value: Any) -> str:
    import json

    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False)
    except (TypeError, ValueError):
        return str(value)
