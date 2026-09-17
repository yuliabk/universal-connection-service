# Agent tool catalog

## Problem

`POST /v1/connections/execute` assumes the caller already knows the service, the
capability and the shape of `input`. A model-driven agent knows none of these. A
`ConnectorManifest` lists capability names only, and `compile_openapi_connector`
discards parameter schemas once bindings are built, so nothing in the service
could tell an agent what arguments a capability accepts.

## What was added

Two modules and one router, with no second execution path.

### `capability_schemas.py`

- `CapabilitySchema` describes one capability: description, operation, read-only
  flag, risk hints and a JSON Schema over the envelope the adapters already use,
  `{"path": {...}, "query": {...}, "body": ...}`.
- `schemas_from_openapi(spec)` derives those schemas from an OpenAPI document,
  following the same binding rules as `compile_openapi_connector`: an operation
  needs an `operationId`, `x-ucs-capability` overrides the capability name,
  remote `$ref` is rejected, and a recursive local `$ref` collapses into an
  untyped object. Path parameters are always required; header and cookie
  parameters are left out because the envelope does not carry them.
- `SchemaAnnotatedConnector` wraps an existing connector and adds
  `capability_schemas()` to it. No existing contract changes, and a connector
  that publishes nothing falls back to a permissive envelope.

### `tool_catalog.py`

- `ToolCatalog` lists tools for one organization and one agent. A capability
  becomes a tool only when the registry resolves it as `trusted` **and** the
  agent's allowlist names it. No policy means no tools, which is the intended
  fail-closed default.
- Tool naming is `<serviceId>__<capability>` sanitized to `[A-Za-z0-9_]`, which
  both the MCP tool contract and provider function-calling APIs accept.
- `to_mcp_tools` and `to_gemini_declarations` render the same definitions for
  either consumer. The Gemini rendering strips schema keywords the function
  declaration format rejects.
- `validate_tool_input` checks arguments against the published schema before any
  outbound work happens. It uses `jsonschema` when installed and falls back to a
  structural check when it is not.
- The router translates a tool call into a normal `ConnectionRequest` plus
  `ExecutionContext` and hands it to `ConnectionService.execute`, so policy
  evaluation, approval verification, credential brokering, evidence and the
  audit identifier behave exactly as they do for a direct call.

## API

```
GET  /v1/agents/{agentId}/tools?organizationId=...&format=mcp|gemini
POST /v1/agents/{agentId}/tools/call
POST /v1/agents/{agentId}/mcp                       (native MCP endpoint)
POST /v1/agents/connectors/{connectorId}/schema-drift?organizationId=...&version=...
```

Both require the control-plane bearer token. `format` defaults to `mcp`.

Call body:

```json
{
  "actor": {"userId": "u-1", "organizationId": "org-1", "agentId": "travel-proposal"},
  "tool": "flights__flights_search",
  "input": {"query": {"origin": "TLV", "destination": "ATH"}},
  "runId": "turn-1",
  "approvalId": null,
  "deadlineMs": 15000
}
```

The response is a standard `ConnectionResult`, audit identifier included.

## Configuration

```bash
export UCS_AGENT_TOOL_POLICIES_JSON='[
  {"organizationId":"org-1","agentId":"travel-proposal",
   "tools":["flights__flights_search","maps__geocode"],"maxCallsPerRun":8}
]'
```

`/health` reports `agentToolPolicies` (`static` or `disabled`), `runBudget`
(`sqlite` or `in-memory`) and `driftSweep`.

## Failure codes

| Code | Status | Meaning |
|---|---|---|
| `AGENT_TOOLS_DISABLED` | 503 | No authenticator configured |
| `AGENT_TOOLS_UNAUTHENTICATED` | 401 | Missing or invalid bearer token |
| `AGENT_MISMATCH` | 400 | Actor agent differs from the path agent |
| `AGENT_TOOL_POLICY_MISSING` | 403 | No allowlist exists for this agent |
| `TOOL_NOT_ALLOWED` | 403 | Tool is outside the allowlist |
| `TOOL_UNAVAILABLE` | 404 | No trusted connector provides the tool |
| `INVALID_TOOL_INPUT` | 422 | Arguments do not match the published schema |
| `TOOL_RUN_BUDGET_EXCEEDED` | 429 | The agent run used its `maxCallsPerRun` allowance |
| `DRIFT_CHECK_DISABLED` | 503 | No drift verifier configured |
| `CONNECTOR_NOT_FOUND` | 404 | No such connector version for this organization |

## Where schemas come from

Both adapters publish their own contracts, so nothing has to annotate a
connector by hand and every construction site benefits at once: the build
pipeline, package rehydration, the sandbox runtimes and `app.py`.

### OpenAPI connectors

`compile_openapi_connector` now derives a `CapabilitySchema` per operation and
stores it on the binding as `capabilitySchema`. The field is optional, so a
connector package written before this change still loads and falls back to the
permissive envelope rather than disappearing from the catalog. Because the schema
lives in the connector config, it survives the package round trip.

### MCP connectors

`MCPToolBinding` carries an optional `capabilitySchema` too, and
`MCPToolSnapshot` now keeps the introspected `inputSchema` next to its SHA-256
digest: the digest still detects drift, the schema is what an agent needs in
order to call the tool. During validation, `_capability_schema_for` turns the
selected tool's metadata into the published contract.

There is no path/query/body envelope on the MCP side. `execute` forwards input
straight to `call_tool`, so the published schema is the tool's own inputSchema.
The catalog does not care which shape a connector uses; it publishes whatever the
connector declares.

Annotation hints are treated conservatively. A server that says nothing about
read-only or destructive behaviour is recorded as neither, because risk
classification stays with the policy engine and not with the remote server.

`SchemaAnnotatedConnector` remains for hand-written or third-party connectors
that do not publish schemas themselves.

## Run budgets

`maxCallsPerRun` is enforced. A caller passes the same `runId` on every tool call
that belongs to one agent turn, and the budget is counted per
(organization, agent, run). Exceeding it returns 429 `TOOL_RUN_BUDGET_EXCEEDED`.

- A refused call does not consume budget: the counter tracks work that was
  actually dispatched.
- A call without a `runId` falls back to its own request id, so the budget stops
  aggregating rather than silently vanishing.
- `maxCallsPerRun: 0` blocks every tool call for that agent.

Two implementations ship. `InMemoryRunBudget` is bounded on purpose (oldest runs
evicted, idle runs expired) so a caller-supplied identifier cannot grow the table
without limit. `SQLiteRunBudget` consumes the counter inside a single immediate
transaction, so two workers cannot both read the same value and both allow a
call. The app picks the durable one whenever `UCS_STATE_DB_PATH` (or
`UCS_RUN_BUDGET_DB_PATH`) is set, since two in-memory counters would give an
agent twice its allowance. Postgres is one method on the same protocol.

## Schema drift

```
POST /v1/agents/connectors/{connectorId}/schema-drift?organizationId=...&version=...
```

The verifier re-lists the MCP server's tools and compares each live
`inputSchemaSha256` against the digest of the published schema. On drift, or when
a bound tool has disappeared, a `trusted` connector is demoted to `degraded` and
evidence is written. Demotion can be turned off with `demote_on_drift=False`.

Three deliberate choices:

- **Not on the call path.** Verifying inside `tools/call` would put a remote
  listing on the latency of every agent turn. Drift checking runs on a schedule
  or before promotion, where the other trust decisions already live.
- **An unreachable server is not drift.** A failed listing reports
  `DRIFT_INTROSPECTION_FAILED` and changes nothing.
- **OpenAPI connectors report `DRIFT_CHECK_NOT_APPLICABLE`.** Verifying one means
  re-fetching its source document, which belongs to the build pipeline that
  produced it.

### Scheduled sweeps

`SchemaDriftScheduler` runs one pass at a fixed interval over trusted connectors,
staggering between them so a pass does not burst a listing at every server at
once. Enable it with `UCS_DRIFT_SWEEP_INTERVAL_SECONDS`; it is off by default and
`/health` reports `driftSweep`. A failing connector is counted and skipped rather
than ending the sweep. With several instances, enable it on one.

## Native MCP endpoint

```
POST /v1/agents/{agentId}/mcp
```

The same catalog served as an actual MCP server, so any MCP client can use it
without learning the REST shape. `initialize`, `notifications/initialized`,
`ping`, `tools/list` and `tools/call` are implemented.

- **JSON-RPC over HTTP POST, one response per request.** No SSE, no session
  resumption, no server-initiated messages: the request/response subset of
  Streamable HTTP, which is what a tool-calling client needs.
- **Unimplemented methods return method-not-found**, not an empty success, so a
  client is never told a capability exists when it does not. Resources, prompts,
  sampling and completion are not implemented.
- **Identity comes from headers, never from the payload.** The bearer token
  authenticates the caller; `x-ucs-user-id` and `x-ucs-organization-id` carry the
  acting identity, and `x-ucs-run-id` carries the run budget key. An MCP client
  cannot promote itself to another tenant by editing a JSON-RPC parameter.
- **Refusals are tool errors, not transport errors.** A denied tool, an invalid
  argument or an upstream failure comes back as `isError: true` with the audit id
  in `_meta`, which a model can react to. Only a malformed request is a protocol
  error.

Both surfaces call the same `ToolExecutor`, so allowlist, argument validation,
run budget, policy, approval and audit behave identically on either.

## Deliberately not included

- **No streaming transport.** Adding SSE means session state and resumability,
  which is a transport decision rather than a catalog one.
- **No MCP resources or prompts.** The catalog exposes tools; there is nothing
  behind a resource list to serve yet.
