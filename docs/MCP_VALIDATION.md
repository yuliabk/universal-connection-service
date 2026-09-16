# UCS-10 - MCP Candidate Validation + Tool Introspection

## Goal

UCS-09 can discover an MCP server candidate, but discovery metadata is untrusted and cannot execute. UCS-10 adds the next trust gate: connect to an actionable Streamable HTTP candidate, inspect its MCP tool catalog without invoking tools, map one tool to the requested business capability, verify the resulting binding, and persist the connector only as `validated`.

```text
Discovery candidate
      |
      v
Endpoint safety checks
      |
      v
MCP initialize + list_tools
      |
      v
Bounded metadata inspection
      |
      v
Capability mapping
      |
      +-- ambiguous -> requiresSelection
      |
      v
Create sandboxed MCPConnectorAdapter
      |
      v
Post-binding health check
      |
      v
validated
```

`validated` is not `trusted`. The existing registry/compiler therefore still refuse to execute this connector until a later promotion/approval step explicitly moves it to `trusted`.

## What validation does

`MCPValidationService.validate()` accepts:

- the selected `DiscoveryCandidateRef` from planning;
- the original `ConnectionRequest`;
- an optional brokered `ExecutionContext` for authenticated candidates;
- an optional explicit tool selection when automatic mapping is ambiguous.

Validation performs only MCP metadata operations. It does not call any discovered tool.

## Tool introspection

`MCPToolIntrospector` uses the official MCP client and `list_tools` pagination.

The validator is bounded:

- at most 100 tools;
- at most 10 `list_tools` pages;
- at most 64 KiB serialized metadata per tool;
- a caller-controlled validation deadline;
- no tool execution.

Tool reports intentionally keep only review-oriented metadata:

- tool name;
- clipped title and description;
- SHA-256 of input schema;
- SHA-256 of output schema when present;
- required input field names;
- `readOnlyHint`, `destructiveHint`, and `idempotentHint` when supplied;
- explicit UCS capability metadata when supplied.

Full schemas are not persisted in validation evidence.

The implementation accepts both object and boolean JSON Schemas, which are valid in current MCP/JSON Schema surfaces.

## Capability mapping

Automatic mapping is deterministic and conservative.

Priority:

1. explicit UCS capability metadata in tool `_meta`;
2. exact normalized capability/tool-name match;
3. service + operation tokens in tool name/title;
4. weaker service/capability-leaf matches.

Supported explicit metadata keys are:

```text
io.universal-connection-service/capability
io.universal-connection-service/capabilities
ucs/capability
ucs/capabilities
```

When two tools have the same best score, UCS does not guess. The report returns:

```text
code = MCP_TOOL_SELECTION_REQUIRED
requiresSelection = true
```

A control-plane caller may rerun validation with `selected_tool=<name>`.

## Read-safety guard

A user-selected tool cannot bypass operation safety.

For a request declared as `operation=read`, UCS refuses to bind a tool when:

- `destructiveHint=true`;
- `readOnlyHint=false`;
- the tool name/title clearly contains create/update/delete operation words.

This guard is important because otherwise a destructive tool could be mislabeled as a read capability and later inherit a lower-risk policy decision.

Missing `readOnlyHint` is recorded as `safetyUnknown`, but is not by itself enough to execute: the connector remains only `validated` after this stage.

## Authenticated candidates

Validation preserves the UCS-04 credential boundary.

For `authRequirement.type != none`, MCP validation requires:

- a `CredentialResolver`;
- an `ExecutionContext` carrying an opaque `credentialHandle`.

The raw credential is never placed in the candidate, validation report, or evidence store. The resolver receives the actual requested `serviceId`, not a validator-specific pseudo-service, so tenant/service credential scoping remains enforceable.

## Lifecycle

When one tool has been selected, UCS constructs a normal `MCPConnectorAdapter` with exactly one binding:

```text
requested business capability -> selected MCP tool name
```

The runtime registration starts as:

```text
sandboxed
```

The adapter then performs its normal health check and confirms that the bound tool is still present. On success:

```text
sandboxed -> validated
```

No UCS-10 code sets `trusted`.

## Evidence

When an `EvidenceStore` is configured, every validation attempt records normalized validation evidence:

```json
{
  "type": "mcp_candidate_validation",
  "candidateId": "...",
  "endpointHash": "sha256...",
  "toolCount": 4,
  "selectedTool": "get_weather",
  "selectionMode": "automatic",
  "requiresSelection": false,
  "passed": true,
  "code": "MCP_CANDIDATE_VALIDATED",
  "lifecycle": "validated"
}
```

The evidence omits:

- raw endpoint URL;
- tool input/output schemas;
- credentials / credential handles;
- request input;
- MCP response bodies.

## Public API boundary

UCS-10 deliberately does not expose a public `validate arbitrary MCP URL` endpoint.

Validation can cause outbound network connections, so exposing it before an authenticated admin/control-plane API would create an avoidable SSRF/egress surface. The service is currently an internal orchestration primitive. A later control-plane endpoint must authenticate the caller, bind validation to a server-side discovery candidate, apply egress policy, and audit the action.

## Acceptance criteria

UCS-10 is ready when CI proves that:

1. a real in-process MCP server can be inspected through the official MCP client;
2. a unique service/operation tool is mapped automatically;
3. ambiguous tool matches require explicit selection;
4. explicit selection resolves ambiguity without granting trust;
5. a non-actionable candidate never opens an MCP client;
6. authenticated validation without a credential handle fails before network access;
7. destructive-looking tools cannot auto-map to a read capability;
8. validation evidence stores only an endpoint hash, not the raw URL;
9. successful validation persists `sandboxed -> validated` lifecycle;
10. the resulting connector is still absent from `registry.trusted()`;
11. all UCS-02 through UCS-09 regression tests continue to pass.

## Deferred

- authenticated candidate-selection/validation API;
- server-side candidate IDs persisted between planning and promotion;
- explicit egress allow/deny policy for validation endpoints;
- OAuth bootstrap/consent UX for newly discovered authenticated MCP servers;
- richer semantic capability mapping using a model with reviewable evidence;
- multi-capability validation in a single MCP server session;
- resource/prompt introspection;
- server instructions and icon review;
- provenance/reputation signals from registry metadata;
- promotion workflow from `validated` to `awaiting_approval` / `trusted`.
