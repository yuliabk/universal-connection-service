# UCS-12 - End-to-End Connection Orchestrator / Auto-Connect

## Goal

UCS-02 through UCS-11 provide the connection primitives independently: planning, discovery, validation, credentials, policy, approval, trust promotion, execution and audit. UCS-12 composes those primitives into one persistent workflow that can stop when human or external input is needed and resume later without replaying completed governance steps.

```text
ConnectionRequest
    |
    v
persistent workflow
    |
    +-> trusted connector? --------------------------+
    |                                                |
    | no                                             | yes
    v                                                v
 discovery                                      execution policy
    |                                                |
    +-> ambiguous -> await candidate selection       +-> approval? -> await approval
    |
    +-> package/API build required -> await build
    |
    v
 MCP validation
    |
    +-> auth missing -> await credential handle
    +-> tool ambiguity -> await tool selection
    +-> transient validation failure -> retry
    |
    v
 validated
    |
    v
 await promotion approval
    |
    v
 trusted
    |
    v
 execution approval when policy requires it
    |
    v
 execute
    |
    v
 completed
```

## Persistent workflow state

UCS-12 adds `connection_workflow` to SQLite and PostgreSQL/Supabase.

PostgreSQL schema version is now **3**.

Persistent fields contain only control-plane metadata:

- workflow ID;
- request ID and organization;
- SHA-256 request fingerprint;
- service/capability/operation;
- workflow stage;
- selected candidate/tool identifiers;
- connector ID/version;
- promotion ID;
- last normalized code;
- final audit ID;
- optimistic revision;
- short internal lease metadata.

The workflow table does **not** store:

- `ConnectionRequest.input`;
- credential handles;
- raw API/OAuth credentials;
- raw promotion approvals;
- raw execution approvals;
- connector response bodies.

The caller must resubmit the exact original `ConnectionRequest` on every resume. UCS canonicalizes and hashes that request. Any mutation, including a changed input payload, fails with `WORKFLOW_REQUEST_MISMATCH` before validation, promotion or execution.

## Concurrency and leases

Every state-changing advance first acquires an atomic 120-second workflow lease.

SQLite performs this under its process lock and conditional update. PostgreSQL performs the same conditional update in the database, so competing UCS instances cannot both own the workflow.

State writes also require the expected workflow `revision` plus the active lease token. Successful updates increment the revision and clear the lease.

This prevents ordinary concurrent resume requests from invoking the same workflow step twice. A crashed worker eventually loses its lease and another worker can resume.

The lease is an internal concurrency token, not a user credential, and is excluded from API models.

## API

Auto-Connect is exposed under the authenticated UCS-11 control plane:

```text
POST /v1/control-plane/auto-connect
GET  /v1/control-plane/auto-connect/{workflowId}
POST /v1/control-plane/auto-connect/{workflowId}/advance
POST /v1/control-plane/auto-connect/{workflowId}/promotion-approval
POST /v1/control-plane/auto-connect/{workflowId}/execution-approval
```

The feature is enabled only when a persistent `WorkflowStore` exists. In-memory-only UCS returns `503 AUTO_CONNECT_DISABLED`.

`GET /health` reports:

```json
{"autoConnect": "persistent"}
```

or `disabled`.

## Authorization model

UCS-12 does not introduce a super-scope that bypasses UCS-11 governance.

Creating, viewing and resuming a workflow requires `connectors:review` for the target organization. Individual transitions retain their existing scopes:

- MCP validation: `connectors:validate`;
- promotion approval issuance: `approvals:issue`;
- trust promotion: `connectors:promote`;
- execution approval issuance: `approvals:issue`.

Therefore a workflow operator cannot use Auto-Connect to perform a step the same principal could not perform directly through the UCS-11 control plane.

## Workflow stages

```text
planning
awaiting_candidate_selection
awaiting_build
awaiting_credentials
awaiting_tool_selection
awaiting_promotion_approval
awaiting_promotion
awaiting_execution_approval
ready_to_execute
completed
failed
```

Each response includes a `nextAction` so a UI or agent can render the next required human/system step without reverse-engineering state.

Examples:

```text
awaiting_candidate_selection -> select_candidate
awaiting_credentials          -> provide_credential_handle
awaiting_tool_selection       -> select_tool
awaiting_promotion_approval   -> issue_promotion_approval
awaiting_promotion            -> provide_promotion_approval
awaiting_execution_approval   -> issue_execution_approval
completed                     -> none
```

## Trusted connector fast path

When planning already resolves a trusted connector, Auto-Connect skips discovery and validation entirely.

For a low-risk read with policy `ALLOW`, `executeWhenReady=true` can execute immediately.

For write/destructive/financial/permission-increase requests, existing policy still pauses for execution approval.

For authenticated connectors, a missing opaque credential handle pauses the workflow at `awaiting_credentials`.

## Discovery and validation path

When no trusted connector exists:

1. the existing compiler/discovery engine runs;
2. ambiguous candidates pause at `awaiting_candidate_selection`;
3. the selected candidate must still exist in a current server-side plan;
4. safe actionable Streamable HTTP MCP candidates enter UCS-10 validation;
5. auth-required MCP candidates pause for a credential handle;
6. tool ambiguity pauses for explicit tool selection;
7. successful validation creates only a `validated` connector;
8. workflow pauses for UCS-11 promotion approval.

Auto-Connect never changes `validated` to `trusted` without the UCS-11 approval/promotion path.

## Promotion

The workflow generates a stable promotion ID:

```text
auto-connect:<workflowId>
```

The promotion-approval endpoint delegates to `ControlPlaneService.issue_promotion_approval()`. The raw approval is returned once and remains outside workflow persistence.

The next advance supplies that approval to the normal UCS-11 `promote()` gate. If distinct approver/promoter mode is enabled, the same separation-of-duties rule still applies.

## Execution approval

After promotion, the connector is replanned as trusted.

If policy still returns `REQUIRE_APPROVAL`, the workflow pauses at `awaiting_execution_approval`.

The execution-approval endpoint creates the same exact request-scoped `ApprovalRecord` used by `ConnectionService`:

- request ID;
- organization/user/agent;
- service/capability/operation;
- expiration;
- one-time atomic consume.

Only the approval hash is persisted. The raw approval is returned once to the authenticated approver and supplied on the later advance call.

## Build boundary

UCS-12 deliberately does not pretend that every discovered service can already be built automatically.

If planning selects:

- a package-only MCP candidate;
- a non-actionable transport;
- an OpenAPI/API candidate that still requires adapter generation;
- the generated API fallback;

the workflow stops at:

```text
awaiting_build
```

with:

```text
lastCode = CONNECTION_BUILD_REQUIRED
```

A future build/compiler stage can resume this same persisted workflow after producing and validating a runtime connector.

## Output persistence

Successful execution stores only the normal UCS audit ID in the workflow.

The response data returned by the external service is returned to the current caller but is not copied into `connection_workflow`. This preserves the UCS-06 metadata-only persistence boundary.

## Failure and retry

Policy denial is terminal for that workflow (`failed`).

Validation transport/introspection failures are treated as retryable orchestration state: the workflow returns to `planning` with `MCP_VALIDATION_RETRYABLE`, allowing a later advance to retry discovery/validation.

Credential and approval errors return to their corresponding waiting states instead of silently bypassing the gate.

## Acceptance criteria

UCS-12 is ready when CI proves that:

1. PostgreSQL migrates to schema version 3;
2. workflow state persists in SQLite and PostgreSQL;
3. request input is absent from workflow persistence;
4. resuming with a changed request fails before execution;
5. only one concurrent workflow lease can be acquired;
6. a trusted read can auto-execute and complete;
7. a trusted write pauses for one-time execution approval;
8. ambiguous discovery pauses for candidate selection;
9. an MCP candidate can traverse discovery -> validation -> promotion -> trusted -> execution;
10. raw promotion/execution approvals are absent from workflow/evidence persistence;
11. completed workflows are idempotent and do not execute twice on repeat advance;
12. build-required candidates pause instead of executing;
13. all UCS-02 through UCS-11 regression tests remain green.

## Deferred

- automatic OpenAPI adapter generation/build inside the workflow;
- package download + signing/build automation from MCP Registry package candidates;
- crash-safe exactly-once semantics for arbitrary external side effects beyond the existing lease/audit boundaries;
- persisted discovery candidate snapshots;
- workflow cancellation/restart API;
- approval revocation;
- operator UI;
- webhook/event-based wakeups;
- OpenTelemetry workflow spans/metrics;
- background worker/queue mode for long-running validation/build steps.
