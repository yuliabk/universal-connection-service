# UCS-17 - Least-Privilege Policy Compiler

## Goal

UCS-16 made sandbox privileges capability-scoped and isolated each privileged egress call on an ephemeral internal Docker network. UCS-17 adds a deterministic proposal layer so operators do not have to hand-author every sandbox profile from scratch.

The compiler produces a reviewable proposal only. It never activates a profile and never bypasses the existing one-time approval flow.

```text
trusted sandboxed connector
        |
        v
capability + bound MCP tool
        |
        v
Least-Privilege Policy Compiler
   |          |             |
   |          |             +-- MCP annotations (advisory only)
   |          +-- Agent Vault binding scopes (operator controlled)
   +-- Sandbox policy catalog (operator controlled)
        |
        v
reviewable proposal
        |
        +-- exact profile
        +-- profile hash
        +-- reasons
        +-- unresolved requirements
        +-- confidence
        |
        v
human approval remains mandatory
```

## Security model

MCP tool annotations are treated as untrusted hints. `readOnlyHint`, `destructiveHint`, `idempotentHint`, and `openWorldHint` can improve explanation and risk review, but they do not grant network, mounts, or credentials.

Concrete privileges may come only from operator-controlled sources:

- `UCS_SANDBOX_POLICY_CATALOG_JSON`;
- an already configured Agent Vault binding for the same organization and service;
- an existing sandbox mount catalog entry referenced by ID.

The compiler never infers an egress hostname from a tool name, title, description, user prompt, or package manifest.

If evidence is insufficient or conflicting, the compiler keeps the profile at zero privilege and returns an `unresolvedRequirements` code.

## Proposal contract

A proposal contains:

```json
{
  "proposalId": "...",
  "organizationId": "org-1",
  "connectorId": "sandbox-records",
  "version": "1.0.0",
  "serviceId": "records",
  "capability": "records.read",
  "toolName": "records_read",
  "profile": {
    "egressHosts": [],
    "mounts": [],
    "brokeredCredentials": false
  },
  "profileHash": "...",
  "confidence": "LOW",
  "reasons": [],
  "unresolvedRequirements": ["open_world_behavior_unverified"],
  "toolRisk": {
    "readOnlyHint": null,
    "destructiveHint": null,
    "idempotentHint": null,
    "openWorldHint": null
  },
  "requiresHumanApproval": true
}
```

`requiresHumanApproval` is always true in UCS-17.

## Operator policy catalog

`UCS_SANDBOX_POLICY_CATALOG_JSON` is an array of deterministic rules.

Example:

```json
[
  {
    "organizationId": "org-1",
    "serviceId": "records",
    "capability": "records.read",
    "toolName": "records_read",
    "profile": {
      "egressHosts": [],
      "mounts": [
        {"mountId": "records-snapshot", "access": "read_only"}
      ],
      "brokeredCredentials": false
    },
    "reason": "records.read needs the approved read-only snapshot"
  }
]
```

Rules are matched by service and then ranked by specificity:

1. organization-specific beats global `*`;
2. capability-specific beats service-only;
3. tool-specific beats capability-only.

If equally specific rules propose different profiles, the compiler fails closed with `operator_policy_conflict` and proposes zero privilege.

Mounts are still validated against `UCS_MCP_SANDBOX_MOUNTS_JSON`. Host paths never appear in a proposal or evidence record; only mount IDs are persisted.

## Agent Vault-assisted proposal

If there is no operator policy rule and the tool advertises `openWorldHint=true`, the compiler may use Agent Vault configuration as a trusted source of concrete egress scope.

A proposal is generated only when the organization/service has exactly one distinct `allowedHosts` set. Multiple distinct scopes produce:

```text
credential_scope_selection_required
```

No scopes produce:

```text
egress_targets_unknown
```

The credential handle, Agent Vault control token, session token, and upstream credential are never persisted in proposal evidence.

## Zero-privilege behavior

Examples that remain zero privilege:

- no annotations and no operator policy;
- multiple competing Agent Vault host scopes;
- conflicting equally specific policy rules;
- unavailable referenced mount;
- missing runtime tool metadata;
- a tool that only has a description suggesting an external API.

The compiler explains the missing evidence instead of guessing.

## Control-plane endpoint

```text
GET /v1/control-plane/connectors/{connectorId}/sandbox-profile-proposal
    ?organizationId=org-1
    &version=1.0.0
    &capability=records.read
```

The caller needs `connectors:review` for the organization. The endpoint is read-only with respect to active sandbox policy; it writes only sanitized policy-decision evidence.

To activate a proposal, the existing UCS-16 flow remains unchanged:

```text
POST .../sandbox-profile-approval
POST .../sandbox-profile
```

The exact proposal profile/profile hash can be copied into that approval request, but UCS-17 does not issue or consume the approval automatically.

## Evidence

Proposal evidence stores:

- connector/version/service/capability/tool;
- safe profile body (egress hostnames and mount IDs only);
- profile hash;
- confidence;
- reasons;
- unresolved requirement codes;
- MCP risk hints;
- `requiresHumanApproval=true`.

It does not store:

- raw credential handles;
- Agent Vault management token;
- short-lived proxy tokens;
- upstream API credentials;
- host filesystem paths;
- request payloads.

## Health

`GET /health` includes:

```json
{
  "sandboxPolicyCompiler": "deterministic"
}
```

When the MCP sandbox runtime is not configured, the compiler is reported as `metadata-only`; it can still compile from persistent metadata/operator catalogs, but runtime tool annotations may be unavailable and therefore lower confidence.

## Acceptance criteria

UCS-17 is ready when CI proves that:

1. missing evidence produces zero privilege and an unresolved requirement;
2. a unique Agent Vault scope can propose only its exact host set;
3. multiple Agent Vault scopes are never unioned automatically;
4. operator catalog rules can propose exact mount IDs without persisting host paths;
5. equally specific conflicting rules fail closed;
6. raw credential handles/control tokens never enter evidence;
7. `connectors:review` is required;
8. proposal generation never activates sandbox privileges;
9. human approval remains mandatory;
10. UCS-02 through UCS-16 regressions remain green.

## Deferred

- explicit credential-scope selector UI when multiple Agent Vault bindings exist;
- signed policy catalogs;
- policy proposal diff UI versus currently active profile;
- per-call temporary grants narrower than the capability profile;
- business-intent-to-policy compilation;
- organization policy templates and inheritance;
- policy linting and stale-rule detection;
- automatic revocation suggestions when observed usage is narrower than approved policy.
