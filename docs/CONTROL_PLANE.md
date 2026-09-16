# UCS-11 - Authenticated Control Plane + Promotion Workflow

## Goal

UCS-10 can validate a discovered MCP candidate and persist it as `validated`, but validated code is intentionally not executable through the trusted runtime path. UCS-11 adds the authenticated human/control-plane gate that promotes a reviewed connector from `validated` to `trusted`.

```text
Discovery
   -> validation
   -> sandboxed
   -> validated
   -> authenticated review
   -> promotion approval
   -> awaiting_approval
   -> atomic approval consume
   -> trusted
   -> execution may resolve the connector
```

The control plane also exposes candidate-bound MCP validation. It never accepts an arbitrary MCP URL.

## Fail-closed default

Control-plane routes are registered under:

```text
/v1/control-plane
```

but are disabled unless this environment variable is configured:

```text
UCS_CONTROL_PLANE_CREDENTIALS_JSON
```

When it is absent, control-plane routes return `503 CONTROL_PLANE_DISABLED`.

`GET /health` reports only:

```json
{"controlPlane": "enabled"}
```

or `disabled`. It never exposes configured subjects, token hashes, organizations or scopes.

## Bearer credentials

UCS does not store raw control-plane bearer tokens in configuration. Operators generate a high-entropy token and configure only its SHA-256 digest.

Example token generation:

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Hash it:

```bash
python -c "import hashlib; print(hashlib.sha256(b'PASTE_TOKEN_HERE').hexdigest())"
```

Configure one or more principals:

```json
[
  {
    "tokenSha256": "<64 lowercase hex characters>",
    "subject": "owner@example",
    "tokenId": "owner-primary",
    "organizations": ["org-1"],
    "scopes": [
      "connectors:review",
      "connectors:validate",
      "approvals:issue",
      "connectors:promote"
    ]
  }
]
```

A high-entropy raw token is sent only as:

```text
Authorization: Bearer <raw token>
```

UCS hashes the presented token and compares digests with constant-time comparison.

## Scopes

Control-plane capabilities are split into four independent scopes:

```text
connectors:review
connectors:validate
approvals:issue
connectors:promote
```

Each credential is also bound to one or more organizations. `"*"` is allowed for an explicitly global operator.

This makes separation of duties possible without changing the API.

## Connector review

```text
GET /v1/control-plane/connectors/{connectorId}/review
    ?organizationId=org-1
    &version=1.0.0
```

Review returns:

- exact organization/connector/version;
- lifecycle;
- whether the executable registration is present in this runtime;
- connector manifest;
- normalized validation evidence summaries;
- `validationReady`.

Promotion readiness requires all of the following:

1. exact runtime implementation is loaded;
2. lifecycle is `validated` or `awaiting_approval`;
3. at least one passing validation evidence item exists for the connector.

Persistent metadata alone is insufficient.

## Candidate-bound MCP validation

```text
POST /v1/control-plane/mcp/validate
```

The body contains the original `ConnectionRequest`, a `candidateId`, optional selected tool, and optional opaque credential handle.

The endpoint does **not** accept an endpoint URL.

UCS reruns server-side planning/discovery and requires the supplied `candidateId` to be present in the current discovery result. Only then is the candidate passed to `MCPValidationService`.

This preserves the UCS-09/10 boundary:

```text
caller candidateId
    -> server-side discovery
    -> exact candidate match
    -> endpoint safety checks
    -> list_tools only
    -> capability mapping
    -> sandboxed -> validated
```

A forged candidate ID fails before MCP validation.

## Promotion approval issuance

```text
POST /v1/control-plane/connectors/{connectorId}/promotion-approvals
```

Example body:

```json
{
  "organizationId": "org-1",
  "version": "1.0.0",
  "promotionId": "release-2026-09-16-records",
  "expiresInSeconds": 900
}
```

The issuer must have `approvals:issue` for the target organization.

If the connector is promotable, UCS:

1. generates a cryptographically random approval ID;
2. hashes it with SHA-256;
3. persists only the hash plus exact promotion scope;
4. changes lifecycle `validated -> awaiting_approval`;
5. returns the raw approval ID once to the authenticated caller.

The persisted approval is scoped to:

```text
promotionId
organizationId
connectorId
version
service = ucs-control-plane
operation = update
expiry
```

The raw approval ID is not written to connector state, evidence or audit storage.

## Promotion

```text
POST /v1/control-plane/connectors/{connectorId}/promote
```

Example body:

```json
{
  "organizationId": "org-1",
  "version": "1.0.0",
  "promotionId": "release-2026-09-16-records",
  "approvalId": "<one-time approval returned above>"
}
```

The promoter must have `connectors:promote` for the target organization.

Before promotion UCS verifies again that:

- exact runtime connector is still loaded;
- lifecycle is promotable;
- passing validation evidence still exists;
- approval exists;
- approval is unexpired and unused;
- approval scope matches exact organization/connector/version/promotion;
- optional separation-of-duties rule passes.

The approval is consumed atomically **before** lifecycle becomes `trusted`.

On success:

```text
awaiting_approval -> trusted
```

The connector-state approval reference is the SHA-256 hash only.

## Separation of duties

By default, a small deployment may give one principal both approval and promotion scopes.

To require two different principals:

```bash
UCS_CONTROL_PLANE_REQUIRE_DISTINCT_APPROVER=true
```

Then the principal that issued the promotion approval cannot perform the promotion. A different authorized subject must consume it.

## SQLite and PostgreSQL

UCS-11 adds the approval-grant table to the SQLite reference backend so local and CI flows behave like PostgreSQL.

PostgreSQL/Supabase continues to use the UCS-07 `ucs_internal.approval_grant` table and atomic conditional update.

No new PostgreSQL migration is required for UCS-11.

## Evidence

Control-plane actions append normalized `approval_verification` evidence.

Approval issuance stores fields such as:

```text
type = promotion_approval_issued
promotionRefHash
approvalRefHash
version
expiresAt
approverSubject
```

Successful promotion stores:

```text
type = connector_promoted
promotionRefHash
approvalRefHash
fromLifecycle
toLifecycle
approverSubject
promoterSubject
```

Neither event contains the raw bearer token or raw approval ID.

## Security boundaries

- no control-plane action is available without bearer authentication;
- configured bearer secrets are stored as SHA-256 digests only;
- credentials are organization- and scope-bound;
- candidate validation accepts candidate IDs, never arbitrary endpoint URLs;
- promotion requires a runtime-loaded validated connector;
- promotion requires passing validation evidence;
- approval is exact-scope, expiring and one-time;
- approval consume is atomic in SQLite and PostgreSQL;
- raw approval IDs are never persisted;
- `validated` remains non-executable through `registry.trusted()`;
- promotion is the only UCS-11 path to `trusted`;
- optional two-person approval can be enforced.

Control-plane endpoints must still be deployed behind TLS and normal perimeter controls. Bearer-token authentication is an application control, not a substitute for transport encryption, network policy or operator identity management.

## Acceptance criteria

UCS-11 is ready when CI proves that:

1. disabled control plane fails closed;
2. missing/invalid bearer credentials return authentication failure;
3. organization and scope boundaries return authorization failure;
4. review requires an exact runtime connector and passing validation evidence;
5. raw promotion approval is stored only as SHA-256;
6. lifecycle moves `validated -> awaiting_approval -> trusted`;
7. trusted resolution works only after promotion;
8. approval is consumed atomically and cannot authorize another promotion;
9. optional distinct-approver mode blocks self-promotion;
10. MCP validation is bound to a server-side discovery candidate ID;
11. a forged candidate ID is rejected before validation;
12. SQLite and PostgreSQL approval stores preserve one-time semantics;
13. all UCS-02 through UCS-10 regression tests continue to pass.

## Deferred

- Clerk/OIDC/JWT control-plane identity provider;
- WebAuthn/passkey approval UX;
- approval revocation endpoint;
- persisted server-side discovery-candidate snapshots;
- signed promotion attestations;
- multi-reviewer/quorum approvals;
- emergency disable/revoke flow for trusted connectors;
- operator UI;
- OpenTelemetry control-plane spans and metrics;
- organization-specific promotion policy through OPA;
- automatic package signing after dynamic connector generation.
