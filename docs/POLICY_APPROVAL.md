# UCS-05 - Policy Engine + Approval Verification

## Goal

Replace the previous hard-coded `write => human approval` rule with a provider-neutral policy decision layer and enforce approval grants before outbound execution.

```text
ConnectionRequest
      -> policy facts
      -> PolicyEngine
           -> ALLOW
           -> DENY
           -> REQUIRE_APPROVAL
      -> ApprovalVerifier when required
      -> trusted connector
      -> CredentialResolver when required
      -> outbound execution
```

Policy is evaluated during both planning and execution. Execution re-evaluates policy so a stale plan cannot bypass a newer policy decision.

## Explicit risk facts

UCS does not infer financial or permission-increasing semantics from capability names.

`ConnectionRequest.riskHints` may explicitly carry:

- `destructive`
- `financial`
- `permissionIncrease`

Objective request facts are also included in the policy input. In particular, `operation=delete` is treated as destructive even when no hint is supplied.

The policy input contains request, actor, tenant, service, capability, operation, read-only state, trusted-connector state and normalized risk facts.

## Policy decisions

Every plan contains:

- `policyDecision`: `ALLOW`, `DENY`, or `REQUIRE_APPROVAL`
- `policyReasons`
- normalized `risk`
- the compatibility field `requiresHumanApproval`

The default bootstrap policy is conservative:

- trusted read-only reads: `ALLOW`
- writes / side-effecting operations: `REQUIRE_APPROVAL`
- destructive, financial, or permission-increasing operations: `REQUIRE_APPROVAL` with HIGH risk
- explicitly denied services/capabilities: `DENY`
- untrusted implementations: `REQUIRE_APPROVAL` in addition to the existing build/validation gates

## OPA adapter

`OPAPolicyEngine` supports the Open Policy Agent Data API using:

```http
POST /v1/data/<decision-path>
Content-Type: application/json

{"input": { ...policy facts... }}
```

UCS expects a named decision payload with this shape:

```json
{
  "result": {
    "decision": "ALLOW",
    "reasons": [],
    "risk": {
      "level": "LOW",
      "reasons": []
    }
  }
}
```

OPA is optional. It is an implementation of `PolicyEngine`, not part of the UCS core contract.

Remote OPA endpoints require HTTPS. Loopback HTTP is allowed for local development. Network errors, HTTP errors, missing decisions and invalid schemas fail closed to `DENY`.

## Approval grants

An approval is not a generic boolean and is not transferable between requests.

`ApprovalGrant` is bound to:

- approval ID
- request ID
- organization ID
- user ID
- agent ID
- service ID
- capability
- operation
- expiration time

The reference `InMemoryApprovalVerifier` is intended for tests and single-process development only. Production approval storage and verification must be persistent.

Approvals authorize one execution attempt. A valid grant is consumed before the connector's outbound call to prevent concurrent replay.

## Execution enforcement

`ConnectionService` now enforces these gates before connector execution:

1. `ExecutionContext` request/user/organization identity must match the request.
2. `DENY` returns `POLICY_DENIED` before connector execution.
3. No trusted connector returns `CONNECTION_UNAVAILABLE`.
4. `REQUIRE_APPROVAL` requires `approvalId`.
5. Approval verification must be configured and the grant must match the exact request.
6. The approval is consumed before outbound execution.
7. Only then may the connector execute.

## Error codes

- `EXECUTION_CONTEXT_MISMATCH`
- `POLICY_DENIED`
- `APPROVAL_REQUIRED`
- `APPROVAL_VERIFICATION_UNAVAILABLE`
- `APPROVAL_INVALID`
- `APPROVAL_EXPIRED`
- `APPROVAL_SCOPE_MISMATCH`
- `APPROVAL_ALREADY_USED`

## Security properties

- A plan is informative, not an authorization token.
- Policy is re-evaluated at execution time.
- Approval IDs are request-bound and one-time use in the reference verifier.
- Tenant/user/request mismatches fail before outbound access.
- Policy provider failure cannot silently become `ALLOW`.
- Financial and permission-increase semantics are explicit facts rather than capability-name heuristics.
- Credential resolution remains a separate outbound boundary from approval and policy.

## Deferred

- persistent approval store and approval UI/workflow;
- signed approval artifacts;
- multi-approver / quorum policies;
- approval revocation and organization-level delegation;
- policy bundle distribution and OPA lifecycle management;
- persistent policy decision/audit evidence;
- capability risk metadata signed with connector packages;
- rate/budget-aware policy facts.

## Acceptance criteria

UCS-05 is ready when CI proves that:

1. trusted read-only operations are allowed without approval;
2. writes require approval by default;
3. delete is classified as destructive/high risk;
4. explicit financial and permission-increase facts are high risk;
5. policy denial prevents connector execution;
6. missing, expired, reused, or mismatched approvals prevent connector execution;
7. a valid exact-match approval permits one execution attempt;
8. execution-context identity mismatch fails closed;
9. OPA Data API decisions can drive the policy contract;
10. OPA/provider failures deny fail-closed;
11. all UCS-02 through UCS-04 regression tests continue to pass.
