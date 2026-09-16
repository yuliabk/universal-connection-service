# UCS-18 - Policy Proposal to Approval Workflow Integration

## Goal

UCS-17 can compile a least-privilege sandbox profile proposal, but the proposal was previously reviewed and activated outside Auto-Connect. UCS-18 makes that governance step part of the same persistent workflow.

For a trusted sandboxed MCP connector the flow is now:

```text
trusted connector
    -> compile least-privilege proposal
    -> unresolved requirements? stop fail-closed
    -> exact profile already approved? continue
    -> otherwise require sandbox-policy approval
    -> consume one-time approval
    -> activate exact capability profile
    -> continue to execution approval when required
    -> execute
```

OpenAPI connectors and remote MCP connectors continue to use the existing Auto-Connect path. The new policy workflow applies only to trusted `SandboxedMCPConnector` runtimes.

## Persistent workflow state

UCS-18 deliberately does not add secrets or policy JSON to the `connection_workflow` table.

The workflow remains on its existing persistent `planning` stage while `lastCode` identifies the sandbox-policy checkpoint:

```text
SANDBOX_POLICY_RESOLUTION_REQUIRED
SANDBOX_POLICY_APPROVAL_REQUIRED
SANDBOX_POLICY_APPROVAL_ISSUED
SANDBOX_POLICY_ACTIVATED
```

The exact reviewed proposal snapshot is stored as sanitized `policy_decision` evidence bound to the `workflowId`.

This gives restart-safe recovery without persisting:

- raw approval IDs;
- credential handles;
- Agent Vault tokens;
- proxy session tokens;
- upstream credentials;
- host filesystem paths.

## Proposal stability

When Auto-Connect reaches a trusted sandboxed connector, UCS-17 compiles a proposal and UCS-18 stores a workflow-specific snapshot.

Once `SANDBOX_POLICY_APPROVAL_REQUIRED` is reached, ordinary `advance` calls do not silently replace that reviewed proposal. Approval issuance and activation use the exact persisted snapshot.

If the compiler reports unresolved requirements, Auto-Connect stays fail-closed with `SANDBOX_POLICY_RESOLUTION_REQUIRED`. After an operator fixes the policy catalog, mount catalog or credential scope, another normal `advance` recompiles the proposal.

## Approval and activation

New workflow endpoints:

```text
GET  /v1/control-plane/auto-connect/{workflowId}/sandbox-policy
POST /v1/control-plane/auto-connect/{workflowId}/sandbox-policy-approval
POST /v1/control-plane/auto-connect/{workflowId}/sandbox-policy-activate
```

The approval endpoint requires the normal `approvals:issue` scope through `SandboxToolPolicyService`.

Activation requires the normal `connectors:promote` scope and consumes the approval atomically before profile activation.

The approval is bound to:

```text
organization
connectorId
connectorVersion
capability
profileHash
workflow policy change id
```

An approval for one profile cannot activate a different profile, capability, connector or version.

## Reuse and drift

An already activated profile can be reused by a later workflow only when its profile hash exactly matches the newly compiled proposal for the same connector version and capability.

This avoids unnecessary repeated approval for an unchanged least-privilege grant.

If the operator policy catalog or trusted credential scope changes and the compiler produces a different profile hash, execution stops again at `SANDBOX_POLICY_APPROVAL_REQUIRED`.

Unresolved compiler output always wins over an old active profile. UCS never falls back to a previously approved profile when the current policy cannot be justified.

## Security boundary

UCS-18 does not merge sandbox-policy approval with execution approval.

They remain independent gates:

```text
sandbox-policy approval
    -> permission to expose specific runtime capabilities

execution approval
    -> permission to perform a specific side-effecting ConnectionRequest
```

A sandbox-policy approval therefore cannot authorize a write/delete request, and an execution approval cannot widen sandbox egress, mounts or credentials.

## Health

When the integrated workflow is available:

```json
{
  "autoConnect": "persistent+build+mcpb-sandbox+policy-workflow",
  "sandboxPolicyWorkflow": "integrated"
}
```

## Acceptance criteria

UCS-18 is ready when CI proves that:

1. a trusted sandboxed connector does not execute before a least-privilege proposal is reviewed;
2. a proposal with unresolved requirements remains fail-closed;
3. a workflow-specific proposal snapshot is persisted without secrets;
4. one-time sandbox-policy approval is issued through the existing approval store;
5. activation consumes the exact approval and then resumes the same workflow;
6. the activated capability executes only after profile activation;
7. a later workflow can reuse an identical already-approved profile;
8. changed profile hashes require a fresh approval;
9. raw sandbox-policy approval IDs never appear in workflow rows or evidence;
10. non-sandbox connector behavior is unchanged;
11. the complete UCS regression suite remains green.
