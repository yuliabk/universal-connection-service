# UCS-16 - Managed Sandbox Gateway + Per-Tool Policy

## Goal

UCS-15 introduced approved sandbox capability profiles, but two operational gaps remained:

1. egress required an operator-prepared Docker internal network and proxy attachment;
2. privileges were connector-version scoped, so every tool exposed by the same trusted connector shared the same runtime profile.

UCS-16 closes both gaps.

```text
trusted MCPB connector
        |
        +-- capability A -> profile A -> sandbox execution A
        |
        +-- capability B -> profile B -> sandbox execution B

managed egress path:
MCPB sandbox
   -> Docker internal network managed by UCS
   -> existing Agent Vault / broker container attached by UCS
   -> broker-controlled outbound destination
```

The MCPB process never receives Docker access and never chooses its network, gateway, mounts or credentials.

## Per-capability policy

A sandbox profile is now activated for the tuple:

```text
organization
connectorId
connectorVersion
capability
profileHash
```

The profile body remains the UCS-15 safe structure:

```json
{
  "egressHosts": ["api.example.com"],
  "mounts": [
    {"mountId": "client-files", "access": "read_only"}
  ],
  "brokeredCredentials": true
}
```

The capability is supplied separately in the control-plane command and is included in the approval scope.

Examples:

```text
records.read
  -> read-only client-files mount
  -> no network

records.delete
  -> no mounts
  -> api.records.example through broker
```

Approval for `records.read` cannot be replayed for `records.delete`, even with an identical profile body.

## Zero-privilege introspection

`health_check`, `list_tools`, package validation and build-time MCP negotiation do not select a business capability.

Therefore they always receive the empty profile:

```text
network = none
mounts = none
broker credentials = none
```

Privileges are selected only immediately before execution of the requested capability.

## Migration from UCS-15

Existing `sandbox_profile_activated` evidence from UCS-15 is retained for audit history but is not treated as an active UCS-16 tool policy.

This is intentional. Automatically translating one connector-wide profile into every tool would widen privileges without a new human approval.

Operators must approve the intended profile separately for each capability.

## Control-plane flow

Endpoints remain under the same connector namespace but are capability-aware:

```text
GET  /v1/control-plane/connectors/{connectorId}/sandbox-profile
POST /v1/control-plane/connectors/{connectorId}/sandbox-profile-approval
POST /v1/control-plane/connectors/{connectorId}/sandbox-profile
```

The GET route requires a `capability` query parameter. Approval/apply bodies include `capability`.

Governance remains:

```text
approvals:issue
    -> one-time approval bound to exact capability + profile hash
connectors:promote
    -> activate exact approved profile
```

`UCS_CONTROL_PLANE_REQUIRE_DISTINCT_APPROVER=true` still enforces separate approver and applier identities.

## Managed Docker gateway

When configured, UCS manages the network boundary around an existing credential-broker container.

Runtime configuration:

```text
UCS_MCP_SANDBOX_GATEWAY_CONTAINER=agent-vault
UCS_MCP_SANDBOX_EGRESS_NETWORK=ucs-sandbox-egress
UCS_MCP_SANDBOX_EGRESS_PROXY_HOST=agent-vault-proxy
```

If `UCS_MCP_SANDBOX_GATEWAY_CONTAINER` is set, UCS performs an idempotent `ensure` operation:

1. inspect the configured network;
2. create it as an internal bridge if it does not exist;
3. verify `Internal=true` and `Driver=bridge`;
4. verify the configured gateway container is running;
5. connect the gateway container to the internal network when needed;
6. attach the configured network-scoped alias;
7. re-read state and fail closed on mismatch.

Network creation uses the equivalent of:

```text
docker network create \
  --driver bridge \
  --internal \
  --label io.universal-connection-service.sandbox-gateway=true \
  ucs-sandbox-egress
```

UCS does not create the secrets backend itself. The gateway container is still operator-provisioned because its own credentials, storage and lifecycle are deployment concerns.

## Startup and repair behavior

At FastAPI startup UCS attempts to ensure the managed gateway.

A gateway failure does not disable zero-capability MCPB validation or local sandbox execution. Health reports the gateway as unavailable and any capability requiring egress fails closed.

Before every privileged egress execution the managed runner calls `ensure()` again. This provides lightweight self-repair for a deleted network or detached gateway without allowing a fallback to Docker's default bridge.

## Network security

Docker documents `--internal` networks as externally isolated while still allowing communication among containers on the same network. UCS relies on that property for the MCPB-to-gateway hop.

The sandbox container is connected only to the managed internal network. The credential-broker container may separately have its own operator-managed outbound connectivity.

The sandbox still has:

```text
--read-only
--cap-drop=ALL
--security-opt=no-new-privileges
non-root UID/GID
PID/CPU/memory limits
immutable local runtime image ID
```

No Docker socket is mounted into the sandbox.

## Credential boundary

Agent Vault integration remains brokered:

- the opaque credential handle stays in UCS execution context;
- UCS mints a short-lived proxy session;
- the upstream API credential never enters UCS or MCPB;
- the requested egress host set must exactly match the credential binding host set;
- proxy token and CA are temporary execution material only;
- raw handles and proxy tokens are not persisted in audit/evidence.

Infisical's current Agent Proxy/Agent Vault architecture follows the same credential-brokering principle: credentials are attached at the network boundary rather than exposed to the agent process.

## Runtime wrapping and restart

New MCPB connectors are initially validated with the zero-capability UCS-14 runner. After validation the runtime registration is wrapped with `ToolScopedSandboxedMCPConnector`.

Signed connector packages still serialize only the existing sandbox connector config. On restart, UCS-08 package verification runs first, then the runtime binder wraps the verified connector with the tool-scoped managed runner.

This preserves package compatibility while keeping runtime privileges outside the signed connector artifact.

## Health

Relevant health fields:

```json
{
  "packageSandbox": "docker+managed-policy",
  "sandboxPolicy": "per-tool-approved-profiles",
  "sandboxGateway": "ready"
}
```

Possible gateway states include:

```text
managed/pending
ready
unavailable
static
disabled
```

No gateway container name, network secrets, egress host lists, mount paths or credential handles are returned.

## Acceptance criteria

UCS-16 is ready when CI proves that:

1. profiles are capability-scoped;
2. one capability cannot inherit another capability's profile;
3. an approval for capability A cannot activate capability B;
4. health checks and introspection stay zero-privilege;
5. a requested tool executes with only its own capability profile selected;
6. the managed gateway creates an internal bridge network when absent;
7. the gateway container is attached with the configured network alias;
8. repeated gateway `ensure()` calls are idempotent;
9. privileged execution re-checks/repairs the managed gateway;
10. no fallback to Docker's ordinary bridge network exists;
11. UCS-15 connector-wide evidence is not automatically promoted into per-tool privileges;
12. UCS-02 through UCS-15 regressions remain green.

## Deferred

- starting/stopping the credential-broker container itself;
- multi-host gateway orchestration;
- Kubernetes NetworkPolicy/service equivalents;
- time-windowed tool profiles and scheduled revocation;
- per-call ephemeral grants narrower than a capability profile;
- policy-generated profiles from business intent;
- managed gVisor/Kata/Firecracker backends;
- gateway metrics and OpenTelemetry traces;
- automated Agent Proxy migration from legacy Agent Vault deployments.
