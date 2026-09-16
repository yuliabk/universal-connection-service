# UCS-16 - Managed Sandbox Gateway + Per-Tool Policy

## Goal

UCS-16 removes two broad privilege boundaries left by UCS-15:

1. sandbox privileges become capability/tool scoped instead of connector-wide;
2. egress uses a UCS-managed ephemeral Docker network per execution instead of a shared prepared network.

```text
trusted MCPB connector
   -> capability A -> profile A
   -> capability B -> profile B

privileged tool call
   -> create unique Docker internal network
   -> attach existing broker/gateway container with UCS alias
   -> start one sandbox on that network
   -> execute tool through broker
   -> stop sandbox
   -> detach gateway
   -> delete network
```

The MCPB never receives Docker access and never chooses its network, gateway, mounts or credentials.

## Per-capability policy

A profile is active only for:

```text
organization + connectorId + version + capability + profileHash
```

The safe profile body remains:

```json
{
  "egressHosts": ["api.example.com"],
  "mounts": [{"mountId": "client-files", "access": "read_only"}],
  "brokeredCredentials": true
}
```

The capability is a separate field in the approval/apply command. The one-time approval is scoped to that exact capability and profile hash.

Approval for `records.read` cannot activate `records.delete`, even when both tools belong to the same MCP server and use an identical profile body.

## Zero-privilege health and validation

`health_check`, `list_tools`, package validation and build-time MCP negotiation do not select a business capability. They therefore use the empty profile:

```text
network = none
mounts = none
broker credentials = none
```

Privileges are selected only immediately before execution of the requested capability.

## UCS-15 migration boundary

Historical `sandbox_profile_activated` evidence is retained for audit but is not inherited by UCS-16.

Automatically applying an old connector-wide profile to every tool would widen privileges without fresh approval. Operators must approve the intended profile for each capability.

## Control plane

Routes remain:

```text
GET  /v1/control-plane/connectors/{connectorId}/sandbox-profile
POST /v1/control-plane/connectors/{connectorId}/sandbox-profile-approval
POST /v1/control-plane/connectors/{connectorId}/sandbox-profile
```

The GET route now requires `capability`. Approval/apply bodies also include `capability`.

Governance remains:

```text
approvals:issue -> one-time exact capability/profile approval
connectors:promote -> activate exact approved profile
```

`UCS_CONTROL_PLANE_REQUIRE_DISTINCT_APPROVER=true` still enforces separate approver and applier identities.

## Managed gateway

UCS manages the network lifecycle around an existing broker container. It does not create the secrets backend itself.

Configuration:

```text
UCS_MCP_SANDBOX_GATEWAY_CONTAINER=agent-vault
UCS_MCP_SANDBOX_EGRESS_NETWORK=ucs-sandbox-egress
UCS_MCP_SANDBOX_EGRESS_PROXY_HOST=agent-vault-proxy
```

`UCS_MCP_SANDBOX_EGRESS_NETWORK` is a network-name prefix in managed mode.

At startup, `ensure()` verifies Docker is reachable and the configured gateway container is running. It does not create a shared execution network.

For every capability execution that actually needs egress, UCS creates a unique lease network similar to:

```text
docker network create \
  --driver bridge \
  --internal \
  --label io.universal-connection-service.sandbox-gateway=true \
  --label io.universal-connection-service.sandbox-gateway-lease=true \
  ucs-sandbox-egress-<random>
```

UCS verifies the network is internal, bridge-based and has both UCS labels, then connects the broker container with the configured network-scoped alias. After the sandbox process exits, UCS forcibly disconnects the broker and removes the lease network.

This prevents two concurrent sandbox executions from sharing a network and removes lateral sandbox-to-sandbox communication through a long-lived bridge.

## Docker security boundary

Docker documents `--internal` networks as externally isolated while still permitting communication between members of that specific network. UCS uses that property only for the one sandbox-to-gateway hop. See Docker Engine networking and `docker network create --internal` documentation.

The sandbox still runs with:

```text
--read-only
--cap-drop=ALL
--security-opt=no-new-privileges
non-root UID/GID
PID/CPU/memory limits
immutable local runtime image ID
```

No Docker socket is mounted into the MCPB sandbox.

## Credential boundary

Agent Vault/Agent Proxy style credential brokering remains the only supported HTTP(S) egress path:

- the opaque credential handle remains in UCS execution context;
- UCS mints a short-lived proxy session;
- upstream API credentials never enter the MCPB process;
- approved egress hosts must exactly match the credential binding host set;
- proxy token and CA exist only for the execution;
- raw handles, proxy tokens and approval IDs are never persisted.

Infisical describes this credential-brokering pattern as attaching credentials at the network boundary rather than exposing them to the agent process.

## Runtime and restart

MCPB validation continues with the zero-capability UCS-14 runner. After successful build, the runtime registration is wrapped with `ToolScopedSandboxedMCPConnector`.

Signed packages remain compatible with UCS-14 because they serialize only the sandbox connector config. After restart, UCS-08 verifies the signed package first, then the runtime binder attaches the tool-scoped managed runner.

## Health

Aggregate health fields:

```json
{
  "packageSandbox": "docker+managed-policy",
  "sandboxPolicy": "per-tool-approved-profiles",
  "sandboxGateway": "ready"
}
```

Possible gateway states are `pending`, `ready`, `unavailable`, `static`, or `disabled`. Health never exposes container names, network lease names, egress hosts, mount paths, credentials or proxy tokens.

## Acceptance criteria

UCS-16 is ready when CI proves that:

1. profiles are capability-scoped;
2. one capability cannot inherit another capability's profile;
3. an approval for capability A cannot activate capability B;
4. non-sandbox connectors cannot receive sandbox profiles;
5. health checks and introspection remain zero-privilege;
6. a tool execution selects only its own capability profile;
7. managed gateway health is idempotent;
8. every privileged execution gets a distinct Docker internal network;
9. the broker container receives the configured alias on that network;
10. the execution network is removed after the tool call;
11. there is no fallback to Docker's ordinary bridge network;
12. UCS-15 connector-wide evidence is not translated into tool privileges;
13. UCS-02 through UCS-15 regressions remain green.

## Deferred

- starting/stopping the broker container itself;
- multi-host/Kubernetes gateway orchestration;
- time-windowed tool profiles and scheduled revocation;
- per-call grants narrower than a capability profile;
- managed gVisor/Kata/Firecracker backends;
- gateway metrics and OpenTelemetry traces;
- automated migration from legacy Agent Vault deployments to Agent Proxy.
