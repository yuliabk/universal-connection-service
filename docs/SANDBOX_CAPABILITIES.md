# UCS-15 - Policy-Controlled Sandbox Capabilities

## Goal

UCS-14 executes local MCPB packages inside a Docker sandbox with no network, no host data mounts and no credentials. UCS-15 adds controlled runtime capabilities without letting the package decide its own permissions.

The default remains:

```text
network = none
host data mounts = none
credential handle = unavailable to the package
```

A trusted `SandboxedMCPConnector` can receive a capability profile only through the authenticated control plane and a one-time approval.

## Sandbox capability profile

A profile contains only safe identifiers:

```json
{
  "egressHosts": ["api.example.com"],
  "mounts": [
    {"mountId": "client-files", "access": "read_only"}
  ],
  "brokeredCredentials": true
}
```

The profile does not contain host paths, raw credentials, proxy tokens or Docker options.

Profiles are connector-version scoped. Applying a different profile requires a new approval. An empty profile revokes previously approved capabilities.

## Governance flow

```text
trusted sandbox connector
        |
        v
requested capability profile
        |
        v
approvals:issue
        |
        v
one-time profile approval
        |
        v
connectors:promote
        |
        v
activate exact profile hash
        |
        v
persistent evidence
```

Endpoints:

```text
GET  /v1/control-plane/connectors/{connectorId}/sandbox-profile
POST /v1/control-plane/connectors/{connectorId}/sandbox-profile-approval
POST /v1/control-plane/connectors/{connectorId}/sandbox-profile
```

The approval is bound to organization, connector ID, version, change ID and the SHA-256 of the exact profile. Replay or changing a mount from read-only to read-write after approval fails closed.

When `UCS_CONTROL_PLANE_REQUIRE_DISTINCT_APPROVER=true`, the approver and profile applier must be different principals.

## Mount catalog

Host paths are never accepted from the package or request. Operators configure them through:

```text
UCS_MCP_SANDBOX_MOUNTS_JSON
```

Example:

```json
[
  {
    "organizationId": "org-1",
    "mountId": "client-files",
    "hostPath": "/srv/ucs/client-files",
    "containerPath": "/data/client-files",
    "maxAccess": "read_only"
  }
]
```

Rules:

- host paths must be absolute and operator-configured;
- broad system roots such as `/`, `/proc`, `/sys`, `/dev` and `/run` are rejected;
- container paths must be below `/data/`;
- profile mount grants reference only `mountId`;
- read-write is allowed only when the catalog entry explicitly permits it;
- the source must exist at runtime and cannot be a socket;
- evidence stores only the mount ID and requested access, never the host path.

## Brokered egress

Sandbox egress is proxy-only. A profile with `egressHosts` must also set:

```text
brokeredCredentials = true
```

UCS requires an Agent Vault credential handle at execution time. The requested host set must exactly match the handle's configured `allowedHosts` scope. A narrower egress policy therefore uses a narrower credential handle.

The Agent Vault session is short-lived. The upstream API credential still never enters UCS or the connector package.

Runtime configuration:

```text
UCS_AGENT_VAULT_CONFIG_JSON=...
UCS_MCP_SANDBOX_EGRESS_NETWORK=ucs-sandbox-egress
UCS_MCP_SANDBOX_EGRESS_PROXY_HOST=agent-vault-proxy
```

`UCS_MCP_SANDBOX_EGRESS_NETWORK` must already exist as a Docker **internal** network. UCS verifies `Internal=true` before starting a privileged-egress sandbox.

The Agent Vault proxy/gateway is operator-managed and must be reachable on that internal network under `UCS_MCP_SANDBOX_EGRESS_PROXY_HOST`. The sandbox itself has no direct Internet route.

At execution UCS injects only a short-lived proxy URL through `HTTP_PROXY` / `HTTPS_PROXY` and mounts the broker CA certificate from a temporary read-only directory. The proxy token and credential handle are never written to audit/evidence.

## Trusted execution

Validation/build still runs with the UCS-14 zero-capability sandbox. Approved mounts or egress are applied only to an already trusted connector during normal execution/health checks.

This separation prevents a package from asking for extra permissions as a prerequisite for becoming trusted.

The runtime connector passes `ExecutionContext` into the sandbox runner. If an active profile requires egress but the caller does not supply the approved opaque credential handle, execution fails with a credential error instead of opening unrestricted network access.

## Security invariants

- no capability is inferred from MCPB manifest fields;
- manifest environment variables do not become sandbox environment variables;
- no host path is supplied by a user request;
- network egress never switches to the ordinary Docker bridge;
- egress requires an operator-configured Docker internal network;
- outbound HTTP(S) is routed through Agent Vault;
- requested egress hosts must match credential binding scope exactly;
- raw approvals, credential handles and proxy session tokens are not persisted;
- profile changes require one-time approval;
- connector package signatures and UCS-11 trust promotion remain unchanged.

## Health

`GET /health` reports only aggregate state:

```json
{
  "packageSandbox": "docker+policy",
  "sandboxPolicy": "approved-profiles"
}
```

It does not expose mount paths, egress hosts, proxy tokens or credential bindings.

## Acceptance criteria

UCS-15 is ready when CI proves that:

1. a trusted sandbox connector can receive a version-scoped profile only after one-time approval;
2. approval replay is rejected;
3. changing the profile after approval produces scope mismatch;
4. mount catalog limits read-only vs read-write access;
5. host paths are absent from profile evidence;
6. raw profile approval IDs are absent from evidence;
7. Agent Vault sandbox egress requires the exact credential binding host set;
8. proxy host is rewritten to the internal-network alias without persisting the short-lived token;
9. egress requires an internal Docker network and never falls back to ordinary bridge networking;
10. zero-profile connectors retain `network=none` and no extra mounts;
11. UCS-02 through UCS-14 regressions remain green.

## Deferred

- managed creation of the internal egress network/gateway;
- non-HTTP egress protocols;
- per-tool profiles inside one connector;
- time-windowed profile activation/revocation;
- host directory snapshotting rather than live bind mounts;
- stronger mount isolation through dedicated volume drivers;
- gVisor/Kata/Firecracker execution backends;
- automatic policy generation from business intent;
- UI for reviewing profile diffs before approval.
