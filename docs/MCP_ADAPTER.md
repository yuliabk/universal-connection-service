# UCS-02 - MCP Adapter Foundation

## Scope

UCS-02 adds an MCP implementation behind the existing `ConnectorContract` without making MCP part of the UCS core contract.

The adapter maps stable UCS capabilities to MCP tool names:

```text
ConnectionRequest(capability="records.read")
    -> trusted MCPConnectorAdapter
    -> MCP tool "echo" / provider-specific tool
    -> normalized ConnectorResult
    -> ConnectionResult + auditId
```

## Dependency

MCP support is optional for consumers of the package:

```bash
pip install -e '.[mcp]'
```

Development installs include MCP so the synthetic in-process tests run in CI.

The supported SDK line is `mcp>=2,<3`. UCS uses the official v2 `Client` abstraction and does not implement the MCP wire protocol.

## Security boundaries

- Connector configuration never accepts raw credentials.
- Endpoint URLs reject embedded credentials, query strings and fragments.
- Remote HTTP endpoints are rejected; remote endpoints must use HTTPS.
- Plain HTTP is allowed only for loopback development endpoints.
- Authenticated MCP transports are not assembled directly by the adapter. They require a future `CredentialResolver`-backed client factory.
- Unknown capabilities fail closed.
- Tool errors are normalized and do not expose provider exception text.
- Execution honors the UCS `deadlineMs` boundary.
- MCP remains a replaceable adapter. The core contracts, registry and service do not import MCP.

## Supported in this foundation

- Streamable HTTP through the official MCP v2 client.
- In-process MCP server injection for deterministic tests.
- Capability-to-tool binding.
- MCP tool discovery in `health_check`.
- Structured MCP tool result normalization.
- UCS error normalization for unavailable capabilities, tool errors, timeouts and transport failures.
- End-to-end execution through a trusted `ConnectorRegistry` registration.

## Intentionally deferred

- CredentialResolver and OAuth/header injection.
- stdio subprocess execution policy and command allow-listing.
- MCP Registry discovery and automatic connector registration.
- SSRF/network egress policy beyond the URL-level baseline in this adapter.
- Persistent connector registry and lifecycle promotion evidence.
- OpenTelemetry spans and persistent audit storage.

These remain separate milestones so MCP transport code cannot become an alternate path around UCS policy, approval or credential controls.

## Acceptance criteria

UCS-02 is ready when CI proves all of the following:

1. A synthetic MCP server is reachable in-process with no network dependency.
2. `health_check` verifies that every configured MCP tool exists.
3. A mapped capability returns structured data through `MCPConnectorAdapter`.
4. An unknown capability fails closed.
5. An MCP tool failure is normalized without leaking the underlying exception.
6. A trusted MCP connector executes successfully through the existing `ConnectionService` and returns an `auditId`.
