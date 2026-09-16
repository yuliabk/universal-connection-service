# UCS-04 - CredentialResolver + Secure Credential Broker

## Goal

Allow authenticated MCP and OpenAPI connectors to use credentials without returning upstream secret values to the agent, `ConnectionPlan`, connector input, logs, or normalized results.

UCS treats `ExecutionContext.credentialHandle` as an opaque selector. It is not an API key or OAuth token.

```text
ConnectionRequest
      -> ConnectionPlan
      -> trusted connector
      -> credentialHandle
      -> CredentialResolver
      -> brokered outbound transport
      -> upstream service
```

The `CredentialResolver` contract returns a context-managed outbound client/transport. It never returns credential material.

## Provider-neutral contract

`CredentialTarget` contains only:

- transport kind (`http` or `mcp`);
- service identifier;
- target URL;
- normalized `AuthRequirement`.

The resolver also receives the existing `ExecutionContext`, including tenant identity and the opaque credential handle.

A resolver implementation must fail closed when the handle is missing, belongs to another organization, is scoped to another service, or is not authorized for the target host.

## Agent Vault implementation

UCS-04 includes an optional `AgentVaultCredentialResolver` based on the current Agent Vault HTTP API and MITM proxy model.

For a matching tenant-scoped binding it:

1. authenticates to the Agent Vault control plane with a server-side agent token;
2. mints a short-lived vault-scoped session through `POST /v1/sessions`;
3. reads the Agent Vault MITM CA from `GET /v1/mitm/ca.pem`;
4. builds a proxy URL from the short-lived session token and vault name;
5. creates an outbound HTTP or MCP transport through that proxy;
6. discards the transport/session context after the connector call.

The real upstream API credential stays inside Agent Vault and is attached at the outbound proxy boundary.

## Security boundaries

- `credentialHandle` is stored as `SecretStr` and must not be logged.
- Agent Vault control-plane tokens are stored as `SecretStr` and are never used as upstream API credentials.
- Bindings are organization-scoped and service-scoped.
- Every Agent Vault binding has an explicit host allow-list.
- Remote Agent Vault management endpoints require HTTPS. Plain HTTP is permitted only on loopback for development.
- Agent Vault session tokens are short-lived and exist only inside the resolver execution boundary.
- Resolver errors are normalized to safe UCS error codes/messages; broker response bodies are not surfaced.
- OpenAPI connector inputs still reject raw headers.
- MCP and OpenAPI remain replaceable adapters behind the same `ConnectorContract`.

## Adapter behavior

Authenticated OpenAPI or MCP execution now follows this order:

1. an explicitly injected test/custom client factory, when present;
2. otherwise a configured `CredentialResolver` plus `credentialHandle`;
3. otherwise fail closed.

Unauthenticated connectors continue to work directly without a resolver.

## Error codes

- `CREDENTIAL_HANDLE_REQUIRED` - authenticated operation has no opaque handle.
- `CREDENTIAL_HANDLE_INVALID` - handle is unavailable in this organization.
- `CREDENTIAL_SCOPE_DENIED` - handle is not scoped to the requested service.
- `CREDENTIAL_TARGET_DENIED` - target host is outside the binding allow-list.
- `CREDENTIAL_RESOLUTION_UNAVAILABLE` - connector has auth requirements but no resolver.
- `CREDENTIAL_BROKER_UNAVAILABLE` - Agent Vault control plane or MITM proxy is unavailable.
- `CREDENTIAL_BROKER_INVALID_RESPONSE` - broker returned unusable session/CA metadata.
- `CREDENTIAL_TRANSPORT_UNAVAILABLE` - required protocol transport support is not installed.

## Acceptance criteria

UCS-04 is ready when CI proves that:

1. authenticated OpenAPI execution uses a resolver without accepting raw credentials in input;
2. authenticated MCP execution uses a resolver;
3. missing credential handles fail closed;
4. tenant, service, and host scope violations fail before outbound network access;
5. sensitive handle and control-plane token values are masked in model representations;
6. the Agent Vault integration mints a short-lived session using the documented control-plane API;
7. the broker session token is used only to configure the proxy and is not confused with the upstream credential;
8. all UCS-02 and UCS-03 tests continue to pass.

## Deferred

- persistent credential-binding storage;
- automatic Agent Vault service/proposal creation;
- OAuth consent UI and callback flow;
- rotating the UCS-to-broker control-plane credential;
- persistent broker/session audit evidence;
- egress enforcement at the network/firewall layer;
- production deployment of Agent Vault or Infisical Agent Proxy;
- retry/caching policy for short-lived broker sessions.
