# UCS-11 - Agent Vault wiring for authenticated MCP validation

The UCS-11 control-plane MCP validation endpoint can validate discovered MCP servers that require authentication without exposing the upstream credential to the control-plane caller.

Configure the existing UCS-04 Agent Vault resolver through one server-side environment variable:

```text
UCS_AGENT_VAULT_CONFIG_JSON
```

The value must validate as `AgentVaultCredentialResolverConfig`, for example:

```json
{
  "address": "https://agent-vault.internal.example",
  "agentToken": "<server-side Agent Vault token>",
  "bindings": [
    {
      "handle": "weather-prod",
      "organizationId": "org-1",
      "serviceId": "weather",
      "vault": "weather-production",
      "allowedHosts": ["weather.example"]
    }
  ],
  "sessionTtlSeconds": 300
}
```

The raw Agent Vault token remains server-side. A control-plane validation request supplies only the opaque `credentialHandle`.

The validation flow is:

```text
candidateId
  -> server-side discovery match
  -> MCP endpoint / service scope
  -> credentialHandle
  -> AgentVaultCredentialResolver
  -> short-lived broker session
  -> MCP initialize + list_tools
  -> validated connector
```

The resolver still enforces organization, service and allowed-host scope. The control-plane route cannot substitute a different URL because it accepts only a `candidateId` that must be present in current server-side discovery results.

If `UCS_AGENT_VAULT_CONFIG_JSON` is absent, unauthenticated MCP candidates can still be validated, while candidates whose `authRequirement` is not `none` fail closed at the credential boundary.

`GET /health` reports only:

```json
{"credentialBroker": "agent_vault"}
```

or `disabled`. It does not expose Agent Vault addresses, tokens, bindings, handles or target hosts.
