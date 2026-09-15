# UCS-03 - OpenAPI Adapter + Automatic Validation

## Goal

Compile a valid OpenAPI document into a provider-neutral UCS connector candidate, validate it in a bounded sandbox, and promote it to `validated` only when both structural and dynamic contract checks pass.

UCS-03 does **not** make a generated connector trusted automatically.

```text
OpenAPI document
    -> structural validation
    -> operation discovery
    -> capability bindings
    -> generated connector
    -> sandboxed
    -> Schemathesis validation
    -> validated
    -> later approval / trust decision
```

## Capability discovery

For every supported HTTP operation UCS uses:

1. `x-ucs-capability` when explicitly present.
2. Otherwise `operationId` as the capability identifier.
3. Operations without `operationId` are skipped rather than guessed from URL semantics.

This prevents UCS from inventing business meaning from paths such as `/users/{id}`.

## Request contract

Generated OpenAPI connectors accept only these UCS input fields:

```json
{
  "path": {"record_id": "123"},
  "query": {"limit": 10},
  "body": {"name": "Ada"}
}
```

Raw request headers are intentionally not accepted. Credential/header injection remains the responsibility of the future `CredentialResolver` boundary.

## Authentication

The compiler inspects OpenAPI `security` and `components.securitySchemes` and normalizes discovered requirements to the existing UCS `AuthRequirement` types.

If an operation requires authentication and no externally supplied credential-aware client factory exists, execution fails closed with `CREDENTIAL_RESOLUTION_UNAVAILABLE`.

## Static validation

UCS uses `openapi-spec-validator` before generating bindings.

Remote `$ref` values are rejected in UCS-03. Local references such as `#/components/schemas/...` remain allowed. Remote reference resolution is deferred until UCS has a dedicated egress/SSRF policy.

## Dynamic validation

Dynamic contract validation uses Schemathesis. The validator runs a bounded set of:

- examples;
- coverage cases;
- fuzzing cases;
- server-error, status-code, and response-schema checks.

Stateful workflows are deliberately excluded from this foundation because they may chain write/destructive operations.

### Sandbox boundary

UCS-03 allows dynamic validation only against loopback targets:

- `localhost`
- `127.0.0.1`
- `::1`

A public or private remote API cannot accidentally become a fuzzing target. Broader sandbox networks require a later explicit egress policy.

No authentication headers, API keys, OAuth tokens, or credentials are accepted by the Schemathesis runner.

## Lifecycle

The validation service owns only this transition:

```text
generated -> sandboxed -> validated
```

A failed dynamic validation remains `sandboxed` so the candidate can be repaired and re-tested.

`validated` is not equivalent to `trusted`. Existing `ConnectorRegistry.trusted()` continues to return only explicitly trusted registrations.

## Dependencies

Install OpenAPI support with:

```bash
pip install -e '.[openapi]'
```

Current compatibility line:

- `openapi-spec-validator>=0.9,<1`
- `schemathesis>=4.27,<5`

## Deferred

- fetching arbitrary remote OpenAPI documents;
- DNS/IP-aware SSRF and network egress controls;
- CredentialResolver-backed authentication;
- automatic MCP/OpenAPI strategy comparison;
- persistent validation evidence and audit storage;
- stateful validation of write workflows;
- automatic approval/trust promotion;
- schema drift monitoring.

## Acceptance criteria

UCS-03 is ready when CI proves that:

1. A valid OpenAPI 3.1 schema compiles into capability bindings.
2. `x-ucs-capability` takes precedence over `operationId`.
3. An operation can execute through an in-process synthetic HTTP API.
4. Path values are encoded and request bodies are restricted to documented JSON operations.
5. Remote `$ref` values fail closed.
6. Authenticated operations cannot receive raw credentials through connector input.
7. Schemathesis validation is bounded and restricted to loopback sandbox targets.
8. Only a passing dynamic validation promotes a registration to `validated`.
9. A validated connector is still not implicitly trusted.
