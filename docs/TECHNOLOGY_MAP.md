# Universal Connection Service - GitHub Technology Map

Date: 2026-09-15

## Purpose

This document maps mature and emerging GitHub projects that can accelerate Universal Connection Service (UCS) without weakening its provider-neutral architecture.

UCS should remain the control layer that turns a tenant-scoped `ConnectionRequest` into a reviewable `ConnectionPlan`, resolves or builds an implementation, applies policy and approval, resolves credentials only at the outbound boundary, executes through a replaceable adapter, normalizes the result, and records an audit identifier.

The goal is not to reimplement OAuth, MCP transports, API testing, browser automation, webhook delivery, secrets management, or connector ecosystems when reliable components already exist.

## Decision labels

- `USE` - strong candidate for direct dependency or integration.
- `ADAPT` - reuse concepts, APIs, patterns, or optional integration while preserving the UCS contract.
- `STUDY` - strategically important, but do not couple the core to it yet.
- `IGNORE` - overlapping or low-value for the current roadmap.

## Executive recommendation

The next UCS milestone should not be "add many hand-written connectors". It should be "make UCS able to consume, validate, govern, and execute connectors from multiple ecosystems".

Recommended control flow:

```text
ConnectionRequest
    -> ConnectionCompiler
    -> Capability / Connector Registry
    -> Strategy selection
         -> Native Connector
         -> MCP Adapter
         -> OpenAPI Adapter
         -> Browser Adapter
    -> Policy decision
    -> Approval verification when required
    -> CredentialResolver / broker
    -> Execute
    -> Normalize
    -> Audit / Trace
```

## Priority 1 - direct candidates

| Project | Decision | License | UCS role | Why it matters | Adoption note |
|---|---|---|---|---|---|
| [modelcontextprotocol/python-sdk](https://github.com/modelcontextprotocol/python-sdk) | USE | MIT | `MCPAdapter` transport and client | Official MCP Python SDK, current v2 line, supports stdio, Streamable HTTP and SSE, with compatibility across MCP revisions | Pin a tested v2 range. Do not implement MCP wire protocol in UCS |
| [Infisical/agent-vault](https://github.com/Infisical/agent-vault) | ADAPT / PoC | MIT for OSS portions, enterprise exceptions | Credential broker behind `credentialHandle` | Agents can call upstream APIs without seeing raw credentials. Strong match to the UCS outbound credential boundary | Add a `CredentialResolver` interface first so Agent Vault remains replaceable |
| [schemathesis/schemathesis](https://github.com/schemathesis/schemathesis) | USE | MIT | OpenAPI connector validation | Property-based API testing from OpenAPI/GraphQL schemas, useful for moving generated connectors from generated/sandboxed to validated | Use only in validation/sandbox path, not on every production call |
| [open-policy-agent/opa](https://github.com/open-policy-agent/opa) | ADAPT | Apache-2.0 | Policy engine | Mature default-deny policy engine suitable for `ALLOW`, `DENY`, `REQUIRE_APPROVAL` decisions | Keep a UCS `PolicyEngine` port so OPA is an implementation, not the business contract |
| [modelcontextprotocol/registry](https://github.com/modelcontextprotocol/registry) | ADAPT | Apache-2.0/MIT transition, docs CC-BY-4.0 | MCP discovery source | Official registry and metadata source for discovering MCP servers | Treat it as one discovery provider feeding the UCS registry, never as the UCS registry itself |
| [svix/svix-webhooks](https://github.com/svix/svix-webhooks) | ADAPT | MIT | Webhook delivery / event ingress patterns | Mature signing, retry, event delivery and webhook infrastructure | Useful when UCS adds asynchronous connectors and inbound event capabilities |

## Priority 2 - connector ecosystems to learn from or import through adapters

| Project | Decision | License | What to reuse | UCS implication |
|---|---|---|---|---|
| [ComposioHQ/composio](https://github.com/ComposioHQ/composio) | STUDY / optional adapter | MIT | Toolkit discovery, authentication UX, tool search, context management, sandbox patterns | Strong adjacent platform. Prefer adapter/integration over making UCS depend on its execution model |
| [activepieces/activepieces](https://github.com/activepieces/activepieces) | STUDY | MIT for core, enterprise directories have separate license | Connector packaging, actions/triggers, community integration structure | Excellent reference for small modular connector packages and capability metadata |
| [PipedreamHQ/pipedream](https://github.com/PipedreamHQ/pipedream) | STUDY | Mixed repository terms, verify per component before reuse | Large collection of app components, triggers, actions and event patterns | Useful as a catalog of real-world integration shapes. Avoid copying code without per-component license verification |
| [airbytehq/airbyte-python-cdk](https://github.com/airbytehq/airbyte-python-cdk) | STUDY | MIT for this CDK | Declarative connector manifests, connector builder, REST/GraphQL patterns | Very useful design reference for a future UCS low-code connector compiler |
| [n8n-io/n8n-nodes-starter](https://github.com/n8n-io/n8n-nodes-starter) | STUDY | MIT for starter | Node scaffolding, credentials separation, integration package ergonomics | Useful for developer experience and a future UCS connector SDK |

## Strategic watch - Airbyte Agent SDK

Repository: [airbytehq/airbyte-agent-sdk](https://github.com/airbytehq/airbyte-agent-sdk)

Decision: `STUDY`, not direct code reuse for the UCS hosted product without legal review.

License: Elastic License 2.0.

Why it matters:

- It provides a type-safe connector execution framework for 50+ third-party APIs.
- It exposes strongly typed entities/actions.
- Hosted mode manages credentials, token refresh, rate limiting and connector execution.
- It provides an `inspect -> read docs -> execute` progressive-discovery pattern for agents.
- It supports several agent frameworks and FastMCP.
- It uses organization/workspace boundaries for connector isolation.

This is the closest current adjacent architecture found in the scan.

### Where UCS must differentiate

Airbyte Agent SDK makes it clear that "typed connectors for many APIs" is not enough as the UCS product thesis.

UCS differentiation should be:

1. Protocol neutral - MCP, REST/OpenAPI, browser, database and native connectors behind one `ConnectorContract`.
2. Dynamic planning - compile a `ConnectionPlan` before execution instead of requiring a pre-existing connector.
3. Connector lifecycle - `discovered -> generated -> sandboxed -> validated -> awaiting_approval -> trusted`, with degraded/repairing/disabled states.
4. Build path for unknown services - unknown integrations can produce a build-and-validation plan rather than a hard product boundary.
5. Independent policy/approval plane - elevated-risk operations can require explicit approval regardless of transport/provider.
6. Opaque credential handles - credentials can be resolved only at the outbound execution boundary.
7. Multi-source discovery - official APIs, MCP Registry, local registry, generated adapters and controlled browser fallback.
8. Validation as a first-class gate - generated code does not become trusted merely because it executes once.

### What UCS should copy as a pattern, not as code

- Progressive capability discovery to keep agent context small.
- Typed entity/action schemas.
- Clear workspace/tenant isolation.
- Connector descriptions that are machine-readable and human-reviewable.
- Reliable execution wrappers that translate provider failures into stable typed errors.

## MCP gateway and governance references

| Project | Decision | License | Useful pattern |
|---|---|---|---|
| [agentic-community/mcp-gateway-registry](https://github.com/agentic-community/mcp-gateway-registry) | STUDY | Apache-2.0 | Central MCP gateway, registry, OAuth, discovery, governance and audit. Useful enterprise control-plane reference |
| [sparfenyuk/mcp-proxy](https://github.com/sparfenyuk/mcp-proxy) | ADAPT | Verify before production adoption | Transport bridge patterns between stdio/SSE/HTTP | Could sit below `MCPAdapter`; UCS should not expose it as a core abstraction |
| [Samuel-Mencke/mcp-gateway](https://github.com/Samuel-Mencke/mcp-gateway) | STUDY | Verify before reuse | Aggregated MCP endpoint, registry provisioning, OAuth2 PKCE and workflow ideas | Useful prototype ideas, but less mature than official/community governance projects |

## Browser fallback

| Project | Decision | License | UCS role | Guardrails |
|---|---|---|---|---|
| [browser-use/browser-use](https://github.com/browser-use/browser-use) | ADAPT | MIT | Controlled `BrowserAdapter` for services without usable APIs | Browser must remain last-resort, policy-gated, domain-restricted, time-limited and fully audited |
| [open-browser-use/open-browser-use](https://github.com/open-browser-use/open-browser-use) | STUDY | Verify before reuse | Control of an already-authenticated local browser through an agent/MCP pattern | Interesting for local desktop mode, but has a larger trust boundary than server-side connectors |

Browser automation must never become the default strategy when a trusted connector, official API, OAuth integration, or MCP implementation exists.

## Credential and secret patterns

### Recommended UCS interface

```python
class CredentialResolver(Protocol):
    async def resolve_for_request(
        self,
        *,
        credential_handle: str,
        service_id: str,
        capability: str,
        actor: ActorRef,
        target: str,
    ) -> ResolvedCredentialLease: ...
```

Requirements:

- `ConnectionRequest`, `ConnectionPlan`, connector manifests and audit summaries must never contain raw secrets.
- Resolution occurs immediately before an allowed outbound call.
- Leases should be scoped by tenant, actor, service, capability and destination.
- Secret values must be excluded from exception messages, traces and model-visible output.
- Credential backends must remain replaceable: Agent Vault, cloud vaults, local development resolver, enterprise secret stores.

Additional projects worth watching:

- [IchenDEV/passka](https://github.com/IchenDEV/passka) - local lease broker and proxy pattern for agent credentials.
- [ikkun1222/trustless](https://github.com/ikkun1222/trustless) - local credential injection, DLP and structured audit ideas.

Use these as threat-model references before adding dependencies.

## OpenAPI connector compiler path

Recommended generated adapter flow:

```text
OpenAPI document / API endpoint
    -> schema normalization
    -> endpoint and auth discovery
    -> capability candidates
    -> generated UCS connector manifest
    -> generated adapter
    -> sandbox
    -> Schemathesis validation
    -> UCS contract tests
    -> security checks
    -> approval if required
    -> trusted registry entry
```

Important implementation rules:

- Do not execute arbitrary schema-provided URLs without SSRF controls.
- Resolve and pin allowed upstream origins before execution.
- Reject schema drift that changes sensitive auth/host/security assumptions until revalidated.
- Generate the smallest adapter possible around the existing `ConnectorContract`.
- Generated code starts untrusted.
- Network access in validation must be explicitly scoped.

## Connector registry evolution

The current in-memory registry should evolve into a tenant-aware registry with separate connector identity, version, trust and deployment state.

Suggested metadata:

```text
ConnectorRecord
  connector_id
  service_id
  version
  strategy
  capabilities[]
  auth_requirement
  source
  package_digest
  signature
  lifecycle
  trust_level
  schema_digest
  allowed_origins[]
  created_at
  validated_at
  approved_at
  disabled_at
```

Discovery sources can include:

- UCS native packages.
- MCP Registry.
- Tenant-private MCP servers.
- Imported OpenAPI documents.
- Generated API adapters.
- Optional third-party connector ecosystems.

Registry resolution must remain deterministic and fail closed when more than one trusted candidate is ambiguous.

## Supply chain

Project: [sigstore/cosign](https://github.com/sigstore/cosign)

Decision: `ADAPT` for a later milestone.

Use it when UCS starts distributing or dynamically loading connector packages.

Target lifecycle:

```text
build connector
  -> test
  -> generate SBOM/provenance
  -> sign artifact
  -> store digest + signature metadata
  -> verify before install/load
  -> execute only verified package
```

This is not required for the current alpha, but connector signing should be part of the data model before public dynamic connector installation.

## Observability

Project: [open-telemetry/opentelemetry-collector](https://github.com/open-telemetry/opentelemetry-collector)

Decision: `ADAPT`.

UCS should emit provider-neutral telemetry for:

- request ID and audit ID;
- tenant and actor references using safe identifiers;
- selected strategy and connector version;
- plan/execute latency;
- policy decision and approval requirement;
- retries and rate-limit events;
- validation state;
- normalized error code;
- upstream host, when safe;
- credential handle identifier or class, never secret material.

Tracing must not leak request bodies or provider responses by default.

## Webhooks and asynchronous connectors

Project: [svix/svix-webhooks](https://github.com/svix/svix-webhooks)

Decision: `ADAPT` or managed integration later.

Useful capabilities:

- signatures;
- retries;
- delivery tracking;
- endpoint management;
- event replay;
- queue-backed delivery.

UCS should add asynchronous/event connectors only after synchronous connector execution, auth, policy and audit are stable.

## Projects not to make core dependencies

### Nango

Repository: [NangoHQ/nango](https://github.com/NangoHQ/nango)

Decision: `ADAPT / optional provider`.

Strengths:

- OAuth/API-key auth and token refresh across 900+ APIs.
- Multi-tenant connection management.
- Authenticated proxy and production integration runtime.
- Strong evidence of production maturity.

Constraint:

- Current repository is under Elastic License terms and hosted/enterprise functionality varies by plan.

Recommendation:

Define a `ConnectionAuthProvider` / `CredentialResolver` boundary that can use Nango without making the UCS contract or business model depend on Nango.

### n8n

Decision: `STUDY`, not a core dependency.

It solves workflow automation. UCS solves connection resolution and governed capability execution. Its node ecosystem is useful as prior art for package ergonomics, but importing its workflow runtime would blur the UCS boundary.

### Full integration platforms

Do not embed Activepieces, Pipedream, Composio, Airbyte or n8n as the UCS runtime. They are sources of connectors, patterns or optional adapters. UCS remains the stable provider-neutral contract above them.

## Recommended next PRs

### UCS-02 - MCP Adapter Foundation

Goal: execute trusted MCP capabilities through the existing `ConnectorContract`.

Scope:

- add official `mcp` Python SDK dependency;
- implement `MCPConnectorAdapter`;
- support Streamable HTTP first;
- add stdio only for trusted/local deployments;
- map MCP tool metadata to UCS capability metadata;
- normalize MCP failures into `ConnectionError`;
- add strict timeouts and maximum response size;
- no raw secrets in MCP configuration;
- contract tests with a synthetic MCP server.

Definition of Done:

- trusted MCP connector lists and executes a read capability;
- unknown tool fails closed;
- timeout and malformed response return typed errors;
- write operation still follows UCS approval rules;
- tenant context is preserved through execution;
- test fixture contains no network dependency.

### UCS-03 - OpenAPI Adapter and Validation PoC

Goal: prove UCS can consume an unknown OpenAPI service and produce a safe candidate connector.

Scope:

- OpenAPI 3.x parser;
- origin/SSRF guard;
- endpoint/auth extraction;
- generate `ConnectorManifest` candidate;
- generate or interpret a minimal adapter;
- sandbox execution;
- Schemathesis validation;
- schema digest stored in validation evidence;
- lifecycle transition only on successful validation.

Definition of Done:

- one synthetic API can be discovered from OpenAPI and executed through `ConnectorContract`;
- invalid schema cannot execute;
- changed security scheme requires revalidation;
- untrusted generated connector cannot be marked trusted automatically;
- test suite proves fail-closed behavior.

### UCS-04 - CredentialResolver and Agent Vault PoC

Goal: remove credential implementation details from connectors.

Scope:

- introduce `CredentialResolver` interface;
- development no-secret/fake resolver for tests;
- Agent Vault experimental backend;
- outbound lease resolution;
- secret-redaction tests;
- audit metadata without secret values.

Definition of Done:

- connector receives usable authorization at the outbound boundary without raw credentials appearing in plan/result/audit;
- cross-tenant credential handle reuse fails;
- wrong service/capability scope fails;
- failed resolver returns a typed, non-secret-bearing error;
- tests prove model-visible data never contains the secret fixture.

### UCS-05 - Policy Decision Port

Goal: replace hard-coded `write => approval` logic with a stable policy contract.

Scope:

- `PolicyDecision = ALLOW | DENY | REQUIRE_APPROVAL`;
- default local policy preserving current behavior;
- optional OPA implementation;
- policy input includes actor, tenant, service, capability, operation, connector trust and risk facts;
- policy explanation is safe and does not leak secrets.

Definition of Done:

- read can be auto-allowed by policy;
- write can require approval;
- destructive, financial and permission-increasing operations can be denied or approval-gated;
- policy failure is fail-closed;
- no connector can bypass policy by transport choice.

## Suggested order

1. UCS-02 MCP Adapter Foundation.
2. UCS-03 OpenAPI Adapter and Validation PoC.
3. UCS-04 CredentialResolver and Agent Vault PoC.
4. UCS-05 Policy Decision Port.
5. Persistent registry and audit storage.
6. Signed connector packages and provenance.
7. Browser fallback.
8. Webhook/event connectors.

MCP and OpenAPI come first because they demonstrate the main UCS thesis: one stable connection contract can govern different protocols without callers knowing the implementation.

## Architecture guardrails

The following remain non-negotiable:

- provider-neutral core;
- tenant isolation;
- default-deny behavior;
- opaque credential handles;
- explicit typed errors;
- approval for risk increases;
- auditable lifecycle transitions;
- adapters remain replaceable;
- no raw credentials in manifests, plans, logs or model-visible results;
- generated code is untrusted until validated;
- browser automation is a fallback, not a primary connector strategy;
- external platforms are optional implementations, never the UCS public contract.

## Revisit cadence

Repeat this GitHub scan before each major UCS milestone and specifically watch:

- MCP specification and official SDK changes;
- MCP Registry metadata and authentication changes;
- Airbyte Agent SDK connector/permission architecture;
- Nango licensing and auth platform changes;
- Agent Vault production maturity;
- new open-source policy/approval engines built specifically for agents;
- OpenAPI-to-tool compiler projects;
- connector package signing and provenance standards.
