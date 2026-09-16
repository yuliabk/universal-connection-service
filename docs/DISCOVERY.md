# UCS-09 - Connector Discovery + MCP Registry Ingestion

## Goal

Allow UCS planning to discover candidate connector implementations before falling back to building a new adapter.

The planning order is now:

```text
ConnectionRequest
    -> trusted runtime connector?
         yes -> use trusted connector
         no  -> discovery providers
                  -> MCP Registry candidate(s)
                  -> existing explicit API base URL
                  -> generated API adapter fallback
```

Discovery is **not execution** and does not grant trust.

## Official MCP Registry

UCS-09 consumes the official MCP Registry's read-only discovery API:

```text
https://registry.modelcontextprotocol.io/v0.1/servers
```

The provider sends bounded searches with:

- `search=<service name>`
- `version=latest`
- a configurable page size
- opaque cursor pagination using the exact `metadata.nextCursor` returned by the registry

The official registry is currently documented as preview. UCS therefore treats it as an optional discovery source, not as an availability dependency or source of trust.

The registry documentation also recommends that downstream aggregators avoid high-frequency per-user scraping. The UCS provider therefore keeps an in-process TTL cache, defaulting to one hour.

## Discovery data is untrusted

Registry metadata is never treated as executable authorization.

A discovered candidate can influence a **reviewable ConnectionPlan** only. It cannot:

- become `trusted`;
- execute a tool;
- receive credentials;
- bypass validation;
- bypass policy or approval;
- install an npm/PyPI/Docker package;
- modify persistent connector lifecycle state.

A discovered MCP endpoint must still pass later validation and trust gates before execution can ever occur.

## Remote MCP candidates

UCS accepts remote MCP discovery metadata for:

- `streamable-http`
- legacy `sse` as informational metadata only

Only `streamable-http` is actionable in UCS-09.

Remote endpoints must pass the same URL validation as the UCS MCP adapter:

- absolute HTTP(S) URL;
- remote endpoints require HTTPS;
- no embedded username/password;
- no query or fragment;
- unresolved URL templates are not auto-selected.

Header values and registry-provided secrets are never copied into a ConnectionPlan. If registry metadata indicates headers or variables are needed, the candidate's auth requirement is normalized to `other`, preserving the CredentialResolver boundary.

## Package-based MCP servers

The MCP Registry may point to npm, PyPI, OCI, MCPB and other package registries.

UCS-09 does **not** install or execute those packages automatically.

Package candidates are returned with:

- registry type;
- package identifier;
- exact package version;
- file SHA-256 when the registry supplies one;
- transport type when supplied;
- `requiresBuild=true`;
- `actionable=false`.

A later promotion path may fetch such a candidate into the UCS-08 signed-package and validation pipeline. Registry metadata alone is never sufficient to run package code.

## ConnectionPlan additions

`ConnectionPlan` now includes:

```text
discoveryCandidates[]
selectedDiscoveryCandidateId
requiresSelection
```

Each candidate contains only normalized metadata required for review:

```text
candidateId
source
name
version
strategy
transport
endpoint (remote candidate only)
packageRegistry / packageIdentifier / packageVersion / packageSha256
normalized auth requirement
confidence
requiresBuild
actionable
```

The candidate ID is deterministic and derived from source metadata.

## Selection behavior

UCS is deliberately conservative:

1. A trusted connector always wins. Discovery is not called.
2. One actionable remote candidate can be selected into the plan.
3. Multiple actionable candidates with an unambiguous higher-confidence match may select that one.
4. Equally plausible candidates set `requiresSelection=true` instead of guessing.
5. A single package-only candidate may be selected as a build candidate but remains non-actionable.
6. Discovery provider failures fall back to the pre-existing API/generation path.

A selected discovered candidate still has:

```text
connectorId = null
requiresValidation = true
policyDecision = REQUIRE_APPROVAL   # under the default policy for untrusted implementations
```

It is therefore impossible to execute merely because discovery found something.

## Planning-only network boundary

External discovery runs only when:

```python
compiler.compile(request, phase="plan")
```

It does **not** run for:

```python
compiler.compile(request, phase="execution")
```

This prevents a third-party registry response from changing the implementation chosen at the moment an action is being executed.

Execution still requires an already-loaded trusted connector from the runtime registry.

## Failure behavior

Discovery is fail-soft while execution remains fail-closed.

Examples:

- MCP Registry timeout -> continue to existing API/generation plan.
- malformed registry JSON -> ignore that provider result.
- unsafe remote endpoint -> skip candidate.
- ambiguous candidates -> require selection.
- package-only candidate -> no automatic install.
- no trusted runtime connector at execution -> `CONNECTION_UNAVAILABLE`.

## Evidence

When persistent evidence storage is configured, planning records a small discovery evidence item using the existing validation evidence channel:

```json
{
  "type": "discovery",
  "sources": ["mcp_registry"],
  "candidateIds": ["..."],
  "selectedCandidateId": "...",
  "requiresSelection": false
}
```

The evidence deliberately omits endpoint URLs, registry response bodies, package contents, request input and credentials.

## Runtime configuration

Discovery is opt-in because it creates outbound network traffic to a registry.

Enable the official MCP Registry provider with:

```bash
UCS_MCP_REGISTRY_ENABLED=true
```

Optional configuration:

```bash
UCS_MCP_REGISTRY_URL=https://registry.modelcontextprotocol.io
UCS_MCP_REGISTRY_TIMEOUT_SECONDS=4
UCS_MCP_REGISTRY_PAGE_SIZE=20
UCS_MCP_REGISTRY_MAX_PAGES=2
UCS_MCP_REGISTRY_CACHE_TTL_SECONDS=3600
```

`GET /health` reports:

```json
{
  "discovery": "mcp_registry"
}
```

or `disabled` when discovery is not configured.

## Acceptance criteria

UCS-09 is ready when CI proves that:

1. current wrapped MCP Registry responses are parsed correctly;
2. the provider uses `/v0.1/servers`, `version=latest` and exact opaque cursors;
3. repeated requests use the TTL cache;
4. unsafe remote endpoints are rejected;
5. package entries are discovery-only and are never installed;
6. a trusted runtime connector prevents any discovery call;
7. one safe remote candidate produces a reviewable MCP ConnectionPlan;
8. ambiguous candidates require explicit selection rather than guessing;
9. provider failure falls back to the existing generation path;
10. execution phase never calls an external discovery provider;
11. persistent discovery evidence contains only normalized candidate identifiers;
12. all UCS-02 through UCS-08 regression tests continue to pass.

## Deferred

- persistent full MCP Registry mirror / incremental `updated_since` sync;
- authenticated private registry providers;
- MCP Registry detail fetch and server health validation;
- tool-list introspection to map MCP tools to business capabilities;
- package candidate download into UCS-08 verification pipeline;
- OpenAPI document discovery with explicit SSRF/egress policy;
- local/private catalog provider;
- user/admin candidate selection API;
- reputation/security scanner signals;
- discovery metrics and OpenTelemetry spans.
