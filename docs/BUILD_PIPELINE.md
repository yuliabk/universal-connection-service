# UCS-13 - Automatic Connector Build Pipeline

## Goal

UCS-12 stops at `awaiting_build` when discovery finds an implementation that is not yet a validated runtime connector. UCS-13 turns that state into an actual governed build step.

The initial automatic build paths are intentionally asymmetric:

```text
Pinned OpenAPI catalog candidate
    -> fetch exact schema
    -> verify SHA-256
    -> compile OpenAPI adapter
    -> sandbox validation
    -> package generated connector
    -> Ed25519 sign
    -> verify package through UCS-08 loader
    -> validated
    -> normal UCS-11 approval/promotion
    -> package pin
    -> trusted + restart rehydration

MCP Registry package candidate
    -> acquire package only when integrity rules are sufficient
    -> verify package hash
    -> store digest-addressed build input
    -> STOP before local code execution
    -> sandbox runner required
```

UCS-13 does not turn package discovery into arbitrary remote code execution.

## OpenAPI catalog

Automatic OpenAPI builds are not allowed to take an arbitrary schema URL from a user request. Operators configure a server-side catalog through:

```text
UCS_OPENAPI_CATALOG_JSON
```

Each entry contains:

```json
{
  "serviceId": "records",
  "serviceName": "Records",
  "version": "1.0.0",
  "schemaUrl": "https://records.example/openapi.json",
  "schemaSha256": "<64 hex characters>",
  "baseUrl": "https://records.example",
  "sandboxUrl": "http://127.0.0.1:9001",
  "authRequirement": {"type": "none", "scopes": []}
}
```

Security rules:

- `schemaUrl` and `baseUrl` must use HTTPS;
- they must use the same host in UCS-13;
- credentials, query strings and fragments are rejected;
- the OpenAPI document must match the configured SHA-256 exactly;
- document size is bounded;
- remote `$ref` remains rejected by the existing OpenAPI compiler;
- dynamic validation still uses the UCS-03 loopback sandbox restriction.

The catalog provider also participates in normal discovery. It returns an `openapi` candidate with `requiresBuild=true`, but the public candidate does not contain the schema document or signing material.

## Generated OpenAPI package

After validation passes, UCS creates a small deterministic connector package containing:

- `ucs-package.json`;
- a generated `connector.py` factory;
- the already-compiled `OpenAPIConnectorConfig`.

The package does not contain request data or credentials.

The archive is SHA-256 addressed and signed with Ed25519. Runtime configuration:

```text
UCS_CONNECTOR_PACKAGE_DIR
UCS_PACKAGE_VERIFIER=ed25519
UCS_PACKAGE_ED25519_SIGNING_KEY=<base64 raw 32-byte private key>
UCS_PACKAGE_SIGNER_REF=ucs-local-builder
```

`UCS_PACKAGE_ED25519_KEYS_JSON` may still be supplied explicitly. If it is omitted while a build signing key is configured, UCS derives the matching public key in memory for verification.

The private signing key is never persisted into connector packages, evidence or workflow state.

## Verification before promotion

A generated package is not accepted merely because the same process created it.

`VerifiedBuildCoordinator` loads the artifact again through the existing UCS-08 `ConnectorPackageLoader` and verifies:

1. archive SHA-256;
2. Ed25519 signature and trusted signer;
3. signed package manifest;
4. runtime manifest equality with the validated connector.

Only then does Auto-Connect advance from `awaiting_build` to `awaiting_promotion_approval`.

The connector is still only `validated`. UCS-13 never promotes it directly to `trusted`.

## Promotion and package pinning

The normal UCS-11 flow remains authoritative:

```text
validated
  -> promotion approval
  -> awaiting_approval
  -> approval consume
  -> trusted
```

After promotion succeeds, the build-aware orchestrator finds the verified generated package evidence and calls the existing `ConnectorPackagePinService`.

This creates the same `package_verification` evidence consumed by UCS-08 runtime rehydration.

Therefore a connector built automatically in UCS-13 can survive restart only after:

```text
build -> validation -> signed package verification -> human promotion -> package pin
```

## Credential binding after restart

Signed packages contain connector configuration, not credential broker objects.

UCS-13 extends runtime rehydration with an optional dependency binder. The application reconstructs OpenAPI or MCP adapters with the configured `CredentialResolver` after the signed package has already passed verification. The binder is required to preserve brokered authentication across restart without serializing secrets into packages.

The binder must not change the connector manifest. Rehydration fails closed if it does.

## MCP package acquisition

The official MCP Registry currently permits package types including npm, PyPI, Cargo, OCI, NuGet and MCPB. Registry metadata also defines `fileSha256`; it is required for MCPB and optional for several other package types.

UCS-13 automatically acquires only the conservative MCPB case:

- registry type must be `mcpb`;
- identifier must be a direct HTTPS URL;
- `fileSha256` must be present;
- redirects are disabled;
- download size is bounded;
- downloaded bytes must match the SHA-256 exactly.

Optional persistent build-input storage is configured through:

```text
UCS_BUILD_ARTIFACT_DIR
```

The artifact is stored only by digest-derived filename.

Even after successful acquisition, the workflow remains blocked with:

```text
MCP_PACKAGE_SANDBOX_REQUIRED
```

UCS-13 never imports, extracts, starts or executes the MCPB package.

Other package registries return:

```text
MCP_PACKAGE_REGISTRY_SANDBOX_REQUIRED
```

until a dedicated resolver + sandbox runner exists.

## Auto-Connect integration

The existing Auto-Connect route does not change. When a selected candidate would previously stop at `awaiting_build`, the build-aware orchestrator now attempts the governed build automatically.

The principal must still have:

```text
connectors:validate
```

for the organization. UCS-13 treats build as part of the validation trust gate rather than introducing a super-scope that could bypass UCS-11.

Successful OpenAPI build:

```text
awaiting_build
 -> OPENAPI_CONNECTOR_BUILT
 -> awaiting_promotion_approval
```

Examples of safe blocking results:

```text
OPENAPI_SANDBOX_REQUIRED
PACKAGE_SIGNER_REQUIRED
PACKAGE_VERIFIER_REQUIRED
OPENAPI_SCHEMA_DIGEST_MISMATCH
MCP_PACKAGE_SANDBOX_REQUIRED
MCP_PACKAGE_REGISTRY_SANDBOX_REQUIRED
```

## Health

`GET /health` now reports build/package capability at an aggregate level only:

```json
{
  "autoConnect": "persistent+build",
  "buildPipeline": "openapi+package-acquisition",
  "packageVerifier": "ed25519"
}
```

No catalog URLs, hashes, signer keys, credential bindings or artifact paths are returned.

## Acceptance criteria

UCS-13 is ready when CI proves that:

1. a matching server-side OpenAPI catalog entry becomes a discovery candidate;
2. the fetched OpenAPI bytes must match the pinned SHA-256;
3. the generated connector reaches `validated` only after sandbox validation passes;
4. generated connector packages are Ed25519 signed;
5. packages are reloaded and verified before Auto-Connect advances;
6. validation/build evidence does not contain the raw OpenAPI schema URL or request input;
7. human promotion remains mandatory;
8. successful promotion pins the signed package for UCS-08 rehydration;
9. rehydration can reconstruct the trusted generated connector;
10. MCPB acquisition validates `fileSha256` and does not execute package code;
11. other MCP package registries remain blocked pending a sandbox resolver;
12. all UCS-02 through UCS-12 regression tests remain green.

## Deferred

- local process sandbox for stdio MCP packages;
- npm/PyPI/Cargo/OCI/NuGet package resolver implementations;
- automatic container/image sandboxing;
- build worker queue and long-running build jobs;
- keyless Sigstore signing for generated packages;
- operator UI for OpenAPI catalog management;
- automatic creation of a loopback API sandbox from an external staging environment;
- signed build attestations/SBOM/provenance beyond the current package signature and evidence records.
