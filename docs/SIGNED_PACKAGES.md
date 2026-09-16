# UCS-08 - Signed Connector Packages + Runtime Rehydration

## Goal

UCS-06/07 persist connector metadata and lifecycle across restarts, but deliberately do not deserialize executable Python objects. UCS-08 closes that gap by loading executable connector implementations only from cryptographically verified, digest-addressed packages.

```text
Persistent connector metadata (trusted)
        +
Pinned package digest evidence
        +
Digest-addressed package archive
        +
Trusted signer verification
        |
        v
Package manifest match
        |
        v
Import entrypoint
        |
        v
ConnectorContract match
        |
        v
Runtime registry
```

A connector that is present in persistent metadata but cannot pass every package gate remains unavailable for execution.

## Trust model

Signing and UCS lifecycle trust are separate controls.

A valid signature proves that the package bytes were signed by a configured signer and were not modified after signing. It does **not** prove that the code is safe or that UCS should trust the connector.

UCS therefore requires all of the following before runtime loading:

1. persistent connector lifecycle is `trusted`;
2. an immutable package digest is pinned in persistent evidence;
3. package bytes hash to that SHA-256 digest;
4. the cryptographic signature is valid;
5. signer identity/key is configured as trusted by the deployment;
6. the signed package manifest exactly matches persistent trusted connector metadata;
7. the runtime object returned by the entrypoint exactly matches the signed package manifest;
8. the runtime object implements `ConnectorContract`.

Failure at any gate is fail-closed.

## Package layout

UCS packages are ZIP archives addressed by SHA-256 digest.

Required files:

```text
ucs-package.json
connector.py   # or another Python module referenced by entrypoint
```

`ucs-package.json` example:

```json
{
  "formatVersion": 1,
  "connector": {
    "connectorId": "records-api",
    "serviceId": "records",
    "name": "Records API",
    "version": "1.0.0",
    "strategy": "api",
    "capabilities": ["records.read"],
    "auth": {"type": "none", "scopes": []}
  },
  "entrypoint": "connector:build"
}
```

The entrypoint factory must return an object implementing `ConnectorContract`.

The package loader currently permits only `.py` and `.json` files, rejects absolute paths, parent traversal, symlinks, oversized members, oversized archives and excessive file counts. Native extensions are not supported.

Packages are read directly from ZIP bytes; UCS does not extract package members into an execution directory.

## Digest-addressed filesystem source

The reference package source uses:

```text
<UCS_CONNECTOR_PACKAGE_DIR>/
    <sha256>.zip
    <sha256>.sig.json
```

Package paths are derived only from validated hexadecimal digests. Persistent metadata cannot provide an arbitrary filesystem path.

## Ed25519 verification

The built-in verifier supports Ed25519 signatures over the complete ZIP archive.

Sidecar example:

```json
{
  "scheme": "ed25519",
  "signerRef": "production-release-key",
  "signature": "<base64 signature>"
}
```

Deployment configuration supplies a map from `signerRef` to trusted base64-encoded raw Ed25519 public keys.

```bash
UCS_PACKAGE_VERIFIER=ed25519
UCS_PACKAGE_ED25519_KEYS_JSON='{"production-release-key":"<base64 raw public key>"}'
```

Private signing keys never belong in the UCS runtime.

## Sigstore / Cosign verification

UCS also includes an optional `CosignBundleVerifier`.

Sigstore's current blob workflow uses `cosign sign-blob` with a bundle, and verification uses `cosign verify-blob` with the bundle plus an expected certificate identity and OIDC issuer. Current Cosign v3 documentation recommends bundle-based signatures.

The UCS signature sidecar stores the Sigstore bundle under `bundle` and the expected signer identity under `signerRef`. The actual trusted identity and issuer come from deployment configuration, not package-controlled metadata.

Example runtime configuration:

```bash
UCS_PACKAGE_VERIFIER=sigstore
UCS_PACKAGE_SIGSTORE_IDENTITY='release-bot@example.com'
UCS_PACKAGE_SIGSTORE_ISSUER='https://accounts.example.com'
UCS_COSIGN_EXECUTABLE=cosign
```

Cosign must be installed and independently trusted on the runtime image when this verifier is selected.

## Package pinning

Package pinning is a control-plane action, not a public execution endpoint.

`ConnectorPackagePinService`:

1. requires the connector registration to already be `trusted`;
2. retrieves the package by digest;
3. verifies digest and signature;
4. validates package layout and manifest;
5. loads the signed entrypoint and verifies the runtime manifest;
6. compares the package manifest with the trusted registration;
7. writes persistent validation evidence containing the immutable digest, connector version and signer reference.

The raw package bytes and signing key are not copied into audit/evidence storage.

The package pin is stored using the existing EvidenceStore as `kind=validation`, with `payload.type=package_verification`. This avoids a database schema change solely for package metadata while keeping the digest persistent in both SQLite and PostgreSQL backends.

## Runtime rehydration

At startup, when package rehydration is configured, `ConnectorRuntimeRehydrator`:

1. reads persistent connector state;
2. skips non-trusted connectors;
3. locates the pinned package digest evidence for the exact organization, connector ID and version;
4. fails closed if no pin exists or multiple distinct digests are pinned to the same immutable connector version;
5. re-fetches and re-verifies the signed package;
6. compares its manifest to persistent trusted metadata;
7. imports the entrypoint only after verification;
8. registers the reconstructed runtime connector.

Every attempt records validation evidence with `payload.type=package_rehydration` and a normalized result code.

## Application configuration

Rehydration is enabled when all of these exist:

- persistent state store (`UCS_DATABASE_URL` or `UCS_STATE_DB_PATH`);
- `UCS_CONNECTOR_PACKAGE_DIR`;
- verifier-specific trust configuration.

When no package directory is configured, startup behavior remains unchanged.

`GET /health` includes only aggregate package status:

```json
{
  "packages": {
    "loaded": 3,
    "skipped": 1,
    "failed": 0
  }
}
```

It does not reveal filesystem paths, public-key configuration, signer secrets or package contents.

## Security boundaries

- package verification happens before code import;
- package digest is SHA-256 and immutable for a pinned connector version;
- signer trust comes from deployment configuration;
- raw signing private keys are never needed by UCS runtime;
- ZIP path traversal and symlinks are rejected;
- native extension loading is not supported by the package format;
- persistent `trusted` metadata alone is insufficient to execute after restart;
- a valid signature alone is insufficient to grant connector trust;
- manifest mismatch fails closed;
- package verification failures do not load the connector;
- package code is trusted code after all gates pass; UCS-08 is not a sandbox for malicious signed code.

## Supply-chain direction

Sigstore/Cosign remains an optional verifier behind the same package-verifier contract. This lets deployments use:

- built-in Ed25519 for offline/private release pipelines;
- Sigstore keyless identity verification and transparency-log evidence;
- a future enterprise KMS/PKI verifier without changing the package loader or registry.

A later supply-chain milestone can add SBOM/provenance attestations and policy requirements around builder identity.

## Acceptance criteria

UCS-08 is ready when CI proves that:

1. a correctly signed package loads and executes through `ConnectorContract`;
2. modified package bytes fail digest verification before import;
3. an untrusted signer is rejected;
4. unsafe ZIP members are rejected;
5. only `trusted` persistent connector metadata can pin executable packages;
6. trusted metadata plus a pinned valid package rehydrates into a new runtime registry after restart;
7. signed package manifest must match persistent trusted metadata exactly;
8. rehydration evidence is persisted;
9. all UCS-02 through UCS-07 regression tests continue to pass.

## Deferred

- remote object-store / OCI package source;
- authenticated package upload/admin API;
- package revocation list;
- signer/key rotation workflow;
- Sigstore verification inside CI with a real OIDC identity;
- SBOM and in-toto/SLSA provenance requirements;
- package dependency vendoring or isolated virtual environments;
- OS/process sandboxing for third-party connector code;
- native/WASM connector package format.
