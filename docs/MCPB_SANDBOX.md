# UCS-14 - Isolated MCPB Package Sandbox Runner

## Goal

UCS-13 can acquire an MCPB package by an exact registry SHA-256, but deliberately stops before executing it. UCS-14 adds the missing execution boundary for local/stdio MCP packages.

```text
MCP Registry package candidate
    -> HTTPS acquisition
    -> exact SHA-256 verification
    -> digest-addressed MCPB artifact
    -> archive + manifest validation
    -> isolated Docker stdio runtime
    -> list_tools only
    -> capability mapping
    -> sandbox health check
    -> validated connector
    -> signed UCS connector package
    -> UCS-11 promotion approval
    -> trusted
    -> execution remains inside the sandbox
```

Discovery, package integrity and sandbox validation do not grant trust. The existing human promotion gate remains authoritative.

## MCPB format

UCS-14 treats MCPB as an untrusted ZIP archive containing `manifest.json` and a local MCP server. The parser accepts the current MCPB server metadata needed to select a runtime, but it does not execute `mcp_config.command` supplied by the bundle.

The sandbox derives its own command from `server.type` and `server.entry_point`:

- `python` -> configured Python container + `python /bundle/<entry_point>`;
- `node` -> configured Node container + `node /bundle/<entry_point>`;
- `uv` -> blocked with `MCPB_UV_BUILD_REQUIRED` until dependency installation has its own build sandbox;
- `binary` -> blocked with `MCPB_BINARY_POLICY_REQUIRED` until an explicit platform/image policy exists.

Manifest environment variables and host substitutions are not inherited during validation.

## Archive validation

Before a container is started UCS validates the archive without using `ZipFile.extract()`:

- absolute paths are rejected;
- `..`, backslashes and NUL paths are rejected;
- duplicate paths are rejected;
- symlinks are rejected;
- member count is bounded;
- individual and total uncompressed size are bounded;
- `manifest.json` size is bounded;
- the declared entry point must exist inside the bundle.

Extraction writes only into a newly-created temporary directory and preserves no executable filesystem state after the sandbox session exits.

## Docker isolation

The Docker stdio process is launched with the following baseline controls:

```text
--pull=never
--network=none
--read-only
--cap-drop=ALL
--security-opt=no-new-privileges
--pids-limit=<bounded>
--memory=<bounded>
--cpus=<bounded>
--user=65534:65534
--tmpfs=/tmp:rw,nosuid,nodev,noexec,...
--mount type=bind,src=<temporary bundle>,dst=/bundle,readonly
```

The container receives no Docker socket and no host filesystem mounts other than the read-only extracted bundle. The MCP connection uses only stdio.

`--pull=never` is intentional: validation never causes an implicit image download. Operators pre-provision approved runtime images.

## Runtime configuration

Enable MCPB sandboxing only with persistent artifact storage:

```text
UCS_MCP_PACKAGE_SANDBOX_ENABLED=true
UCS_BUILD_ARTIFACT_DIR=/var/lib/ucs/build-artifacts
```

Optional runtime controls:

```text
UCS_MCP_SANDBOX_DOCKER=docker
UCS_MCP_SANDBOX_PYTHON_IMAGE=python:3.12-slim
UCS_MCP_SANDBOX_NODE_IMAGE=node:22-bookworm-slim
UCS_MCP_SANDBOX_MEMORY=256m
UCS_MCP_SANDBOX_CPUS=1
UCS_MCP_SANDBOX_PIDS=64
UCS_MCP_SANDBOX_TMPFS_BYTES=67108864
UCS_MCP_SANDBOX_STARTUP_TIMEOUT=5
```

If sandboxing is not enabled, the UCS-13 behavior is preserved and MCPB remains blocked before local execution.

## Validation

The sandbox client performs MCP stdio negotiation and `list_tools` only. It does not call business tools during validation.

Tool metadata is passed through the same UCS-10 snapshot and mapping rules used for remote MCP validation. Therefore:

- explicit UCS capability metadata wins when present;
- deterministic name/service/operation matching is allowed;
- read requests reject tools whose annotations or names conflict with read-only safety;
- ambiguous matches return `MCP_TOOL_SELECTION_REQUIRED`.

A successful mapping creates a `SandboxedMCPConnector` in lifecycle `sandboxed`. A second sandbox health check confirms the selected tool is still exposed before lifecycle becomes `validated`.

## Signed connector package

The MCPB itself is stored separately by its registry-pinned digest. UCS creates a small signed connector package containing only:

- the MCPB SHA-256 digest;
- service/connector/version metadata;
- capability -> tool binding.

It does not embed the MCPB bytes, request inputs, credentials or approvals.

The connector package is Ed25519-signed and reloaded through the existing UCS-08 package verifier before it can proceed to promotion.

After human promotion, the normal package pin evidence is created. On restart the signed connector is rehydrated and the runtime binder attaches the configured Docker sandbox runner. Rehydration fails closed if the sandbox runtime is unavailable.

## Trusted execution

A trusted `SandboxedMCPConnector` still launches the MCPB inside the same Docker isolation boundary for `health_check` and `execute`. Trust does not convert the package into a host process.

The current default sandbox has no network and no host data mounts. This makes UCS-14 suitable for package introspection and isolated/local tools, but it intentionally does not yet support MCP packages that require outbound APIs or access to user directories.

Future egress or data mounts must be explicit policy-controlled capabilities, not generic container options derived from package metadata.

## Evidence

Sandbox validation evidence records only normalized control-plane facts such as:

```text
type = mcp_package_sandbox_validation
candidateId
sourceDigest
passed
code
selectedTool
toolCount
signed connector package digest
```

It does not store:

- package URL;
- extracted filesystem paths;
- bundle contents;
- request input;
- environment variables;
- credentials;
- raw approvals.

## Health

When configured, `/health` reports only an aggregate runtime state:

```json
{
  "packageSandbox": "docker",
  "buildPipeline": "openapi+mcpb-docker"
}
```

No image credentials, artifact paths, package URLs or bundle metadata are exposed.

## Acceptance criteria

UCS-14 is ready when CI proves that:

1. path traversal and MCPB symlinks are rejected before execution;
2. manifest-provided commands/environment do not control the sandbox command;
3. Docker runs with no network, read-only root, dropped capabilities, no-new-privileges, non-root UID, PID/CPU/memory limits and a read-only bundle mount;
4. a real stdio MCPB can negotiate inside Docker and return `list_tools`;
5. a trusted sandbox connector can execute a tool without running the bundle on the host;
6. capability mapping remains conservative and can require explicit tool selection;
7. a validated MCPB connector is signed and independently package-verified;
8. build/validation does not auto-promote the connector to `trusted`;
9. after promotion the connector receives package-pin evidence;
10. restart rehydration reattaches the sandbox runtime and remains executable;
11. raw request input and MCPB URL are absent from validation evidence;
12. all UCS-02 through UCS-13 regression tests remain green.

## Deferred

- controlled outbound-network policies and domain allow-lists;
- user-approved read-only/read-write host directory mounts;
- Agent Vault credential injection into local package sandboxes;
- `uv` dependency-resolution/build sandbox;
- binary MCPB platform/image policies;
- npm/PyPI/Cargo/OCI/NuGet package resolvers;
- stronger kernel isolation through gVisor/Kata/Firecracker;
- seccomp/AppArmor profiles managed by deployment policy;
- SBOM and malware/static analysis for MCPB contents;
- long-running sandbox worker pools and warm containers;
- per-tool egress/filesystem policy decisions.
