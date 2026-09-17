# UCS-06 - Persistent Registry Metadata + Audit/Evidence Store

## Goal

Persist UCS control-plane state across process restarts without serializing or trusting arbitrary runtime connector objects.

UCS-06 separates two concerns:

```text
Runtime plane                         Persistent control plane
-------------                         ------------------------
Connector Python objects              Connector manifest metadata
Transport/client instances            Organization scope
In-process SDK state                  Lifecycle status
                                      Validation evidence
                                      Policy decision evidence
                                      Approval verification evidence
                                      Execution audit
```

Runtime connector implementations remain process-local. A future package/deployment loader will rehydrate trusted implementations after restart from signed connector packages or deployment configuration.

## Store contracts

`persistence.py` defines provider-neutral ports:

- `ConnectorStateStore`
- `EvidenceStore`
- `AuditStore`
- combined `StateStore`

The UCS core depends on these contracts rather than SQLite.

`SQLiteStateStore` is the reference implementation and uses only Python's standard-library `sqlite3` module.

## Tenant-aware connector metadata

Every runtime `Registration` now has an `organizationId` scope.

- `*` means explicitly global/shared.
- a concrete organization ID means tenant-specific.
- tenant-specific trusted connectors override a global connector for the same service/capability.
- one tenant cannot see another tenant's scoped runtime manifests or persisted metadata through tenant-scoped store queries.

Registration persists:

- organization ID;
- connector manifest;
- lifecycle status;
- approval metadata reference when present;
- update timestamp.

Lifecycle transitions made through `Registration.set_status()` are written to the configured connector state store.

## Validation evidence

`OpenAPIValidationService` can write persistent validation evidence.

Evidence contains:

- organization ID;
- connector ID;
- validation engine;
- normalized validation report;
- sandbox scheme/host;
- timestamp.

It does not store OpenAPI credentials, request headers, or raw upstream traffic.

The generated connector lifecycle is persisted during:

```text
generated -> sandboxed -> validated
```

A failed validation remains `sandboxed` and the failed report remains available as evidence.

## Policy and approval evidence

`ConnectionCompiler` writes policy-decision evidence during both:

- planning (`phase=plan`);
- execution-time policy re-evaluation (`phase=execution`).

The evidence stores the normalized decision, reasons and risk facts. It does not store the request input body.

Approval evidence stores:

- validity;
- normalized verification code;
- SHA-256 reference of the approval ID.

The raw approval ID is never persisted by UCS-06.

## Execution audit

Every `ConnectionService` result can be persisted as an `AuditEvent`.

Audit fields include:

- audit ID;
- request ID;
- organization/user/agent IDs;
- service/capability/operation;
- result status;
- connector ID when selected;
- policy decision;
- normalized error code;
- SHA-256 approval reference;
- timestamp.

Audit deliberately excludes:

- `ConnectionRequest.input`;
- response bodies;
- `credentialHandle`;
- API keys / OAuth tokens;
- raw approval IDs;
- Agent Vault session tokens.

## SQLite reference backend

Enable the reference persistent backend by setting:

```bash
export UCS_STATE_DB_PATH=/var/lib/ucs/ucs-state.sqlite3
```

When unset, UCS preserves the previous in-memory behavior.

`GET /health` reports:

```json
{"ok": true, "version": "0.1.0", "state": "sqlite"}
```

or `memory` when persistence is not configured.

SQLite uses WAL mode for file-backed databases and is intended for local development, CI, demos and single-node stateful deployments.

## Important deployment boundary

SQLite is **not** a durable production persistence choice for ephemeral/serverless filesystems such as a typical Vercel function runtime. A production deployment on ephemeral compute should use a persistent database adapter, expected next to be PostgreSQL.

The provider-neutral store interfaces introduced in UCS-06 are specifically intended to allow that swap without changing compiler, registry or connection-service contracts.

## Restart semantics

After restart, UCS can recover persistent metadata, lifecycle and evidence from the database.

UCS-06 does **not** reconstruct executable connector Python objects automatically. Therefore:

- persistent metadata may say a connector is `trusted`;
- the runtime registry is still empty until a trusted implementation is loaded;
- execution remains fail-closed if no runtime connector implementation is present.

This avoids unsafe object deserialization and keeps supply-chain verification as a separate future boundary.

## Persistence failure semantics

When a persistent store is explicitly configured, writes are not silently discarded. Store failures propagate to the caller instead of pretending durable evidence was recorded.

For side-effecting production workflows, a future database-backed implementation should add stronger delivery guarantees such as transactional/outbox semantics and operational monitoring.

## Acceptance criteria

UCS-06 is ready when CI proves that:

1. connector metadata and lifecycle survive reopening a SQLite database;
2. tenant-specific connectors override global connectors only for their tenant;
3. tenant-scoped registry/store queries exclude other tenants;
4. OpenAPI validation writes durable lifecycle and validation evidence;
5. planning and execution write policy decision evidence;
6. successful and failed connection results can be written to audit storage;
7. raw request input, credential handles and raw approval IDs are absent from persisted evidence/audit;
8. approval references are hashed before persistence;
9. all UCS-02 through UCS-05 regression tests continue to pass.

## Deferred

- PostgreSQL/Supabase state-store adapter;
- signed connector package metadata and runtime rehydration;
- persistent approval grant storage/consumption;
- audit retention and deletion policies;
- tenant-authenticated admin/query APIs;
- schema migrations/version table;
- encryption-at-rest configuration owned by the deployment database;
- transactional outbox / event export;
- OpenTelemetry correlation and external SIEM export.

## UCS-19 runtime update

Persistent runtime storage now requires pre-provisioned encrypted metadata profiles and keyrings. Setting UCS_STATE_DB_PATH alone is no longer sufficient. Missing keys or legacy rows block startup rather than falling back to plaintext. The native SQLiteStateStore remains available to trusted SDK/migration code; it is not the app runtime's persistent store. See UCS19_METADATA_ENCRYPTION.md for provisioning and current migration limitations.
