# UCS-07 - PostgreSQL / Supabase StateStore + Persistent Approvals

## Goal

Move UCS persistent control-plane state from the SQLite reference backend to a production-capable PostgreSQL backend while keeping persistence provider-neutral.

UCS-07 adds:

- `PostgresStateStore` for connector metadata, evidence and audit;
- versioned PostgreSQL schema migrations;
- persistent request-bound approvals;
- atomic one-time approval consumption across multiple UCS instances;
- Supabase-compatible connection settings;
- an explicit database migration command.

SQLite remains supported for local, CI-light and single-node development.

## Install

```bash
pip install -e '.[postgres]'
```

The PostgreSQL extra pins the current Psycopg 3 line and its connection-pool package.

## Database configuration

UCS reads the production PostgreSQL connection string only from:

```bash
UCS_DATABASE_URL=postgresql://...
```

The DSN is held as `SecretStr` and is never returned through the UCS API.

Optional settings:

```bash
UCS_POSTGRES_POOL_MIN=1
UCS_POSTGRES_POOL_MAX=1
UCS_POSTGRES_TIMEOUT_SECONDS=10
UCS_POSTGRES_SSLMODE=require
UCS_POSTGRES_AUTO_MIGRATE=false
```

Defaults deliberately keep the application-side pool at one connection. This is safe for serverless/pooler deployments and can be raised for a long-running backend after measuring concurrency and database connection limits.

Prepared statements are disabled on PostgreSQL connections so UCS remains compatible with transaction-mode poolers.

## Supabase connection choice

Supabase currently recommends choosing the database connection mode according to where the application runs:

- persistent VM/container: direct connection, or session pooler when IPv4 compatibility is needed;
- serverless/ephemeral runtime: transaction pooler;
- migrations and administration: prefer a direct or session connection rather than relying on transaction-mode session semantics.

Always copy the exact connection string from the Supabase **Connect** dialog. Do not derive the pooler hostname from the region.

For remote databases UCS requires encrypted PostgreSQL connections. `require`, `verify-ca`, and `verify-full` are accepted. For local CI only, `sslmode=disable` is allowed.

For stronger server identity verification use Supabase's database CA with `verify-full` where your deployment supports it.

## Private database schema

UCS stores control-plane data in:

```text
ucs_internal
```

The migration revokes `PUBLIC` access to the schema/tables. The schema is intended for backend database connections only and should **not** be added to Supabase Data API exposed schemas.

The backend database role still needs explicit privileges to use `ucs_internal`. In the default owner/admin connection used for initial deployment, the migration owner already has those privileges. For a dedicated runtime role, grant only the required schema/table privileges separately.

## Migrations

Schema changes are versioned in:

```text
ucs_internal.schema_migration
```

The current migrations are:

1. connector state, validation/policy evidence, execution audit;
2. persistent approval grants;
3. persistent auto-connect workflows;
4. durable execution receipts, attempts and audit outbox;
5. operation-bound approvals and encrypted execution results;
6. tenant-scoped execution operational notices;
7. encrypted metadata storage primitives (profile, tenant directory, documents); runtime integration is still pending.

Migrations run under a transaction-scoped PostgreSQL advisory lock so two deploy processes cannot apply the same UCS migration concurrently.

Run migrations explicitly:

```bash
export UCS_DATABASE_URL='postgresql://...'
ucs-db migrate
```

Inspect the current version:

```bash
ucs-db status
```

Production runtime startup does not perform DDL by default. If the database schema is not current, UCS fails closed and instructs the operator to run the migration command.

For local/demo environments only, automatic migration can be enabled with:

```bash
UCS_POSTGRES_AUTO_MIGRATE=true
```

## Persistent approvals

Approval IDs remain opaque credentials. UCS does not persist the raw ID.

When an approval is registered:

```text
raw approval id
      -> SHA-256
      -> approval_ref_hash
      -> PostgreSQL approval_grant
```

The persisted record contains:

- hashed approval reference;
- request ID;
- organization/user/agent scope;
- service/capability/operation scope;
- expiry;
- consumed timestamp.

It does not contain the raw approval ID.

`PersistentApprovalVerifier` verifies the exact request scope and then calls an atomic update:

```sql
UPDATE ...
SET consumed_at = ...
WHERE approval_ref_hash = ...
  AND consumed_at IS NULL
  AND expires_at > ...
```

Therefore two concurrent UCS instances cannot successfully consume the same grant. Exactly one update may win.

No public approval-issuance endpoint is added in UCS-07. Approval creation is an internal control-plane action until an authenticated human approval workflow is implemented.

## Runtime selection

Application startup chooses persistence in this order:

1. `UCS_DATABASE_URL` -> PostgreSQL/Supabase;
2. `UCS_STATE_DB_PATH` -> SQLite reference backend;
3. neither -> in-memory behavior.

`GET /health` reports `postgres`, `sqlite`, or `memory` in the `state` field.

## Security properties

- no database DSN in plans, results, audit or model-visible errors;
- raw approval IDs are not persisted;
- request inputs and connector response bodies remain outside audit/evidence storage;
- connector/evidence/audit queries remain organization-scoped;
- internal schema is separated from public application tables;
- remote PostgreSQL must use SSL;
- prepared statements are disabled for pooler compatibility;
- stale/unmigrated schemas fail closed;
- atomic approval consumption prevents cross-instance replay.

## Supabase-specific notes

UCS uses PostgreSQL directly, not the public Data API, for internal control-plane state. This is intentional: audit, lifecycle and approval operations are server-side infrastructure data rather than frontend-accessible product tables.

Do not expose a Supabase `service_role`/secret key to browsers. If UCS is deployed behind a frontend, only the UCS backend receives `UCS_DATABASE_URL`.

When running on a serverless platform, use the Supabase transaction pooler connection string, keep the application pool small, and disable prepared statements. For a persistent backend, direct/session mode is usually the better default.

## Acceptance criteria

UCS-07 is ready when CI proves that:

1. PostgreSQL migrations reach the expected schema version and are idempotent;
2. connector metadata, evidence and audit persist in PostgreSQL;
3. tenant-scoped reads do not return another tenant's records;
4. approval IDs are stored only as hashes;
5. two PostgreSQL-backed UCS instances cannot both consume the same approval;
6. a persistent approval authorizes exactly one matching execution;
7. a replay returns `APPROVAL_ALREADY_USED` before connector execution;
8. request input secrets and raw approval IDs remain absent from audit/evidence;
9. all UCS-02 through UCS-06 tests continue to pass.

## Deferred

- authenticated approval issuance/revocation API and UI;
- dedicated least-privilege PostgreSQL runtime role bootstrap;
- Postgres RLS policies for deployments that intentionally expose the internal schema;
- retention/partitioning for high-volume audit tables;
- connection-pool metrics in OpenTelemetry;
- backup/PITR policy validation;
- signed connector package persistence and runtime rehydration.
