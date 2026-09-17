"""Independent, append-only dispatch witness. Never restore it with UCS state."""
from pathlib import Path

from .receipts import ExecutionReceipt, ReceiptError


class DispatchWitness:
    def __init__(self, store, witness_id: str):
        if not store.receipts_durable or not witness_id:
            raise ValueError("a durable independently provisioned witness is required")
        self.store, self.witness_id = store, witness_id
        with self._transaction() as conn:
            self._identity(conn)

    def _transaction(self):
        return self.store._receipt_transaction()

    @staticmethod
    def initialize(store, witness_id: str):
        """Explicit operator provisioning ONLY for a new, empty witness database.

        No IF NOT EXISTS: cannot silently reset or replace an existing witness.
        """
        if not witness_id or not store.receipts_durable:
            raise ValueError("durable witness and identity required")
        with store._receipt_transaction() as conn:
            store._receipt_query(conn, """CREATE TABLE dispatch_witness_identity
                (singleton INTEGER PRIMARY KEY CHECK (singleton = 1), witness_id TEXT NOT NULL)""")
            store._receipt_query(conn, "INSERT INTO dispatch_witness_identity VALUES (1, ?)", (witness_id,))
            store._receipt_query(conn, """CREATE TABLE dispatch_witness_attempt
                (organization_id TEXT NOT NULL, operation_id TEXT NOT NULL,
                 attempt_count INTEGER NOT NULL, receipt_json TEXT NOT NULL,
                 PRIMARY KEY (organization_id, operation_id, attempt_count))""")

    def _identity(self, conn):
        row = self.store._receipt_query(conn,
            "SELECT witness_id FROM dispatch_witness_identity WHERE singleton = 1").fetchone()
        if row is None or row["witness_id"] != self.witness_id:
            raise ReceiptError("EXECUTION_WITNESS_IDENTITY_MISMATCH")

    def assert_independent(self, primary):
        if primary is self.store:
            raise ValueError("witness must be separate from primary state")
        if hasattr(primary, "path") and hasattr(self.store, "path"):
            a, b = Path(primary.path), Path(self.store.path)
            if a.resolve() == b.resolve() or (a.exists() and b.exists() and a.samefile(b)):
                raise ValueError("witness must be a separate database")
        elif hasattr(primary, "config") and hasattr(self.store, "config"):
            def identity(store):
                with store._receipt_transaction() as conn:
                    row = conn.execute("SELECT current_database() AS db, inet_server_addr()::text AS host, inet_server_port() AS port").fetchone()
                    return tuple(row[key] for key in ("db", "host", "port"))
            if identity(primary) == identity(self.store):
                raise ValueError("witness must be a separate PostgreSQL database")

    def _latest(self, conn, organization_id, operation_id):
        row = self.store._receipt_query(conn, """SELECT receipt_json FROM dispatch_witness_attempt
            WHERE organization_id = ? AND operation_id = ? ORDER BY attempt_count DESC LIMIT 1""",
            (organization_id, operation_id)).fetchone()
        return ExecutionReceipt.model_validate_json(row["receipt_json"]) if row else None

    @staticmethod
    def _matches(current, previous):
        fields = ("receipt_id", "binding_digest", "provider_key", "provider_account_id", "recovery_contract_digest",
                  "provider_not_after", "connector_id", "connector_version", "approval_ref_hash")
        return all(getattr(current, field) == getattr(previous, field) for field in fields)

    def check(self, organization_id, operation_id, receipt):
        with self._transaction() as conn:
            self._identity(conn)
            previous = self._latest(conn, organization_id, operation_id)
            if previous is None:
                if receipt is not None and receipt.attempt_count:
                    raise ReceiptError("EXECUTION_RESTORE_QUARANTINED")
                return
            if (receipt is None or not self._matches(receipt, previous)
                or receipt.attempt_count < previous.attempt_count
                or (receipt.attempt_count == previous.attempt_count and receipt.attempt_id != previous.attempt_id)):
                raise ReceiptError("EXECUTION_RESTORE_QUARANTINED")

    def record_dispatch(self, receipt):
        with self._transaction() as conn:
            self._identity(conn)
            previous = self._latest(conn, receipt.organization_id, receipt.operation_id)
            if (receipt.state != "dispatching" or not receipt.attempt_id or
                (previous is None and receipt.attempt_count != 1) or
                (previous is not None and (not self._matches(receipt, previous) or
                    receipt.attempt_count != previous.attempt_count + 1))):
                raise ReceiptError("EXECUTION_RESTORE_QUARANTINED")
            if not self._insert_attempt(conn, receipt):
                raise ReceiptError("EXECUTION_RESTORE_QUARANTINED")

    def _insert_attempt(self, conn, receipt):
        return self.store._receipt_query(conn, """INSERT INTO dispatch_witness_attempt
            (organization_id, operation_id, attempt_count, receipt_json) VALUES (?, ?, ?, ?)
            ON CONFLICT (organization_id, operation_id, attempt_count) DO NOTHING""",
            (receipt.organization_id, receipt.operation_id, receipt.attempt_count, receipt.model_dump_json())).rowcount == 1

    def close(self):
        self.store.close()


def main():
    """Explicit new-deployment provisioning; never a restore/unquarantine tool."""
    import argparse
    import os
    parser = argparse.ArgumentParser(description="Provision an independent witness for a new execution keyspace")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--sqlite-path")
    source.add_argument("--postgres-env", help="Name of environment variable containing the dedicated witness database URL")
    parser.add_argument("--witness-id", required=True)
    parser.add_argument("--confirm-new-keyspace", action="store_true", required=True)
    args = parser.parse_args()
    store = None
    try:
        if args.sqlite_path:
            from .persistence import SQLiteStateStore
            if Path(args.sqlite_path).exists():
                raise ValueError("existing database cannot be initialized")
            store = SQLiteStateStore(args.sqlite_path)
        else:
            from .postgres_store import PostgresStateStore, PostgresStoreConfig
            from pydantic import SecretStr
            store = PostgresStateStore(PostgresStoreConfig(dsn=SecretStr(os.environ[args.postgres_env]), autoMigrate=True))
        with store._receipt_transaction() as conn:
            if store._receipt_query(conn, "SELECT 1 FROM execution_receipt LIMIT 1").fetchone():
                raise ValueError("witness database contains primary execution state")
        DispatchWitness.initialize(store, args.witness_id)
        print("Independent dispatch witness provisioned. Preserve its identity outside database backups.")
    except Exception:
        parser.exit(1, "Witness provisioning failed; existing witness state was not reset.\n")
    finally:
        if store is not None:
            store.close()


if __name__ == "__main__":
    main()
