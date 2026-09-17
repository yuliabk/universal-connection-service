"""Fail-closed runtime selection and explicit encrypted-store provisioning."""
from __future__ import annotations

import argparse
import base64
import json
import os
from pathlib import Path

from .encrypted_receipt_store import EncryptedStateStore
from .encrypted_witness import EncryptedDispatchWitness
from .metadata_crypto import MetadataCipher
from .metadata_storage import MetadataRepository


_PRIMARY_PREFIX = "UCS_METADATA"
_WITNESS_PREFIX = "UCS_WITNESS_METADATA"
_LEGACY_TABLES = ("connector_state", "evidence", "audit_event", "approval_grant", "connection_workflow",
                  "execution_receipt", "execution_attempt", "execution_outbox", "execution_result", "execution_notice")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate configuration field")
        result[key] = value
    return result


def metadata_configuration(prefix):
    """Secrets are read from environment, never command-line arguments."""
    profile_id = os.getenv(prefix + "_PROFILE_ID")
    raw = os.getenv(prefix + "_KEYRING_JSON")
    if not profile_id or not raw:
        raise ValueError("metadata configuration required")
    packet = json.loads(raw, object_pairs_hook=_unique_object)
    if not isinstance(packet, dict) or set(packet) != {"activeKey", "keys", "indexKey"} or not isinstance(packet["keys"], dict):
        raise ValueError("metadata configuration invalid")
    keys = {key: base64.b64decode(value, validate=True) for key, value in packet["keys"].items()}
    return MetadataCipher(keys, packet["activeKey"], base64.b64decode(packet["indexKey"], validate=True)), profile_id


def assert_legacy_empty(store, conn):
    """An encrypted profile must never hide older plaintext operation identities."""
    postgres = hasattr(store, "config")
    prefix = "ucs_internal." if postgres else ""
    for table in _LEGACY_TABLES:
        if conn.execute(f"SELECT 1 FROM {prefix}{table} LIMIT 1").fetchone():
            raise ValueError("offline migration required")
    legacy_witness = (conn.execute("SELECT to_regclass('ucs_internal.dispatch_witness_identity') AS existing").fetchone()["existing"]
                      if postgres else conn.execute("SELECT 1 FROM sqlite_master WHERE name = 'dispatch_witness_identity'").fetchone())
    if legacy_witness:
        raise ValueError("legacy witness requires offline migration")


def open_runtime_primary(store):
    cipher, profile_id = metadata_configuration(_PRIMARY_PREFIX)
    repository = MetadataRepository(store, cipher, profile_id)
    with repository.transaction() as conn:
        assert_legacy_empty(store, conn)
        if store._receipt_query(conn, "SELECT 1 FROM metadata_document WHERE domain = 'witness-identity' LIMIT 1").fetchone():
            raise ValueError("witness database cannot be used as primary")
    return EncryptedStateStore(repository)


def open_runtime_witness(store, witness_id):
    cipher, profile_id = metadata_configuration(_WITNESS_PREFIX)
    repository = MetadataRepository(store, cipher, profile_id)
    with repository.transaction() as conn:
        assert_legacy_empty(store, conn)
    return EncryptedDispatchWitness(repository, witness_id)


def build_state_store_from_env():
    path, dsn = os.getenv("UCS_STATE_DB_PATH"), os.getenv("UCS_DATABASE_URL")
    configured = any(os.getenv(name) is not None for name in (
        "UCS_STATE_DB_PATH", "UCS_DATABASE_URL", "UCS_METADATA_PROFILE_ID", "UCS_METADATA_KEYRING_JSON"))
    if not configured:
        return None, "memory"
    store = None
    try:
        # Validate all key material before opening a file or database connection.
        metadata_configuration(_PRIMARY_PREFIX)
        if bool(path) == bool(dsn):
            raise ValueError("one persistent backend required")
        if dsn:
            from .postgres_store import PostgresStateStore, config_from_env
            store = PostgresStateStore(config_from_env())
            kind = "postgres"
        else:
            from .persistence import SQLiteStateStore
            store = SQLiteStateStore(path, must_exist=True)
            kind = "sqlite"
        return open_runtime_primary(store), kind
    except Exception:
        if store is not None:
            store.close()
        raise RuntimeError("Encrypted state configuration is invalid; provision or migrate storage before startup") from None


def main():
    parser = argparse.ArgumentParser(description="Provision a NEW encrypted UCS keyspace; never migrate or reset an existing one")
    parser.add_argument("--role", choices=("primary", "witness"), required=True)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--sqlite-path")
    source.add_argument("--postgres-env", help="Environment variable containing an existing empty PostgreSQL database URL")
    parser.add_argument("--confirm-new-keyspace", action="store_true", required=True)
    args = parser.parse_args()
    store = None
    try:
        cipher, profile_id = metadata_configuration(_PRIMARY_PREFIX if args.role == "primary" else _WITNESS_PREFIX)
        witness_id = os.getenv("UCS_EXECUTION_WITNESS_ID")
        if args.role == "witness" and not witness_id:
            raise ValueError("witness identity required")
        if args.sqlite_path:
            from .persistence import SQLiteStateStore
            # Exclusive creation prevents an existence-check race from opening an
            # old keyspace. A failed provisioning may leave an empty file to inspect.
            with Path(args.sqlite_path).open("xb"):
                pass
            store = SQLiteStateStore(args.sqlite_path, must_exist=True)
        else:
            from pydantic import SecretStr
            from .postgres_store import PostgresStateStore, PostgresStoreConfig
            store = PostgresStateStore(PostgresStoreConfig(dsn=SecretStr(os.environ[args.postgres_env]), autoMigrate=True))
        with store._receipt_transaction() as conn:
            assert_legacy_empty(store, conn)
        MetadataRepository.provision(store, cipher, profile_id)
        repository = MetadataRepository(store, cipher, profile_id)
        if args.role == "witness":
            EncryptedDispatchWitness.initialize(repository, witness_id)
        print("New encrypted storage provisioned. Preserve its profile, keys and independent witness identity.")
    except Exception:
        parser.exit(1, "Encrypted storage provisioning failed; existing identities were not reset.\n")
    finally:
        if store is not None:
            store.close()


if __name__ == "__main__":
    main()
