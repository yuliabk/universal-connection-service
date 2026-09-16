"""Synthetic independent witness databases; never a runtime provisioning path."""
from contextlib import contextmanager
from uuid import uuid4

from universal_connection_service.encrypted_witness import EncryptedDispatchWitness
from universal_connection_service.metadata_storage import MetadataRepository
from test_metadata_storage import cipher


@contextmanager
def witness_factory(primary, tmp_path):
    opened = []
    name = "ucs_encrypted_witness_test_" + uuid4().hex
    postgres = hasattr(primary, "config")
    if postgres:
        import psycopg
        from psycopg import sql
        from psycopg.conninfo import make_conninfo
        from pydantic import SecretStr
        from universal_connection_service.postgres_store import PostgresStateStore, PostgresStoreConfig
        dsn = primary.config.dsn.get_secret_value()
        witness_dsn = make_conninfo(dsn, dbname=name)
        with psycopg.connect(dsn, autocommit=True) as admin:
            admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
        def backing():
            return PostgresStateStore(PostgresStoreConfig(dsn=SecretStr(witness_dsn), sslmode="disable", autoMigrate=True))
    else:
        from universal_connection_service.persistence import SQLiteStateStore
        path = tmp_path / "encrypted-witness.sqlite3"
        def backing():
            return SQLiteStateStore(path)
    initialized = False
    try:
        def factory():
            nonlocal initialized
            store = backing()
            opened.append(store)
            if not initialized:
                MetadataRepository.provision(store, cipher(), name)
            repository = MetadataRepository(store, cipher(), name)
            if not initialized:
                EncryptedDispatchWitness.initialize(repository, name)
                initialized = True
            return EncryptedDispatchWitness(repository, name)
        yield factory
    finally:
        for store in opened:
            store.close()
        if postgres:
            with psycopg.connect(dsn, autocommit=True) as admin:
                admin.execute(sql.SQL("DROP DATABASE {}").format(sql.Identifier(name)))
