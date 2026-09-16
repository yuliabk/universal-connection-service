import os
import pytest
from uuid import uuid4

from test_receipts import stores
from test_durable_execution import request, approve, build_service, execute
from universal_connection_service.dispatch_witness import DispatchWitness
from universal_connection_service.persistence import SQLiteStateStore
from universal_connection_service.receipts import ReceiptError


@pytest.mark.parametrize("restore", ["missing", "prepared"])
def test_restore_of_primary_cannot_reexecute_witnessed_operation(stores, restore):
    store = stores()
    req = request()
    raw = approve(store, req, raw=req.actor.organization_id)
    svc, connector = build_service(store, req)
    assert execute(svc, req, raw).status == "success"
    final = store.get_receipt(req.actor.organization_id, req.operation_id)
    old = final.model_copy(update={"state": "prepared", "version": 0, "attempt_count": 0,
        "attempt_id": None, "audit_id": None, "approval_ref_hash": None})
    with store._receipt_transaction() as conn:
        for table in ("execution_result", "execution_outbox", "execution_attempt", "execution_receipt"):
            store._receipt_query(conn, f"DELETE FROM {table} WHERE organization_id = ? AND operation_id = ?",
                (req.actor.organization_id, req.operation_id))
        if restore == "prepared":
            store._receipt_query(conn, """INSERT INTO execution_receipt
                (organization_id, operation_id, receipt_id, state, version, receipt_json) VALUES (?, ?, ?, ?, ?, ?)""",
                (old.organization_id, old.operation_id, old.receipt_id, old.state, old.version, old.model_dump_json()))
    # Even a fresh grant cannot reopen the lost operation key.
    replacement = approve(store, req, raw=raw + "-after-restore")
    reopened, new_connector = build_service(stores(), req)
    result = execute(reopened, req, replacement)
    assert result.error.code == "EXECUTION_RESTORE_QUARANTINED"
    assert connector.calls == 1 and new_connector.calls == 0


@pytest.mark.parametrize("committed", [False, True])
def test_witness_failure_or_lost_ack_prevents_provider_io(stores, monkeypatch, committed):
    store = stores()
    req = request()
    raw = approve(store, req, raw=req.actor.organization_id)
    svc, provider = build_service(store, req)
    witness = svc.durable_executor.witness
    record = witness.record_dispatch
    def fail(receipt):
        if committed:
            record(receipt)
        raise RuntimeError("synthetic witness unavailable or commit ack lost")
    with monkeypatch.context() as patch:
        patch.setattr(witness, "record_dispatch", fail)
        assert execute(svc, req, raw).error.code == "OUTCOME_UNKNOWN"
    retry = execute(svc, req, raw)
    assert retry.error.code == ("OUTCOME_UNKNOWN" if committed else "EXECUTION_RESTORE_QUARANTINED")
    assert provider.calls == 0


def test_witness_identity_and_same_database_fail_closed(tmp_path):
    store = SQLiteStateStore(tmp_path / "witness.sqlite3")
    DispatchWitness.initialize(store, "expected-id")
    with pytest.raises(ReceiptError, match="IDENTITY_MISMATCH"):
        DispatchWitness(store, "other-id")
    witness = DispatchWitness(store, "expected-id")
    reopened = SQLiteStateStore(store.path)
    with pytest.raises(ValueError, match="separate database"):
        witness.assert_independent(reopened)
    with pytest.raises(Exception):
        DispatchWitness.initialize(store, "replacement-id")
    DispatchWitness(store, "expected-id")
    reopened.close()
    store.close()


def test_postgres_witness_uses_separate_database_and_survives_reopen():
    dsn = os.getenv("UCS_TEST_POSTGRES_URL")
    if not dsn:
        pytest.skip("PostgreSQL not configured")
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import make_conninfo
    from pydantic import SecretStr
    from universal_connection_service.postgres_store import PostgresStateStore, PostgresStoreConfig
    from universal_connection_service.execution import DurableExecutor, ResultCipher
    from test_durable_execution import make_target
    name = "ucs_witness_test_" + uuid4().hex
    witness_dsn = make_conninfo(dsn, dbname=name)
    opened = []
    with psycopg.connect(dsn, autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
    try:
        def open_store(url):
            store = PostgresStateStore(PostgresStoreConfig(dsn=SecretStr(url), autoMigrate=True))
            opened.append(store)
            return store
        primary, backing = open_store(dsn), open_store(witness_dsn)
        DispatchWitness.initialize(backing, name)
        witness = DispatchWitness(backing, name)
        witness.assert_independent(primary)
        with pytest.raises(ValueError, match="separate PostgreSQL"):
            witness.assert_independent(open_store(witness_dsn))
        req = request()
        from test_durable_execution import WriteConnector
        from universal_connection_service.registry import ConnectorRegistry, Registration
        from universal_connection_service.service import ConnectionService
        provider = WriteConnector()
        registry = ConnectorRegistry()
        registry.register(Registration(connector=provider, status="trusted", organization_id=req.actor.organization_id))
        svc = ConnectionService(registry, durable_executor=DurableExecutor(primary,
            ResultCipher({"test": b"x" * 32}, "test"), (make_target(req),), witness=witness))
        raw = approve(primary, req, raw=req.actor.organization_id)
        assert execute(svc, req, raw).status == "success"
        reopened = DispatchWitness(open_store(witness_dsn), name)
        with pytest.raises(ReceiptError, match="RESTORE_QUARANTINED"):
            reopened.check(req.actor.organization_id, req.operation_id, None)
        assert provider.calls == 1
    finally:
        for store in opened:
            store.close()
        with psycopg.connect(dsn, autocommit=True) as admin:
            admin.execute(sql.SQL("DROP DATABASE {}").format(sql.Identifier(name)))


def test_host_configuration_requires_existing_witness_and_matching_identity(tmp_path, monkeypatch):
    import base64
    import json
    from test_durable_execution import make_target
    from universal_connection_service.execution import executor_from_env
    primary = SQLiteStateStore(tmp_path / "primary.sqlite3")
    backing = SQLiteStateStore(tmp_path / "witness.sqlite3")
    DispatchWitness.initialize(backing, "deployment-1")
    backing.close()
    monkeypatch.delenv("UCS_EXECUTION_WITNESS_POSTGRES_URL", raising=False)
    monkeypatch.setenv("UCS_EXECUTION_TARGETS_JSON", json.dumps([make_target(request()).model_dump(by_alias=True)]))
    monkeypatch.setenv("UCS_RECEIPT_KEYRING_JSON", json.dumps({"activeKey": "test", "keys": {"test": base64.b64encode(b"x" * 32).decode()}}))
    monkeypatch.setenv("UCS_EXECUTION_WITNESS_ID", "deployment-1")
    missing = tmp_path / "missing.sqlite3"
    monkeypatch.setenv("UCS_EXECUTION_WITNESS_PATH", str(missing))
    with pytest.raises(RuntimeError, match="configuration is invalid"):
        executor_from_env(primary)
    assert not missing.exists()
    monkeypatch.setenv("UCS_EXECUTION_WITNESS_PATH", str(tmp_path / "witness.sqlite3"))
    executor = executor_from_env(primary)
    executor.witness.close()
    monkeypatch.setenv("UCS_EXECUTION_WITNESS_ID", "wrong-id")
    with pytest.raises(RuntimeError, match="configuration is invalid"):
        executor_from_env(primary)
    primary.close()
