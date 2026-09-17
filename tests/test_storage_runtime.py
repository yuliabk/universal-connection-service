import base64
import json
import os
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

import pytest

from test_durable_execution import request, approve, make_target, WriteConnector, execute
from universal_connection_service.encrypted_receipt_store import EncryptedStateStore
from universal_connection_service.encrypted_witness import EncryptedDispatchWitness
from universal_connection_service.execution import executor_from_env
from universal_connection_service.metadata_storage import MetadataRepository
from universal_connection_service.persistence import SQLiteStateStore
from universal_connection_service.registry import ConnectorRegistry, Registration
from universal_connection_service.service import ConnectionService
from universal_connection_service.storage_runtime import build_state_store_from_env, metadata_configuration, main


ENV = ("UCS_STATE_DB_PATH", "UCS_DATABASE_URL", "UCS_METADATA_PROFILE_ID", "UCS_METADATA_KEYRING_JSON",
       "UCS_WITNESS_METADATA_PROFILE_ID", "UCS_WITNESS_METADATA_KEYRING_JSON", "UCS_EXECUTION_WITNESS_ID",
       "UCS_EXECUTION_WITNESS_PATH", "UCS_EXECUTION_WITNESS_POSTGRES_URL", "UCS_EXECUTION_TARGETS_JSON", "UCS_RECEIPT_KEYRING_JSON")


def keyring(index=b"i" * 32, data=b"d" * 32):
    return json.dumps(dict(activeKey="synthetic", keys={"synthetic": base64.b64encode(data).decode()},
                           indexKey=base64.b64encode(index).decode()))


@pytest.fixture
def clean_env(monkeypatch):
    for name in ENV:
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


@pytest.fixture
def runtime_configuration(tmp_path, clean_env):
    patch = clean_env
    req = request()
    for prefix, profile in (("UCS_METADATA", "primary-synthetic"), ("UCS_WITNESS_METADATA", "witness-synthetic")):
        patch.setenv(prefix + "_PROFILE_ID", profile)
        patch.setenv(prefix + "_KEYRING_JSON", keyring())
    patch.setenv("UCS_EXECUTION_WITNESS_ID", "synthetic-witness-id")
    for role in ("primary", "witness"):
        path = tmp_path / (role + ".sqlite3")
        with patch.context() as argv:
            argv.setattr(sys, "argv", ["storage_runtime", "--role", role, "--sqlite-path", str(path), "--confirm-new-keyspace"])
            main()
    patch.setenv("UCS_STATE_DB_PATH", str(tmp_path / "primary.sqlite3"))
    patch.setenv("UCS_EXECUTION_WITNESS_PATH", str(tmp_path / "witness.sqlite3"))
    patch.setenv("UCS_EXECUTION_TARGETS_JSON", json.dumps([make_target(req).model_dump(mode="json", by_alias=True)]))
    patch.setenv("UCS_RECEIPT_KEYRING_JSON", json.dumps(dict(activeKey="result", keys={"result": base64.b64encode(b"r" * 32).decode()})))
    return req, patch


def test_unconfigured_runtime_stays_in_memory_and_partial_config_never_creates_file(tmp_path, clean_env):
    assert build_state_store_from_env() == (None, "memory")
    missing = tmp_path / "must-not-be-created.sqlite3"
    clean_env.setenv("UCS_STATE_DB_PATH", str(missing))
    with pytest.raises(RuntimeError, match="Encrypted state configuration is invalid"):
        build_state_store_from_env()
    assert not missing.exists()
    clean_env.setenv("UCS_METADATA_PROFILE_ID", "profile")
    clean_env.setenv("UCS_METADATA_KEYRING_JSON", keyring())
    with pytest.raises(RuntimeError):
        build_state_store_from_env()
    assert not missing.exists()


def test_environment_runtime_executes_and_recovers_with_both_encrypted_stores(runtime_configuration):
    req, _ = runtime_configuration
    store, kind = build_state_store_from_env()
    assert kind == "sqlite" and isinstance(store, EncryptedStateStore)
    executor = executor_from_env(store)
    assert isinstance(executor.witness, EncryptedDispatchWitness)
    provider = WriteConnector()
    registry = ConnectorRegistry()
    registry.register(Registration(connector=provider, status="trusted", organization_id=req.actor.organization_id))
    service = ConnectionService(registry, durable_executor=executor)
    try:
        raw = approve(store, req, raw=req.actor.organization_id)
        first = execute(service, req, raw)
        assert first.status == "success" and provider.calls == 1
    finally:
        executor.witness.close()
        store.close()
    reopened, _ = build_state_store_from_env()
    recovered = executor_from_env(reopened)
    try:
        retried = execute(ConnectionService(registry, durable_executor=recovered), req, approval=None)
        assert retried.receipt_id == first.receipt_id and retried.data == first.data
        assert provider.calls == 1
    finally:
        recovered.witness.close()
        reopened.close()


@pytest.mark.parametrize("fault", ["missing-keyring", "index-key", "data-key", "profile", "ambiguous-backend", "witness-as-primary"])
def test_bad_primary_configuration_fails_closed_without_secret_echo(runtime_configuration, fault):
    _, patch = runtime_configuration
    if fault == "missing-keyring":
        patch.delenv("UCS_METADATA_KEYRING_JSON")
    elif fault == "index-key":
        patch.setenv("UCS_METADATA_KEYRING_JSON", keyring(index=b"j" * 32))
    elif fault == "data-key":
        patch.setenv("UCS_METADATA_KEYRING_JSON", keyring(data=b"e" * 32))
    elif fault == "profile":
        patch.setenv("UCS_METADATA_PROFILE_ID", "unmatched-profile")
    elif fault == "ambiguous-backend":
        patch.setenv("UCS_DATABASE_URL", "postgresql://must-not-contact")
    else:
        patch.setenv("UCS_STATE_DB_PATH", os.environ["UCS_EXECUTION_WITNESS_PATH"])
        patch.setenv("UCS_METADATA_PROFILE_ID", "witness-synthetic")
    with pytest.raises(RuntimeError) as error:
        build_state_store_from_env()
    assert str(error.value) == "Encrypted state configuration is invalid; provision or migrate storage before startup"


@pytest.mark.parametrize("fault", ["missing-keyring", "index-key", "identity", "missing-file", "plaintext-primary"])
def test_bad_witness_configuration_blocks_executor(runtime_configuration, tmp_path, fault):
    _, patch = runtime_configuration
    store, _ = build_state_store_from_env()
    try:
        if fault == "missing-keyring":
            patch.delenv("UCS_WITNESS_METADATA_KEYRING_JSON")
        elif fault == "index-key":
            patch.setenv("UCS_WITNESS_METADATA_KEYRING_JSON", keyring(index=b"j" * 32))
        elif fault == "identity":
            patch.setenv("UCS_EXECUTION_WITNESS_ID", "unmatched")
        elif fault == "missing-file":
            patch.setenv("UCS_EXECUTION_WITNESS_PATH", str(tmp_path / "absent.sqlite3"))
        supplied = store.repository.store if fault == "plaintext-primary" else store
        with pytest.raises(RuntimeError, match="^Durable execution configuration is invalid$"):
            executor_from_env(supplied)
        assert not (tmp_path / "absent.sqlite3").exists()
    finally:
        store.close()


def test_runtime_does_not_hide_plaintext_identity_under_encrypted_profile(tmp_path, clean_env):
    path = tmp_path / "legacy.sqlite3"
    physical = SQLiteStateStore(path)
    req = request()
    approve(physical, req, raw=req.actor.organization_id)
    clean_env.setenv("UCS_METADATA_PROFILE_ID", "profile")
    clean_env.setenv("UCS_METADATA_KEYRING_JSON", keyring())
    crypto, profile = metadata_configuration("UCS_METADATA")
    MetadataRepository.provision(physical, crypto, profile)
    physical.close()
    clean_env.setenv("UCS_STATE_DB_PATH", str(path))
    with pytest.raises(RuntimeError, match="provision or migrate"):
        build_state_store_from_env()


def test_provisioning_refuses_existing_path_and_does_not_echo_keys(runtime_configuration, capsys):
    _, patch = runtime_configuration
    path = os.environ["UCS_STATE_DB_PATH"]
    patch.setattr(sys, "argv", ["storage_runtime", "--role", "primary", "--sqlite-path", path, "--confirm-new-keyspace"])
    with pytest.raises(SystemExit) as error:
        main()
    assert error.value.code == 1
    output = capsys.readouterr()
    assert "existing identities were not reset" in output.err
    assert os.environ["UCS_METADATA_KEYRING_JSON"] not in output.err
    store, _ = build_state_store_from_env()
    store.close()


def test_actual_application_import_selects_encrypted_runtime(runtime_configuration):
    env = dict(os.environ, PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src"))
    code = "from universal_connection_service.app import state_store, service; from universal_connection_service.encrypted_receipt_store import EncryptedStateStore; from universal_connection_service.encrypted_witness import EncryptedDispatchWitness; assert isinstance(state_store, EncryptedStateStore); assert isinstance(service.durable_executor.witness, EncryptedDispatchWitness); service.durable_executor.witness.close(); state_store.close(); print('encrypted runtime selected')"
    completed = subprocess.run([sys.executable, "-c", code], env=env, capture_output=True, text=True, timeout=30)
    assert completed.returncode == 0, completed.stderr
    assert "encrypted runtime selected" in completed.stdout


def test_postgres_runtime_provisions_independent_encrypted_databases(clean_env):
    dsn = os.getenv("UCS_TEST_POSTGRES_URL")
    if not dsn:
        pytest.skip("PostgreSQL not configured")
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import make_conninfo
    patch = clean_env
    req = request()
    names, opened, executors = [], [], []
    try:
        for role, prefix in (("primary", "UCS_METADATA"), ("witness", "UCS_WITNESS_METADATA")):
            name = "ucs_runtime_test_" + uuid4().hex
            with psycopg.connect(dsn, autocommit=True) as admin:
                admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(name)))
            names.append(name)
            variable = "UCS_SYNTHETIC_" + role.upper() + "_URL"
            patch.setenv(variable, make_conninfo(dsn, dbname=name))
            patch.setenv(prefix + "_PROFILE_ID", role + "-profile")
            patch.setenv(prefix + "_KEYRING_JSON", keyring())
            patch.setenv("UCS_EXECUTION_WITNESS_ID", "independent-postgres-witness")
            with patch.context() as argv:
                argv.setattr(sys, "argv", ["storage_runtime", "--role", role, "--postgres-env", variable, "--confirm-new-keyspace"])
                main()
        patch.setenv("UCS_DATABASE_URL", os.environ["UCS_SYNTHETIC_PRIMARY_URL"])
        patch.setenv("UCS_EXECUTION_WITNESS_POSTGRES_URL", os.environ["UCS_SYNTHETIC_WITNESS_URL"])
        patch.setenv("UCS_EXECUTION_TARGETS_JSON", json.dumps([make_target(req).model_dump(mode="json", by_alias=True)]))
        patch.setenv("UCS_RECEIPT_KEYRING_JSON", json.dumps(dict(activeKey="result", keys={"result": base64.b64encode(b"r" * 32).decode()})))
        primary, kind = build_state_store_from_env()
        opened.append(primary)
        assert kind == "postgres"
        executor = executor_from_env(primary)
        executors.append(executor)
        assert isinstance(executor.witness, EncryptedDispatchWitness)
        provider = WriteConnector()
        registry = ConnectorRegistry()
        registry.register(Registration(connector=provider, status="trusted", organization_id=req.actor.organization_id))
        service = ConnectionService(registry, durable_executor=executor)
        raw = approve(primary, req, raw=req.actor.organization_id)
        first = execute(service, req, raw)
        assert first.status == "success"
        reopened, _ = build_state_store_from_env()
        opened.append(reopened)
        recovered = executor_from_env(reopened)
        executors.append(recovered)
        result = execute(ConnectionService(registry, durable_executor=recovered), req, approval=None)
        assert result.receipt_id == first.receipt_id and provider.calls == 1
    finally:
        for executor in executors:
            executor.witness.close()
        for store in opened:
            store.close()
        for name in names:
            with psycopg.connect(dsn, autocommit=True) as admin:
                admin.execute(sql.SQL("DROP DATABASE {}").format(sql.Identifier(name)))
