import os
from uuid import uuid4

import pytest

from test_metadata_storage import cipher
from test_durable_execution import request, approve, build_service, execute
from test_encrypted_control_store import workflow
from universal_connection_service.dispatch_witness import DispatchWitness
from universal_connection_service.encrypted_receipt_store import EncryptedStateStore
from universal_connection_service.encrypted_witness import EncryptedDispatchWitness
from universal_connection_service.execution import ResultCipher
from universal_connection_service.metadata_crypto import MetadataCryptoError
from universal_connection_service.metadata_storage import MetadataRepository
from universal_connection_service.metadata_migration import MigrationTarget, migrate_legacy_pair
from universal_connection_service.persistence import SQLiteStateStore, EvidenceRecord, ConnectorStateRecord
from universal_connection_service.approvals import approval_ref_hash


@pytest.fixture(params=["sqlite", "postgres"])
def migration(request, tmp_path):
    opened, databases = [], []
    postgres = request.param == "postgres"
    if postgres:
        dsn = os.getenv("UCS_TEST_POSTGRES_URL")
        if not dsn:
            pytest.skip("PostgreSQL not configured")
        import psycopg
        from psycopg import sql
        from psycopg.conninfo import make_conninfo
        from pydantic import SecretStr
        from universal_connection_service.postgres_store import PostgresStateStore, PostgresStoreConfig
    try:
        for role in ("old_primary", "old_witness", "new_primary", "new_witness"):
            if postgres:
                database = "ucs_migration_test_" + uuid4().hex
                with psycopg.connect(dsn, autocommit=True) as admin:
                    admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(database)))
                databases.append(database)
                store = PostgresStateStore(PostgresStoreConfig(dsn=SecretStr(make_conninfo(dsn, dbname=database)), sslmode="disable", autoMigrate=True))
            else:
                store = SQLiteStateStore(tmp_path / (role + ".sqlite3"))
            opened.append(store)
        primary, witness_store, new_primary, new_witness = opened
        DispatchWitness.initialize(witness_store, "original-witness-identity")
        witness = DispatchWitness(witness_store, "original-witness-identity")
        primary._test_witness = witness
        yield primary, witness, MigrationTarget(new_primary, cipher(), "new-primary"), MigrationTarget(new_witness, cipher(), "new-witness")
    finally:
        for store in opened:
            store.close()
        if postgres:
            for database in databases:
                with psycopg.connect(dsn, autocommit=True) as admin:
                    admin.execute(sql.SQL("DROP DATABASE {}").format(sql.Identifier(database)))


def migrate(pair):
    return migrate_legacy_pair(*pair, result_cipher=ResultCipher({"test": b"x" * 32}, "test"), writers_stopped=True)


def reopen(pair):
    _, witness, pt, wt = pair
    primary = EncryptedStateStore(MetadataRepository(pt.store, pt.cipher, pt.profile_id))
    primary._test_witness = EncryptedDispatchWitness(MetadataRepository(wt.store, wt.cipher, wt.profile_id), witness.witness_id)
    return primary


def test_migration_preserves_execution_control_and_delivered_audit(migration):
    old = migration[0]
    req = request()
    org = req.actor.organization_id
    raw = approve(old, req, raw=org)
    service, provider = build_service(old, req)
    first = execute(service, req, raw)
    assert first.status == "success"
    receipt = old.get_receipt(org, req.operation_id)
    old.deliver_receipt_audit(org)
    old.record_execution_notice(org, receipt.receipt_id, "OUTCOME_UNKNOWN")
    old.append_evidence(EvidenceRecord(evidenceId="private-evidence", organizationId=org,
        kind="validation", phase="validation", payload={"private": "synthetic-secret-marker"}))
    old.upsert_connector(ConnectorStateRecord(organizationId=org, manifest=provider.manifest(), status="trusted"))
    wf = old.create_workflow(workflow(org))
    from datetime import timedelta
    from universal_connection_service.persistence import utc_now
    now = utc_now()
    assert old.claim_workflow(org, wf.workflow_id, "original-lease", now + timedelta(minutes=5), now)
    summary = migrate(migration)
    assert summary["primaryDocuments"] > 0 and summary["witnessDocuments"] == 2
    new = reopen(migration)
    assert new.get_receipt(org, req.operation_id) == receipt
    assert new.get_approval(approval_ref_hash(raw)) == old.get_approval(approval_ref_hash(raw))
    assert new.get_workflow(org, wf.workflow_id) == old.get_workflow(org, wf.workflow_id)
    assert not new.claim_workflow(org, wf.workflow_id, "replacement-lease", now + timedelta(minutes=5), now)
    assert new.list_evidence(org) == old.list_evidence(org)
    assert new.list_connectors(org) == old.list_connectors(org)
    assert new.list_audit(org) == old.list_audit(org)
    assert new.execution_notices(org) == old.execution_notices(org)
    assert new.deliver_receipt_audit(org) == 0
    recovered, unused = build_service(new, req)
    assert execute(recovered, req, raw).receipt_id == first.receipt_id
    assert provider.calls == 1 and unused.calls == 0
    assert old.get_receipt(org, req.operation_id) == receipt
    with new.repository.transaction() as conn:
        rows = new.repository.store._receipt_query(conn, "SELECT * FROM metadata_document").fetchall()
        physical = repr([dict(row) for row in rows])
    assert org not in physical and "synthetic-secret-marker" not in physical


@pytest.mark.parametrize("state", ["pending", "unknown"])
def test_migration_preserves_unresolved_receipt_without_dispatch(migration, state):
    from test_dispatch_outcomes import setup
    old = migration[0]
    req, provider, target, service, raw = setup(old)
    provider.state = state
    result = execute(service, req, raw)
    assert result.execution_state == state
    receipt = old.get_receipt(req.actor.organization_id, req.operation_id)
    migrate(migration)
    new = reopen(migration)
    assert new.get_receipt(req.actor.organization_id, req.operation_id) == receipt
    recovered, _ = build_service(new, req, connector=provider, target=target)
    assert execute(recovered, req, raw).execution_state == state
    assert provider.calls == 1


@pytest.mark.parametrize("phase", ["copy", "verify", "activate_primary"])
def test_interrupted_migration_never_opens_partial_primary(migration, monkeypatch, phase):
    import universal_connection_service.metadata_migration as module
    old = migration[0]
    req = request()
    raw = approve(old, req, raw=req.actor.organization_id)
    service, provider = build_service(old, req)
    assert execute(service, req, raw).status == "success"
    saved = old.get_receipt(req.actor.organization_id, req.operation_id)
    original_transfer, original_activate = module._transfer, module._PendingRepository._activate
    def transfer(repo, entries, *, verify=False):
        if (phase == "copy" and not verify) or (phase == "verify" and verify):
            if phase == "copy":
                original_transfer(repo, [next(iter(entries))])
            raise RuntimeError("synthetic interruption")
        return original_transfer(repo, entries, verify=verify)
    def activate(repo):
        if phase == "activate_primary" and repo.profile_id == migration[2].profile_id:
            raise RuntimeError("synthetic interruption")
        return original_activate(repo)
    monkeypatch.setattr(module, "_transfer", transfer)
    monkeypatch.setattr(module._PendingRepository, "_activate", activate)
    with pytest.raises(RuntimeError, match="synthetic interruption"):
        migrate(migration)
    target = migration[2]
    with pytest.raises(MetadataCryptoError):
        MetadataRepository(target.store, target.cipher, target.profile_id)
    assert old.get_receipt(req.actor.organization_id, req.operation_id) == saved
    assert provider.calls == 1


def test_migration_rejects_reused_target_and_requires_drained_writers(migration):
    with pytest.raises(ValueError, match="stop and drain"):
        migrate_legacy_pair(*migration, result_cipher=None)
    migrate(migration)
    with pytest.raises(ValueError, match="unprovisioned empty"):
        migrate(migration)
    reopen(migration)


def test_migration_rejects_primary_restored_behind_witness(migration):
    old, witness, _, _ = migration
    req = request()
    raw = approve(old, req, raw=req.actor.organization_id)
    service, provider = build_service(old, req)
    assert execute(service, req, raw).status == "success"
    with old._receipt_transaction() as conn:
        for table in ("execution_result", "execution_outbox", "execution_attempt", "execution_receipt"):
            old._receipt_query(conn, f"DELETE FROM {table}")
    with pytest.raises(ValueError, match="orphan execution"):
        migrate(migration)
    target = migration[2]
    with pytest.raises(MetadataCryptoError):
        MetadataRepository(target.store, target.cipher, target.profile_id)
    assert provider.calls == 1


def test_migration_preserves_retention_tombstone_and_revocation(migration, monkeypatch):
    from test_receipt_retention import expired_execution, scan
    old = migration[0]
    req, service, provider, first = expired_execution(old, monkeypatch)
    scan(old, service.durable_executor.cipher)
    org = req.actor.organization_id
    receipt = old.get_receipt(org, req.operation_id)
    assert receipt.result_purged_at is not None
    assert old.revoke_execution_approval(org, receipt.approval_ref_hash)
    migrate(migration)
    new = reopen(migration)
    assert new.get_receipt(org, req.operation_id) == receipt
    assert new.get_receipt_result(org, req.operation_id) is None
    assert new.get_approval(receipt.approval_ref_hash).revoked_at == old.get_approval(receipt.approval_ref_hash).revoked_at
    recovered, unused = build_service(new, req)
    retry = execute(recovered, req, None)
    assert retry.error.code == "RESULT_EXPIRED" and retry.receipt_id == first.receipt_id
    assert provider.calls == 1 and unused.calls == 0


@pytest.mark.parametrize("tamper", ["document", "tenant", "orphan_tenant"])
def test_verification_detects_target_tampering_and_blocks_runtime(migration, monkeypatch, tamper):
    import universal_connection_service.metadata_migration as module
    import universal_connection_service.storage_runtime as runtime
    old = migration[0]
    req = request()
    raw = approve(old, req, raw=req.actor.organization_id)
    service, provider = build_service(old, req)
    assert execute(service, req, raw).status == "success"
    transfer = module._transfer
    def corrupt_before_verify(repo, entries, *, verify=False):
        if verify and repo.profile_id == migration[2].profile_id:
            with repo.transaction() as conn:
                if tamper == "document":
                    repo.store._receipt_query(conn, "UPDATE metadata_document SET envelope = ? WHERE domain = ?", ("invalid", "receipt"))
                elif tamper == "tenant":
                    repo.store._receipt_query(conn, "UPDATE metadata_tenant SET envelope = ?", ("invalid",))
                else:
                    repo._register_tenant(conn, "orphan-tenant", repo._tenant_index("orphan-tenant"))
        return transfer(repo, entries, verify=verify)
    monkeypatch.setattr(module, "_transfer", corrupt_before_verify)
    with pytest.raises(MetadataCryptoError):
        migrate(migration)
    target = migration[2]
    monkeypatch.setattr(runtime, "metadata_configuration", lambda prefix: (target.cipher, target.profile_id))
    with pytest.raises(MetadataCryptoError):
        runtime.open_runtime_primary(target.store)
    assert provider.calls == 1


def test_process_exit_during_migration_leaves_durable_activation_gate(migration):
    import json
    import subprocess
    import sys
    from pathlib import Path
    old, witness, pt, wt = migration
    req = request()
    raw = approve(old, req, raw=req.actor.organization_id)
    service, provider = build_service(old, req)
    assert execute(service, req, raw).status == "success"
    saved = old.get_receipt(req.actor.organization_id, req.operation_id)
    locations = []
    for store in (old, witness.store, pt.store, wt.store):
        locations.append({"dsn": store.config.dsn.get_secret_value()} if hasattr(store, "config") else {"path": store.path})
    script = r"""
import os, sys, json
sys.path.insert(0, sys.argv[1])
from test_metadata_storage import cipher
from universal_connection_service.persistence import SQLiteStateStore
from universal_connection_service.metadata_migration import *
import universal_connection_service.metadata_migration as module
from universal_connection_service.execution import ResultCipher
opened = []
for item in json.loads(os.environ['UCS_SYNTHETIC_MIGRATION_LOCATIONS']):
    if 'path' in item:
        opened.append(SQLiteStateStore(item['path'], must_exist=True))
    else:
        from pydantic import SecretStr
        from universal_connection_service.postgres_store import PostgresStateStore, PostgresStoreConfig
        opened.append(PostgresStateStore(PostgresStoreConfig(dsn=SecretStr(item['dsn']), sslmode='disable')))
original = module._transfer
def crash(repository, entries, **kwargs):
    original(repository, [next(iter(entries))])
    os._exit(42)
module._transfer = crash
migrate_legacy_pair(opened[0], DispatchWitness(opened[1], 'original-witness-identity'),
    MigrationTarget(opened[2], cipher(), 'new-primary'), MigrationTarget(opened[3], cipher(), 'new-witness'),
    result_cipher=ResultCipher({'test': b'x' * 32}, 'test'), writers_stopped=True)
"""
    env = dict(os.environ, UCS_SYNTHETIC_MIGRATION_LOCATIONS=json.dumps(locations))
    child = subprocess.run([sys.executable, "-c", script, str(Path(__file__).parent)], env=env, capture_output=True, timeout=30)
    assert child.returncode == 42, child.stderr.decode(errors="replace")
    for target in (pt, wt):
        with pytest.raises(MetadataCryptoError):
            MetadataRepository(target.store, target.cipher, target.profile_id)
    assert old.get_receipt(req.actor.organization_id, req.operation_id) == saved
    assert provider.calls == 1


def test_migration_paginates_and_keeps_tenants_separate(migration):
    old = migration[0]
    for index in range(105):
        old.append_evidence(EvidenceRecord(evidenceId=f"evidence-{index:03}", organizationId="tenant-" + str(index % 2),
            kind="validation", phase="validation", payload={"index": index}))
    report = migrate(migration)
    new = reopen(migration)
    assert report["primaryDocuments"] == 210
    for org in ("tenant-0", "tenant-1"):
        assert new.list_evidence(org) == old.list_evidence(org)
    assert new.list_evidence("other-tenant") == []


def test_migration_cli_uses_explicit_locations_without_echoing_keys(migration, monkeypatch, capsys):
    import base64
    import json
    import sys
    from universal_connection_service.metadata_migration import main
    old, witness, pt, wt = migration
    req = request()
    raw = approve(old, req, raw=req.actor.organization_id)
    service, provider = build_service(old, req)
    first = execute(service, req, raw)
    assert first.status == "success"
    descriptors = []
    for number, store in enumerate((old, witness.store, pt.store, wt.store)):
        if hasattr(store, "config"):
            descriptor = {"postgresUrl": store.config.dsn.get_secret_value()}
        else:
            descriptor = {"sqlitePath": store.path + (".cli" if number >= 2 else "")}
        descriptors.append(descriptor)
    for role, descriptor in zip(("SOURCE_PRIMARY", "SOURCE_WITNESS", "TARGET_PRIMARY", "TARGET_WITNESS"), descriptors):
        monkeypatch.setenv("UCS_MIGRATION_" + role + "_JSON", json.dumps(descriptor))
    metadata_keys = json.dumps(dict(activeKey="initial", keys={"initial": base64.b64encode(b"d" * 32).decode()}, indexKey=base64.b64encode(b"i" * 32).decode()))
    for prefix, profile in (("UCS_METADATA", pt.profile_id), ("UCS_WITNESS_METADATA", wt.profile_id)):
        monkeypatch.setenv(prefix + "_PROFILE_ID", profile)
        monkeypatch.setenv(prefix + "_KEYRING_JSON", metadata_keys)
    monkeypatch.setenv("UCS_RECEIPT_KEYRING_JSON", json.dumps(dict(activeKey="test", keys={"test": base64.b64encode(b"x" * 32).decode()})))
    monkeypatch.setenv("UCS_EXECUTION_WITNESS_ID", witness.witness_id)
    monkeypatch.setattr(sys, "argv", ["metadata_migration", "--confirm-writers-stopped-and-drained"])
    main()
    output = capsys.readouterr()
    assert metadata_keys not in output.out + output.err
    assert json.loads(output.out)["witnessDocuments"] == 2
    extra = []
    try:
        targets = []
        for descriptor, target in zip(descriptors[2:], (pt, wt)):
            physical = target.store if "postgresUrl" in descriptor else SQLiteStateStore(descriptor["sqlitePath"], must_exist=True)
            if physical is not target.store:
                extra.append(physical)
            targets.append(MigrationTarget(physical, target.cipher, target.profile_id))
        new = reopen((old, witness, *targets))
        recovered, unused = build_service(new, req)
        assert execute(recovered, req, raw).receipt_id == first.receipt_id
        assert provider.calls == 1 and unused.calls == 0
    finally:
        for physical in extra:
            physical.close()
