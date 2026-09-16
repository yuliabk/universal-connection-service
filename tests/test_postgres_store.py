import asyncio
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from pydantic import SecretStr

from universal_connection_service.approvals import (
    PersistentApprovalVerifier,
    approval_ref_hash,
)
from universal_connection_service.contracts import (
    ActorRef,
    AuthRequirement,
    ConnectionRequest,
    ConnectorManifest,
    ConnectorResult,
    ExecutionContext,
    ServiceRef,
)
from universal_connection_service.persistence import AuditEvent, ConnectorStateRecord, EvidenceRecord
from universal_connection_service.policy import ApprovalGrant
from universal_connection_service.postgres_store import (
    LATEST_SCHEMA_VERSION,
    PostgresStateStore,
    PostgresStoreConfig,
)
from universal_connection_service.registry import ConnectorRegistry, Registration
from universal_connection_service.service import ConnectionService


DSN = os.getenv("UCS_TEST_POSTGRES_URL")
pytestmark = pytest.mark.skipif(not DSN, reason="UCS_TEST_POSTGRES_URL is not configured")


class StubConnector:
    def __init__(self, connector_id: str):
        self.connector_id = connector_id
        self.calls = 0

    def manifest(self):
        return ConnectorManifest(
            connectorId=self.connector_id,
            serviceId="records",
            name=self.connector_id,
            version="1.0.0",
            strategy="api",
            capabilities=("records.read", "records.write"),
            auth=AuthRequirement(type="none"),
        )

    async def health_check(self, ctx):
        return True

    async def execute(self, capability, input, ctx):
        self.calls += 1
        return ConnectorResult(status="success", data={"ok": True})


def config(*, auto_migrate=True):
    return PostgresStoreConfig(
        dsn=SecretStr(DSN),
        minSize=1,
        maxSize=1,
        timeoutSeconds=10,
        sslmode="disable",
        autoMigrate=auto_migrate,
    )


def grant(raw_id: str, *, request_id: str, organization_id: str):
    return ApprovalGrant(
        approvalId=raw_id,
        requestId=request_id,
        organizationId=organization_id,
        userId="u1",
        agentId="a1",
        serviceId="records",
        capability="records.write",
        operation="update",
        expiresAt=datetime.now(timezone.utc) + timedelta(minutes=5),
    )


def request(*, request_id: str, organization_id: str):
    return ConnectionRequest(
        requestId=request_id,
        actor=ActorRef(userId="u1", organizationId=organization_id, agentId="a1"),
        service=ServiceRef(id="records", name="Records"),
        capability="records.write",
        operation="update",
        input={"secret": "must-not-enter-control-plane"},
    )


def context(*, request_id: str, organization_id: str, approval_id: str):
    return ExecutionContext(
        requestId=request_id,
        userId="u1",
        organizationId=organization_id,
        approvalId=approval_id,
        deadlineMs=1000,
    )


def test_postgres_migrations_reach_latest_version_and_reopen_cleanly():
    store = PostgresStateStore(config(auto_migrate=True))
    assert store.schema_version() == LATEST_SCHEMA_VERSION
    store.close()

    reopened = PostgresStateStore(config(auto_migrate=False))
    assert reopened.schema_version() == LATEST_SCHEMA_VERSION
    reopened.close()


def test_postgres_persists_tenant_state_evidence_and_audit():
    store = PostgresStateStore(config(auto_migrate=True))
    suffix = uuid4().hex
    organization_id = f"org-{suffix}"
    connector_id = f"connector-{suffix}"
    request_id = f"request-{suffix}"
    connector = StubConnector(connector_id)
    manifest = connector.manifest()

    store.upsert_connector(
        ConnectorStateRecord(
            organizationId=organization_id,
            manifest=manifest,
            status="validated",
        )
    )
    store.append_evidence(
        EvidenceRecord(
            evidenceId=f"e-{suffix}",
            organizationId=organization_id,
            kind="policy_decision",
            phase="plan",
            requestId=request_id,
            connectorId=connector_id,
            payload={"decision": "ALLOW"},
        )
    )
    store.append_audit(
        AuditEvent(
            auditId=f"a-{suffix}",
            requestId=request_id,
            organizationId=organization_id,
            userId="u1",
            agentId="a1",
            serviceId="records",
            capability="records.read",
            operation="read",
            status="success",
            connectorId=connector_id,
            policyDecision="ALLOW",
        )
    )

    assert store.list_connectors(organization_id)[0].manifest.connector_id == connector_id
    assert store.list_evidence(organization_id, request_id=request_id)[0].payload == {"decision": "ALLOW"}
    assert store.list_audit(organization_id, request_id=request_id)[0].connector_id == connector_id
    assert store.list_connectors(f"other-{suffix}") == []
    store.close()


def test_persistent_approval_store_hashes_raw_id_and_consumes_atomically():
    store1 = PostgresStateStore(config(auto_migrate=True))
    store2 = PostgresStateStore(config(auto_migrate=False))
    suffix = uuid4().hex
    raw_id = f"approval-secret-{suffix}"
    organization_id = f"org-{suffix}"
    request_id = f"request-{suffix}"
    verifier = PersistentApprovalVerifier(store1)
    record = verifier.register(grant(raw_id, request_id=request_id, organization_id=organization_id))

    assert record.approval_ref_hash == approval_ref_hash(raw_id)
    assert raw_id not in record.model_dump_json(by_alias=True)

    with store1._pool.connection() as conn:
        row = conn.execute(
            "SELECT approval_ref_hash, request_id FROM ucs_internal.approval_grant WHERE approval_ref_hash = %s",
            (record.approval_ref_hash,),
        ).fetchone()
    assert row["approval_ref_hash"] == approval_ref_hash(raw_id)
    assert raw_id not in str(dict(row))

    consumed_at = datetime.now(timezone.utc)
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(
            executor.map(
                lambda store: store.consume_approval(record.approval_ref_hash, consumed_at),
                (store1, store2),
            )
        )
    assert sorted(results) == [False, True]
    assert store1.get_approval(record.approval_ref_hash).consumed_at is not None
    store1.close()
    store2.close()


def test_persistent_approval_verifier_allows_exactly_one_service_execution():
    store = PostgresStateStore(config(auto_migrate=True))
    suffix = uuid4().hex
    raw_id = f"approval-{suffix}"
    organization_id = f"org-{suffix}"
    request_id = f"request-{suffix}"
    connector = StubConnector(f"runtime-{suffix}")
    registry = ConnectorRegistry(state_store=store)
    registry.register(
        Registration(
            connector=connector,
            status="trusted",
            organization_id=organization_id,
        )
    )
    verifier = PersistentApprovalVerifier(store)
    verifier.register(grant(raw_id, request_id=request_id, organization_id=organization_id))
    service = ConnectionService(
        registry,
        approval_verifier=verifier,
        audit_store=store,
        evidence_store=store,
    )
    req = request(request_id=request_id, organization_id=organization_id)
    ctx = context(request_id=request_id, organization_id=organization_id, approval_id=raw_id)

    first = asyncio.run(service.execute(req, ctx))
    second = asyncio.run(service.execute(req, ctx))

    assert first.status == "success"
    assert second.status == "failed"
    assert second.error.code == "APPROVAL_ALREADY_USED"
    assert connector.calls == 1

    audits = store.list_audit(organization_id, request_id=request_id)
    evidence = store.list_evidence(organization_id, request_id=request_id)
    serialized = str(
        {
            "audit": [item.model_dump(by_alias=True, mode="json") for item in audits],
            "evidence": [item.model_dump(by_alias=True, mode="json") for item in evidence],
        }
    )
    assert raw_id not in serialized
    assert "must-not-enter-control-plane" not in serialized
    store.close()
