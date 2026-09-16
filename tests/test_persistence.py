import asyncio
import json
from datetime import datetime, timedelta, timezone

from universal_connection_service.contracts import (
    ActorRef,
    AuthRequirement,
    ConnectionRequest,
    ConnectorManifest,
    ConnectorResult,
    ExecutionContext,
    ServiceRef,
)
from universal_connection_service.openapi_validation import (
    OpenAPIValidationReport,
    OpenAPIValidationService,
)
from universal_connection_service.persistence import SQLiteStateStore
from universal_connection_service.policy import ApprovalGrant, InMemoryApprovalVerifier
from universal_connection_service.registry import ConnectorRegistry, Registration
from universal_connection_service.service import ConnectionService


class StubConnector:
    def __init__(self, connector_id="global-connector", *, strategy="api"):
        self.connector_id = connector_id
        self.strategy = strategy
        self.calls = 0

    def manifest(self):
        return ConnectorManifest(
            connectorId=self.connector_id,
            serviceId="records",
            name=self.connector_id,
            version="1.0.0",
            strategy=self.strategy,
            capabilities=("records.read", "records.write"),
            auth=AuthRequirement(type="none"),
        )

    async def health_check(self, ctx):
        return True

    async def execute(self, capability, input, ctx):
        self.calls += 1
        return ConnectorResult(status="success", data={"ok": True})


class PassingValidator:
    def validate(self, schema, sandbox_url):
        return OpenAPIValidationReport(
            staticValid=True,
            dynamicAttempted=True,
            dynamicPassed=True,
            passed=True,
            exitCode=0,
        )


def request(
    *,
    organization_id="org-1",
    capability="records.read",
    operation="read",
    request_id="r1",
    input=None,
):
    return ConnectionRequest(
        requestId=request_id,
        actor=ActorRef(userId="u1", organizationId=organization_id, agentId="a1"),
        service=ServiceRef(id="records", name="Records"),
        capability=capability,
        operation=operation,
        input=input or {},
    )


def context(
    *,
    organization_id="org-1",
    request_id="r1",
    approval_id=None,
    credential_handle=None,
):
    return ExecutionContext(
        requestId=request_id,
        userId="u1",
        organizationId=organization_id,
        approvalId=approval_id,
        credentialHandle=credential_handle,
        deadlineMs=1000,
    )


def test_sqlite_connector_metadata_survives_restart(tmp_path):
    path = tmp_path / "ucs-state.sqlite3"
    store = SQLiteStateStore(path)
    registry = ConnectorRegistry(state_store=store)
    registration = Registration(
        connector=StubConnector("tenant-connector"),
        status="generated",
        organization_id="org-1",
    )
    registry.register(registration)
    registration.set_status("validated")
    store.close()

    reopened = SQLiteStateStore(path)
    records = reopened.list_connectors("org-1")
    assert len(records) == 1
    assert records[0].manifest.connector_id == "tenant-connector"
    assert records[0].status == "validated"
    reopened.close()


def test_registry_prefers_tenant_connector_and_keeps_other_tenants_isolated():
    registry = ConnectorRegistry()
    global_registration = Registration(
        connector=StubConnector("global-connector"),
        status="trusted",
    )
    tenant_registration = Registration(
        connector=StubConnector("tenant-connector"),
        status="trusted",
        organization_id="org-1",
    )
    other_registration = Registration(
        connector=StubConnector("other-connector"),
        status="trusted",
        organization_id="org-2",
    )
    registry.register(global_registration)
    registry.register(tenant_registration)
    registry.register(other_registration)

    assert registry.trusted("records", "records.read", "org-1") is tenant_registration
    assert registry.trusted("records", "records.read", "org-2") is other_registration
    assert registry.trusted("records", "records.read", "org-3") is global_registration

    org1_ids = {manifest.connector_id for manifest in registry.manifests("org-1")}
    assert org1_ids == {"global-connector", "tenant-connector"}
    assert "other-connector" not in org1_ids


def test_validation_persists_lifecycle_and_evidence():
    store = SQLiteStateStore(":memory:")
    registry = ConnectorRegistry(state_store=store)
    registration = Registration(
        connector=StubConnector("candidate"),
        status="generated",
        organization_id="org-1",
    )
    registry.register(registration)

    report = OpenAPIValidationService(
        PassingValidator(),
        evidence_store=store,
    ).validate_registration(
        registration,
        schema={"openapi": "3.1.0"},
        sandbox_url="http://127.0.0.1:9999",
    )

    assert report.passed is True
    persisted = store.list_connectors("org-1")
    assert persisted[0].status == "validated"
    evidence = store.list_evidence("org-1", kind="validation")
    assert len(evidence) == 1
    assert evidence[0].connector_id == "candidate"
    assert evidence[0].payload["report"]["passed"] is True
    store.close()


def test_policy_evidence_and_execution_audit_are_persisted_without_request_secrets():
    store = SQLiteStateStore(":memory:")
    registry = ConnectorRegistry(state_store=store)
    registry.register(Registration(connector=StubConnector(), status="trusted"))
    service = ConnectionService(
        registry,
        audit_store=store,
        evidence_store=store,
    )
    req = request(input={"secret": "raw-request-secret"})

    plan = service.compiler.compile(req)
    assert plan.policy_decision == "ALLOW"
    result = asyncio.run(
        service.execute(
            req,
            context(credential_handle="opaque-credential-handle"),
        )
    )
    assert result.status == "success"

    evidence = store.list_evidence("org-1", request_id="r1", kind="policy_decision")
    assert {item.phase for item in evidence} == {"plan", "execution"}
    audit = store.list_audit("org-1", request_id="r1")
    assert len(audit) == 1
    assert audit[0].audit_id == result.audit_id
    assert audit[0].status == "success"

    serialized = json.dumps(
        {
            "evidence": [item.model_dump(by_alias=True, mode="json") for item in evidence],
            "audit": [item.model_dump(by_alias=True, mode="json") for item in audit],
        }
    )
    assert "raw-request-secret" not in serialized
    assert "opaque-credential-handle" not in serialized
    store.close()


def test_approval_evidence_and_audit_store_only_hashed_reference():
    store = SQLiteStateStore(":memory:")
    registry = ConnectorRegistry(state_store=store)
    registry.register(Registration(connector=StubConnector(), status="trusted"))
    raw_approval_id = "approval-secret-reference"
    verifier = InMemoryApprovalVerifier(
        (
            ApprovalGrant(
                approvalId=raw_approval_id,
                requestId="r-write",
                organizationId="org-1",
                userId="u1",
                agentId="a1",
                serviceId="records",
                capability="records.write",
                operation="update",
                expiresAt=datetime.now(timezone.utc) + timedelta(minutes=5),
            ),
        )
    )
    service = ConnectionService(
        registry,
        approval_verifier=verifier,
        audit_store=store,
        evidence_store=store,
    )
    req = request(
        capability="records.write",
        operation="update",
        request_id="r-write",
    )

    result = asyncio.run(
        service.execute(
            req,
            context(request_id="r-write", approval_id=raw_approval_id),
        )
    )
    assert result.status == "failed"
    assert result.error.code == "DURABLE_EXECUTION_REQUIRED"

    approval_evidence = store.list_evidence(
        "org-1",
        request_id="r-write",
        kind="approval_verification",
    )
    assert len(approval_evidence) == 1
    assert approval_evidence[0].payload["valid"] is False
    assert approval_evidence[0].payload["approvalRefHash"]

    audit = store.list_audit("org-1", request_id="r-write")
    assert len(audit) == 1
    assert audit[0].approval_ref_hash

    serialized = json.dumps(
        {
            "evidence": [item.model_dump(by_alias=True, mode="json") for item in approval_evidence],
            "audit": [item.model_dump(by_alias=True, mode="json") for item in audit],
        }
    )
    assert raw_approval_id not in serialized
    store.close()


def test_audit_and_evidence_queries_are_tenant_scoped():
    store = SQLiteStateStore(":memory:")
    registry = ConnectorRegistry(state_store=store)
    registry.register(Registration(connector=StubConnector(), status="trusted"))
    service = ConnectionService(registry, audit_store=store, evidence_store=store)

    first = asyncio.run(service.execute(request(organization_id="org-1", request_id="o1"), context(organization_id="org-1", request_id="o1")))
    second = asyncio.run(service.execute(request(organization_id="org-2", request_id="o2"), context(organization_id="org-2", request_id="o2")))
    assert first.status == second.status == "success"

    assert [event.request_id for event in store.list_audit("org-1")] == ["o1"]
    assert [event.request_id for event in store.list_audit("org-2")] == ["o2"]
    assert {item.request_id for item in store.list_evidence("org-1")} == {"o1"}
    assert {item.request_id for item in store.list_evidence("org-2")} == {"o2"}
    store.close()
