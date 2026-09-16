import asyncio
import base64
import hashlib
import json
from pathlib import Path

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from universal_connection_service.approvals import PersistentApprovalVerifier
from universal_connection_service.auto_connect import AutoConnectAdvanceCommand, AutoConnectStartCommand
from universal_connection_service.build_auto_connect import BuildAwareAutoConnectOrchestrator, VerifiedBuildCoordinator
from universal_connection_service.build_pipeline import (
    ConnectorBuildPipeline,
    Ed25519BuildSigner,
    FilesystemBuildArtifactStore,
    FilesystemPackageWriter,
    GeneratedOpenAPIPackageBuilder,
    MCPPackageAcquirer,
    OpenAPIBuildDescriptor,
    OpenAPICatalogProvider,
    PinnedOpenAPIDocumentFetcher,
)
from universal_connection_service.contracts import ActorRef, AuthRequirement, ConnectionRequest, DiscoveryCandidateRef, ServiceRef
from universal_connection_service.control_plane import ControlPlanePrincipal, ControlPlaneService
from universal_connection_service.discovery import DiscoveryEngine, DiscoveryQuery
from universal_connection_service.openapi_validation import OpenAPIValidationReport, OpenAPIValidationService
from universal_connection_service.packages import ConnectorPackageLoader, Ed25519PackageVerifier, FilesystemPackageSource
from universal_connection_service.persistence import SQLiteStateStore
from universal_connection_service.registry import ConnectorRegistry
from universal_connection_service.rehydration import ConnectorRuntimeRehydrator
from universal_connection_service.service import ConnectionService


SCHEMA = {
    "openapi": "3.0.3",
    "info": {"title": "Records", "version": "1.0.0"},
    "paths": {
        "/records": {
            "get": {
                "operationId": "records.read",
                "x-ucs-capability": "records.read",
                "responses": {"200": {"description": "ok"}},
            }
        }
    },
}
SCHEMA_BYTES = json.dumps(SCHEMA, sort_keys=True, separators=(",", ":")).encode()
SCHEMA_DIGEST = hashlib.sha256(SCHEMA_BYTES).hexdigest()


class PassingValidator:
    def validate(self, schema, sandbox_url):
        assert schema["openapi"] == "3.0.3"
        assert sandbox_url.startswith("http://127.0.0.1")
        return OpenAPIValidationReport(
            staticValid=True,
            dynamicAttempted=True,
            dynamicPassed=True,
            passed=True,
            exitCode=0,
        )


def principal(*scopes):
    return ControlPlanePrincipal(
        subject="owner",
        tokenId="owner-token",
        organizations=("org-1",),
        scopes=scopes,
    )


def request():
    return ConnectionRequest(
        requestId="build-request-1",
        actor=ActorRef(userId="u1", organizationId="org-1", agentId="a1"),
        service=ServiceRef(id="records", name="Records"),
        capability="records.read",
        operation="read",
        input={"secret": "never-persist-build-input"},
        readOnly=True,
    )


def descriptor():
    return OpenAPIBuildDescriptor(
        serviceId="records",
        serviceName="Records",
        version="1.0.0",
        schemaUrl="https://records.example/openapi.json",
        schemaSha256=SCHEMA_DIGEST,
        baseUrl="https://records.example",
        sandboxUrl="http://127.0.0.1:9999",
    )


def package_runtime(tmp_path: Path):
    private = Ed25519PrivateKey.generate()
    private_raw = private.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    public_raw = private.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    signer = Ed25519BuildSigner(
        signer_ref="builder-test",
        private_key=base64.b64encode(private_raw).decode(),
    )
    builder = GeneratedOpenAPIPackageBuilder(FilesystemPackageWriter(tmp_path), signer)
    loader = ConnectorPackageLoader(
        FilesystemPackageSource(tmp_path),
        Ed25519PackageVerifier({"builder-test": public_raw}),
    )
    return builder, loader


def schema_fetcher():
    transport = httpx.MockTransport(
        lambda request: httpx.Response(200, content=SCHEMA_BYTES, headers={"content-type": "application/json"})
    )
    return PinnedOpenAPIDocumentFetcher(client_factory=lambda: httpx.Client(transport=transport))


def test_openapi_catalog_discovers_only_matching_pinned_service():
    catalog = OpenAPICatalogProvider((descriptor(),))
    found = catalog.discover(DiscoveryQuery(serviceId="records", serviceName="Records", capability="records.read"))
    assert len(found) == 1
    assert found[0].strategy == "api"
    assert found[0].requires_build is True
    assert found[0].actionable is False
    assert catalog.descriptor_for(found[0].candidate_id).schema_sha256 == SCHEMA_DIGEST


def test_openapi_build_validates_signs_and_verifies_package(tmp_path):
    store = SQLiteStateStore(":memory:")
    registry = ConnectorRegistry(state_store=store)
    catalog = OpenAPICatalogProvider((descriptor(),))
    builder, loader = package_runtime(tmp_path)
    pipeline = ConnectorBuildPipeline(
        registry=registry,
        evidence_store=store,
        openapi_descriptors=(catalog,),
        openapi_fetcher=schema_fetcher(),
        openapi_validator=OpenAPIValidationService(PassingValidator(), evidence_store=store),
        package_builder=builder,
    )
    candidate = catalog.discover(DiscoveryQuery(serviceId="records", serviceName="Records", capability="records.read"))[0]
    result = pipeline.build(candidate, request())

    assert result.passed is True
    assert result.code == "OPENAPI_CONNECTOR_BUILT"
    assert result.package_digest
    registration = registry.exact("org-1", result.connector_id, result.connector_version)
    assert registration is not None and registration.status == "validated"
    loaded = loader.load(result.package_digest)
    assert loaded.manifest.connector == registration.manifest
    assert (tmp_path / f"{result.package_digest}.zip").exists()
    assert (tmp_path / f"{result.package_digest}.sig.json").exists()

    serialized = " ".join(item.model_dump_json(by_alias=True) for item in store.list_evidence("org-1"))
    assert "https://records.example/openapi.json" not in serialized
    assert "never-persist-build-input" not in serialized
    store.close()


def test_verified_build_can_pin_after_trust_and_rehydrate(tmp_path):
    store = SQLiteStateStore(":memory:")
    registry = ConnectorRegistry(state_store=store)
    catalog = OpenAPICatalogProvider((descriptor(),))
    builder, loader = package_runtime(tmp_path)
    pipeline = ConnectorBuildPipeline(
        registry=registry,
        evidence_store=store,
        openapi_descriptors=(catalog,),
        openapi_fetcher=schema_fetcher(),
        openapi_validator=OpenAPIValidationService(PassingValidator(), evidence_store=store),
        package_builder=builder,
    )
    coordinator = VerifiedBuildCoordinator(pipeline=pipeline, package_loader=loader, evidence_store=store)
    candidate = catalog.discover(DiscoveryQuery(serviceId="records", serviceName="Records", capability="records.read"))[0]
    result = coordinator.build(candidate, request())
    assert result.passed is True

    registration = registry.exact("org-1", result.connector_id, result.connector_version)
    registration.set_status("trusted")
    coordinator.pin_after_trust("org-1", result.connector_id, result.connector_version)
    pins = [
        item for item in store.list_evidence("org-1", kind="validation")
        if item.payload.get("type") == "package_verification"
    ]
    assert len(pins) == 1
    assert pins[0].payload["digest"] == result.package_digest

    new_registry = ConnectorRegistry(state_store=store)
    report = ConnectorRuntimeRehydrator(
        state_store=store,
        evidence_store=store,
        registry=new_registry,
        loader=loader,
    ).rehydrate()
    assert report.loaded == 1
    assert new_registry.trusted("records", "records.read", "org-1") is not None
    store.close()


def test_mcpb_acquisition_verifies_hash_and_never_executes(tmp_path):
    package = b"not executable by UCS-13; just a verified MCPB artifact"
    digest = hashlib.sha256(package).hexdigest()
    calls = []

    def handler(request):
        calls.append(str(request.url))
        return httpx.Response(200, content=package)

    acquirer = MCPPackageAcquirer(
        FilesystemBuildArtifactStore(tmp_path),
        client_factory=lambda: httpx.Client(transport=httpx.MockTransport(handler)),
    )
    candidate = DiscoveryCandidateRef(
        candidateId="mcpb-1",
        source="mcp_registry",
        name="Records MCPB",
        version="1.0.0",
        strategy="mcp",
        transport="stdio",
        packageRegistry="mcpb",
        packageIdentifier="https://packages.example/records.mcpb",
        packageVersion="1.0.0",
        packageSha256=digest,
        authRequirement=AuthRequirement(type="none"),
        confidence=100,
        actionable=False,
        requiresBuild=True,
    )
    assert acquirer.acquire(candidate) == digest
    assert calls == ["https://packages.example/records.mcpb"]
    assert (tmp_path / f"{digest}.mcpb").read_bytes() == package


def test_auto_connect_builds_openapi_then_waits_for_normal_promotion(tmp_path):
    store = SQLiteStateStore(":memory:")
    registry = ConnectorRegistry(state_store=store)
    catalog = OpenAPICatalogProvider((descriptor(),))
    discovery = DiscoveryEngine((catalog,))
    verifier = PersistentApprovalVerifier(store)
    service = ConnectionService(
        registry,
        approval_verifier=verifier,
        audit_store=store,
        evidence_store=store,
        discovery_engine=discovery,
    )
    control = ControlPlaneService(
        registry=registry,
        connection_service=service,
        state_store=store,
        evidence_store=store,
        approval_store=store,
    )
    builder, loader = package_runtime(tmp_path)
    pipeline = ConnectorBuildPipeline(
        registry=registry,
        evidence_store=store,
        openapi_descriptors=(catalog,),
        openapi_fetcher=schema_fetcher(),
        openapi_validator=OpenAPIValidationService(PassingValidator(), evidence_store=store),
        package_builder=builder,
    )
    coordinator = VerifiedBuildCoordinator(pipeline=pipeline, package_loader=loader, evidence_store=store)
    orchestrator = BuildAwareAutoConnectOrchestrator(
        build_coordinator=coordinator,
        workflow_store=store,
        connection_service=service,
        control_plane_service=control,
        registry=registry,
        approval_store=store,
        evidence_store=store,
    )
    actor = principal("connectors:review", "connectors:validate", "approvals:issue", "connectors:promote")
    req = request()
    started = asyncio.run(orchestrator.start(actor, AutoConnectStartCommand(request=req)))
    assert started.workflow.stage == "awaiting_promotion_approval"
    assert started.workflow.last_code == "PROMOTION_APPROVAL_REQUIRED"
    assert started.workflow.connector_id.startswith("openapi-built-")

    workflow, approval = orchestrator.issue_promotion_approval(
        actor, started.workflow.workflow_id, "org-1", expires_in_seconds=300
    )
    assert workflow.stage == "awaiting_promotion"
    ready = asyncio.run(
        orchestrator.promote_and_advance(
            actor,
            started.workflow.workflow_id,
            AutoConnectAdvanceCommand(
                request=req,
                promotionApprovalId=approval.approval_id,
                executeWhenReady=False,
            ),
        )
    )
    assert ready.workflow.stage == "ready_to_execute"
    assert registry.trusted("records", "records.read", "org-1") is not None
    pins = [item for item in store.list_evidence("org-1") if item.payload.get("type") == "package_verification"]
    assert len(pins) == 1

    row = store._connection.execute("SELECT * FROM connection_workflow").fetchone()
    assert approval.approval_id not in str(dict(row))
    assert "never-persist-build-input" not in str(dict(row))
    store.close()
