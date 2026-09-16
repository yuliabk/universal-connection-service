import asyncio
import hashlib

from fastapi import FastAPI
from fastapi.testclient import TestClient
from mcp import Client
from mcp.server.mcpserver import MCPServer

from universal_connection_service.contracts import (
    ActorRef,
    AuthRequirement,
    ConnectionRequest,
    ConnectorManifest,
    ConnectorResult,
    DiscoveryCandidateRef,
    ServiceRef,
)
from universal_connection_service.control_plane import (
    ControlPlaneCredential,
    ControlPlanePrincipal,
    ControlPlaneService,
    MCPValidationCommand,
    PromotionApprovalCommand,
    PromotionCommand,
    StaticBearerAuthenticator,
    build_control_plane_router,
)
from universal_connection_service.discovery import DiscoveryEngine
from universal_connection_service.mcp_validation import MCPValidationService
from universal_connection_service.persistence import EvidenceRecord, SQLiteStateStore
from universal_connection_service.registry import ConnectorRegistry, Registration
from universal_connection_service.service import ConnectionService


class StubConnector:
    def __init__(self, connector_id="validated-records", version="1.0.0"):
        self.connector_id = connector_id
        self.version = version

    def manifest(self):
        return ConnectorManifest(
            connectorId=self.connector_id,
            serviceId="records",
            name="Validated Records",
            version=self.version,
            strategy="mcp",
            capabilities=("records.read",),
            auth=AuthRequirement(type="none"),
        )

    async def health_check(self, ctx):
        return True

    async def execute(self, capability, input, ctx):
        return ConnectorResult(status="success", data={"ok": True})


class StaticDiscoveryProvider:
    def __init__(self, candidate):
        self.candidate = candidate
        self.calls = 0

    def discover(self, query):
        self.calls += 1
        return (self.candidate,)


def principal(*scopes, subject="owner", organizations=("org-1",), token_id="owner-token"):
    return ControlPlanePrincipal(
        subject=subject,
        tokenId=token_id,
        organizations=organizations,
        scopes=scopes,
    )


def bearer_auth(raw_token="control-plane-secret"):
    credential = ControlPlaneCredential(
        tokenSha256=hashlib.sha256(raw_token.encode()).hexdigest(),
        subject="owner",
        tokenId="owner-token",
        organizations=("org-1",),
        scopes=("connectors:review", "connectors:validate", "approvals:issue", "connectors:promote"),
    )
    return raw_token, StaticBearerAuthenticator((credential,))


def validated_fixture(*, with_evidence=True):
    store = SQLiteStateStore(":memory:")
    registry = ConnectorRegistry(state_store=store)
    registration = Registration(
        connector=StubConnector(),
        status="validated",
        organization_id="org-1",
    )
    registry.register(registration)
    if with_evidence:
        store.append_evidence(
            EvidenceRecord(
                evidenceId="validation-e1",
                organizationId="org-1",
                kind="validation",
                phase="validation",
                requestId="validation-request",
                connectorId="validated-records",
                payload={
                    "type": "mcp_candidate_validation",
                    "passed": True,
                    "code": "MCP_CANDIDATE_VALIDATED",
                    "lifecycle": "validated",
                },
            )
        )
    connection_service = ConnectionService(
        registry,
        audit_store=store,
        evidence_store=store,
    )
    cp = ControlPlaneService(
        registry=registry,
        connection_service=connection_service,
        state_store=store,
        evidence_store=store,
        approval_store=store,
    )
    return store, registry, registration, cp


def test_static_bearer_authenticator_hashes_token_and_enforces_org_scope():
    raw, auth = bearer_auth()
    assert auth.authenticate(None) is None
    assert auth.authenticate("Bearer wrong") is None
    actor = auth.authenticate(f"Bearer {raw}")
    assert actor is not None
    assert actor.subject == "owner"
    assert actor.allows("connectors:review", "org-1") is True
    assert actor.allows("connectors:review", "org-2") is False


def test_router_fails_closed_when_disabled_and_rejects_bad_bearer():
    store, _, _, cp = validated_fixture()
    disabled_app = FastAPI()
    disabled_app.include_router(build_control_plane_router(cp, None))
    response = TestClient(disabled_app).get(
        "/v1/control-plane/connectors/validated-records/review",
        params={"organizationId": "org-1", "version": "1.0.0"},
    )
    assert response.status_code == 503

    _, auth = bearer_auth()
    enabled_app = FastAPI()
    enabled_app.include_router(build_control_plane_router(cp, auth))
    response = TestClient(enabled_app).get(
        "/v1/control-plane/connectors/validated-records/review",
        params={"organizationId": "org-1", "version": "1.0.0"},
        headers={"Authorization": "Bearer wrong"},
    )
    assert response.status_code == 401
    store.close()


def test_review_requires_scope_and_reports_passing_validation_evidence():
    store, _, _, cp = validated_fixture()
    review = cp.review(
        principal("connectors:review"),
        "org-1",
        "validated-records",
        "1.0.0",
    )
    assert review.lifecycle == "validated"
    assert review.runtime_available is True
    assert review.validation_ready is True
    assert review.validation_evidence[0].passed is True

    try:
        cp.review(principal("connectors:review", organizations=("org-2",)), "org-1", "validated-records", "1.0.0")
        assert False, "expected authorization failure"
    except Exception as exc:
        assert getattr(exc, "code", None) == "CONTROL_PLANE_FORBIDDEN"
    store.close()


def test_promotion_approval_is_hashed_and_promotes_validated_connector_to_trusted():
    store, registry, registration, cp = validated_fixture()
    approval = cp.issue_promotion_approval(
        principal("approvals:issue"),
        "validated-records",
        PromotionApprovalCommand(
            organizationId="org-1",
            version="1.0.0",
            promotionId="promotion-001",
            expiresInSeconds=300,
        ),
    )
    raw = approval.approval_id
    ref = hashlib.sha256(raw.encode()).hexdigest()
    assert raw != ref
    assert registration.status == "awaiting_approval"
    persisted = store.get_approval(ref)
    assert persisted is not None
    assert persisted.approval_ref_hash == ref
    assert raw not in persisted.model_dump_json(by_alias=True)

    result = cp.promote(
        principal("connectors:promote"),
        "validated-records",
        PromotionCommand(
            organizationId="org-1",
            version="1.0.0",
            promotionId="promotion-001",
            approvalId=raw,
        ),
    )
    assert result.lifecycle == "trusted"
    assert result.approval_ref_hash == ref
    assert registration.status == "trusted"
    assert registration.approval_id == ref
    assert registry.trusted("records", "records.read", "org-1") is registration
    consumed = store.get_approval(ref)
    assert consumed is not None and consumed.consumed_at is not None

    evidence = store.list_evidence("org-1", request_id="promotion-001", kind="approval_verification")
    serialized = " ".join(item.model_dump_json(by_alias=True) for item in evidence)
    assert "promotion_approval_issued" in serialized
    assert "connector_promoted" in serialized
    assert raw not in serialized
    store.close()


def test_promotion_requires_passing_validation_evidence():
    store, _, _, cp = validated_fixture(with_evidence=False)
    try:
        cp.issue_promotion_approval(
            principal("approvals:issue"),
            "validated-records",
            PromotionApprovalCommand(
                organizationId="org-1",
                version="1.0.0",
                promotionId="promotion-002",
            ),
        )
        assert False, "expected promotion readiness failure"
    except Exception as exc:
        assert getattr(exc, "code", None) == "CONNECTOR_NOT_PROMOTABLE"
    store.close()


def test_distinct_approver_policy_can_be_enforced():
    store, registry, _, base = validated_fixture()
    cp = ControlPlaneService(
        registry=registry,
        connection_service=base.connection_service,
        state_store=store,
        evidence_store=store,
        approval_store=store,
        require_distinct_approver=True,
    )
    approval = cp.issue_promotion_approval(
        principal("approvals:issue", subject="alice", token_id="alice-token"),
        "validated-records",
        PromotionApprovalCommand(
            organizationId="org-1",
            version="1.0.0",
            promotionId="promotion-003",
        ),
    )
    try:
        cp.promote(
            principal("connectors:promote", subject="alice", token_id="alice-promoter"),
            "validated-records",
            PromotionCommand(
                organizationId="org-1",
                version="1.0.0",
                promotionId="promotion-003",
                approvalId=approval.approval_id,
            ),
        )
        assert False, "expected separation-of-duties failure"
    except Exception as exc:
        assert getattr(exc, "code", None) == "APPROVER_SEPARATION_REQUIRED"

    result = cp.promote(
        principal("connectors:promote", subject="bob", token_id="bob-token"),
        "validated-records",
        PromotionCommand(
            organizationId="org-1",
            version="1.0.0",
            promotionId="promotion-003",
            approvalId=approval.approval_id,
        ),
    )
    assert result.lifecycle == "trusted"
    store.close()


def test_router_end_to_end_review_approval_and_promotion():
    store, _, _, cp = validated_fixture()
    raw_token, auth = bearer_auth()
    app = FastAPI()
    app.include_router(build_control_plane_router(cp, auth))
    client = TestClient(app)
    headers = {"Authorization": f"Bearer {raw_token}"}

    review = client.get(
        "/v1/control-plane/connectors/validated-records/review",
        params={"organizationId": "org-1", "version": "1.0.0"},
        headers=headers,
    )
    assert review.status_code == 200
    assert review.json()["validationReady"] is True

    approval = client.post(
        "/v1/control-plane/connectors/validated-records/promotion-approvals",
        json={
            "organizationId": "org-1",
            "version": "1.0.0",
            "promotionId": "promotion-api-1",
            "expiresInSeconds": 300,
        },
        headers=headers,
    )
    assert approval.status_code == 200

    promoted = client.post(
        "/v1/control-plane/connectors/validated-records/promote",
        json={
            "organizationId": "org-1",
            "version": "1.0.0",
            "promotionId": "promotion-api-1",
            "approvalId": approval.json()["approvalId"],
        },
        headers=headers,
    )
    assert promoted.status_code == 200
    assert promoted.json()["lifecycle"] == "trusted"
    store.close()


mcp_server = MCPServer("Control Plane MCP", version="1.0.0")


@mcp_server.tool()
def get_weather(city: str) -> dict:
    return {"city": city, "temperature": 20}


def test_candidate_bound_mcp_validation_uses_server_side_discovery_result():
    candidate = DiscoveryCandidateRef(
        candidateId="candidate-weather",
        source="mcp_registry",
        name="Weather MCP",
        version="1.0.0",
        strategy="mcp",
        transport="streamable-http",
        endpoint="https://weather.example/mcp",
        authRequirement=AuthRequirement(type="none"),
        confidence=100,
        actionable=True,
        requiresBuild=False,
    )
    provider = StaticDiscoveryProvider(candidate)
    store = SQLiteStateStore(":memory:")
    registry = ConnectorRegistry(state_store=store)
    connection_service = ConnectionService(
        registry,
        evidence_store=store,
        discovery_engine=DiscoveryEngine((provider,)),
    )
    validator = MCPValidationService(
        registry,
        evidence_store=store,
        client_factory=lambda: Client(mcp_server),
    )
    cp = ControlPlaneService(
        registry=registry,
        connection_service=connection_service,
        state_store=store,
        evidence_store=store,
        approval_store=store,
        mcp_validation_service=validator,
    )
    request = ConnectionRequest(
        requestId="weather-validation-1",
        actor=ActorRef(userId="u1", organizationId="org-1", agentId="a1"),
        service=ServiceRef(id="weather", name="Weather"),
        capability="weather.read",
        operation="read",
    )
    report = asyncio.run(
        cp.validate_mcp_candidate(
            principal("connectors:validate"),
            MCPValidationCommand(
                request=request,
                candidateId="candidate-weather",
            ),
        )
    )
    assert report.passed is True
    assert report.lifecycle == "validated"
    assert report.selected_tool == "get_weather"
    assert registry.trusted("weather", "weather.read", "org-1") is None

    try:
        asyncio.run(
            cp.validate_mcp_candidate(
                principal("connectors:validate"),
                MCPValidationCommand(request=request, candidateId="forged-candidate"),
            )
        )
        assert False, "expected server-side candidate binding failure"
    except Exception as exc:
        assert getattr(exc, "code", None) == "DISCOVERY_CANDIDATE_NOT_FOUND"
    store.close()
