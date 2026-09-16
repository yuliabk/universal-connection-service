import asyncio
from datetime import datetime, timedelta, timezone

import httpx

from universal_connection_service.contracts import (
    ActorRef,
    AuthRequirement,
    ConnectionRequest,
    ConnectorManifest,
    ConnectorResult,
    ExecutionContext,
    ServiceRef,
)
from universal_connection_service.policy import (
    ApprovalGrant,
    DefaultPolicyEngine,
    InMemoryApprovalVerifier,
    OPAConfig,
    OPAPolicyEngine,
    PolicyFacts,
)
from universal_connection_service.registry import ConnectorRegistry, Registration
from universal_connection_service.service import ConnectionService


class StubConnector:
    def __init__(self):
        self.calls = 0

    def manifest(self):
        return ConnectorManifest(
            connectorId="policy-stub",
            serviceId="records",
            name="Policy Stub",
            version="1.0.0",
            strategy="api",
            capabilities=("records.read", "records.write", "records.delete", "billing.charge", "users.promote"),
            auth=AuthRequirement(type="none"),
        )

    async def health_check(self, ctx):
        return True

    async def execute(self, capability, input, ctx):
        self.calls += 1
        return ConnectorResult(status="success", data={"capability": capability, "input": input})


def request(
    capability="records.read",
    operation="read",
    *,
    risk_hints=None,
    request_id="r1",
):
    return ConnectionRequest(
        requestId=request_id,
        actor=ActorRef(userId="u1", organizationId="o1", agentId="a1"),
        service=ServiceRef(id="records", name="Records"),
        capability=capability,
        operation=operation,
        input={"value": 1},
        riskHints=risk_hints or {},
    )


def context(*, approval_id=None, request_id="r1", user_id="u1", organization_id="o1"):
    return ExecutionContext(
        requestId=request_id,
        userId=user_id,
        organizationId=organization_id,
        approvalId=approval_id,
        deadlineMs=1000,
    )


def service(*, policy=None, verifier=None):
    registry = ConnectorRegistry()
    connector = StubConnector()
    registry.register(Registration(connector=connector, status="trusted"))
    return ConnectionService(registry, policy_engine=policy, approval_verifier=verifier), connector


def grant(
    *,
    approval_id="ap-1",
    request_id="r1",
    organization_id="o1",
    capability="records.write",
    operation="update",
    expires_at=None,
):
    return ApprovalGrant(
        approvalId=approval_id,
        requestId=request_id,
        organizationId=organization_id,
        userId="u1",
        agentId="a1",
        serviceId="records",
        capability=capability,
        operation=operation,
        expiresAt=expires_at or (datetime.now(timezone.utc) + timedelta(minutes=10)),
    )


def test_read_plan_is_allowed_and_executes_without_approval():
    svc, connector = service()
    req = request()
    plan = svc.compiler.compile(req)
    assert plan.policy_decision == "ALLOW"
    assert plan.requires_human_approval is False
    assert plan.risk.level == "LOW"

    result = asyncio.run(svc.execute(req, context()))
    assert result.status == "success"
    assert connector.calls == 1


def test_write_requires_approval_before_connector_execution():
    svc, connector = service()
    req = request(capability="records.write", operation="update")
    plan = svc.compiler.compile(req)
    assert plan.policy_decision == "REQUIRE_APPROVAL"
    assert plan.requires_human_approval is True
    assert plan.risk.level == "MEDIUM"

    result = asyncio.run(svc.execute(req, context()))
    assert result.status == "failed"
    assert result.error.code == "APPROVAL_REQUIRED"
    assert connector.calls == 0


def test_valid_approval_is_request_bound_and_single_use():
    verifier = InMemoryApprovalVerifier((grant(),))
    svc, connector = service(verifier=verifier)
    req = request(capability="records.write", operation="update")

    first = asyncio.run(svc.execute(req, context(approval_id="ap-1")))
    assert first.status == "success"
    assert connector.calls == 1

    second = asyncio.run(svc.execute(req, context(approval_id="ap-1")))
    assert second.status == "failed"
    assert second.error.code == "APPROVAL_ALREADY_USED"
    assert connector.calls == 1


def test_approval_scope_mismatch_fails_before_execution():
    verifier = InMemoryApprovalVerifier((grant(organization_id="other-org"),))
    svc, connector = service(verifier=verifier)
    req = request(capability="records.write", operation="update")

    result = asyncio.run(svc.execute(req, context(approval_id="ap-1")))
    assert result.status == "failed"
    assert result.error.code in {"APPROVAL_SCOPE_MISMATCH", "APPROVAL_INVALID"}
    assert connector.calls == 0


def test_expired_approval_fails_before_execution():
    verifier = InMemoryApprovalVerifier(
        (grant(expires_at=datetime.now(timezone.utc) - timedelta(seconds=1)),)
    )
    svc, connector = service(verifier=verifier)
    req = request(capability="records.write", operation="update")

    result = asyncio.run(svc.execute(req, context(approval_id="ap-1")))
    assert result.status == "failed"
    assert result.error.code == "APPROVAL_EXPIRED"
    assert connector.calls == 0


def test_delete_is_objectively_destructive_and_high_risk():
    svc, _ = service()
    plan = svc.compiler.compile(request(capability="records.delete", operation="delete"))
    assert plan.policy_decision == "REQUIRE_APPROVAL"
    assert plan.risk.level == "HIGH"
    assert plan.risk.destructive is True
    assert "destructive operation" in plan.policy_reasons


def test_explicit_financial_and_permission_increase_hints_are_high_risk():
    svc, _ = service()
    financial = svc.compiler.compile(
        request(
            capability="billing.charge",
            operation="execute",
            risk_hints={"financial": True},
        )
    )
    assert financial.policy_decision == "REQUIRE_APPROVAL"
    assert financial.risk.financial is True
    assert financial.risk.level == "HIGH"

    permission = svc.compiler.compile(
        request(
            capability="users.promote",
            operation="update",
            risk_hints={"permissionIncrease": True},
        )
    )
    assert permission.policy_decision == "REQUIRE_APPROVAL"
    assert permission.risk.permission_increase is True
    assert permission.risk.level == "HIGH"


def test_policy_deny_blocks_connector_even_if_trusted():
    policy = DefaultPolicyEngine(denied_capabilities=("records.read",))
    svc, connector = service(policy=policy)
    req = request()

    plan = svc.compiler.compile(req)
    assert plan.policy_decision == "DENY"

    result = asyncio.run(svc.execute(req, context()))
    assert result.status == "failed"
    assert result.error.code == "POLICY_DENIED"
    assert connector.calls == 0


def test_execution_context_identity_mismatch_fails_closed():
    svc, connector = service()
    result = asyncio.run(svc.execute(request(), context(user_id="other-user")))
    assert result.status == "failed"
    assert result.error.code == "EXECUTION_CONTEXT_MISMATCH"
    assert connector.calls == 0


def test_opa_policy_engine_uses_data_api_and_parses_decision():
    captured = {}

    def handler(req):
        captured["path"] = req.url.path
        captured["payload"] = req.read().decode()
        return httpx.Response(
            200,
            json={
                "result": {
                    "decision": "REQUIRE_APPROVAL",
                    "reasons": ["external policy"],
                    "risk": {"level": "HIGH", "reasons": ["external policy"]},
                }
            },
        )

    def client_factory():
        return httpx.Client(
            transport=httpx.MockTransport(handler),
            base_url="http://127.0.0.1:8181",
        )

    engine = OPAPolicyEngine(
        OPAConfig(address="http://127.0.0.1:8181", decisionPath="ucs/policy/decision"),
        client_factory=client_factory,
    )
    facts = PolicyFacts(
        requestId="r1",
        organizationId="o1",
        userId="u1",
        agentId="a1",
        serviceId="records",
        capability="records.read",
        operation="read",
        readOnly=True,
        trustedConnector=True,
    )
    result = engine.evaluate(facts)
    assert result.decision == "REQUIRE_APPROVAL"
    assert captured["path"] == "/v1/data/ucs/policy/decision"
    assert '"input"' in captured["payload"]


def test_opa_provider_failure_denies_fail_closed():
    def handler(req):
        return httpx.Response(503, json={"error": "unavailable"})

    engine = OPAPolicyEngine(
        OPAConfig(address="http://127.0.0.1:8181"),
        client_factory=lambda: httpx.Client(
            transport=httpx.MockTransport(handler),
            base_url="http://127.0.0.1:8181",
        ),
    )
    facts = PolicyFacts(
        requestId="r1",
        organizationId="o1",
        userId="u1",
        agentId="a1",
        serviceId="records",
        capability="records.read",
        operation="read",
        readOnly=True,
        trustedConnector=True,
    )
    result = engine.evaluate(facts)
    assert result.decision == "DENY"
    assert result.risk.level == "HIGH"
