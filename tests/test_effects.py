import asyncio
import json

import pytest
from pydantic import ValidationError

from effect_helpers import approve_read
from test_policy import StubConnector, request, context
from universal_connection_service.effects import EffectCatalog, EffectClassification, effects_from_env
from universal_connection_service.registry import ConnectorRegistry, Registration
from universal_connection_service.service import ConnectionService


def classification(**overrides):
    fields = dict(organizationId="o1", serviceId="records", connectorId="policy-stub",
                  connectorVersion="1.0.0", capability="records.read", effect="read_only",
                  evidenceSha256="a" * 64, approvalReference="synthetic-review")
    fields.update(overrides)
    return EffectClassification(**fields)


def stack(entries=(), strategy="api"):
    class Connector(StubConnector):
        def manifest(self):
            return super().manifest().model_copy(update={"strategy": strategy})
    connector = Connector()
    registry = ConnectorRegistry()
    registry.register(Registration(connector=connector, status="trusted"))
    return ConnectionService(registry, effect_catalog=EffectCatalog(entries)), connector


@pytest.mark.parametrize("strategy", ["api", "oauth", "mcp", "browser"])
def test_caller_read_claim_is_not_host_evidence(strategy):
    service, connector = stack(strategy=strategy)
    result = asyncio.run(service.execute(request(), context(approval_id="unrelated-grant")))
    assert result.error.code == "EFFECT_CLASSIFICATION_REQUIRED"
    assert result.error.user_action_required
    assert connector.calls == 0
    approve_read(service, request())
    assert asyncio.run(service.execute(request(), context())).status == "success"
    assert connector.calls == 1


@pytest.mark.parametrize("wrong", [dict(organizationId="other"), dict(serviceId="other"),
    dict(connectorId="other"), dict(connectorVersion="2.0.0"), dict(capability="records.write")])
def test_classification_is_bound_to_exact_tenant_and_connector(wrong):
    service, connector = stack([classification(**wrong)])
    assert asyncio.run(service.execute(request(), context())).error.code == "EFFECT_CLASSIFICATION_REQUIRED"
    assert connector.calls == 0


def test_side_effect_classification_cannot_be_downgraded_by_caller():
    service, connector = stack([classification(effect="side_effecting")])
    assert service.compiler.compile(request()).policy_decision == "REQUIRE_APPROVAL"
    result = asyncio.run(service.execute(request(), context(approval_id="legacy-grant")))
    assert result.error.code == "DURABLE_EXECUTION_REQUIRED"
    assert connector.calls == 0


def test_read_classification_does_not_override_explicit_write():
    service, connector = stack([classification()])
    result = asyncio.run(service.execute(request(operation="delete"), context(approval_id="legacy-grant")))
    assert result.error.code == "DURABLE_EXECUTION_REQUIRED"
    assert connector.calls == 0


def test_catalog_copies_and_revalidates_host_entries():
    entry = classification(effect="side_effecting")
    service, connector = stack([entry])
    entry.effect = "read_only"
    assert asyncio.run(service.execute(request(), context(approval_id="legacy-grant"))).error.code == "DURABLE_EXECUTION_REQUIRED"
    assert connector.calls == 0
    with pytest.raises(ValueError, match="duplicate"):
        service.effect_catalog.approve(entry)
    entry.evidence_sha256 = "invalid"
    with pytest.raises(ValidationError):
        EffectCatalog([entry])


@pytest.mark.parametrize("raw", ['{}', 'null', '[{}]', 'secret-invalid-config'])
def test_invalid_host_configuration_fails_without_echoing_input(monkeypatch, raw):
    monkeypatch.setenv("UCS_CAPABILITY_EFFECTS_JSON", raw)
    with pytest.raises(RuntimeError, match="^Capability effect configuration is invalid$"):
        effects_from_env()


def test_configuration_round_trip_and_default_deny(monkeypatch):
    monkeypatch.delenv("UCS_CAPABILITY_EFFECTS_JSON", raising=False)
    service, connector = stack()
    item = service.registry.trusted("records", "records.read", "o1")
    assert effects_from_env().classify(request(), item) == "unknown"
    monkeypatch.setenv("UCS_CAPABILITY_EFFECTS_JSON", json.dumps([classification().model_dump(by_alias=True)]))
    assert effects_from_env().classify(request(), item) == "read_only"


def test_workflow_pauses_then_resumes_after_host_review():
    from test_auto_connect import stack as workflow_stack, request as workflow_request, principal
    from universal_connection_service.auto_connect import AutoConnectStartCommand, AutoConnectAdvanceCommand
    from test_auto_connect import StubConnector as WorkflowConnector
    connector = WorkflowConnector()
    store, _, service, _, orchestrator = workflow_stack(trusted=connector)
    service.effect_catalog = EffectCatalog()
    req = workflow_request()
    actor = principal("connectors:review")
    started = asyncio.run(orchestrator.start(actor, AutoConnectStartCommand(request=req)))
    assert started.workflow.stage == "awaiting_effect_classification"
    assert connector.calls == 0
    approve_read(service, req)
    completed = asyncio.run(orchestrator.advance(actor, started.workflow.workflow_id,
        AutoConnectAdvanceCommand(request=req)))
    assert completed.workflow.stage == "completed"
    assert connector.calls == 1
    store.close()


def test_connector_change_while_verifying_approval_blocks_read_dispatch():
    from universal_connection_service.policy import PolicyEvaluation, ApprovalVerification
    from universal_connection_service.contracts import RiskAssessment

    service, connector = stack([classification()])

    class RequireApproval:
        def evaluate(self, facts):
            return PolicyEvaluation(decision="REQUIRE_APPROVAL", risk=RiskAssessment(level="LOW"))

    class Replacement(StubConnector):
        def manifest(self):
            return super().manifest().model_copy(update={"version": "2.0.0"})

    replacement = Replacement()

    class Verifier:
        async def verify(self, approval_id, req):
            service.registry.register(Registration(connector=replacement, status="trusted"))
            return ApprovalVerification(valid=True)

        async def consume(self, approval_id):
            pass

    service.compiler.policy_engine = RequireApproval()
    service.approval_verifier = Verifier()
    # Even a separately approved new version must not inherit in-flight authorization.
    service.effect_catalog.approve(classification(connectorVersion="2.0.0"))
    result = asyncio.run(service.execute(request(), context(approval_id="synthetic-grant")))
    assert result.error.code == "EFFECT_CLASSIFICATION_REQUIRED"
    assert connector.calls == replacement.calls == 0


def test_real_mcp_adapter_is_blocked_before_transport():
    from test_mcp_adapter import adapter
    from universal_connection_service.contracts import ServiceRef
    registry = ConnectorRegistry()
    connector = adapter()
    registry.register(Registration(connector=connector, status="trusted"))
    service = ConnectionService(registry)
    req = request().model_copy(update={"service": ServiceRef(id="synthetic", name="Synthetic")})
    result = asyncio.run(service.execute(req, context()))
    assert result.error.code == "EFFECT_CLASSIFICATION_REQUIRED"


def test_sandbox_connector_is_blocked_before_runner():
    from test_policy_auto_connect import stack as sandbox_stack, request as sandbox_request
    store, runner, _, orchestrator = sandbox_stack(False)
    service = orchestrator.connection_service
    service.effect_catalog = EffectCatalog()
    req = sandbox_request()
    ctx = context(request_id=req.request_id, organization_id=req.actor.organization_id)
    result = asyncio.run(service.execute(req, ctx))
    assert result.error.code == "EFFECT_CLASSIFICATION_REQUIRED"
    assert runner.calls == 0
    store.close()
