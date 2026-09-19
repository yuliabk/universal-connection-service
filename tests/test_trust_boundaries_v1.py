"""Regressions for the three trust defects found in the UCS-20 audit.

Each test below reproduces a request that the service used to accept.
"""

import asyncio
from datetime import datetime, timedelta, timezone

import pytest

from universal_connection_service.approvals import PersistentApprovalVerifier
from universal_connection_service.capability_schemas import CapabilitySchema, SchemaAnnotatedConnector
from universal_connection_service.contracts import (
    ActorRef,
    ConnectionRequest,
    ConnectorManifest,
    ConnectorResult,
    ExecutionContext,
    RiskHints,
    ServiceRef,
)
from universal_connection_service.persistence import SQLiteStateStore
from universal_connection_service.policy import ApprovalGrant, approval_input_digest
from universal_connection_service.registry import ConnectorRegistry, Registration, _version_key
from universal_connection_service.service import ConnectionService

ORG = "org-1"


class RecordsConnector:
    def __init__(self, capabilities=("records.delete",)) -> None:
        self.capabilities = capabilities
        self.calls: list[tuple[str, dict]] = []

    def manifest(self) -> ConnectorManifest:
        return ConnectorManifest(
            connectorId="records-1",
            serviceId="records",
            name="Records",
            version="1.0.0",
            strategy="api",
            capabilities=self.capabilities,
        )

    async def health_check(self, ctx) -> bool:
        return True

    async def execute(self, capability, input, ctx) -> ConnectorResult:
        self.calls.append((capability, input))
        return ConnectorResult(status="success", data={"done": True})


def request(
    *,
    capability="records.delete",
    operation="read",
    read_only=True,
    risk_hints=None,
    request_id="r-1",
    input=None,
):
    return ConnectionRequest(
        requestId=request_id,
        actor=ActorRef(userId="u1", organizationId=ORG, agentId="a1"),
        service=ServiceRef(id="records", name="Records"),
        capability=capability,
        operation=operation,
        input=input if input is not None else {"id": 42},
        readOnly=read_only,
        riskHints=risk_hints or RiskHints(),
    )


def context(*, request_id="r-1", approval_id=None):
    return ExecutionContext(
        requestId=request_id,
        userId="u1",
        organizationId=ORG,
        approvalId=approval_id,
    )


def service(connector, *, verifier=None):
    registry = ConnectorRegistry()
    registry.register(Registration(connector=connector, status="trusted", organization_id=ORG))
    return ConnectionService(registry, approval_verifier=verifier)


DELETE_SCHEMA = CapabilitySchema(
    capability="records.delete",
    description="Delete a record",
    operation="delete",
    readOnly=False,
    riskHints=RiskHints(destructive=True),
)


# --- risk comes from the connector -------------------------------------


def test_caller_cannot_declare_a_delete_capability_as_a_read():
    inner = RecordsConnector()
    svc = service(SchemaAnnotatedConnector(inner, (DELETE_SCHEMA,)))
    result = asyncio.run(svc.execute(request(), context()))
    assert result.status == "failed"
    assert result.error.code == "APPROVAL_REQUIRED"
    assert inner.calls == []  # nothing reached the connector


def test_caller_may_still_raise_the_risk_above_what_the_connector_declares():
    read_schema = CapabilitySchema(capability="records.read", operation="read", readOnly=True)
    inner = RecordsConnector(capabilities=("records.read",))
    svc = service(SchemaAnnotatedConnector(inner, (read_schema,)))
    result = asyncio.run(
        svc.execute(
            request(capability="records.read", risk_hints=RiskHints(financial=True)),
            context(),
        )
    )
    assert result.status == "failed"
    assert result.error.code == "APPROVAL_REQUIRED"


def test_declared_read_only_capability_still_executes_without_approval():
    read_schema = CapabilitySchema(capability="records.read", operation="read", readOnly=True)
    inner = RecordsConnector(capabilities=("records.read",))
    svc = service(SchemaAnnotatedConnector(inner, (read_schema,)))
    result = asyncio.run(svc.execute(request(capability="records.read"), context()))
    assert result.status == "success"


def test_connector_that_declares_nothing_leaves_the_caller_claim_intact():
    """An absent declaration is not a claim of safety, and not a claim of danger.

    A connector publishing no schemas keeps the previous behaviour: the caller's
    own declaration governs. Treating silence as read-only would hide a delete;
    treating it as dangerous would send every unannotated MCP tool to a human.
    """
    inner = RecordsConnector(capabilities=("records.read",))
    svc = service(inner)
    assert asyncio.run(svc.execute(request(capability="records.read"), context())).status == "success"

    honest_delete = request(capability="records.read", operation="delete", read_only=False)
    result = asyncio.run(svc.execute(honest_delete, context()))
    assert result.error.code == "APPROVAL_REQUIRED"


def test_undeclared_risk_on_a_published_schema_is_not_treated_as_a_declaration():
    undeclared = CapabilitySchema(
        capability="records.delete",
        operation="read",
        readOnly=True,
        riskDeclared=False,
    )
    inner = RecordsConnector()
    svc = service(SchemaAnnotatedConnector(inner, (undeclared,)))
    honest = request(operation="delete", read_only=False)
    assert asyncio.run(svc.execute(honest, context())).error.code == "APPROVAL_REQUIRED"


# --- approvals bind to the payload -------------------------------------


def approval_stack(*, input_digest, connector=None):
    store = SQLiteStateStore(":memory:")
    verifier = PersistentApprovalVerifier(store)
    inner = connector or RecordsConnector(capabilities=("payments.send",))
    svc = service(inner, verifier=verifier)
    verifier.register(
        ApprovalGrant(
            approvalId="ap-1",
            requestId="r-1",
            organizationId=ORG,
            userId="u1",
            agentId="a1",
            serviceId="records",
            capability="payments.send",
            operation="create",
            expiresAt=datetime.now(timezone.utc) + timedelta(minutes=5),
            inputDigest=input_digest,
        )
    )
    return svc, inner, store


def payment(amount, to="alice"):
    return request(
        capability="payments.send",
        operation="create",
        read_only=False,
        risk_hints=RiskHints(financial=True),
        input={"to": to, "amount": amount},
    )


def test_approval_for_one_payment_does_not_authorize_another():
    approved = payment(10)
    svc, inner, _ = approval_stack(input_digest=approval_input_digest(approved.input))
    result = asyncio.run(svc.execute(payment(1_000_000, to="attacker"), context(approval_id="ap-1")))
    assert result.status == "failed"
    assert result.error.code == "APPROVAL_INPUT_MISMATCH"
    assert inner.calls == []


def test_approval_for_the_approved_payload_executes():
    approved = payment(10)
    svc, inner, _ = approval_stack(input_digest=approval_input_digest(approved.input))
    result = asyncio.run(svc.execute(approved, context(approval_id="ap-1")))
    assert result.status == "success"
    assert inner.calls[0][1] == {"to": "alice", "amount": 10}


def test_unbound_approval_is_refused_by_default():
    svc, inner, _ = approval_stack(input_digest=None)
    result = asyncio.run(svc.execute(payment(10), context(approval_id="ap-1")))
    assert result.error.code == "APPROVAL_INPUT_UNBOUND"
    assert inner.calls == []


def test_digest_is_insensitive_to_key_order_but_not_to_values():
    assert approval_input_digest({"a": 1, "b": 2}) == approval_input_digest({"b": 2, "a": 1})
    assert approval_input_digest({"a": 1}) != approval_input_digest({"a": 2})
    assert len(approval_input_digest({"a": 1})) == 64


# --- version ordering ---------------------------------------------------


def versioned(version):
    class Versioned:
        def manifest(self):
            return ConnectorManifest(
                connectorId="c",
                serviceId="svc",
                name="C",
                version=version,
                strategy="api",
                capabilities=("cap",),
            )

        async def health_check(self, ctx):
            return True

        async def execute(self, capability, input, ctx):
            return ConnectorResult(status="success", data={"version": version})

    return Versioned()


def test_tenth_release_is_selected_over_the_ninth():
    registry = ConnectorRegistry()
    for version in ("1.2.0", "1.9.0", "1.10.0"):
        registry.register(Registration(connector=versioned(version), status="trusted", organization_id=ORG))
    assert registry.trusted("svc", "cap", ORG).manifest.version == "1.10.0"


def test_version_key_orders_numerically_and_tolerates_suffixes():
    assert _version_key("1.10.0") > _version_key("1.9.0")
    assert _version_key("2.0.0") > _version_key("1.999.0")
    assert _version_key("1.0.0-rc1") != _version_key("1.0.0")


def test_tenant_connector_still_wins_over_a_newer_global_one():
    registry = ConnectorRegistry()
    registry.register(Registration(connector=versioned("9.9.9"), status="trusted"))  # global
    registry.register(Registration(connector=versioned("1.0.0"), status="trusted", organization_id=ORG))
    assert registry.trusted("svc", "cap", ORG).organization_id == ORG


# --- bounds -------------------------------------------------------------


def test_deadline_is_bounded():
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        ExecutionContext(requestId="r", userId="u", organizationId=ORG, deadlineMs=86_400_000)
