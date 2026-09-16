import asyncio
from datetime import datetime, timedelta, timezone

from mcp import Client
from mcp.server.mcpserver import MCPServer

from universal_connection_service.approvals import PersistentApprovalVerifier
from universal_connection_service.auto_connect import (
    AutoConnectAdvanceCommand,
    AutoConnectError,
    AutoConnectExecutionApprovalCommand,
    AutoConnectOrchestrator,
    AutoConnectStartCommand,
)
from universal_connection_service.contracts import (
    ActorRef,
    AuthRequirement,
    ConnectionRequest,
    ConnectorManifest,
    ConnectorResult,
    DiscoveryCandidateRef,
    ServiceRef,
)
from universal_connection_service.control_plane import ControlPlanePrincipal, ControlPlaneService
from universal_connection_service.discovery import DiscoveryEngine
from universal_connection_service.mcp_validation import MCPValidationService
from universal_connection_service.persistence import ConnectionWorkflowRecord, SQLiteStateStore
from universal_connection_service.registry import ConnectorRegistry, Registration
from universal_connection_service.service import ConnectionService


class StubConnector:
    def __init__(self, *, connector_id="trusted-records", capabilities=("records.read",), strategy="api"):
        self.connector_id = connector_id
        self.capabilities = capabilities
        self.strategy = strategy
        self.calls = 0

    def manifest(self):
        return ConnectorManifest(
            connectorId=self.connector_id,
            serviceId="records",
            name="Records",
            version="1.0.0",
            strategy=self.strategy,
            capabilities=self.capabilities,
            auth=AuthRequirement(type="none"),
        )

    async def health_check(self, ctx):
        return True

    async def execute(self, capability, input, ctx):
        self.calls += 1
        return ConnectorResult(status="success", data={"ok": True, "capability": capability})


class StaticProvider:
    def __init__(self, candidates):
        self.candidates = tuple(candidates)
        self.calls = 0

    def discover(self, query):
        self.calls += 1
        return self.candidates


mcp = MCPServer("Auto Connect MCP", version="1.0.0")


@mcp.tool()
def records_read() -> dict:
    return {"ok": True}


def principal(*scopes):
    return ControlPlanePrincipal(
        subject="owner",
        tokenId="owner-token",
        organizations=("org-1",),
        scopes=scopes,
    )


def request(*, operation="read", capability="records.read", input=None):
    return ConnectionRequest(
        requestId="req-1",
        actor=ActorRef(userId="u1", organizationId="org-1", agentId="a1"),
        service=ServiceRef(id="records", name="Records"),
        capability=capability,
        operation=operation,
        input=input or {"secret": "must-not-be-persisted"},
        readOnly=operation == "read",
    )


def candidate(candidate_id="candidate-1", endpoint="https://records.example/mcp"):
    return DiscoveryCandidateRef(
        candidateId=candidate_id,
        source="mcp_registry",
        name="Records MCP",
        version="1.0.0",
        strategy="mcp",
        transport="streamable-http",
        endpoint=endpoint,
        authRequirement=AuthRequirement(type="none"),
        confidence=100,
        actionable=True,
        requiresBuild=False,
    )


def stack(*, trusted=None, candidates=()):
    store = SQLiteStateStore(":memory:")
    registry = ConnectorRegistry(state_store=store)
    if trusted is not None:
        registry.register(Registration(connector=trusted, status="trusted", organization_id="org-1"))
    discovery = DiscoveryEngine((StaticProvider(candidates),)) if candidates else None
    verifier = PersistentApprovalVerifier(store)
    service = ConnectionService(
        registry,
        approval_verifier=verifier,
        audit_store=store,
        evidence_store=store,
        discovery_engine=discovery,
    )
    validator = MCPValidationService(
        registry,
        evidence_store=store,
        client_factory=lambda: Client(mcp),
    )
    control = ControlPlaneService(
        registry=registry,
        connection_service=service,
        state_store=store,
        evidence_store=store,
        approval_store=store,
        mcp_validation_service=validator,
    )
    orchestrator = AutoConnectOrchestrator(
        workflow_store=store,
        connection_service=service,
        control_plane_service=control,
        registry=registry,
        approval_store=store,
        evidence_store=store,
    )
    return store, registry, service, control, orchestrator


def test_trusted_read_auto_executes_and_workflow_persists_no_request_input():
    connector = StubConnector()
    store, _, _, _, orchestrator = stack(trusted=connector)
    response = asyncio.run(
        orchestrator.start(
            principal("connectors:review"),
            AutoConnectStartCommand(request=request()),
        )
    )
    assert response.workflow.stage == "completed"
    assert response.result is not None and response.result.status == "success"
    assert connector.calls == 1

    row = store._connection.execute("SELECT * FROM connection_workflow").fetchone()
    serialized = str(dict(row))
    assert "must-not-be-persisted" not in serialized
    assert response.workflow.result_audit_id
    store.close()


def test_resume_rejects_mutated_request_fingerprint_before_execution():
    connector = StubConnector()
    store, _, _, _, orchestrator = stack(trusted=connector)
    original = request()
    started = asyncio.run(
        orchestrator.start(
            principal("connectors:review"),
            AutoConnectStartCommand(request=original, executeWhenReady=False),
        )
    )
    assert started.workflow.stage == "ready_to_execute"
    assert connector.calls == 0

    mutated = request(input={"secret": "changed"})
    try:
        asyncio.run(
            orchestrator.advance(
                principal("connectors:review"),
                started.workflow.workflow_id,
                AutoConnectAdvanceCommand(request=mutated),
            )
        )
        assert False, "expected workflow fingerprint mismatch"
    except AutoConnectError as exc:
        assert exc.code == "WORKFLOW_REQUEST_MISMATCH"
    assert connector.calls == 0
    store.close()


def test_ambiguous_discovery_pauses_for_candidate_selection():
    store, _, _, _, orchestrator = stack(
        candidates=(
            candidate("candidate-1", "https://one.example/mcp"),
            candidate("candidate-2", "https://two.example/mcp"),
        )
    )
    actor = principal("connectors:review", "connectors:validate")
    started = asyncio.run(orchestrator.start(actor, AutoConnectStartCommand(request=request())))
    assert started.workflow.stage == "awaiting_candidate_selection"
    assert started.workflow.next_action == "select_candidate"
    assert len(started.candidates) == 2

    selected = asyncio.run(
        orchestrator.advance(
            actor,
            started.workflow.workflow_id,
            AutoConnectAdvanceCommand(request=request(), selectedCandidateId="candidate-1"),
        )
    )
    assert selected.workflow.stage == "awaiting_promotion_approval"
    assert selected.workflow.selected_candidate_id == "candidate-1"
    assert selected.workflow.connector_id is not None
    store.close()


def test_mcp_candidate_runs_discovery_validation_promotion_and_execution_end_to_end():
    store, registry, _, _, orchestrator = stack(candidates=(candidate(),))
    actor = principal("connectors:review", "connectors:validate", "approvals:issue", "connectors:promote")
    req = request()
    started = asyncio.run(orchestrator.start(actor, AutoConnectStartCommand(request=req)))
    assert started.workflow.stage == "awaiting_promotion_approval"
    connector_id = started.workflow.connector_id
    assert connector_id is not None
    assert registry.trusted("records", "records.read", "org-1") is None

    workflow, approval = orchestrator.issue_promotion_approval(
        actor,
        started.workflow.workflow_id,
        "org-1",
        expires_in_seconds=300,
    )
    assert workflow.stage == "awaiting_promotion"
    raw = approval.approval_id

    completed = asyncio.run(
        orchestrator.promote_and_advance(
            actor,
            started.workflow.workflow_id,
            AutoConnectAdvanceCommand(request=req, promotionApprovalId=raw),
        )
    )
    assert completed.workflow.stage == "completed"
    assert completed.result is not None and completed.result.status == "success"
    assert registry.trusted("records", "records.read", "org-1") is not None

    workflow_row = store._connection.execute("SELECT * FROM connection_workflow").fetchone()
    assert raw not in str(dict(workflow_row))
    evidence = store.list_evidence("org-1")
    assert raw not in " ".join(item.model_dump_json(by_alias=True) for item in evidence)
    store.close()


def test_trusted_write_pauses_for_execution_approval_and_consumes_once():
    connector = StubConnector(capabilities=("records.write",))
    store, _, _, _, orchestrator = stack(trusted=connector)
    actor = principal("connectors:review", "approvals:issue")
    req = request(operation="update", capability="records.write")

    started = asyncio.run(orchestrator.start(actor, AutoConnectStartCommand(request=req)))
    assert started.workflow.stage == "awaiting_execution_approval"
    assert connector.calls == 0

    issued = orchestrator.issue_execution_approval(
        actor,
        started.workflow.workflow_id,
        AutoConnectExecutionApprovalCommand(request=req, expiresInSeconds=300),
    )
    assert issued.approval_id not in issued.approval_ref_hash

    completed = asyncio.run(
        orchestrator.advance(
            actor,
            started.workflow.workflow_id,
            AutoConnectAdvanceCommand(request=req, executionApprovalId=issued.approval_id),
        )
    )
    assert completed.workflow.stage == "completed"
    assert connector.calls == 1

    repeated = asyncio.run(
        orchestrator.advance(
            actor,
            started.workflow.workflow_id,
            AutoConnectAdvanceCommand(request=req, executionApprovalId=issued.approval_id),
        )
    )
    assert repeated.workflow.stage == "completed"
    assert connector.calls == 1
    store.close()


def test_workflow_lease_is_atomic_and_can_be_reclaimed_after_expiry():
    store = SQLiteStateStore(":memory:")
    now = datetime.now(timezone.utc)
    record = store.create_workflow(
        ConnectionWorkflowRecord(
            workflowId="wf-lease",
            requestId="req-lease",
            organizationId="org-1",
            requestFingerprint="a" * 64,
            serviceId="records",
            capability="records.read",
            operation="read",
        )
    )
    assert store.claim_workflow("org-1", record.workflow_id, "lease-a", now + timedelta(seconds=10), now) is True
    assert store.claim_workflow("org-1", record.workflow_id, "lease-b", now + timedelta(seconds=10), now) is False
    later = now + timedelta(seconds=11)
    assert store.claim_workflow("org-1", record.workflow_id, "lease-c", later + timedelta(seconds=10), later) is True
    store.close()
