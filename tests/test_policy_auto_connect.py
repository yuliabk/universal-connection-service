import asyncio
from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest

from universal_connection_service.approvals import PersistentApprovalVerifier
from universal_connection_service.auto_connect import AutoConnectAdvanceCommand, AutoConnectStartCommand
from universal_connection_service.contracts import ActorRef, ConnectionRequest, ServiceRef
from universal_connection_service.control_plane import ControlPlanePrincipal, ControlPlaneService
from universal_connection_service.mcp_adapter import MCPToolBinding
from universal_connection_service.mcpb_sandbox import SandboxedMCPConnectorConfig
from universal_connection_service.persistence import SQLiteStateStore
from universal_connection_service.policy_auto_connect import AutoConnectSandboxPolicyActivateCommand, PolicyAwareAutoConnectOrchestrator
from universal_connection_service.registry import ConnectorRegistry, Registration
from universal_connection_service.sandbox_managed_runtime import ToolScopedSandboxedMCPConnector
from universal_connection_service.sandbox_policy import SandboxCapabilityProfile, SandboxMountCatalog
from universal_connection_service.sandbox_policy_compiler import LeastPrivilegePolicyCompiler, SandboxPolicyCatalog, SandboxPolicyRule
from universal_connection_service.sandbox_tool_policy import SandboxToolPolicyService
from universal_connection_service.service import ConnectionService


class FakeTool:
    def __init__(self, open_world=False): self.open_world = open_world
    def model_dump(self, **kwargs):
        return {"name":"records_read","inputSchema":{"type":"object"},"annotations":{"readOnlyHint":True,"destructiveHint":False,"idempotentHint":True,"openWorldHint":self.open_world}}


class FakeMCPClient:
    def __init__(self, runner): self.runner = runner
    async def list_tools(self, cursor=None): return SimpleNamespace(tools=[FakeTool(self.runner.open_world)], next_cursor=None)
    async def call_tool(self, tool, input):
        self.runner.calls += 1
        return SimpleNamespace(is_error=False, structured_content={"ok":True,"tool":tool}, content=[])


class FakeRunner:
    def __init__(self, open_world=False): self.open_world=open_world; self.calls=0; self.capability_calls=[]
    @asynccontextmanager
    async def client(self, digest, **kwargs): yield FakeMCPClient(self)
    @asynccontextmanager
    async def client_for_capability(self, digest, *, capability, **kwargs):
        self.capability_calls.append(capability); yield FakeMCPClient(self)


class UnusedBuildCoordinator:
    async def build_async(self, *args, **kwargs): raise AssertionError("build path should not run")
    def pin_after_trust(self, *args, **kwargs): return None


class NoopValidationService: pass


def principal(*scopes):
    return ControlPlanePrincipal(subject="operator", tokenId="operator-token", organizations=("org-1",), scopes=scopes)


def request(request_id="req-policy-1"):
    return ConnectionRequest(requestId=request_id, actor=ActorRef(userId="u1", organizationId="org-1", agentId="a1"), service=ServiceRef(id="records", name="Records"), capability="records.read", operation="read", input={"id":"42"}, readOnly=True)


def stack(open_world=False):
    store=SQLiteStateStore(":memory:"); registry=ConnectorRegistry(state_store=store); runner=FakeRunner(open_world)
    connector=ToolScopedSandboxedMCPConnector(SandboxedMCPConnectorConfig(connectorId="sandbox-records", serviceId="records", name="Records sandbox", version="1.0.0", bundleDigest="a"*64, bindings=(MCPToolBinding(capability="records.read", tool="records_read"),)), runner=runner)
    registry.register(Registration(connector=connector, status="trusted", organization_id="org-1"))
    service=ConnectionService(registry, approval_verifier=PersistentApprovalVerifier(store), audit_store=store, evidence_store=store)
    control=ControlPlaneService(registry=registry, connection_service=service, state_store=store, evidence_store=store, approval_store=store, mcp_validation_service=NoopValidationService())
    mounts=SandboxMountCatalog(); policy_service=SandboxToolPolicyService(registry=registry, evidence_store=store, approval_store=store, mount_catalog=mounts)
    compiler=LeastPrivilegePolicyCompiler(registry=registry, evidence_store=store, mount_catalog=mounts, policy_catalog=SandboxPolicyCatalog())
    orchestrator=PolicyAwareAutoConnectOrchestrator(build_coordinator=UnusedBuildCoordinator(), policy_compiler=compiler, sandbox_policy_service=policy_service, workflow_store=store, connection_service=service, control_plane_service=control, registry=registry, approval_store=store, evidence_store=store)
    return store, runner, compiler, orchestrator


def test_policy_approval_activation_execution_and_reuse():
    store, runner, _, orchestrator=stack(False); actor=principal("connectors:review","approvals:issue","connectors:promote"); req=request()
    started=asyncio.run(orchestrator.start(actor, AutoConnectStartCommand(request=req)))
    assert started.workflow.last_code=="SANDBOX_POLICY_APPROVAL_REQUIRED" and runner.calls==0
    state=orchestrator.policy_status(actor,"org-1",started.workflow.workflow_id)
    assert state.proposal.profile==SandboxCapabilityProfile() and not state.proposal.unresolved_requirements
    issued=orchestrator.issue_sandbox_policy_approval(actor,started.workflow.workflow_id,"org-1",expires_in_seconds=300)
    raw=issued.approval.approval_id
    completed=asyncio.run(orchestrator.activate_sandbox_policy_and_advance(actor,started.workflow.workflow_id,AutoConnectSandboxPolicyActivateCommand(request=req,sandboxPolicyApprovalId=raw)))
    assert completed.workflow.stage=="completed" and completed.result.status=="success"
    assert runner.calls==1 and runner.capability_calls==["records.read"]
    serialized=str(dict(store._connection.execute("SELECT * FROM connection_workflow").fetchone()))
    evidence=" ".join(i.model_dump_json(by_alias=True) for i in store.list_evidence("org-1"))
    assert raw not in serialized and raw not in evidence
    second=asyncio.run(orchestrator.start(actor,AutoConnectStartCommand(request=request("req-policy-2"))))
    assert second.workflow.stage=="completed" and runner.calls==2
    store.close()


def test_unresolved_policy_fails_closed_then_recompiles_after_operator_rule():
    store, runner, compiler, orchestrator=stack(True); actor=principal("connectors:review","approvals:issue","connectors:promote"); req=request()
    started=asyncio.run(orchestrator.start(actor,AutoConnectStartCommand(request=req)))
    assert started.workflow.last_code=="SANDBOX_POLICY_RESOLUTION_REQUIRED" and runner.calls==0
    assert "egress_targets_unknown" in orchestrator.policy_status(actor,"org-1",started.workflow.workflow_id).proposal.unresolved_requirements
    with pytest.raises(Exception) as captured: orchestrator.issue_sandbox_policy_approval(actor,started.workflow.workflow_id,"org-1")
    assert getattr(captured.value,"code",None)=="WORKFLOW_NOT_AWAITING_SANDBOX_POLICY_APPROVAL"
    compiler.policy_catalog=SandboxPolicyCatalog((SandboxPolicyRule(organizationId="org-1",serviceId="records",capability="records.read",toolName="records_read",profile=SandboxCapabilityProfile(egressHosts=("api.records.example",),brokeredCredentials=True),reason="Approved upstream"),))
    advanced=asyncio.run(orchestrator.advance(actor,started.workflow.workflow_id,AutoConnectAdvanceCommand(request=req)))
    assert advanced.workflow.last_code=="SANDBOX_POLICY_APPROVAL_REQUIRED"
    assert orchestrator.policy_status(actor,"org-1",started.workflow.workflow_id).proposal.profile.egress_hosts==("api.records.example",)
    store.close()
