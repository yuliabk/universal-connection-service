import asyncio
import shutil
import subprocess
from contextlib import asynccontextmanager
from types import SimpleNamespace
from uuid import uuid4

import pytest

from universal_connection_service.contracts import ExecutionContext
from universal_connection_service.control_plane import ControlPlanePrincipal
from universal_connection_service.mcp_adapter import MCPToolBinding
from universal_connection_service.mcpb_sandbox import SandboxedMCPConnector, SandboxedMCPConnectorConfig
from universal_connection_service.persistence import SQLiteStateStore
from universal_connection_service.registry import ConnectorRegistry, Registration
from universal_connection_service.sandbox_managed_runtime import (
    DockerSandboxGatewayConfig,
    DockerSandboxGatewayManager,
    ToolScopedSandboxedMCPConnector,
)
from universal_connection_service.sandbox_policy import SandboxCapabilityProfile
from universal_connection_service.sandbox_tool_policy import (
    SandboxToolPolicyService,
    SandboxToolProfileApplyCommand,
    SandboxToolProfileApprovalCommand,
)


def principal(subject: str, *scopes: str) -> ControlPlanePrincipal:
    return ControlPlanePrincipal(
        subject=subject,
        tokenId=f"token-{subject}",
        organizations=("org-1",),
        scopes=scopes,
    )


def multi_tool_connector() -> SandboxedMCPConnector:
    return SandboxedMCPConnector(
        SandboxedMCPConnectorConfig(
            connectorId="sandbox-records",
            serviceId="records",
            name="Records sandbox",
            version="1.0.0",
            bundleDigest="a" * 64,
            bindings=(
                MCPToolBinding(capability="records.read", tool="records_read"),
                MCPToolBinding(capability="records.delete", tool="records_delete"),
            ),
        )
    )


def test_tool_profile_isolation_and_approval_scope():
    store = SQLiteStateStore(":memory:")
    registry = ConnectorRegistry(state_store=store)
    registry.register(Registration(connector=multi_tool_connector(), status="trusted", organization_id="org-1"))
    service = SandboxToolPolicyService(
        registry=registry,
        evidence_store=store,
        approval_store=store,
        require_distinct_approver=True,
    )
    profile = SandboxCapabilityProfile()
    issued = service.issue_approval(
        principal("approver", "approvals:issue"),
        "sandbox-records",
        SandboxToolProfileApprovalCommand(
            organizationId="org-1",
            version="1.0.0",
            capability="records.read",
            changeId="tool-policy-change-1",
            profile=profile,
        ),
    )
    applied = service.apply(
        principal("operator", "connectors:promote"),
        "sandbox-records",
        SandboxToolProfileApplyCommand(
            organizationId="org-1",
            version="1.0.0",
            capability="records.read",
            changeId="tool-policy-change-1",
            profile=profile,
            approvalId=issued.approval_id,
        ),
    )
    assert applied.capability == "records.read"
    assert service.active_profile("org-1", "sandbox-records", "1.0.0", "records.read") == profile
    assert service.active_profile("org-1", "sandbox-records", "1.0.0", "records.delete") == SandboxCapabilityProfile()
    assert service.active_profile("org-1", "sandbox-records", "1.0.0", None) == SandboxCapabilityProfile()

    second = service.issue_approval(
        principal("approver", "approvals:issue"),
        "sandbox-records",
        SandboxToolProfileApprovalCommand(
            organizationId="org-1",
            version="1.0.0",
            capability="records.read",
            changeId="tool-policy-change-2",
            profile=profile,
        ),
    )
    with pytest.raises(Exception) as captured:
        service.apply(
            principal("operator", "connectors:promote"),
            "sandbox-records",
            SandboxToolProfileApplyCommand(
                organizationId="org-1",
                version="1.0.0",
                capability="records.delete",
                changeId="tool-policy-change-2",
                profile=profile,
                approvalId=second.approval_id,
            ),
        )
    assert getattr(captured.value, "code", None) == "APPROVAL_SCOPE_MISMATCH"

    evidence_text = " ".join(item.model_dump_json(by_alias=True) for item in store.list_evidence("org-1"))
    assert issued.approval_id not in evidence_text
    assert "records.read" in evidence_text
    store.close()


class FakeMCPClient:
    async def call_tool(self, tool, input):
        return SimpleNamespace(is_error=False, structured_content={"tool": tool, "input": input}, content=[])


class FakeToolRunner:
    def __init__(self):
        self.capabilities = []

    @asynccontextmanager
    async def client_for_capability(self, digest, *, capability, service_id, connector_id, version, ctx):
        self.capabilities.append(capability)
        yield FakeMCPClient()


async def _execute_tool_scoped_connector():
    runner = FakeToolRunner()
    connector = ToolScopedSandboxedMCPConnector(multi_tool_connector().config, runner=runner)  # type: ignore[arg-type]
    result = await connector.execute(
        "records.delete",
        {"id": "42"},
        ExecutionContext(requestId="req-1", userId="u1", organizationId="org-1"),
    )
    return runner, result


def test_tool_scoped_connector_selects_runtime_profile_by_requested_capability():
    runner, result = asyncio.run(_execute_tool_scoped_connector())
    assert result.status == "success"
    assert result.data["tool"] == "records_delete"
    assert runner.capabilities == ["records.delete"]


def _docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    completed = subprocess.run(
        ["docker", "version", "--format", "{{.Server.Version}}"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    return completed.returncode == 0


@pytest.mark.skipif(not _docker_available(), reason="Docker daemon unavailable")
def test_managed_gateway_creates_internal_network_and_attaches_alias():
    suffix = uuid4().hex[:10]
    container = f"ucs-gateway-{suffix}"
    network = f"ucs-internal-{suffix}"
    alias = f"proxy-{suffix}"
    try:
        subprocess.run(
            ["docker", "run", "-d", "--name", container, "python:3.12-slim", "sleep", "60"],
            check=True,
            capture_output=True,
            text=True,
        )
        manager = DockerSandboxGatewayManager(
            DockerSandboxGatewayConfig(
                networkName=network,
                gatewayContainer=container,
                gatewayAlias=alias,
            )
        )
        first = manager.ensure()
        second = manager.ensure()
        assert first.ready is True and second.ready is True
        internal = subprocess.run(
            ["docker", "network", "inspect", network, "--format", "{{.Internal}}"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        assert internal == "true"
        networks = subprocess.run(
            ["docker", "inspect", container, "--format", "{{json .NetworkSettings.Networks}}"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        assert network in networks
        assert alias in networks
    finally:
        subprocess.run(["docker", "rm", "-f", container], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["docker", "network", "rm", network], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
