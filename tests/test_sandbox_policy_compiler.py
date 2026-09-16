import asyncio
from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest
from pydantic import SecretStr

from universal_connection_service.contracts import ExecutionContext
from universal_connection_service.control_plane import ControlPlanePrincipal
from universal_connection_service.credentials import (
    AgentVaultCredentialBinding,
    AgentVaultCredentialResolver,
    AgentVaultCredentialResolverConfig,
)
from universal_connection_service.mcp_adapter import MCPToolBinding
from universal_connection_service.mcpb_sandbox import SandboxedMCPConnector, SandboxedMCPConnectorConfig
from universal_connection_service.persistence import SQLiteStateStore
from universal_connection_service.registry import ConnectorRegistry, Registration
from universal_connection_service.sandbox_policy import (
    SandboxCapabilityProfile,
    SandboxMountBinding,
    SandboxMountCatalog,
    SandboxMountGrant,
)
from universal_connection_service.sandbox_policy_compiler import (
    LeastPrivilegePolicyCompiler,
    SandboxPolicyCatalog,
    SandboxPolicyRule,
)


def principal(subject: str = "reviewer") -> ControlPlanePrincipal:
    return ControlPlanePrincipal(
        subject=subject,
        tokenId=f"token-{subject}",
        organizations=("org-1",),
        scopes=("connectors:review",),
    )


class FakeTool:
    def __init__(self, name: str, annotations: dict | None = None):
        self.name = name
        self.annotations = annotations or {}

    def model_dump(self, **kwargs):
        return {
            "name": self.name,
            "inputSchema": {"type": "object"},
            "annotations": self.annotations,
        }


class FakePage:
    def __init__(self, tools):
        self.tools = tools
        self.next_cursor = None


class FakeClient:
    def __init__(self, tools):
        self.tools = tools

    async def list_tools(self, cursor=None):
        return FakePage(self.tools)


class FakeRunner:
    def __init__(self, tools):
        self.tools = tools

    @asynccontextmanager
    async def client(self, digest, **kwargs):
        yield FakeClient(self.tools)


def trusted_connector(*, runner=None, capabilities=("records.read",)):
    bindings = tuple(
        MCPToolBinding(capability=capability, tool=capability.replace(".", "_"))
        for capability in capabilities
    )
    return SandboxedMCPConnector(
        SandboxedMCPConnectorConfig(
            connectorId="sandbox-records",
            serviceId="records",
            name="Records sandbox",
            version="1.0.0",
            bundleDigest="a" * 64,
            bindings=bindings,
        ),
        runner=runner,
    )


def setup_compiler(*, runner=None, catalog=None, resolver=None, mount_catalog=None):
    store = SQLiteStateStore(":memory:")
    registry = ConnectorRegistry(state_store=store)
    registry.register(
        Registration(
            connector=trusted_connector(runner=runner),
            status="trusted",
            organization_id="org-1",
        )
    )
    compiler = LeastPrivilegePolicyCompiler(
        registry=registry,
        evidence_store=store,
        mount_catalog=mount_catalog or SandboxMountCatalog(),
        policy_catalog=catalog,
        credential_resolver=resolver,
    )
    return store, compiler


def test_unknown_tool_behavior_keeps_zero_privilege_and_requires_review():
    store, compiler = setup_compiler(runner=FakeRunner([FakeTool("records_read")]))
    proposal = asyncio.run(
        compiler.compile(
            principal(),
            organization_id="org-1",
            connector_id="sandbox-records",
            version="1.0.0",
            capability="records.read",
        )
    )
    assert proposal.profile == SandboxCapabilityProfile()
    assert proposal.confidence == "LOW"
    assert "open_world_behavior_unverified" in proposal.unresolved_requirements
    assert proposal.requires_human_approval is True
    evidence = store.list_evidence("org-1", kind="policy_decision")
    assert any(item.payload.get("type") == "sandbox_policy_proposal" for item in evidence)
    store.close()


def _resolver(bindings):
    return AgentVaultCredentialResolver(
        AgentVaultCredentialResolverConfig(
            address="http://127.0.0.1:14321",
            agentToken="control-secret",
            bindings=bindings,
        )
    )


def test_open_world_tool_uses_unique_operator_credential_scope_without_persisting_handle():
    resolver = _resolver((
        AgentVaultCredentialBinding(
            handle="opaque-handle-1",
            organizationId="org-1",
            serviceId="records",
            vault="records-vault",
            allowedHosts=("api.records.example", "auth.records.example"),
        ),
    ))
    runner = FakeRunner([
        FakeTool(
            "records_read",
            {"readOnlyHint": True, "openWorldHint": True, "idempotentHint": True},
        )
    ])
    store, compiler = setup_compiler(runner=runner, resolver=resolver)
    proposal = asyncio.run(
        compiler.compile(
            principal(),
            organization_id="org-1",
            connector_id="sandbox-records",
            version="1.0.0",
            capability="records.read",
        )
    )
    assert proposal.profile.egress_hosts == ("api.records.example", "auth.records.example")
    assert proposal.profile.brokered_credentials is True
    assert proposal.confidence == "MEDIUM"
    assert proposal.unresolved_requirements == ()
    text = " ".join(item.model_dump_json(by_alias=True) for item in store.list_evidence("org-1"))
    assert "opaque-handle-1" not in text
    assert "control-secret" not in text
    assert "api.records.example" in text
    store.close()


def test_multiple_agent_vault_scopes_require_selection_and_do_not_union_hosts():
    resolver = _resolver((
        AgentVaultCredentialBinding(
            handle="handle-a",
            organizationId="org-1",
            serviceId="records",
            vault="vault-a",
            allowedHosts=("api-a.records.example",),
        ),
        AgentVaultCredentialBinding(
            handle="handle-b",
            organizationId="org-1",
            serviceId="records",
            vault="vault-b",
            allowedHosts=("api-b.records.example",),
        ),
    ))
    runner = FakeRunner([FakeTool("records_read", {"openWorldHint": True})])
    store, compiler = setup_compiler(runner=runner, resolver=resolver)
    proposal = asyncio.run(
        compiler.compile(
            principal(),
            organization_id="org-1",
            connector_id="sandbox-records",
            version="1.0.0",
            capability="records.read",
        )
    )
    assert proposal.profile == SandboxCapabilityProfile()
    assert "credential_scope_selection_required" in proposal.unresolved_requirements
    assert proposal.confidence == "LOW"
    store.close()


def test_operator_catalog_can_propose_exact_mount_profile(tmp_path):
    shared = tmp_path / "shared"
    shared.mkdir()
    mounts = SandboxMountCatalog((
        SandboxMountBinding(
            organizationId="org-1",
            mountId="records-data",
            hostPath=str(shared),
            containerPath="/data/records",
            maxAccess="read_only",
        ),
    ))
    profile = SandboxCapabilityProfile(
        mounts=(SandboxMountGrant(mountId="records-data", access="read_only"),),
    )
    catalog = SandboxPolicyCatalog((
        SandboxPolicyRule(
            organizationId="org-1",
            serviceId="records",
            capability="records.read",
            toolName="records_read",
            profile=profile,
            reason="records.read needs the operator-approved records snapshot",
        ),
    ))
    runner = FakeRunner([FakeTool("records_read", {"readOnlyHint": True, "openWorldHint": False})])
    store, compiler = setup_compiler(runner=runner, catalog=catalog, mount_catalog=mounts)
    proposal = asyncio.run(
        compiler.compile(
            principal(),
            organization_id="org-1",
            connector_id="sandbox-records",
            version="1.0.0",
            capability="records.read",
        )
    )
    assert proposal.profile == profile
    assert proposal.confidence == "HIGH"
    assert proposal.unresolved_requirements == ()
    evidence_text = " ".join(item.model_dump_json(by_alias=True) for item in store.list_evidence("org-1"))
    assert str(shared) not in evidence_text
    assert "records-data" in evidence_text
    store.close()


def test_equal_specificity_conflict_fails_closed_to_zero_profile():
    profile_a = SandboxCapabilityProfile()
    profile_b = SandboxCapabilityProfile(
        egressHosts=("api.records.example",),
        brokeredCredentials=True,
    )
    catalog = SandboxPolicyCatalog((
        SandboxPolicyRule(
            organizationId="org-1", serviceId="records", capability="records.read",
            toolName="records_read", profile=profile_a, reason="rule a",
        ),
        SandboxPolicyRule(
            organizationId="org-1", serviceId="records", capability="records.read",
            toolName="records_read", profile=profile_b, reason="rule b",
        ),
    ))
    store, compiler = setup_compiler(runner=FakeRunner([FakeTool("records_read")]), catalog=catalog)
    proposal = asyncio.run(
        compiler.compile(
            principal(),
            organization_id="org-1",
            connector_id="sandbox-records",
            version="1.0.0",
            capability="records.read",
        )
    )
    assert proposal.profile == SandboxCapabilityProfile()
    assert "operator_policy_conflict" in proposal.unresolved_requirements
    assert proposal.confidence == "LOW"
    store.close()


def test_review_scope_is_required():
    store, compiler = setup_compiler(runner=FakeRunner([FakeTool("records_read")]))
    denied = ControlPlanePrincipal(
        subject="no-review",
        tokenId="token-no-review",
        organizations=("org-1",),
        scopes=("connectors:validate",),
    )
    with pytest.raises(Exception) as captured:
        asyncio.run(
            compiler.compile(
                denied,
                organization_id="org-1",
                connector_id="sandbox-records",
                version="1.0.0",
                capability="records.read",
            )
        )
    assert getattr(captured.value, "code", None) == "CONTROL_PLANE_FORBIDDEN"
    store.close()
