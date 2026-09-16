import asyncio
from types import SimpleNamespace

from pydantic import SecretStr

from universal_connection_service.contracts import AuthRequirement, ConnectorManifest, ExecutionContext
from universal_connection_service.control_plane import ControlPlanePrincipal
from universal_connection_service.credentials import (
    AgentVaultCredentialBinding,
    AgentVaultCredentialResolverConfig,
    CredentialResolutionError,
)
from universal_connection_service.mcp_adapter import MCPToolBinding
from universal_connection_service.mcpb_sandbox import (
    DockerMCPBSandboxConfig,
    DockerMCPBSandboxRunner,
    SandboxedMCPConnector,
    SandboxedMCPConnectorConfig,
)
from universal_connection_service.persistence import SQLiteStateStore
from universal_connection_service.registry import ConnectorRegistry, Registration
from universal_connection_service.sandbox_credentials import AgentVaultSandboxBroker
from universal_connection_service.sandbox_policy import (
    SandboxCapabilityProfile,
    SandboxMountBinding,
    SandboxMountCatalog,
    SandboxMountGrant,
    SandboxPolicyService,
    SandboxProfileApplyCommand,
    SandboxProfileApprovalCommand,
)


class EmptyArtifacts:
    def get(self, digest, suffix):
        raise FileNotFoundError


def principal(subject, *scopes):
    return ControlPlanePrincipal(
        subject=subject,
        tokenId=f"token-{subject}",
        organizations=("org-1",),
        scopes=scopes,
    )


def trusted_sandbox_connector():
    return SandboxedMCPConnector(
        SandboxedMCPConnectorConfig(
            connectorId="sandbox-records",
            serviceId="records",
            name="Records sandbox",
            version="1.0.0",
            bundleDigest="a" * 64,
            bindings=(MCPToolBinding(capability="records.read", tool="records_read"),),
        )
    )


def test_profile_requires_one_time_approval_and_persists_only_safe_mount_metadata(tmp_path):
    shared = tmp_path / "shared"
    shared.mkdir()
    store = SQLiteStateStore(":memory:")
    registry = ConnectorRegistry(state_store=store)
    connector = trusted_sandbox_connector()
    registry.register(Registration(connector=connector, status="trusted", organization_id="org-1"))
    catalog = SandboxMountCatalog((
        SandboxMountBinding(
            organizationId="org-1",
            mountId="client-files",
            hostPath=str(shared),
            containerPath="/data/client-files",
            maxAccess="read_only",
        ),
    ))
    service = SandboxPolicyService(
        registry=registry,
        evidence_store=store,
        approval_store=store,
        mount_catalog=catalog,
        require_distinct_approver=True,
    )
    profile = SandboxCapabilityProfile(
        mounts=(SandboxMountGrant(mountId="client-files", access="read_only"),),
    )
    issued = service.issue_approval(
        principal("approver", "approvals:issue"),
        "sandbox-records",
        SandboxProfileApprovalCommand(
            organizationId="org-1",
            version="1.0.0",
            changeId="profile-change-1",
            profile=profile,
        ),
    )
    applied = service.apply(
        principal("operator", "connectors:promote"),
        "sandbox-records",
        SandboxProfileApplyCommand(
            organizationId="org-1",
            version="1.0.0",
            changeId="profile-change-1",
            profile=profile,
            approvalId=issued.approval_id,
        ),
    )
    assert applied.profile.mounts[0].mount_id == "client-files"
    assert service.active_profile("org-1", "sandbox-records", "1.0.0") == profile

    evidence_text = " ".join(item.model_dump_json(by_alias=True) for item in store.list_evidence("org-1"))
    assert str(shared) not in evidence_text
    assert issued.approval_id not in evidence_text
    assert "client-files" in evidence_text

    try:
        service.apply(
            principal("operator", "connectors:promote"),
            "sandbox-records",
            SandboxProfileApplyCommand(
                organizationId="org-1",
                version="1.0.0",
                changeId="profile-change-1",
                profile=profile,
                approvalId=issued.approval_id,
            ),
        )
        assert False, "expected approval replay rejection"
    except Exception as exc:
        assert getattr(exc, "code", None) == "APPROVAL_ALREADY_USED"
    store.close()


def test_profile_approval_is_bound_to_exact_profile(tmp_path):
    shared = tmp_path / "shared"
    shared.mkdir()
    store = SQLiteStateStore(":memory:")
    registry = ConnectorRegistry(state_store=store)
    registry.register(Registration(connector=trusted_sandbox_connector(), status="trusted", organization_id="org-1"))
    catalog = SandboxMountCatalog((
        SandboxMountBinding(
            organizationId="org-1", mountId="files", hostPath=str(shared),
            containerPath="/data/files", maxAccess="read_write",
        ),
    ))
    service = SandboxPolicyService(registry=registry, evidence_store=store, approval_store=store, mount_catalog=catalog)
    approved = SandboxCapabilityProfile(mounts=(SandboxMountGrant(mountId="files", access="read_only"),))
    issued = service.issue_approval(
        principal("approver", "approvals:issue"), "sandbox-records",
        SandboxProfileApprovalCommand(
            organizationId="org-1", version="1.0.0", changeId="profile-change-2", profile=approved,
        ),
    )
    changed = SandboxCapabilityProfile(mounts=(SandboxMountGrant(mountId="files", access="read_write"),))
    try:
        service.apply(
            principal("operator", "connectors:promote"), "sandbox-records",
            SandboxProfileApplyCommand(
                organizationId="org-1", version="1.0.0", changeId="profile-change-2",
                profile=changed, approvalId=issued.approval_id,
            ),
        )
        assert False, "expected profile scope mismatch"
    except Exception as exc:
        assert getattr(exc, "code", None) == "APPROVAL_SCOPE_MISMATCH"
    store.close()


class FakeResolver:
    def __init__(self, binding):
        self.config = AgentVaultCredentialResolverConfig(
            address="http://127.0.0.1:14321",
            agentToken="control-token",
            bindings=(binding,),
        )

    async def _mint_session(self, binding):
        return SimpleNamespace(
            proxy_url=SecretStr("http://short-token:vault-a@127.0.0.1:14322"),
            ca_certificate="-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
        )


def test_agent_vault_sandbox_broker_requires_exact_host_scope():
    binding = AgentVaultCredentialBinding(
        handle="opaque-handle",
        organizationId="org-1",
        serviceId="records",
        vault="vault-a",
        allowedHosts=("api.records.example", "auth.records.example"),
    )
    broker = AgentVaultSandboxBroker(FakeResolver(binding))
    ctx = ExecutionContext(
        requestId="req-1", userId="u1", organizationId="org-1",
        credentialHandle="opaque-handle",
    )
    session = asyncio.run(broker.sandbox_session(
        "records", ("auth.records.example", "api.records.example"), ctx
    ))
    assert "short-token" in session.proxy_url.get_secret_value()

    try:
        asyncio.run(broker.sandbox_session("records", ("api.records.example",), ctx))
        assert False, "expected host scope rejection"
    except CredentialResolutionError as exc:
        assert exc.code == "CREDENTIAL_TARGET_DENIED"


class FakeProfileProvider:
    def __init__(self, profile):
        self.profile = profile

    def active_profile(self, organization_id, connector_id, version):
        return self.profile


class FakeMountResolver:
    def __init__(self, binding):
        self.binding = binding

    def resolve(self, organization_id, grant):
        return self.binding


class FakeBroker:
    async def sandbox_session(self, service_id, allowed_hosts, ctx):
        return SimpleNamespace(
            proxy_url=SecretStr("http://short-token:vault-a@management.invalid:14322"),
            ca_certificate="CA-CERT",
        )


def test_runtime_capabilities_use_internal_proxy_network_and_catalog_mount(tmp_path):
    shared = tmp_path / "shared"
    shared.mkdir()
    profile = SandboxCapabilityProfile(
        egressHosts=("api.records.example",),
        mounts=(SandboxMountGrant(mountId="files", access="read_only"),),
        brokeredCredentials=True,
    )
    binding = SandboxMountBinding(
        organizationId="org-1", mountId="files", hostPath=str(shared),
        containerPath="/data/files", maxAccess="read_only",
    )
    runner = DockerMCPBSandboxRunner(
        EmptyArtifacts(),
        DockerMCPBSandboxConfig(
            egressNetwork="ucs-egress",
            egressProxyHost="agent-vault-proxy",
        ),
        profile_provider=FakeProfileProvider(profile),
        mount_resolver=FakeMountResolver(binding),
        credential_broker=FakeBroker(),
    )
    runner._require_internal_network = lambda: "ucs-egress"  # type: ignore[method-assign]
    ctx = ExecutionContext(
        requestId="req-1", userId="u1", organizationId="org-1",
        credentialHandle="opaque-handle",
    )
    secret_root = tmp_path / "secrets"
    secret_root.mkdir()
    network, mounts, env, has_secrets = asyncio.run(runner._execution_capabilities(
        service_id="records", connector_id="sandbox-records", version="1.0.0",
        ctx=ctx, secret_root=secret_root,
    ))
    assert network == "ucs-egress"
    assert has_secrets is True
    assert any("dst=/data/files,readonly" in item for item in mounts)
    proxy_values = " ".join(env)
    assert "agent-vault-proxy:14322" in proxy_values
    assert "management.invalid" not in proxy_values
    assert (secret_root / "ca.pem").read_text() == "CA-CERT"
