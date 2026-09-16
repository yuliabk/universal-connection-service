import base64
import json
import os
from contextlib import asynccontextmanager

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import FastAPI

from .approvals import ApprovalStore, PersistentApprovalVerifier
from .auto_connect import build_auto_connect_router
from .build_auto_connect import BuildAwareAutoConnectOrchestrator, VerifiedBuildCoordinator
from .build_pipeline import (
    ConnectorBuildPipeline,
    Ed25519BuildSigner,
    FilesystemBuildArtifactStore,
    FilesystemPackageWriter,
    GeneratedOpenAPIPackageBuilder,
    MCPPackageAcquirer,
    OpenAPICatalogProvider,
)
from .contracts import ConnectionPlan, ConnectionRequest, ConnectionResult, ExecutionContext
from .control_plane import ControlPlaneService, StaticBearerAuthenticator, build_control_plane_router
from .credentials import AgentVaultCredentialResolver, AgentVaultCredentialResolverConfig
from .discovery import DiscoveryEngine, MCPRegistryConfig, MCPRegistryDiscoveryProvider
from .mcp_adapter import MCPConnectorAdapter
from .mcp_validation import MCPValidationService
from .mcpb_sandbox import DockerMCPBSandboxConfig, DockerMCPBSandboxRunner, SandboxedMCPConnector
from .openapi_adapter import OpenAPIConnectorAdapter
from .packages import ConnectorPackageLoader, CosignBundleVerifier, Ed25519PackageVerifier, FilesystemPackageSource
from .persistence import SQLiteStateStore, WorkflowStore
from .postgres_store import PostgresStateStore, config_from_env
from .registry import ConnectorRegistry
from .rehydration import ConnectorRuntimeRehydrator, RehydrationReport
from .sandbox_build import (
    FilesystemMCPBArtifactStore,
    GeneratedSandboxMCPPackageBuilder,
    SandboxAwareBuildCoordinator,
    SandboxBuildAwareAutoConnectOrchestrator,
    SandboxMCPPackageAcquirer,
)
from .service import ConnectionService


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _build_state_store():
    if os.getenv("UCS_DATABASE_URL"):
        return PostgresStateStore(config_from_env()), "postgres"
    path = os.getenv("UCS_STATE_DB_PATH")
    if path:
        return SQLiteStateStore(path), "sqlite"
    return None, "memory"


def _build_openapi_catalog():
    raw = os.getenv("UCS_OPENAPI_CATALOG_JSON")
    if not raw:
        return None
    try:
        return OpenAPICatalogProvider.from_json(raw)
    except ValueError as exc:
        raise RuntimeError("UCS_OPENAPI_CATALOG_JSON is invalid") from exc


def _build_discovery_engine(openapi_catalog):
    providers = []
    kinds = []
    if _env_bool("UCS_MCP_REGISTRY_ENABLED"):
        config = MCPRegistryConfig(
            baseUrl=os.getenv("UCS_MCP_REGISTRY_URL", "https://registry.modelcontextprotocol.io"),
            timeoutSeconds=float(os.getenv("UCS_MCP_REGISTRY_TIMEOUT_SECONDS", "4")),
            pageSize=int(os.getenv("UCS_MCP_REGISTRY_PAGE_SIZE", "20")),
            maxPages=int(os.getenv("UCS_MCP_REGISTRY_MAX_PAGES", "2")),
            cacheTtlSeconds=int(os.getenv("UCS_MCP_REGISTRY_CACHE_TTL_SECONDS", "3600")),
        )
        providers.append(MCPRegistryDiscoveryProvider(config))
        kinds.append("mcp_registry")
    if openapi_catalog is not None:
        providers.append(openapi_catalog)
        kinds.append("openapi_catalog")
    return (DiscoveryEngine(tuple(providers)) if providers else None), ("+".join(kinds) if kinds else "disabled")


def _build_control_plane_authenticator():
    raw = os.getenv("UCS_CONTROL_PLANE_CREDENTIALS_JSON")
    if not raw:
        return None, "disabled"
    try:
        return StaticBearerAuthenticator.from_json(raw), "enabled"
    except ValueError as exc:
        raise RuntimeError("UCS_CONTROL_PLANE_CREDENTIALS_JSON is invalid") from exc


def _build_credential_resolver():
    raw = os.getenv("UCS_AGENT_VAULT_CONFIG_JSON")
    if not raw:
        return None, "disabled"
    try:
        config = AgentVaultCredentialResolverConfig.model_validate_json(raw)
    except Exception as exc:
        raise RuntimeError("UCS_AGENT_VAULT_CONFIG_JSON is invalid") from exc
    return AgentVaultCredentialResolver(config), "agent_vault"


def _signing_public_key(signing_key_b64: str) -> bytes:
    try:
        private = Ed25519PrivateKey.from_private_bytes(base64.b64decode(signing_key_b64, validate=True))
    except Exception:
        raise RuntimeError("UCS_PACKAGE_ED25519_SIGNING_KEY is invalid") from None
    return private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _build_package_runtime():
    root = os.getenv("UCS_CONNECTOR_PACKAGE_DIR")
    if not root:
        return None, None, None, "disabled"
    mode = os.getenv("UCS_PACKAGE_VERIFIER", "ed25519").strip().lower()
    source = FilesystemPackageSource(root)
    openapi_builder = None
    sandbox_builder = None
    if mode == "ed25519":
        raw_keys = os.getenv("UCS_PACKAGE_ED25519_KEYS_JSON")
        signing_key = os.getenv("UCS_PACKAGE_ED25519_SIGNING_KEY")
        signer_ref = os.getenv("UCS_PACKAGE_SIGNER_REF", "ucs-local-builder")
        keys = None
        if raw_keys:
            try:
                keys = json.loads(raw_keys)
            except json.JSONDecodeError:
                raise RuntimeError("UCS_PACKAGE_ED25519_KEYS_JSON must be valid JSON") from None
            if not isinstance(keys, dict) or not keys:
                raise RuntimeError("UCS_PACKAGE_ED25519_KEYS_JSON must be a non-empty object")
        elif signing_key:
            keys = {signer_ref: _signing_public_key(signing_key)}
        else:
            raise RuntimeError("Ed25519 package verification requires public keys or a build signing key")
        verifier = Ed25519PackageVerifier(keys)
        if signing_key:
            writer = FilesystemPackageWriter(root)
            signer = Ed25519BuildSigner(signer_ref=signer_ref, private_key=signing_key)
            openapi_builder = GeneratedOpenAPIPackageBuilder(writer, signer)
            sandbox_builder = GeneratedSandboxMCPPackageBuilder(writer, signer)
    elif mode == "sigstore":
        identity = os.getenv("UCS_PACKAGE_SIGSTORE_IDENTITY")
        issuer = os.getenv("UCS_PACKAGE_SIGSTORE_ISSUER")
        if not identity or not issuer:
            raise RuntimeError("Sigstore package verification requires identity and issuer")
        verifier = CosignBundleVerifier(
            certificate_identity=identity,
            certificate_oidc_issuer=issuer,
            executable=os.getenv("UCS_COSIGN_EXECUTABLE", "cosign"),
        )
    else:
        raise RuntimeError("UCS_PACKAGE_VERIFIER must be ed25519 or sigstore")
    return ConnectorPackageLoader(source, verifier), openapi_builder, sandbox_builder, mode


def _build_sandbox_runner(artifact_store):
    if not _env_bool("UCS_MCP_PACKAGE_SANDBOX_ENABLED"):
        return None, "disabled"
    if artifact_store is None:
        raise RuntimeError("UCS_BUILD_ARTIFACT_DIR is required when MCP package sandboxing is enabled")
    config = DockerMCPBSandboxConfig(
        dockerExecutable=os.getenv("UCS_MCP_SANDBOX_DOCKER", "docker"),
        pythonImage=os.getenv("UCS_MCP_SANDBOX_PYTHON_IMAGE", "python:3.12-slim"),
        nodeImage=os.getenv("UCS_MCP_SANDBOX_NODE_IMAGE", "node:22-bookworm-slim"),
        memoryLimit=os.getenv("UCS_MCP_SANDBOX_MEMORY", "256m"),
        cpuLimit=float(os.getenv("UCS_MCP_SANDBOX_CPUS", "1")),
        pidsLimit=int(os.getenv("UCS_MCP_SANDBOX_PIDS", "64")),
        tmpfsBytes=int(os.getenv("UCS_MCP_SANDBOX_TMPFS_BYTES", str(64 * 1024 * 1024))),
        startupTimeoutSeconds=float(os.getenv("UCS_MCP_SANDBOX_STARTUP_TIMEOUT", "5")),
    )
    return DockerMCPBSandboxRunner(artifact_store, config), "docker"


def _bind_runtime_connector(connector):
    if isinstance(connector, SandboxedMCPConnector):
        if mcp_sandbox_runner is None:
            raise RuntimeError("trusted sandboxed MCP connector cannot rehydrate without the configured sandbox runtime")
        return connector.with_runner(mcp_sandbox_runner)
    if credential_resolver is None:
        return connector
    if isinstance(connector, OpenAPIConnectorAdapter):
        return OpenAPIConnectorAdapter(connector.config, credential_resolver=credential_resolver)
    if isinstance(connector, MCPConnectorAdapter):
        return MCPConnectorAdapter(connector.config, credential_resolver=credential_resolver)
    return connector


state_store, state_kind = _build_state_store()
openapi_catalog = _build_openapi_catalog()
discovery_engine, discovery_kind = _build_discovery_engine(openapi_catalog)
control_plane_authenticator, control_plane_kind = _build_control_plane_authenticator()
credential_resolver, credential_broker_kind = _build_credential_resolver()
package_loader, generated_package_builder, generated_sandbox_package_builder, package_kind = _build_package_runtime()
registry = ConnectorRegistry(state_store=state_store)
approval_store = state_store if isinstance(state_store, ApprovalStore) else None
workflow_store = state_store if isinstance(state_store, WorkflowStore) else None
approval_verifier = PersistentApprovalVerifier(approval_store) if approval_store is not None else None
service = ConnectionService(
    registry,
    approval_verifier=approval_verifier,
    audit_store=state_store,
    evidence_store=state_store,
    discovery_engine=discovery_engine,
)
mcp_validation_service = MCPValidationService(
    registry,
    evidence_store=state_store,
    credential_resolver=credential_resolver,
)
control_plane_service = ControlPlaneService(
    registry=registry,
    connection_service=service,
    state_store=state_store,
    evidence_store=state_store,
    approval_store=approval_store,
    mcp_validation_service=mcp_validation_service,
    require_distinct_approver=_env_bool("UCS_CONTROL_PLANE_REQUIRE_DISTINCT_APPROVER"),
)
artifact_dir = os.getenv("UCS_BUILD_ARTIFACT_DIR")
generic_artifact_store = FilesystemBuildArtifactStore(artifact_dir) if artifact_dir else None
mcpb_artifact_store = FilesystemMCPBArtifactStore(artifact_dir) if artifact_dir else None
mcp_sandbox_runner, mcp_sandbox_kind = _build_sandbox_runner(mcpb_artifact_store)
mcp_package_acquirer = MCPPackageAcquirer(generic_artifact_store)
build_pipeline = ConnectorBuildPipeline(
    registry=registry,
    evidence_store=state_store,
    openapi_descriptors=(openapi_catalog,) if openapi_catalog is not None else (),
    package_builder=generated_package_builder,
    mcp_package_acquirer=mcp_package_acquirer,
    credential_resolver=credential_resolver,
)
build_coordinator = VerifiedBuildCoordinator(
    pipeline=build_pipeline,
    package_loader=package_loader,
    evidence_store=state_store,
)
if mcp_sandbox_runner is not None and mcpb_artifact_store is not None:
    sandbox_build_coordinator = SandboxAwareBuildCoordinator(
        fallback=build_coordinator,
        runner=mcp_sandbox_runner,
        acquirer=SandboxMCPPackageAcquirer(mcpb_artifact_store),
        package_builder=generated_sandbox_package_builder,
        package_loader=package_loader,
        registry=registry,
        evidence_store=state_store,
    )
else:
    sandbox_build_coordinator = None

auto_connect_orchestrator = None
if workflow_store is not None:
    common = dict(
        workflow_store=workflow_store,
        connection_service=service,
        control_plane_service=control_plane_service,
        registry=registry,
        approval_store=approval_store,
        evidence_store=state_store,
    )
    if sandbox_build_coordinator is not None:
        auto_connect_orchestrator = SandboxBuildAwareAutoConnectOrchestrator(
            build_coordinator=sandbox_build_coordinator,
            **common,
        )
    else:
        auto_connect_orchestrator = BuildAwareAutoConnectOrchestrator(
            build_coordinator=build_coordinator,
            **common,
        )

auto_connect_kind = (
    "persistent+build+mcpb-sandbox"
    if auto_connect_orchestrator is not None and mcp_sandbox_runner is not None
    else "persistent+build"
    if auto_connect_orchestrator is not None
    else "disabled"
)
build_kind = (
    "openapi+mcpb-docker"
    if mcp_sandbox_runner is not None
    else "openapi+package-acquisition"
    if auto_connect_orchestrator is not None
    else "disabled"
)
package_rehydration = RehydrationReport()


def _rehydrate_packages() -> RehydrationReport:
    if package_loader is None or state_store is None:
        return RehydrationReport()
    return ConnectorRuntimeRehydrator(
        state_store=state_store,
        evidence_store=state_store,
        registry=registry,
        loader=package_loader,
        runtime_binder=_bind_runtime_connector,
    ).rehydrate()


@asynccontextmanager
async def lifespan(app: FastAPI):
    global package_rehydration
    package_rehydration = _rehydrate_packages()
    yield
    close = getattr(state_store, "close", None)
    if close is not None:
        close()


app = FastAPI(title="Universal Connection Service", version="0.1.0", lifespan=lifespan)
app.include_router(build_control_plane_router(control_plane_service, control_plane_authenticator))
app.include_router(build_auto_connect_router(auto_connect_orchestrator, control_plane_authenticator))


@app.get("/health")
def health():
    return {
        "ok": True,
        "version": "0.1.0",
        "state": state_kind,
        "discovery": discovery_kind,
        "controlPlane": control_plane_kind,
        "credentialBroker": credential_broker_kind,
        "autoConnect": auto_connect_kind,
        "buildPipeline": build_kind,
        "packageVerifier": package_kind,
        "packageSandbox": mcp_sandbox_kind,
        "packages": {
            "loaded": package_rehydration.loaded,
            "skipped": package_rehydration.skipped,
            "failed": package_rehydration.failed,
        },
    }


@app.get("/v1/connectors")
def connectors():
    return [m.model_dump(by_alias=True, mode="json") for m in registry.manifests()]


@app.post("/v1/connections/plan", response_model=ConnectionPlan)
def plan(request: ConnectionRequest):
    return service.compiler.compile(request)


@app.post("/v1/connections/execute", response_model=ConnectionResult)
async def execute(request: ConnectionRequest, context: ExecutionContext):
    return await service.execute(request, context)
