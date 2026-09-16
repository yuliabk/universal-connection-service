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
from .openapi_adapter import OpenAPIConnectorAdapter
from .packages import ConnectorPackageLoader, CosignBundleVerifier, Ed25519PackageVerifier, FilesystemPackageSource
from .persistence import SQLiteStateStore, WorkflowStore
from .postgres_store import PostgresStateStore, config_from_env
from .registry import ConnectorRegistry
from .rehydration import ConnectorRuntimeRehydrator, RehydrationReport
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
        return None, None, "disabled"
    mode = os.getenv("UCS_PACKAGE_VERIFIER", "ed25519").strip().lower()
    source = FilesystemPackageSource(root)
    builder = None
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
            builder = GeneratedOpenAPIPackageBuilder(
                FilesystemPackageWriter(root),
                Ed25519BuildSigner(signer_ref=signer_ref, private_key=signing_key),
            )
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
    return ConnectorPackageLoader(source, verifier), builder, mode


def _bind_runtime_connector(connector):
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
package_loader, generated_package_builder, package_kind = _build_package_runtime()
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
mcp_package_acquirer = MCPPackageAcquirer(
    FilesystemBuildArtifactStore(artifact_dir) if artifact_dir else None
)
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
auto_connect_orchestrator = (
    BuildAwareAutoConnectOrchestrator(
        build_coordinator=build_coordinator,
        workflow_store=workflow_store,
        connection_service=service,
        control_plane_service=control_plane_service,
        registry=registry,
        approval_store=approval_store,
        evidence_store=state_store,
    )
    if workflow_store is not None
    else None
)
auto_connect_kind = "persistent+build" if auto_connect_orchestrator is not None else "disabled"
build_kind = "openapi+package-acquisition" if auto_connect_orchestrator is not None else "disabled"
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
