import json
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI

from .approvals import ApprovalStore, PersistentApprovalVerifier
from .contracts import ConnectionPlan, ConnectionRequest, ConnectionResult, ExecutionContext
from .control_plane import ControlPlaneService, StaticBearerAuthenticator, build_control_plane_router
from .credentials import AgentVaultCredentialResolver, AgentVaultCredentialResolverConfig
from .discovery import DiscoveryEngine, MCPRegistryConfig, MCPRegistryDiscoveryProvider
from .mcp_validation import MCPValidationService
from .packages import (
    ConnectorPackageLoader,
    CosignBundleVerifier,
    Ed25519PackageVerifier,
    FilesystemPackageSource,
)
from .persistence import SQLiteStateStore
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


def _build_discovery_engine():
    if not _env_bool("UCS_MCP_REGISTRY_ENABLED"):
        return None, "disabled"
    config = MCPRegistryConfig(
        baseUrl=os.getenv("UCS_MCP_REGISTRY_URL", "https://registry.modelcontextprotocol.io"),
        timeoutSeconds=float(os.getenv("UCS_MCP_REGISTRY_TIMEOUT_SECONDS", "4")),
        pageSize=int(os.getenv("UCS_MCP_REGISTRY_PAGE_SIZE", "20")),
        maxPages=int(os.getenv("UCS_MCP_REGISTRY_MAX_PAGES", "2")),
        cacheTtlSeconds=int(os.getenv("UCS_MCP_REGISTRY_CACHE_TTL_SECONDS", "3600")),
    )
    return DiscoveryEngine((MCPRegistryDiscoveryProvider(config),)), "mcp_registry"


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


def _package_loader_from_env():
    root = os.getenv("UCS_CONNECTOR_PACKAGE_DIR")
    if not root:
        return None
    mode = os.getenv("UCS_PACKAGE_VERIFIER", "ed25519").strip().lower()
    source = FilesystemPackageSource(root)
    if mode == "ed25519":
        raw_keys = os.getenv("UCS_PACKAGE_ED25519_KEYS_JSON")
        if not raw_keys:
            raise RuntimeError("UCS_PACKAGE_ED25519_KEYS_JSON is required for package rehydration")
        try:
            keys = json.loads(raw_keys)
        except json.JSONDecodeError:
            raise RuntimeError("UCS_PACKAGE_ED25519_KEYS_JSON must be valid JSON") from None
        if not isinstance(keys, dict) or not keys:
            raise RuntimeError("UCS_PACKAGE_ED25519_KEYS_JSON must be a non-empty object")
        verifier = Ed25519PackageVerifier(keys)
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
    return ConnectorPackageLoader(source, verifier)


state_store, state_kind = _build_state_store()
discovery_engine, discovery_kind = _build_discovery_engine()
control_plane_authenticator, control_plane_kind = _build_control_plane_authenticator()
credential_resolver, credential_broker_kind = _build_credential_resolver()
registry = ConnectorRegistry(state_store=state_store)
approval_store = state_store if isinstance(state_store, ApprovalStore) else None
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
package_rehydration = RehydrationReport()


def _rehydrate_packages() -> RehydrationReport:
    loader = _package_loader_from_env()
    if loader is None or state_store is None:
        return RehydrationReport()
    return ConnectorRuntimeRehydrator(
        state_store=state_store,
        evidence_store=state_store,
        registry=registry,
        loader=loader,
    ).rehydrate()


@asynccontextmanager
async def lifespan(app: FastAPI):
    global package_rehydration
    package_rehydration = _rehydrate_packages()
    yield
    close = getattr(state_store, "close", None)
    if close is not None:
        close()


app = FastAPI(
    title="Universal Connection Service",
    version="0.1.0",
    lifespan=lifespan,
)
app.include_router(build_control_plane_router(control_plane_service, control_plane_authenticator))


@app.get("/health")
def health():
    return {
        "ok": True,
        "version": "0.1.0",
        "state": state_kind,
        "discovery": discovery_kind,
        "controlPlane": control_plane_kind,
        "credentialBroker": credential_broker_kind,
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
