import json
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI

from .approvals import ApprovalStore, PersistentApprovalVerifier
from .contracts import ConnectionPlan, ConnectionRequest, ConnectionResult, ExecutionContext
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


def _build_state_store():
    if os.getenv("UCS_DATABASE_URL"):
        return PostgresStateStore(config_from_env()), "postgres"
    path = os.getenv("UCS_STATE_DB_PATH")
    if path:
        return SQLiteStateStore(path), "sqlite"
    return None, "memory"


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
registry = ConnectorRegistry(state_store=state_store)
approval_verifier = (
    PersistentApprovalVerifier(state_store)
    if isinstance(state_store, ApprovalStore)
    else None
)
service = ConnectionService(
    registry,
    approval_verifier=approval_verifier,
    audit_store=state_store,
    evidence_store=state_store,
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


@app.get("/health")
def health():
    return {
        "ok": True,
        "version": "0.1.0",
        "state": state_kind,
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
