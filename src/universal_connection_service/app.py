import os
from contextlib import asynccontextmanager

from fastapi import FastAPI

from .approvals import ApprovalStore, PersistentApprovalVerifier
from .contracts import ConnectionPlan, ConnectionRequest, ConnectionResult, ExecutionContext
from .persistence import SQLiteStateStore
from .postgres_store import PostgresStateStore, config_from_env
from .registry import ConnectorRegistry
from .service import ConnectionService


def _build_state_store():
    if os.getenv("UCS_DATABASE_URL"):
        return PostgresStateStore(config_from_env()), "postgres"
    path = os.getenv("UCS_STATE_DB_PATH")
    if path:
        return SQLiteStateStore(path), "sqlite"
    return None, "memory"


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


@asynccontextmanager
async def lifespan(app: FastAPI):
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
