import os

from fastapi import FastAPI

from .contracts import ConnectionPlan, ConnectionRequest, ConnectionResult, ExecutionContext
from .persistence import SQLiteStateStore
from .registry import ConnectorRegistry
from .service import ConnectionService


def _build_state_store():
    path = os.getenv("UCS_STATE_DB_PATH")
    if not path:
        return None
    return SQLiteStateStore(path)


state_store = _build_state_store()
registry = ConnectorRegistry(state_store=state_store)
service = ConnectionService(
    registry,
    audit_store=state_store,
    evidence_store=state_store,
)
app = FastAPI(title="Universal Connection Service", version="0.1.0")


@app.get("/health")
def health():
    return {
        "ok": True,
        "version": "0.1.0",
        "state": "sqlite" if state_store is not None else "memory",
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
