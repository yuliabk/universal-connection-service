from fastapi import FastAPI
from .contracts import ConnectionPlan, ConnectionRequest, ConnectionResult, ExecutionContext
from .registry import ConnectorRegistry
from .service import ConnectionService

registry = ConnectorRegistry()
service = ConnectionService(registry)
app = FastAPI(title="Universal Connection Service", version="0.1.0")

@app.get("/health")
def health(): return {"ok": True, "version": "0.1.0"}

@app.get("/v1/connectors")
def connectors(): return [m.model_dump(by_alias=True, mode="json") for m in registry.manifests()]

@app.post("/v1/connections/plan", response_model=ConnectionPlan)
def plan(request: ConnectionRequest): return service.compiler.compile(request)

@app.post("/v1/connections/execute", response_model=ConnectionResult)
async def execute(request: ConnectionRequest, context: ExecutionContext): return await service.execute(request, context)
