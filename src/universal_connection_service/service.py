from uuid import uuid4
from .compiler import ConnectionCompiler
from .contracts import ConnectionError, ConnectionRequest, ConnectionResult, ExecutionContext
from .registry import ConnectorRegistry

class ConnectionService:
    def __init__(self, registry: ConnectorRegistry):
        self.registry, self.compiler = registry, ConnectionCompiler(registry)
    async def execute(self, req: ConnectionRequest, ctx: ExecutionContext) -> ConnectionResult:
        plan = self.compiler.compile(req)
        if not plan.connector_id:
            return ConnectionResult(requestId=req.request_id, status="failed", serviceId=plan.service_id,
                capability=req.capability, error=ConnectionError(code="CONNECTION_UNAVAILABLE", message="No trusted connector is available", userActionRequired=True), auditId=str(uuid4()))
        item = self.registry.trusted(plan.service_id, req.capability)
        if not item: raise RuntimeError("registry changed during execution")
        result = await item.connector.execute(req.capability, req.input, ctx)
        return ConnectionResult(requestId=req.request_id, status=result.status, serviceId=plan.service_id,
            capability=req.capability, connectorId=item.manifest.connector_id, data=result.data,
            error=result.error, auditId=str(uuid4()))
