"""Authenticated receipt reconciliation; never a business retry endpoint."""
from fastapi import APIRouter, Header, HTTPException

from .contracts import ConnectionRequest, ConnectionResult, ExecutionContext, Model


class ReconcileCommand(Model):
    request: ConnectionRequest
    context: ExecutionContext


def build_execution_router(service, authenticator):
    router = APIRouter(prefix="/v1/control-plane/executions", tags=["executions"])

    @router.post("/reconcile", response_model=ConnectionResult)
    async def reconcile(command: ReconcileCommand, authorization: str | None = Header(default=None)):
        if authenticator is None:
            raise HTTPException(503, detail={"code": "CONTROL_PLANE_DISABLED"})
        actor = authenticator.authenticate(authorization)
        if actor is None:
            raise HTTPException(401, detail={"code": "CONTROL_PLANE_UNAUTHENTICATED"},
                headers={"WWW-Authenticate": "Bearer"})
        if not actor.allows("executions:reconcile", command.request.actor.organization_id):
            raise HTTPException(403, detail={"code": "CONTROL_PLANE_FORBIDDEN"})
        return await service.execute(command.request, command.context, allow_dispatch=False, reconcile=True)

    return router
