"""Separately authorized lookup and provider-protected business replay."""
from fastapi import APIRouter, Header, HTTPException

from .contracts import ConnectionRequest, ConnectionResult, ExecutionContext, Model


class ReconcileCommand(Model):
    request: ConnectionRequest
    context: ExecutionContext


def build_connection_execution_router(service, authenticator):
    router = APIRouter(prefix="/v1/connections", tags=["connections"])

    @router.post("/execute", response_model=ConnectionResult)
    async def execute(command: ReconcileCommand, authorization: str | None = Header(default=None)):
        if authenticator is None:
            raise HTTPException(503, detail={"code": "EXECUTION_AUTHENTICATION_UNAVAILABLE"})
        principal = authenticator.authenticate(authorization)
        if principal is None:
            raise HTTPException(401, detail={"code": "EXECUTION_UNAUTHENTICATED"},
                headers={"WWW-Authenticate": "Bearer"})
        if not principal.allows_execution(command.request.actor):
            raise HTTPException(403, detail={"code": "EXECUTION_ACTOR_FORBIDDEN"})
        return await service.execute(command.request, command.context)

    return router


def build_execution_router(service, authenticator):
    router = APIRouter(prefix="/v1/control-plane/executions", tags=["executions"])

    def authorize(command, authorization, scope):
        if authenticator is None:
            raise HTTPException(503, detail={"code": "CONTROL_PLANE_DISABLED"})
        actor = authenticator.authenticate(authorization)
        if actor is None:
            raise HTTPException(401, detail={"code": "CONTROL_PLANE_UNAUTHENTICATED"},
                headers={"WWW-Authenticate": "Bearer"})
        if not actor.allows(scope, command.request.actor.organization_id):
            raise HTTPException(403, detail={"code": "CONTROL_PLANE_FORBIDDEN"})

    @router.post("/reconcile", response_model=ConnectionResult)
    async def reconcile(command: ReconcileCommand, authorization: str | None = Header(default=None)):
        authorize(command, authorization, "executions:reconcile")
        return await service.execute(command.request, command.context, allow_dispatch=False, reconcile=True)

    @router.post("/replay", response_model=ConnectionResult)
    async def replay(command: ReconcileCommand, authorization: str | None = Header(default=None)):
        authorize(command, authorization, "executions:replay")
        return await service.execute(command.request, command.context, replay=True)

    return router
