from uuid import uuid4

from .compiler import ConnectionCompiler
from .contracts import ConnectionError, ConnectionRequest, ConnectionResult, ExecutionContext
from .policy import ApprovalVerifier, PolicyEngine
from .registry import ConnectorRegistry


class ConnectionService:
    def __init__(
        self,
        registry: ConnectorRegistry,
        policy_engine: PolicyEngine | None = None,
        approval_verifier: ApprovalVerifier | None = None,
    ):
        self.registry = registry
        self.compiler = ConnectionCompiler(registry, policy_engine=policy_engine)
        self.approval_verifier = approval_verifier

    @staticmethod
    def _failed(req: ConnectionRequest, service_id: str, code: str, message: str, *, user_action=False):
        return ConnectionResult(
            requestId=req.request_id,
            status="failed",
            serviceId=service_id,
            capability=req.capability,
            error=ConnectionError(
                code=code,
                message=message,
                userActionRequired=user_action,
            ),
            auditId=str(uuid4()),
        )

    @staticmethod
    def _context_matches(req: ConnectionRequest, ctx: ExecutionContext) -> bool:
        return (
            ctx.request_id == req.request_id
            and ctx.user_id == req.actor.user_id
            and ctx.organization_id == req.actor.organization_id
        )

    async def execute(self, req: ConnectionRequest, ctx: ExecutionContext) -> ConnectionResult:
        service_id = self.compiler.service_id(req)
        if not self._context_matches(req, ctx):
            return self._failed(
                req,
                service_id,
                "EXECUTION_CONTEXT_MISMATCH",
                "Execution context does not match the connection request",
                user_action=True,
            )

        plan = self.compiler.compile(req)
        if plan.policy_decision == "DENY":
            return self._failed(
                req,
                plan.service_id,
                "POLICY_DENIED",
                "Policy denied this connection request",
                user_action=True,
            )

        if not plan.connector_id:
            return self._failed(
                req,
                plan.service_id,
                "CONNECTION_UNAVAILABLE",
                "No trusted connector is available",
                user_action=True,
            )

        if plan.policy_decision == "REQUIRE_APPROVAL":
            if not ctx.approval_id:
                return self._failed(
                    req,
                    plan.service_id,
                    "APPROVAL_REQUIRED",
                    "This operation requires human approval",
                    user_action=True,
                )
            if self.approval_verifier is None:
                return self._failed(
                    req,
                    plan.service_id,
                    "APPROVAL_VERIFICATION_UNAVAILABLE",
                    "Approval verification is not configured",
                    user_action=True,
                )
            try:
                verification = await self.approval_verifier.verify(ctx.approval_id, req)
            except Exception:
                return self._failed(
                    req,
                    plan.service_id,
                    "APPROVAL_VERIFICATION_UNAVAILABLE",
                    "Approval verification failed",
                    user_action=True,
                )
            if not verification.valid:
                return self._failed(
                    req,
                    plan.service_id,
                    verification.code,
                    verification.message,
                    user_action=True,
                )
            try:
                # Approvals authorize one execution attempt. Consume before the
                # outbound call to prevent concurrent replay of a valid grant.
                await self.approval_verifier.consume(ctx.approval_id)
            except Exception:
                return self._failed(
                    req,
                    plan.service_id,
                    "APPROVAL_VERIFICATION_UNAVAILABLE",
                    "Approval could not be consumed",
                    user_action=True,
                )

        item = self.registry.trusted(plan.service_id, req.capability)
        if not item:
            raise RuntimeError("registry changed during execution")
        result = await item.connector.execute(req.capability, req.input, ctx)
        return ConnectionResult(
            requestId=req.request_id,
            status=result.status,
            serviceId=plan.service_id,
            capability=req.capability,
            connectorId=item.manifest.connector_id,
            data=result.data,
            error=result.error,
            auditId=str(uuid4()),
        )
