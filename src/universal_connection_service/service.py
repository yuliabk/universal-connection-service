from __future__ import annotations

import hashlib
from uuid import uuid4

from .compiler import ConnectionCompiler
from .contracts import ConnectionError, ConnectionRequest, ConnectionResult, ExecutionContext
from .discovery import DiscoveryEngine
from .persistence import AuditEvent, AuditStore, EvidenceRecord, EvidenceStore
from .policy import ApprovalVerifier, PolicyEngine
from .registry import ConnectorRegistry
from .execution import DurableExecutor
from .effects import EffectCatalog


class ConnectionService:
    def __init__(
        self,
        registry: ConnectorRegistry,
        policy_engine: PolicyEngine | None = None,
        approval_verifier: ApprovalVerifier | None = None,
        *,
        audit_store: AuditStore | None = None,
        evidence_store: EvidenceStore | None = None,
        discovery_engine: DiscoveryEngine | None = None,
        durable_executor: DurableExecutor | None = None,
        effect_catalog: EffectCatalog | None = None,
    ):
        self.registry = registry
        self.effect_catalog = effect_catalog if effect_catalog is not None else EffectCatalog()
        self.compiler = ConnectionCompiler(
            registry,
            effect_catalog=self.effect_catalog,
            policy_engine=policy_engine,
            evidence_store=evidence_store,
            discovery_engine=discovery_engine,
        )
        self.approval_verifier = approval_verifier
        self.audit_store = audit_store
        self.evidence_store = evidence_store
        self.durable_executor = durable_executor

    @staticmethod
    def _context_matches(req: ConnectionRequest, ctx: ExecutionContext) -> bool:
        return (
            ctx.request_id == req.request_id
            and ctx.user_id == req.actor.user_id
            and ctx.organization_id == req.actor.organization_id
        )

    @staticmethod
    def _approval_ref_hash(approval_id: str | None) -> str | None:
        if not approval_id:
            return None
        return hashlib.sha256(approval_id.encode("utf-8")).hexdigest()

    def _persist_approval_evidence(
        self,
        req: ConnectionRequest,
        *,
        connector_id: str | None,
        approval_id: str | None,
        valid: bool,
        code: str,
    ) -> None:
        if self.evidence_store is None:
            return
        self.evidence_store.append_evidence(
            EvidenceRecord(
                evidenceId=str(uuid4()),
                organizationId=req.actor.organization_id,
                kind="approval_verification",
                phase="execution",
                requestId=req.request_id,
                connectorId=connector_id,
                payload={
                    "approvalRefHash": self._approval_ref_hash(approval_id),
                    "valid": valid,
                    "code": code,
                },
            )
        )

    def _result(
        self,
        req: ConnectionRequest,
        service_id: str,
        *,
        status: str,
        connector_id: str | None = None,
        data=None,
        error: ConnectionError | None = None,
        policy_decision: str | None = None,
        approval_id: str | None = None,
    ) -> ConnectionResult:
        audit_id = str(uuid4())
        if self.audit_store is not None:
            self.audit_store.append_audit(
                AuditEvent(
                    auditId=audit_id,
                    requestId=req.request_id,
                    organizationId=req.actor.organization_id,
                    userId=req.actor.user_id,
                    agentId=req.actor.agent_id,
                    serviceId=service_id,
                    capability=req.capability,
                    operation=req.operation,
                    status=status,
                    connectorId=connector_id,
                    policyDecision=policy_decision,
                    errorCode=error.code if error else None,
                    approvalRefHash=self._approval_ref_hash(approval_id),
                )
            )
        return ConnectionResult(
            requestId=req.request_id,
            status=status,
            serviceId=service_id,
            capability=req.capability,
            connectorId=connector_id,
            data=data,
            error=error,
            auditId=audit_id,
        )

    def _failed(
        self,
        req: ConnectionRequest,
        service_id: str,
        code: str,
        message: str,
        *,
        user_action: bool = False,
        connector_id: str | None = None,
        policy_decision: str | None = None,
        approval_id: str | None = None,
    ) -> ConnectionResult:
        return self._result(
            req,
            service_id,
            status="failed",
            connector_id=connector_id,
            error=ConnectionError(
                code=code,
                message=message,
                userActionRequired=user_action,
            ),
            policy_decision=policy_decision,
            approval_id=approval_id,
        )

    def requires_durable_execution(self, req, plan, registration):
        return (self.effect_catalog.classify(req, registration) == "side_effecting"
                or req.operation != "read" or not req.read_only or plan.risk.destructive
                or plan.risk.financial or plan.risk.permission_increase
                or req.risk_hints.destructive or req.risk_hints.financial or req.risk_hints.permission_increase
                or (self.durable_executor is not None and self.durable_executor.protects(req)))

    async def execute(self, req: ConnectionRequest, ctx: ExecutionContext, *, allow_dispatch: bool = True, reconcile: bool = False, replay: bool = False) -> ConnectionResult:
        req, ctx = req.model_copy(deep=True), ctx.model_copy(deep=True)
        service_id = self.compiler.service_id(req)
        if not self._context_matches(req, ctx):
            return self._failed(
                req,
                service_id,
                "EXECUTION_CONTEXT_MISMATCH",
                "Execution context does not match the connection request",
                user_action=True,
                approval_id=ctx.approval_id,
            )

        plan = self.compiler.compile(req, phase="execution")
        if plan.policy_decision == "DENY":
            return self._failed(
                req,
                plan.service_id,
                "POLICY_DENIED",
                "Policy denied this connection request",
                user_action=True,
                connector_id=plan.connector_id,
                policy_decision=plan.policy_decision,
                approval_id=ctx.approval_id,
            )

        if not plan.connector_id:
            return self._failed(
                req,
                plan.service_id,
                "CONNECTION_UNAVAILABLE",
                "No trusted connector is available",
                user_action=True,
                policy_decision=plan.policy_decision,
                approval_id=ctx.approval_id,
            )

        item = self.registry.trusted(plan.service_id, req.capability, req.actor.organization_id)
        if item is None or item.manifest.connector_id != plan.connector_id:
            return self._failed(req, plan.service_id, "CONNECTION_UNAVAILABLE", "Connector is no longer available")
        selected_identity = (item.manifest.connector_id, item.manifest.version)
        effect = self.effect_catalog.classify(req, item)
        side_effecting = self.requires_durable_execution(req, plan, item)
        if side_effecting:
            if self.durable_executor is None:
                self._persist_approval_evidence(req, connector_id=plan.connector_id, approval_id=ctx.approval_id,
                    valid=False, code="DURABLE_EXECUTION_REQUIRED")
                return self._failed(req, plan.service_id,
                    "APPROVAL_REQUIRED" if not ctx.approval_id else "DURABLE_EXECUTION_REQUIRED",
                    "Side-effecting execution requires durable receipts and a bound approval", user_action=True,
                    connector_id=plan.connector_id, policy_decision=plan.policy_decision, approval_id=ctx.approval_id)
            item = self.registry.trusted(plan.service_id, req.capability, req.actor.organization_id)
            if item is None or item.manifest.connector_id != plan.connector_id:
                return self._failed(req, plan.service_id, "CONNECTION_UNAVAILABLE", "Connector is no longer available")
            return await self.durable_executor.execute(req, ctx, item, allow_dispatch=allow_dispatch, reconcile=reconcile, replay=replay)

        if effect != "read_only":
            return self._failed(req, plan.service_id, "EFFECT_CLASSIFICATION_REQUIRED",
                "Host-reviewed capability effects are required before execution", user_action=True,
                connector_id=plan.connector_id, policy_decision=plan.policy_decision)

        if not allow_dispatch or reconcile or replay:
            return self._failed(req, plan.service_id, "RECEIPT_NOT_DISPATCHED", "No durable execution to resume")

        if plan.policy_decision == "REQUIRE_APPROVAL":
            if not ctx.approval_id:
                self._persist_approval_evidence(
                    req,
                    connector_id=plan.connector_id,
                    approval_id=None,
                    valid=False,
                    code="APPROVAL_REQUIRED",
                )
                return self._failed(
                    req,
                    plan.service_id,
                    "APPROVAL_REQUIRED",
                    "This operation requires human approval",
                    user_action=True,
                    connector_id=plan.connector_id,
                    policy_decision=plan.policy_decision,
                )
            if self.approval_verifier is None:
                self._persist_approval_evidence(
                    req,
                    connector_id=plan.connector_id,
                    approval_id=ctx.approval_id,
                    valid=False,
                    code="APPROVAL_VERIFICATION_UNAVAILABLE",
                )
                return self._failed(
                    req,
                    plan.service_id,
                    "APPROVAL_VERIFICATION_UNAVAILABLE",
                    "Approval verification is not configured",
                    user_action=True,
                    connector_id=plan.connector_id,
                    policy_decision=plan.policy_decision,
                    approval_id=ctx.approval_id,
                )
            try:
                verification = await self.approval_verifier.verify(ctx.approval_id, req)
            except Exception:
                self._persist_approval_evidence(
                    req,
                    connector_id=plan.connector_id,
                    approval_id=ctx.approval_id,
                    valid=False,
                    code="APPROVAL_VERIFICATION_UNAVAILABLE",
                )
                return self._failed(
                    req,
                    plan.service_id,
                    "APPROVAL_VERIFICATION_UNAVAILABLE",
                    "Approval verification failed",
                    user_action=True,
                    connector_id=plan.connector_id,
                    policy_decision=plan.policy_decision,
                    approval_id=ctx.approval_id,
                )
            if not verification.valid:
                self._persist_approval_evidence(
                    req,
                    connector_id=plan.connector_id,
                    approval_id=ctx.approval_id,
                    valid=False,
                    code=verification.code,
                )
                return self._failed(
                    req,
                    plan.service_id,
                    verification.code,
                    verification.message,
                    user_action=True,
                    connector_id=plan.connector_id,
                    policy_decision=plan.policy_decision,
                    approval_id=ctx.approval_id,
                )
            try:
                await self.approval_verifier.consume(ctx.approval_id)
            except Exception as exc:
                code = getattr(exc, "code", "APPROVAL_VERIFICATION_UNAVAILABLE")
                message = getattr(exc, "safe_message", "Approval could not be consumed")
                self._persist_approval_evidence(
                    req,
                    connector_id=plan.connector_id,
                    approval_id=ctx.approval_id,
                    valid=False,
                    code=code,
                )
                return self._failed(
                    req,
                    plan.service_id,
                    code,
                    message,
                    user_action=True,
                    connector_id=plan.connector_id,
                    policy_decision=plan.policy_decision,
                    approval_id=ctx.approval_id,
                )
            self._persist_approval_evidence(
                req,
                connector_id=plan.connector_id,
                approval_id=ctx.approval_id,
                valid=True,
                code="APPROVAL_CONSUMED",
            )

        item = self.registry.trusted(
            plan.service_id,
            req.capability,
            req.actor.organization_id,
        )
        if (not item or (item.manifest.connector_id, item.manifest.version) != selected_identity
            or self.effect_catalog.classify(req, item) != "read_only"
            or self.requires_durable_execution(req, plan, item)):
            return self._failed(req, plan.service_id, "EFFECT_CLASSIFICATION_REQUIRED",
                "Connector or effect classification changed during authorization", user_action=True)
        result = await item.connector.execute(req.capability, req.input, ctx)
        return self._result(
            req,
            plan.service_id,
            status=result.status,
            connector_id=item.manifest.connector_id,
            data=result.data,
            error=result.error,
            policy_decision=plan.policy_decision,
            approval_id=ctx.approval_id,
        )
