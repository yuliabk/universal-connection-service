from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Literal
from uuid import uuid4

from fastapi import APIRouter, Header, HTTPException, Query
from pydantic import Field, SecretStr

from .approvals import ApprovalRecord, ApprovalStore, approval_ref_hash
from .contracts import ConnectionPlan, ConnectionRequest, ConnectionResult, DiscoveryCandidateRef, ExecutionContext, Model
from .control_plane import (
    ControlPlaneError,
    ControlPlanePrincipal,
    ControlPlaneService,
    MCPValidationCommand,
    PromotionApprovalCommand,
    PromotionApprovalIssued,
    PromotionCommand,
    StaticBearerAuthenticator,
)
from .persistence import ConnectionWorkflowRecord, EvidenceRecord, EvidenceStore, WorkflowStage, WorkflowStore
from .registry import ConnectorRegistry
from .service import ConnectionService


NextAction = Literal[
    "advance",
    "select_candidate",
    "build_connector",
    "provide_credential_handle",
    "select_tool",
    "issue_promotion_approval",
    "provide_promotion_approval",
    "issue_execution_approval",
    "provide_execution_approval",
    "retry_validation",
    "restart",
    "none",
]


class AutoConnectStartCommand(Model):
    request: ConnectionRequest
    selected_candidate_id: str | None = Field(alias="selectedCandidateId", default=None)
    selected_tool: str | None = Field(alias="selectedTool", default=None)
    credential_handle: SecretStr | None = Field(alias="credentialHandle", default=None)
    execution_approval_id: SecretStr | None = Field(alias="executionApprovalId", default=None)
    promotion_approval_id: SecretStr | None = Field(alias="promotionApprovalId", default=None)
    deadline_ms: int = Field(alias="deadlineMs", default=15000, ge=1000, le=60000)
    execute_when_ready: bool = Field(alias="executeWhenReady", default=True)


class AutoConnectAdvanceCommand(AutoConnectStartCommand):
    pass


class AutoConnectExecutionApprovalCommand(Model):
    request: ConnectionRequest
    expires_in_seconds: int = Field(alias="expiresInSeconds", default=900, ge=60, le=3600)


class AutoConnectExecutionApprovalIssued(Model):
    workflow_id: str = Field(alias="workflowId")
    approval_id: str = Field(alias="approvalId")
    approval_ref_hash: str = Field(alias="approvalRefHash")
    expires_at: datetime = Field(alias="expiresAt")


class AutoConnectWorkflowView(Model):
    workflow_id: str = Field(alias="workflowId")
    request_id: str = Field(alias="requestId")
    organization_id: str = Field(alias="organizationId")
    service_id: str = Field(alias="serviceId")
    capability: str
    operation: str
    stage: WorkflowStage
    selected_candidate_id: str | None = Field(alias="selectedCandidateId", default=None)
    selected_tool: str | None = Field(alias="selectedTool", default=None)
    connector_id: str | None = Field(alias="connectorId", default=None)
    connector_version: str | None = Field(alias="connectorVersion", default=None)
    promotion_id: str | None = Field(alias="promotionId", default=None)
    last_code: str | None = Field(alias="lastCode", default=None)
    result_audit_id: str | None = Field(alias="resultAuditId", default=None)
    revision: int
    next_action: NextAction = Field(alias="nextAction")
    updated_at: datetime = Field(alias="updatedAt")


class AutoConnectResponse(Model):
    workflow: AutoConnectWorkflowView
    plan: ConnectionPlan | None = None
    candidates: tuple[DiscoveryCandidateRef, ...] = ()
    result: ConnectionResult | None = None


class AutoConnectError(RuntimeError):
    def __init__(self, code: str, message: str, *, status_code: int = 409) -> None:
        super().__init__(message)
        self.code = code
        self.safe_message = message
        self.status_code = status_code


class AutoConnectOrchestrator:
    """Persistent coordinator over the existing UCS discovery/trust/execution gates."""

    LEASE_SECONDS = 120

    def __init__(
        self,
        *,
        workflow_store: WorkflowStore,
        connection_service: ConnectionService,
        control_plane_service: ControlPlaneService,
        registry: ConnectorRegistry,
        approval_store: ApprovalStore | None,
        evidence_store: EvidenceStore | None = None,
    ) -> None:
        self.workflow_store = workflow_store
        self.connection_service = connection_service
        self.control_plane_service = control_plane_service
        self.registry = registry
        self.approval_store = approval_store
        self.evidence_store = evidence_store

    @staticmethod
    def _fingerprint(request: ConnectionRequest) -> str:
        payload = request.model_dump(by_alias=True, mode="json")
        raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    @staticmethod
    def _service_id(request: ConnectionRequest) -> str:
        return request.service.id or request.service.name.lower().replace(" ", "-")

    @staticmethod
    def _require_review(principal: ControlPlanePrincipal, organization_id: str) -> None:
        if not principal.allows("connectors:review", organization_id):
            raise AutoConnectError(
                "CONTROL_PLANE_FORBIDDEN",
                "Control-plane principal is not authorized to orchestrate connections for this organization",
                status_code=403,
            )

    @staticmethod
    def _next_action(record: ConnectionWorkflowRecord) -> NextAction:
        if record.stage == "planning" and record.last_code == "MCP_VALIDATION_RETRYABLE":
            return "retry_validation"
        return {
            "planning": "advance",
            "awaiting_candidate_selection": "select_candidate",
            "awaiting_build": "build_connector",
            "awaiting_credentials": "provide_credential_handle",
            "awaiting_tool_selection": "select_tool",
            "awaiting_promotion_approval": "issue_promotion_approval",
            "awaiting_promotion": "provide_promotion_approval",
            "awaiting_execution_approval": "issue_execution_approval",
            "ready_to_execute": "advance",
            "completed": "none",
            "failed": "restart",
        }[record.stage]

    @classmethod
    def _view(cls, record: ConnectionWorkflowRecord) -> AutoConnectWorkflowView:
        return AutoConnectWorkflowView(
            workflowId=record.workflow_id,
            requestId=record.request_id,
            organizationId=record.organization_id,
            serviceId=record.service_id,
            capability=record.capability,
            operation=record.operation,
            stage=record.stage,
            selectedCandidateId=record.selected_candidate_id,
            selectedTool=record.selected_tool,
            connectorId=record.connector_id,
            connectorVersion=record.connector_version,
            promotionId=record.promotion_id,
            lastCode=record.last_code,
            resultAuditId=record.result_audit_id,
            revision=record.revision,
            nextAction=cls._next_action(record),
            updatedAt=record.updated_at,
        )

    def _assert_request(self, record: ConnectionWorkflowRecord, request: ConnectionRequest) -> None:
        if request.actor.organization_id != record.organization_id:
            raise AutoConnectError("WORKFLOW_SCOPE_MISMATCH", "Connection request organization does not match workflow", status_code=403)
        if request.request_id != record.request_id or self._fingerprint(request) != record.request_fingerprint:
            raise AutoConnectError("WORKFLOW_REQUEST_MISMATCH", "Resume requires the exact original ConnectionRequest")

    def _claim(self, record: ConnectionWorkflowRecord) -> str:
        token = secrets.token_urlsafe(24)
        now = datetime.now(timezone.utc)
        ok = self.workflow_store.claim_workflow(
            record.organization_id,
            record.workflow_id,
            token,
            now + timedelta(seconds=self.LEASE_SECONDS),
            now,
        )
        if not ok:
            raise AutoConnectError("WORKFLOW_BUSY", "Connection workflow is already being advanced")
        return token

    def _save(self, record: ConnectionWorkflowRecord, revision: int, lease: str) -> ConnectionWorkflowRecord:
        if not self.workflow_store.update_claimed_workflow(record, expected_revision=revision, lease_token=lease):
            raise AutoConnectError("WORKFLOW_CONFLICT", "Connection workflow changed concurrently")
        refreshed = self.workflow_store.get_workflow(record.organization_id, record.workflow_id)
        if refreshed is None:
            raise AutoConnectError("WORKFLOW_NOT_FOUND", "Connection workflow disappeared", status_code=404)
        return refreshed

    def _new_record(self, request: ConnectionRequest) -> ConnectionWorkflowRecord:
        return ConnectionWorkflowRecord(
            workflowId=str(uuid4()),
            requestId=request.request_id,
            organizationId=request.actor.organization_id,
            requestFingerprint=self._fingerprint(request),
            serviceId=self._service_id(request),
            capability=request.capability,
            operation=request.operation,
            stage="planning",
        )

    def status(self, principal: ControlPlanePrincipal, organization_id: str, workflow_id: str) -> AutoConnectResponse:
        self._require_review(principal, organization_id)
        record = self.workflow_store.get_workflow(organization_id, workflow_id)
        if record is None:
            raise AutoConnectError("WORKFLOW_NOT_FOUND", "Connection workflow was not found", status_code=404)
        return AutoConnectResponse(workflow=self._view(record))

    async def start(self, principal: ControlPlanePrincipal, command: AutoConnectStartCommand) -> AutoConnectResponse:
        request = command.request
        organization_id = request.actor.organization_id
        self._require_review(principal, organization_id)
        existing = self.workflow_store.get_workflow_by_request(organization_id, request.request_id)
        if existing is not None:
            self._assert_request(existing, request)
            if existing.stage != "planning":
                return AutoConnectResponse(workflow=self._view(existing))
            return await self.advance(principal, existing.workflow_id, AutoConnectAdvanceCommand.model_validate(command.model_dump()))
        try:
            created = self.workflow_store.create_workflow(self._new_record(request))
        except Exception:
            existing = self.workflow_store.get_workflow_by_request(organization_id, request.request_id)
            if existing is None:
                raise
            self._assert_request(existing, request)
            created = existing
        return await self.advance(principal, created.workflow_id, AutoConnectAdvanceCommand.model_validate(command.model_dump()))

    async def advance(
        self,
        principal: ControlPlanePrincipal,
        workflow_id: str,
        command: AutoConnectAdvanceCommand,
    ) -> AutoConnectResponse:
        request = command.request
        organization_id = request.actor.organization_id
        self._require_review(principal, organization_id)
        record = self.workflow_store.get_workflow(organization_id, workflow_id)
        if record is None:
            raise AutoConnectError("WORKFLOW_NOT_FOUND", "Connection workflow was not found", status_code=404)
        self._assert_request(record, request)
        if record.stage in {"completed", "failed"}:
            return AutoConnectResponse(workflow=self._view(record))

        lease = self._claim(record)
        revision = record.revision
        try:
            transient = await self._drive(principal, record, command)
            saved = self._save(record, revision, lease)
            return AutoConnectResponse(
                workflow=self._view(saved),
                plan=transient.plan,
                candidates=transient.candidates,
                result=transient.result,
            )
        except Exception:
            self.workflow_store.release_workflow(record.organization_id, record.workflow_id, lease)
            raise

    async def _drive(
        self,
        principal: ControlPlanePrincipal,
        record: ConnectionWorkflowRecord,
        command: AutoConnectAdvanceCommand,
    ) -> AutoConnectResponse:
        request = command.request
        plan = self.connection_service.compiler.compile(request, phase="plan")
        if plan.policy_decision == "DENY":
            record.stage = "failed"
            record.last_code = "POLICY_DENIED"
            return AutoConnectResponse(workflow=self._view(record), plan=plan)

        trusted = self.registry.trusted(plan.service_id, request.capability, request.actor.organization_id)
        if trusted is not None:
            record.connector_id = trusted.manifest.connector_id
            record.connector_version = trusted.manifest.version
            return await self._drive_execution(record, command, plan)

        candidate = self._select_candidate(record, command, plan)
        if candidate is None:
            if record.last_code == "DISCOVERY_CANDIDATE_STALE" or (plan.requires_selection and plan.discovery_candidates):
                record.stage = "awaiting_candidate_selection"
                record.last_code = record.last_code or "CANDIDATE_SELECTION_REQUIRED"
                return AutoConnectResponse(workflow=self._view(record), plan=plan, candidates=plan.discovery_candidates)
            record.stage = "awaiting_build"
            record.last_code = "CONNECTION_BUILD_REQUIRED"
            return AutoConnectResponse(workflow=self._view(record), plan=plan, candidates=plan.discovery_candidates)

        record.selected_candidate_id = candidate.candidate_id
        if candidate.requires_build or not candidate.actionable or candidate.strategy != "mcp":
            record.stage = "awaiting_build"
            record.last_code = "CONNECTION_BUILD_REQUIRED"
            return AutoConnectResponse(workflow=self._view(record), plan=plan, candidates=plan.discovery_candidates)

        if candidate.auth_requirement.type != "none" and command.credential_handle is None:
            record.stage = "awaiting_credentials"
            record.last_code = "CREDENTIAL_HANDLE_REQUIRED"
            return AutoConnectResponse(workflow=self._view(record), plan=plan, candidates=plan.discovery_candidates)

        validation = await self.control_plane_service.validate_mcp_candidate(
            principal,
            MCPValidationCommand(
                request=request,
                candidateId=candidate.candidate_id,
                selectedTool=command.selected_tool or record.selected_tool,
                credentialHandle=command.credential_handle,
                deadlineMs=command.deadline_ms,
            ),
        )
        if not validation.passed:
            if validation.code == "MCP_TOOL_SELECTION_REQUIRED":
                record.stage = "awaiting_tool_selection"
                record.last_code = validation.code
            elif validation.code.startswith("CREDENTIAL_"):
                record.stage = "awaiting_credentials"
                record.last_code = validation.code
            else:
                record.stage = "planning"
                record.last_code = "MCP_VALIDATION_RETRYABLE"
            return AutoConnectResponse(workflow=self._view(record), plan=plan, candidates=plan.discovery_candidates)

        record.selected_tool = validation.selected_tool
        record.connector_id = validation.connector_id
        record.connector_version = candidate.version
        record.promotion_id = record.promotion_id or f"auto-connect:{record.workflow_id}"
        record.stage = "awaiting_promotion_approval"
        record.last_code = "PROMOTION_APPROVAL_REQUIRED"
        return AutoConnectResponse(workflow=self._view(record), plan=plan)

    def _select_candidate(
        self,
        record: ConnectionWorkflowRecord,
        command: AutoConnectAdvanceCommand,
        plan: ConnectionPlan,
    ) -> DiscoveryCandidateRef | None:
        candidate_id = command.selected_candidate_id or record.selected_candidate_id or plan.selected_discovery_candidate_id
        if candidate_id is None:
            return None
        candidate = next((item for item in plan.discovery_candidates if item.candidate_id == candidate_id), None)
        if candidate is None:
            record.selected_candidate_id = None
            record.last_code = "DISCOVERY_CANDIDATE_STALE"
        return candidate

    async def _drive_execution(
        self,
        record: ConnectionWorkflowRecord,
        command: AutoConnectAdvanceCommand,
        plan: ConnectionPlan,
    ) -> AutoConnectResponse:
        request = command.request
        if plan.auth_requirement.type != "none" and command.credential_handle is None:
            record.stage = "awaiting_credentials"
            record.last_code = "CREDENTIAL_HANDLE_REQUIRED"
            return AutoConnectResponse(workflow=self._view(record), plan=plan)

        approval = command.execution_approval_id.get_secret_value() if command.execution_approval_id else None
        if plan.policy_decision == "REQUIRE_APPROVAL" and approval is None:
            record.stage = "awaiting_execution_approval"
            record.last_code = "EXECUTION_APPROVAL_REQUIRED"
            return AutoConnectResponse(workflow=self._view(record), plan=plan)

        record.stage = "ready_to_execute"
        record.last_code = "READY_TO_EXECUTE"
        if not command.execute_when_ready:
            return AutoConnectResponse(workflow=self._view(record), plan=plan)

        result = await self.connection_service.execute(
            request,
            ExecutionContext(
                requestId=request.request_id,
                userId=request.actor.user_id,
                organizationId=request.actor.organization_id,
                credentialHandle=command.credential_handle,
                approvalId=approval,
                deadlineMs=command.deadline_ms,
            ),
        )
        record.result_audit_id = result.audit_id
        if result.status in {"success", "partial"}:
            record.stage = "completed"
            record.last_code = "CONNECTION_COMPLETED"
        elif result.error is not None and result.error.code.startswith("CREDENTIAL_"):
            record.stage = "awaiting_credentials"
            record.last_code = result.error.code
        elif result.error is not None and result.error.code.startswith("APPROVAL_"):
            record.stage = "awaiting_execution_approval"
            record.last_code = result.error.code
        else:
            record.stage = "failed"
            record.last_code = result.error.code if result.error else "CONNECTION_EXECUTION_FAILED"
        return AutoConnectResponse(workflow=self._view(record), plan=plan, result=result)

    def issue_promotion_approval(
        self,
        principal: ControlPlanePrincipal,
        workflow_id: str,
        organization_id: str,
        *,
        expires_in_seconds: int = 900,
    ) -> tuple[AutoConnectWorkflowView, PromotionApprovalIssued]:
        self._require_review(principal, organization_id)
        record = self.workflow_store.get_workflow(organization_id, workflow_id)
        if record is None:
            raise AutoConnectError("WORKFLOW_NOT_FOUND", "Connection workflow was not found", status_code=404)
        if record.stage != "awaiting_promotion_approval" or not all((record.connector_id, record.connector_version, record.promotion_id)):
            raise AutoConnectError("WORKFLOW_NOT_AWAITING_PROMOTION_APPROVAL", "Workflow is not awaiting connector promotion approval")
        lease = self._claim(record)
        revision = record.revision
        try:
            issued = self.control_plane_service.issue_promotion_approval(
                principal,
                record.connector_id,
                PromotionApprovalCommand(
                    organizationId=organization_id,
                    version=record.connector_version,
                    promotionId=record.promotion_id,
                    expiresInSeconds=expires_in_seconds,
                ),
            )
            record.stage = "awaiting_promotion"
            record.last_code = "PROMOTION_APPROVAL_ISSUED"
            saved = self._save(record, revision, lease)
            return self._view(saved), issued
        except Exception:
            self.workflow_store.release_workflow(record.organization_id, record.workflow_id, lease)
            raise

    async def promote_and_advance(
        self,
        principal: ControlPlanePrincipal,
        workflow_id: str,
        command: AutoConnectAdvanceCommand,
    ) -> AutoConnectResponse:
        request = command.request
        organization_id = request.actor.organization_id
        self._require_review(principal, organization_id)
        record = self.workflow_store.get_workflow(organization_id, workflow_id)
        if record is None:
            raise AutoConnectError("WORKFLOW_NOT_FOUND", "Connection workflow was not found", status_code=404)
        self._assert_request(record, request)
        if record.stage != "awaiting_promotion" or not all((record.connector_id, record.connector_version, record.promotion_id)):
            return await self.advance(principal, workflow_id, command)
        if command.promotion_approval_id is None:
            return AutoConnectResponse(workflow=self._view(record))

        lease = self._claim(record)
        revision = record.revision
        try:
            self.control_plane_service.promote(
                principal,
                record.connector_id,
                PromotionCommand(
                    organizationId=organization_id,
                    version=record.connector_version,
                    promotionId=record.promotion_id,
                    approvalId=command.promotion_approval_id,
                ),
            )
            record.stage = "planning"
            record.last_code = "CONNECTOR_TRUSTED"
            saved = self._save(record, revision, lease)
        except Exception:
            self.workflow_store.release_workflow(record.organization_id, record.workflow_id, lease)
            raise
        return await self.advance(principal, saved.workflow_id, command)

    def issue_execution_approval(
        self,
        principal: ControlPlanePrincipal,
        workflow_id: str,
        command: AutoConnectExecutionApprovalCommand,
    ) -> AutoConnectExecutionApprovalIssued:
        request = command.request
        organization_id = request.actor.organization_id
        self._require_review(principal, organization_id)
        if not principal.allows("approvals:issue", organization_id):
            raise AutoConnectError("CONTROL_PLANE_FORBIDDEN", "Principal cannot issue execution approvals", status_code=403)
        if self.approval_store is None:
            raise AutoConnectError("APPROVAL_STORE_UNAVAILABLE", "Persistent approval storage is not configured", status_code=503)
        record = self.workflow_store.get_workflow(organization_id, workflow_id)
        if record is None:
            raise AutoConnectError("WORKFLOW_NOT_FOUND", "Connection workflow was not found", status_code=404)
        self._assert_request(record, request)
        if record.stage != "awaiting_execution_approval":
            raise AutoConnectError("WORKFLOW_NOT_AWAITING_EXECUTION_APPROVAL", "Workflow is not awaiting execution approval")

        raw = secrets.token_urlsafe(32)
        ref = approval_ref_hash(raw)
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=command.expires_in_seconds)
        self.approval_store.put_approval(
            ApprovalRecord(
                approvalRefHash=ref,
                requestId=request.request_id,
                organizationId=organization_id,
                userId=request.actor.user_id,
                agentId=request.actor.agent_id,
                serviceId=self._service_id(request),
                capability=request.capability,
                operation=request.operation,
                expiresAt=expires_at,
            )
        )
        if self.evidence_store is not None:
            self.evidence_store.append_evidence(
                EvidenceRecord(
                    evidenceId=str(uuid4()),
                    organizationId=organization_id,
                    kind="approval_verification",
                    phase="execution",
                    requestId=request.request_id,
                    connectorId=record.connector_id,
                    payload={
                        "type": "auto_connect_execution_approval_issued",
                        "workflowId": workflow_id,
                        "approvalRefHash": ref,
                        "approverSubject": principal.subject,
                        "expiresAt": expires_at.isoformat(),
                    },
                )
            )
        return AutoConnectExecutionApprovalIssued(
            workflowId=workflow_id,
            approvalId=raw,
            approvalRefHash=ref,
            expiresAt=expires_at,
        )


def build_auto_connect_router(
    orchestrator: AutoConnectOrchestrator | None,
    authenticator: StaticBearerAuthenticator | None,
) -> APIRouter:
    router = APIRouter(prefix="/v1/control-plane/auto-connect", tags=["auto-connect"])

    def principal(authorization: str | None) -> ControlPlanePrincipal:
        if orchestrator is None:
            raise HTTPException(status_code=503, detail={"code": "AUTO_CONNECT_DISABLED", "message": "Persistent auto-connect orchestration is not configured"})
        if authenticator is None:
            raise HTTPException(status_code=503, detail={"code": "CONTROL_PLANE_DISABLED", "message": "Control plane is not configured"})
        actor = authenticator.authenticate(authorization)
        if actor is None:
            raise HTTPException(
                status_code=401,
                detail={"code": "CONTROL_PLANE_UNAUTHENTICATED", "message": "Valid control-plane bearer token required"},
                headers={"WWW-Authenticate": "Bearer"},
            )
        return actor

    def fail(exc: Exception):
        if isinstance(exc, (AutoConnectError, ControlPlaneError)):
            raise HTTPException(status_code=exc.status_code, detail={"code": exc.code, "message": exc.safe_message})
        raise exc

    @router.post("", response_model=AutoConnectResponse)
    async def start(command: AutoConnectStartCommand, authorization: str | None = Header(default=None)):
        actor = principal(authorization)
        try:
            assert orchestrator is not None
            return await orchestrator.start(actor, command)
        except Exception as exc:
            fail(exc)

    @router.get("/{workflow_id}", response_model=AutoConnectResponse)
    def status(
        workflow_id: str,
        organization_id: str = Query(alias="organizationId"),
        authorization: str | None = Header(default=None),
    ):
        actor = principal(authorization)
        try:
            assert orchestrator is not None
            return orchestrator.status(actor, organization_id, workflow_id)
        except Exception as exc:
            fail(exc)

    @router.post("/{workflow_id}/advance", response_model=AutoConnectResponse)
    async def advance(
        workflow_id: str,
        command: AutoConnectAdvanceCommand,
        authorization: str | None = Header(default=None),
    ):
        actor = principal(authorization)
        try:
            assert orchestrator is not None
            if command.promotion_approval_id is not None:
                return await orchestrator.promote_and_advance(actor, workflow_id, command)
            return await orchestrator.advance(actor, workflow_id, command)
        except Exception as exc:
            fail(exc)

    @router.post("/{workflow_id}/promotion-approval")
    def promotion_approval(
        workflow_id: str,
        organization_id: str = Query(alias="organizationId"),
        expires_in_seconds: int = Query(default=900, alias="expiresInSeconds", ge=60, le=3600),
        authorization: str | None = Header(default=None),
    ):
        actor = principal(authorization)
        try:
            assert orchestrator is not None
            workflow, issued = orchestrator.issue_promotion_approval(
                actor, workflow_id, organization_id, expires_in_seconds=expires_in_seconds
            )
            return {
                "workflow": workflow.model_dump(by_alias=True, mode="json"),
                "approval": issued.model_dump(by_alias=True, mode="json"),
            }
        except Exception as exc:
            fail(exc)

    @router.post("/{workflow_id}/execution-approval", response_model=AutoConnectExecutionApprovalIssued)
    def execution_approval(
        workflow_id: str,
        command: AutoConnectExecutionApprovalCommand,
        authorization: str | None = Header(default=None),
    ):
        actor = principal(authorization)
        try:
            assert orchestrator is not None
            return orchestrator.issue_execution_approval(actor, workflow_id, command)
        except Exception as exc:
            fail(exc)

    return router
