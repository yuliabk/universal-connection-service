from __future__ import annotations

from pydantic import Field, SecretStr
from fastapi import APIRouter, Header, HTTPException, Query

from .auto_connect import (
    AutoConnectAdvanceCommand,
    AutoConnectError,
    AutoConnectResponse,
    AutoConnectWorkflowView,
)
from .contracts import Model
from .control_plane import ControlPlaneError, ControlPlanePrincipal, StaticBearerAuthenticator
from .mcpb_sandbox import SandboxedMCPConnector
from .persistence import ConnectionWorkflowRecord, EvidenceRecord
from .sandbox_build import SandboxBuildAwareAutoConnectOrchestrator
from .sandbox_policy_compiler import LeastPrivilegePolicyCompiler, SandboxPolicyProposal
from .sandbox_tool_policy import (
    SandboxToolPolicyService,
    SandboxToolProfileApplyCommand,
    SandboxToolProfileApprovalCommand,
    SandboxToolProfileApprovalIssued,
)


_POLICY_RESOLUTION_REQUIRED = "SANDBOX_POLICY_RESOLUTION_REQUIRED"
_POLICY_APPROVAL_REQUIRED = "SANDBOX_POLICY_APPROVAL_REQUIRED"
_POLICY_APPROVAL_ISSUED = "SANDBOX_POLICY_APPROVAL_ISSUED"
_POLICY_ACTIVATED = "SANDBOX_POLICY_ACTIVATED"
_POLICY_EVIDENCE_TYPE = "auto_connect_sandbox_policy_proposal"


class AutoConnectSandboxPolicyState(Model):
    workflow: AutoConnectWorkflowView
    proposal: SandboxPolicyProposal


class AutoConnectSandboxPolicyApprovalResponse(Model):
    workflow: AutoConnectWorkflowView
    proposal: SandboxPolicyProposal
    approval: SandboxToolProfileApprovalIssued


class AutoConnectSandboxPolicyActivateCommand(AutoConnectAdvanceCommand):
    sandbox_policy_approval_id: SecretStr = Field(alias="sandboxPolicyApprovalId")


class PolicyAwareAutoConnectOrchestrator(SandboxBuildAwareAutoConnectOrchestrator):
    """Gate trusted sandbox execution on a reviewed least-privilege per-tool profile."""

    def __init__(
        self,
        *,
        policy_compiler: LeastPrivilegePolicyCompiler,
        sandbox_policy_service: SandboxToolPolicyService,
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.policy_compiler = policy_compiler
        self.sandbox_policy_service = sandbox_policy_service

    @staticmethod
    def _policy_change_id(workflow_id: str) -> str:
        return f"auto-connect-policy:{workflow_id}"

    def _persist_workflow_proposal(
        self,
        record: ConnectionWorkflowRecord,
        proposal: SandboxPolicyProposal,
    ) -> None:
        if self.evidence_store is None:
            return
        self.evidence_store.append_evidence(
            EvidenceRecord(
                evidenceId=f"workflow-policy:{record.workflow_id}:{proposal.proposal_id}",
                organizationId=record.organization_id,
                kind="policy_decision",
                phase="plan",
                requestId=record.workflow_id,
                connectorId=proposal.connector_id,
                payload={
                    "type": _POLICY_EVIDENCE_TYPE,
                    "proposal": proposal.model_dump(by_alias=True, mode="json"),
                },
            )
        )

    def _workflow_proposal(self, record: ConnectionWorkflowRecord) -> SandboxPolicyProposal | None:
        if self.evidence_store is None or record.connector_id is None:
            return None
        matches = [
            item
            for item in self.evidence_store.list_evidence(record.organization_id, kind="policy_decision")
            if item.request_id == record.workflow_id
            and item.connector_id == record.connector_id
            and item.payload.get("type") == _POLICY_EVIDENCE_TYPE
            and isinstance(item.payload.get("proposal"), dict)
        ]
        if not matches:
            return None
        matches.sort(key=lambda item: (item.created_at, item.evidence_id))
        try:
            return SandboxPolicyProposal.model_validate(matches[-1].payload["proposal"])
        except Exception:
            return None

    def _active_profile_hash(self, record: ConnectionWorkflowRecord) -> str | None:
        if self.evidence_store is None or record.connector_id is None or record.connector_version is None:
            return None
        matches = [
            item
            for item in self.evidence_store.list_evidence(record.organization_id, kind="approval_verification")
            if item.connector_id == record.connector_id
            and item.payload.get("type") == "sandbox_tool_profile_activated"
            and item.payload.get("version") == record.connector_version
            and item.payload.get("capability") == record.capability
            and isinstance(item.payload.get("profileHash"), str)
        ]
        if not matches:
            return None
        matches.sort(key=lambda item: (item.created_at, item.evidence_id))
        return str(matches[-1].payload["profileHash"])

    def _policy_state(self, record: ConnectionWorkflowRecord) -> AutoConnectSandboxPolicyState:
        proposal = self._workflow_proposal(record)
        if proposal is None:
            raise AutoConnectError(
                "SANDBOX_POLICY_PROPOSAL_NOT_FOUND",
                "Sandbox policy proposal is not available for this workflow",
                status_code=404,
            )
        return AutoConnectSandboxPolicyState(workflow=self._view(record), proposal=proposal)

    def policy_status(
        self,
        principal: ControlPlanePrincipal,
        organization_id: str,
        workflow_id: str,
    ) -> AutoConnectSandboxPolicyState:
        self._require_review(principal, organization_id)
        record = self.workflow_store.get_workflow(organization_id, workflow_id)
        if record is None:
            raise AutoConnectError("WORKFLOW_NOT_FOUND", "Connection workflow was not found", status_code=404)
        return self._policy_state(record)

    async def _drive(self, principal, record, command: AutoConnectAdvanceCommand) -> AutoConnectResponse:
        if record.last_code in {_POLICY_APPROVAL_REQUIRED, _POLICY_APPROVAL_ISSUED}:
            return AutoConnectResponse(workflow=self._view(record))

        request = command.request
        plan = self.connection_service.compiler.compile(request, phase="plan")
        trusted = self.registry.trusted(plan.service_id, request.capability, request.actor.organization_id)
        if trusted is None or not isinstance(trusted.connector, SandboxedMCPConnector):
            return await super()._drive(principal, record, command)

        record.connector_id = trusted.manifest.connector_id
        record.connector_version = trusted.manifest.version
        proposal = await self.policy_compiler.compile(
            principal,
            organization_id=record.organization_id,
            connector_id=record.connector_id,
            version=record.connector_version,
            capability=record.capability,
        )
        self._persist_workflow_proposal(record, proposal)

        if proposal.unresolved_requirements:
            record.last_code = _POLICY_RESOLUTION_REQUIRED
            return AutoConnectResponse(workflow=self._view(record), plan=plan)

        if self._active_profile_hash(record) != proposal.profile_hash:
            record.last_code = _POLICY_APPROVAL_REQUIRED
            return AutoConnectResponse(workflow=self._view(record), plan=plan)

        record.last_code = _POLICY_ACTIVATED
        return await super()._drive(principal, record, command)

    def issue_sandbox_policy_approval(
        self,
        principal: ControlPlanePrincipal,
        workflow_id: str,
        organization_id: str,
        *,
        expires_in_seconds: int = 900,
    ) -> AutoConnectSandboxPolicyApprovalResponse:
        self._require_review(principal, organization_id)
        record = self.workflow_store.get_workflow(organization_id, workflow_id)
        if record is None:
            raise AutoConnectError("WORKFLOW_NOT_FOUND", "Connection workflow was not found", status_code=404)
        if record.last_code != _POLICY_APPROVAL_REQUIRED or not record.connector_id or not record.connector_version:
            raise AutoConnectError(
                "WORKFLOW_NOT_AWAITING_SANDBOX_POLICY_APPROVAL",
                "Workflow is not awaiting sandbox policy approval",
            )
        proposal = self._workflow_proposal(record)
        if proposal is None:
            raise AutoConnectError("SANDBOX_POLICY_PROPOSAL_NOT_FOUND", "Sandbox policy proposal is unavailable", status_code=404)
        if proposal.unresolved_requirements:
            raise AutoConnectError(
                "SANDBOX_POLICY_RESOLUTION_REQUIRED",
                "Sandbox policy proposal still has unresolved requirements",
            )
        if (
            proposal.connector_id != record.connector_id
            or proposal.version != record.connector_version
            or proposal.capability != record.capability
        ):
            raise AutoConnectError("SANDBOX_POLICY_PROPOSAL_STALE", "Sandbox policy proposal no longer matches workflow")

        lease = self._claim(record)
        revision = record.revision
        try:
            issued = self.sandbox_policy_service.issue_approval(
                principal,
                record.connector_id,
                SandboxToolProfileApprovalCommand(
                    organizationId=organization_id,
                    version=record.connector_version,
                    capability=record.capability,
                    changeId=self._policy_change_id(workflow_id),
                    profile=proposal.profile,
                    expiresInSeconds=expires_in_seconds,
                ),
            )
            record.last_code = _POLICY_APPROVAL_ISSUED
            saved = self._save(record, revision, lease)
            return AutoConnectSandboxPolicyApprovalResponse(
                workflow=self._view(saved),
                proposal=proposal,
                approval=issued,
            )
        except Exception:
            self.workflow_store.release_workflow(record.organization_id, record.workflow_id, lease)
            raise

    async def activate_sandbox_policy_and_advance(
        self,
        principal: ControlPlanePrincipal,
        workflow_id: str,
        command: AutoConnectSandboxPolicyActivateCommand,
    ) -> AutoConnectResponse:
        request = command.request
        organization_id = request.actor.organization_id
        self._require_review(principal, organization_id)
        record = self.workflow_store.get_workflow(organization_id, workflow_id)
        if record is None:
            raise AutoConnectError("WORKFLOW_NOT_FOUND", "Connection workflow was not found", status_code=404)
        self._assert_request(record, request)
        if record.last_code != _POLICY_APPROVAL_ISSUED or not record.connector_id or not record.connector_version:
            raise AutoConnectError(
                "WORKFLOW_NOT_AWAITING_SANDBOX_POLICY_ACTIVATION",
                "Workflow is not awaiting sandbox policy activation",
            )
        proposal = self._workflow_proposal(record)
        if proposal is None:
            raise AutoConnectError("SANDBOX_POLICY_PROPOSAL_NOT_FOUND", "Sandbox policy proposal is unavailable", status_code=404)

        lease = self._claim(record)
        revision = record.revision
        try:
            self.sandbox_policy_service.apply(
                principal,
                record.connector_id,
                SandboxToolProfileApplyCommand(
                    organizationId=organization_id,
                    version=record.connector_version,
                    capability=record.capability,
                    changeId=self._policy_change_id(workflow_id),
                    profile=proposal.profile,
                    approvalId=command.sandbox_policy_approval_id,
                ),
            )
            record.last_code = _POLICY_ACTIVATED
            saved = self._save(record, revision, lease)
        except Exception:
            self.workflow_store.release_workflow(record.organization_id, record.workflow_id, lease)
            raise

        payload = command.model_dump(by_alias=True, mode="python", exclude={"sandbox_policy_approval_id"})
        advance_command = AutoConnectAdvanceCommand.model_validate(payload)
        return await self.advance(principal, saved.workflow_id, advance_command)


def build_policy_auto_connect_router(
    orchestrator: PolicyAwareAutoConnectOrchestrator | None,
    authenticator: StaticBearerAuthenticator | None,
) -> APIRouter:
    router = APIRouter(prefix="/v1/control-plane/auto-connect", tags=["auto-connect-sandbox-policy"])

    def principal(authorization: str | None) -> ControlPlanePrincipal:
        if orchestrator is None:
            raise HTTPException(
                status_code=503,
                detail={"code": "AUTO_CONNECT_SANDBOX_POLICY_DISABLED", "message": "Sandbox policy workflow is not configured"},
            )
        if authenticator is None:
            raise HTTPException(
                status_code=503,
                detail={"code": "CONTROL_PLANE_DISABLED", "message": "Control plane is not configured"},
            )
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

    @router.get("/{workflow_id}/sandbox-policy", response_model=AutoConnectSandboxPolicyState)
    def status(
        workflow_id: str,
        organization_id: str = Query(alias="organizationId"),
        authorization: str | None = Header(default=None),
    ):
        try:
            assert orchestrator is not None
            return orchestrator.policy_status(principal(authorization), organization_id, workflow_id)
        except Exception as exc:
            fail(exc)

    @router.post("/{workflow_id}/sandbox-policy-approval", response_model=AutoConnectSandboxPolicyApprovalResponse)
    def issue_approval(
        workflow_id: str,
        organization_id: str = Query(alias="organizationId"),
        expires_in_seconds: int = Query(default=900, alias="expiresInSeconds", ge=60, le=3600),
        authorization: str | None = Header(default=None),
    ):
        try:
            assert orchestrator is not None
            return orchestrator.issue_sandbox_policy_approval(
                principal(authorization),
                workflow_id,
                organization_id,
                expires_in_seconds=expires_in_seconds,
            )
        except Exception as exc:
            fail(exc)

    @router.post("/{workflow_id}/sandbox-policy-activate", response_model=AutoConnectResponse)
    async def activate(
        workflow_id: str,
        command: AutoConnectSandboxPolicyActivateCommand,
        authorization: str | None = Header(default=None),
    ):
        try:
            assert orchestrator is not None
            return await orchestrator.activate_sandbox_policy_and_advance(
                principal(authorization), workflow_id, command
            )
        except Exception as exc:
            fail(exc)

    return router
