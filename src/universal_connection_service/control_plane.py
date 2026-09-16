from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Literal
from uuid import uuid4

from fastapi import APIRouter, Header, HTTPException, Query
from pydantic import Field, SecretStr, field_validator

from .approvals import ApprovalRecord, ApprovalStore, approval_ref_hash
from .contracts import ConnectionRequest, ConnectorManifest, ExecutionContext, Model
from .mcp_validation import MCPValidationReport, MCPValidationService
from .persistence import ConnectorStateStore, EvidenceRecord, EvidenceStore
from .registry import ConnectorRegistry, Registration
from .service import ConnectionService


ControlPlaneScope = Literal[
    "connectors:review",
    "connectors:validate",
    "approvals:issue",
    "connectors:promote",
]
_ALLOWED_SCOPES = {
    "connectors:review",
    "connectors:validate",
    "approvals:issue",
    "connectors:promote",
}
_CONTROL_PLANE_SERVICE = "ucs-control-plane"


class ControlPlaneCredential(Model):
    token_sha256: str = Field(alias="tokenSha256", min_length=64, max_length=64)
    subject: str = Field(min_length=1)
    token_id: str = Field(alias="tokenId", min_length=1)
    organizations: tuple[str, ...] = Field(min_length=1)
    scopes: tuple[ControlPlaneScope, ...] = Field(min_length=1)

    @field_validator("token_sha256")
    @classmethod
    def validate_token_hash(cls, value: str) -> str:
        normalized = value.lower()
        if len(normalized) != 64 or any(ch not in "0123456789abcdef" for ch in normalized):
            raise ValueError("tokenSha256 must be a lowercase SHA-256 hex digest")
        return normalized

    @field_validator("organizations")
    @classmethod
    def unique_organizations(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(item.strip() for item in value if item.strip())
        if not normalized or len(normalized) != len(set(normalized)):
            raise ValueError("organizations must be non-empty and unique")
        return normalized

    @field_validator("scopes")
    @classmethod
    def unique_scopes(cls, value: tuple[ControlPlaneScope, ...]) -> tuple[ControlPlaneScope, ...]:
        if len(value) != len(set(value)):
            raise ValueError("control-plane scopes must be unique")
        return value


class ControlPlanePrincipal(Model):
    subject: str
    token_id: str = Field(alias="tokenId")
    organizations: tuple[str, ...]
    scopes: tuple[ControlPlaneScope, ...]

    def allows(self, scope: ControlPlaneScope, organization_id: str) -> bool:
        return scope in self.scopes and ("*" in self.organizations or organization_id in self.organizations)


class StaticBearerAuthenticator:
    """Authenticate high-entropy bearer tokens against configured SHA-256 digests."""

    def __init__(self, credentials: tuple[ControlPlaneCredential, ...]) -> None:
        if not credentials:
            raise ValueError("at least one control-plane credential is required")
        hashes = [item.token_sha256 for item in credentials]
        ids = [item.token_id for item in credentials]
        if len(hashes) != len(set(hashes)) or len(ids) != len(set(ids)):
            raise ValueError("control-plane token hashes and token IDs must be unique")
        self.credentials = credentials

    @classmethod
    def from_json(cls, value: str) -> "StaticBearerAuthenticator":
        try:
            payload = json.loads(value)
        except json.JSONDecodeError:
            raise ValueError("control-plane credentials JSON is invalid") from None
        if not isinstance(payload, list) or not payload:
            raise ValueError("control-plane credentials JSON must be a non-empty array")
        return cls(tuple(ControlPlaneCredential.model_validate(item) for item in payload))

    def authenticate(self, authorization: str | None) -> ControlPlanePrincipal | None:
        if not authorization or not authorization.startswith("Bearer "):
            return None
        token = authorization[7:]
        if not token:
            return None
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        match = None
        for credential in self.credentials:
            if hmac.compare_digest(digest, credential.token_sha256):
                match = credential
        if match is None:
            return None
        return ControlPlanePrincipal(
            subject=match.subject,
            tokenId=match.token_id,
            organizations=match.organizations,
            scopes=match.scopes,
        )


class ControlPlaneError(RuntimeError):
    def __init__(self, code: str, message: str, *, status_code: int = 409) -> None:
        super().__init__(message)
        self.code = code
        self.safe_message = message
        self.status_code = status_code


class ValidationEvidenceSummary(Model):
    evidence_id: str = Field(alias="evidenceId")
    created_at: datetime = Field(alias="createdAt")
    type: str
    passed: bool
    code: str | None = None
    engine: str | None = None


class ConnectorReview(Model):
    organization_id: str = Field(alias="organizationId")
    connector_id: str = Field(alias="connectorId")
    version: str
    lifecycle: str
    runtime_available: bool = Field(alias="runtimeAvailable")
    manifest: ConnectorManifest
    validation_ready: bool = Field(alias="validationReady")
    validation_evidence: tuple[ValidationEvidenceSummary, ...] = Field(alias="validationEvidence")


class PromotionApprovalCommand(Model):
    organization_id: str = Field(alias="organizationId", min_length=1)
    version: str = Field(min_length=1)
    promotion_id: str = Field(alias="promotionId", min_length=8, max_length=200)
    expires_in_seconds: int = Field(alias="expiresInSeconds", default=900, ge=60, le=3600)


class PromotionApprovalIssued(Model):
    promotion_id: str = Field(alias="promotionId")
    organization_id: str = Field(alias="organizationId")
    connector_id: str = Field(alias="connectorId")
    version: str
    approval_id: str = Field(alias="approvalId")
    expires_at: datetime = Field(alias="expiresAt")


class PromotionCommand(Model):
    organization_id: str = Field(alias="organizationId", min_length=1)
    version: str = Field(min_length=1)
    promotion_id: str = Field(alias="promotionId", min_length=8, max_length=200)
    approval_id: SecretStr = Field(alias="approvalId")


class PromotionResult(Model):
    organization_id: str = Field(alias="organizationId")
    connector_id: str = Field(alias="connectorId")
    version: str
    lifecycle: str
    approval_ref_hash: str = Field(alias="approvalRefHash")


class MCPValidationCommand(Model):
    request: ConnectionRequest
    candidate_id: str = Field(alias="candidateId", min_length=1)
    selected_tool: str | None = Field(alias="selectedTool", default=None)
    credential_handle: SecretStr | None = Field(alias="credentialHandle", default=None)
    deadline_ms: int = Field(alias="deadlineMs", default=10000, ge=1000, le=60000)


class ControlPlaneService:
    def __init__(
        self,
        *,
        registry: ConnectorRegistry,
        connection_service: ConnectionService,
        state_store: ConnectorStateStore | None,
        evidence_store: EvidenceStore | None,
        approval_store: ApprovalStore | None,
        mcp_validation_service: MCPValidationService | None = None,
        require_distinct_approver: bool = False,
    ) -> None:
        self.registry = registry
        self.connection_service = connection_service
        self.state_store = state_store
        self.evidence_store = evidence_store
        self.approval_store = approval_store
        self.mcp_validation_service = mcp_validation_service
        self.require_distinct_approver = require_distinct_approver

    @staticmethod
    def _require(principal: ControlPlanePrincipal, scope: ControlPlaneScope, organization_id: str) -> None:
        if not principal.allows(scope, organization_id):
            raise ControlPlaneError(
                "CONTROL_PLANE_FORBIDDEN",
                "Control-plane principal is not authorized for this organization and scope",
                status_code=403,
            )

    def _runtime_registration(self, organization_id: str, connector_id: str, version: str) -> Registration | None:
        return self.registry.exact(organization_id, connector_id, version)

    def _persisted_record(self, organization_id: str, connector_id: str, version: str):
        if self.state_store is None:
            return None
        for record in self.state_store.list_connectors(organization_id):
            if record.manifest.connector_id == connector_id and record.manifest.version == version:
                return record
        return None

    @staticmethod
    def _validation_passed(record: EvidenceRecord) -> tuple[bool, str | None, str | None]:
        payload = record.payload
        evidence_type = str(payload.get("type") or "validation")
        if evidence_type == "mcp_candidate_validation":
            return payload.get("passed") is True, payload.get("code") if isinstance(payload.get("code"), str) else None, None
        report = payload.get("report")
        if isinstance(report, dict):
            return report.get("passed") is True, None, payload.get("engine") if isinstance(payload.get("engine"), str) else None
        return False, None, None

    def _validation_summaries(
        self,
        organization_id: str,
        connector_id: str,
    ) -> tuple[ValidationEvidenceSummary, ...]:
        if self.evidence_store is None:
            return ()
        summaries: list[ValidationEvidenceSummary] = []
        for record in self.evidence_store.list_evidence(organization_id, kind="validation"):
            if record.connector_id != connector_id:
                continue
            passed, code, engine = self._validation_passed(record)
            if not passed and record.payload.get("type") not in {"mcp_candidate_validation"} and "report" not in record.payload:
                continue
            summaries.append(
                ValidationEvidenceSummary(
                    evidenceId=record.evidence_id,
                    createdAt=record.created_at,
                    type=str(record.payload.get("type") or "openapi_validation"),
                    passed=passed,
                    code=code,
                    engine=engine,
                )
            )
        summaries.sort(key=lambda item: (item.created_at, item.evidence_id))
        return tuple(summaries)

    def review(
        self,
        principal: ControlPlanePrincipal,
        organization_id: str,
        connector_id: str,
        version: str,
    ) -> ConnectorReview:
        self._require(principal, "connectors:review", organization_id)
        runtime = self._runtime_registration(organization_id, connector_id, version)
        persisted = self._persisted_record(organization_id, connector_id, version)
        if runtime is None and persisted is None:
            raise ControlPlaneError("CONNECTOR_NOT_FOUND", "Connector version was not found", status_code=404)
        manifest = runtime.manifest if runtime is not None else persisted.manifest
        lifecycle = runtime.status if runtime is not None else persisted.status
        evidence = self._validation_summaries(organization_id, connector_id)
        ready = runtime is not None and lifecycle in {"validated", "awaiting_approval", "trusted"} and any(item.passed for item in evidence)
        return ConnectorReview(
            organizationId=organization_id,
            connectorId=connector_id,
            version=version,
            lifecycle=lifecycle,
            runtimeAvailable=runtime is not None,
            manifest=manifest,
            validationReady=ready,
            validationEvidence=evidence,
        )

    def _promotion_capability(self, connector_id: str, version: str) -> str:
        return f"connector.promote:{connector_id}:{version}"

    def _append_control_evidence(
        self,
        *,
        organization_id: str,
        connector_id: str,
        promotion_id: str,
        approval_ref: str,
        event_type: str,
        payload: dict,
    ) -> None:
        if self.evidence_store is None:
            return
        self.evidence_store.append_evidence(
            EvidenceRecord(
                evidenceId=str(uuid4()),
                organizationId=organization_id,
                kind="approval_verification",
                phase="execution",
                requestId=promotion_id,
                connectorId=connector_id,
                payload={
                    "type": event_type,
                    "promotionRefHash": hashlib.sha256(promotion_id.encode("utf-8")).hexdigest(),
                    "approvalRefHash": approval_ref,
                    **payload,
                },
            )
        )

    def issue_promotion_approval(
        self,
        principal: ControlPlanePrincipal,
        connector_id: str,
        command: PromotionApprovalCommand,
    ) -> PromotionApprovalIssued:
        self._require(principal, "approvals:issue", command.organization_id)
        if self.approval_store is None:
            raise ControlPlaneError(
                "APPROVAL_STORE_UNAVAILABLE",
                "Persistent approval storage is not configured",
                status_code=503,
            )
        review = self.review(
            ControlPlanePrincipal(
                subject=principal.subject,
                tokenId=principal.token_id,
                organizations=principal.organizations,
                scopes=tuple(set(principal.scopes) | {"connectors:review"}),
            ),
            command.organization_id,
            connector_id,
            command.version,
        )
        if not review.validation_ready or review.lifecycle not in {"validated", "awaiting_approval"}:
            raise ControlPlaneError(
                "CONNECTOR_NOT_PROMOTABLE",
                "Connector must be runtime-available, validated, and backed by passing validation evidence",
            )
        raw_approval = secrets.token_urlsafe(32)
        approval_ref = approval_ref_hash(raw_approval)
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=command.expires_in_seconds)
        self.approval_store.put_approval(
            ApprovalRecord(
                approvalRefHash=approval_ref,
                requestId=command.promotion_id,
                organizationId=command.organization_id,
                userId=principal.subject,
                agentId=principal.token_id,
                serviceId=_CONTROL_PLANE_SERVICE,
                capability=self._promotion_capability(connector_id, command.version),
                operation="update",
                expiresAt=expires_at,
            )
        )
        registration = self._runtime_registration(command.organization_id, connector_id, command.version)
        assert registration is not None
        if registration.status == "validated":
            registration.set_status("awaiting_approval", approval_id=approval_ref)
        self._append_control_evidence(
            organization_id=command.organization_id,
            connector_id=connector_id,
            promotion_id=command.promotion_id,
            approval_ref=approval_ref,
            event_type="promotion_approval_issued",
            payload={"approverSubject": principal.subject, "version": command.version, "expiresAt": expires_at.isoformat()},
        )
        return PromotionApprovalIssued(
            promotionId=command.promotion_id,
            organizationId=command.organization_id,
            connectorId=connector_id,
            version=command.version,
            approvalId=raw_approval,
            expiresAt=expires_at,
        )

    def _verify_promotion_approval(
        self,
        principal: ControlPlanePrincipal,
        connector_id: str,
        command: PromotionCommand,
    ) -> tuple[ApprovalRecord, str]:
        if self.approval_store is None:
            raise ControlPlaneError("APPROVAL_STORE_UNAVAILABLE", "Persistent approval storage is not configured", status_code=503)
        raw = command.approval_id.get_secret_value()
        ref = approval_ref_hash(raw)
        record = self.approval_store.get_approval(ref)
        if record is None:
            raise ControlPlaneError("APPROVAL_INVALID", "Promotion approval is invalid")
        if record.consumed_at is not None:
            raise ControlPlaneError("APPROVAL_ALREADY_USED", "Promotion approval has already been used")
        expires_at = record.expires_at if record.expires_at.tzinfo else record.expires_at.replace(tzinfo=timezone.utc)
        if expires_at <= datetime.now(timezone.utc):
            raise ControlPlaneError("APPROVAL_EXPIRED", "Promotion approval has expired")
        expected = (
            record.request_id == command.promotion_id
            and record.organization_id == command.organization_id
            and record.service_id == _CONTROL_PLANE_SERVICE
            and record.capability == self._promotion_capability(connector_id, command.version)
            and record.operation == "update"
        )
        if not expected:
            raise ControlPlaneError("APPROVAL_SCOPE_MISMATCH", "Promotion approval does not match this connector promotion")
        if self.require_distinct_approver and record.user_id == principal.subject:
            raise ControlPlaneError(
                "APPROVER_SEPARATION_REQUIRED",
                "Promotion requires an approver distinct from the promoting principal",
                status_code=403,
            )
        return record, ref

    def promote(
        self,
        principal: ControlPlanePrincipal,
        connector_id: str,
        command: PromotionCommand,
    ) -> PromotionResult:
        self._require(principal, "connectors:promote", command.organization_id)
        registration = self._runtime_registration(command.organization_id, connector_id, command.version)
        if registration is None:
            raise ControlPlaneError(
                "RUNTIME_CONNECTOR_UNAVAILABLE",
                "Validated connector implementation is not loaded in this runtime",
            )
        if registration.status not in {"validated", "awaiting_approval"}:
            raise ControlPlaneError("CONNECTOR_NOT_PROMOTABLE", "Connector is not in a promotable lifecycle state")
        evidence = self._validation_summaries(command.organization_id, connector_id)
        if not any(item.passed for item in evidence):
            raise ControlPlaneError("VALIDATION_EVIDENCE_REQUIRED", "Passing validation evidence is required before promotion")
        approval, approval_ref = self._verify_promotion_approval(principal, connector_id, command)
        assert self.approval_store is not None
        consumed_at = datetime.now(timezone.utc)
        if not self.approval_store.consume_approval(approval_ref, consumed_at):
            refreshed = self.approval_store.get_approval(approval_ref)
            if refreshed is not None and refreshed.consumed_at is not None:
                raise ControlPlaneError("APPROVAL_ALREADY_USED", "Promotion approval has already been used")
            raise ControlPlaneError("APPROVAL_INVALID", "Promotion approval could not be consumed")
        from_status = registration.status
        registration.set_status("trusted", approval_id=approval_ref)
        self._append_control_evidence(
            organization_id=command.organization_id,
            connector_id=connector_id,
            promotion_id=command.promotion_id,
            approval_ref=approval_ref,
            event_type="connector_promoted",
            payload={
                "version": command.version,
                "fromLifecycle": from_status,
                "toLifecycle": "trusted",
                "approverSubject": approval.user_id,
                "promoterSubject": principal.subject,
            },
        )
        return PromotionResult(
            organizationId=command.organization_id,
            connectorId=connector_id,
            version=command.version,
            lifecycle="trusted",
            approvalRefHash=approval_ref,
        )

    async def validate_mcp_candidate(
        self,
        principal: ControlPlanePrincipal,
        command: MCPValidationCommand,
    ) -> MCPValidationReport:
        organization_id = command.request.actor.organization_id
        self._require(principal, "connectors:validate", organization_id)
        if self.mcp_validation_service is None:
            raise ControlPlaneError("MCP_VALIDATION_UNAVAILABLE", "MCP validation service is not configured", status_code=503)
        plan = self.connection_service.compiler.compile(command.request, phase="plan")
        candidate = next(
            (item for item in plan.discovery_candidates if item.candidate_id == command.candidate_id),
            None,
        )
        if candidate is None:
            raise ControlPlaneError(
                "DISCOVERY_CANDIDATE_NOT_FOUND",
                "Candidate is not present in the current server-side discovery result",
                status_code=404,
            )
        ctx = ExecutionContext(
            requestId=command.request.request_id,
            userId=command.request.actor.user_id,
            organizationId=organization_id,
            credentialHandle=command.credential_handle,
            deadlineMs=command.deadline_ms,
        )
        return await self.mcp_validation_service.validate(
            candidate,
            command.request,
            ctx=ctx,
            selected_tool=command.selected_tool,
            deadline_ms=command.deadline_ms,
        )


def build_control_plane_router(
    service: ControlPlaneService,
    authenticator: StaticBearerAuthenticator | None,
) -> APIRouter:
    router = APIRouter(prefix="/v1/control-plane", tags=["control-plane"])

    def principal(authorization: str | None = Header(default=None)) -> ControlPlanePrincipal:
        if authenticator is None:
            raise HTTPException(status_code=503, detail={"code": "CONTROL_PLANE_DISABLED", "message": "Control plane is not configured"})
        value = authenticator.authenticate(authorization)
        if value is None:
            raise HTTPException(
                status_code=401,
                detail={"code": "CONTROL_PLANE_UNAUTHENTICATED", "message": "Valid control-plane bearer token required"},
                headers={"WWW-Authenticate": "Bearer"},
            )
        return value

    def fail(exc: ControlPlaneError):
        raise HTTPException(status_code=exc.status_code, detail={"code": exc.code, "message": exc.safe_message})

    @router.get("/connectors/{connector_id}/review", response_model=ConnectorReview)
    def review_connector(
        connector_id: str,
        organization_id: str = Query(alias="organizationId"),
        version: str = Query(...),
        authorization: str | None = Header(default=None),
    ):
        actor = principal(authorization)
        try:
            return service.review(actor, organization_id, connector_id, version)
        except ControlPlaneError as exc:
            fail(exc)

    @router.post("/connectors/{connector_id}/promotion-approvals", response_model=PromotionApprovalIssued)
    def issue_approval(
        connector_id: str,
        command: PromotionApprovalCommand,
        authorization: str | None = Header(default=None),
    ):
        actor = principal(authorization)
        try:
            return service.issue_promotion_approval(actor, connector_id, command)
        except ControlPlaneError as exc:
            fail(exc)

    @router.post("/connectors/{connector_id}/promote", response_model=PromotionResult)
    def promote_connector(
        connector_id: str,
        command: PromotionCommand,
        authorization: str | None = Header(default=None),
    ):
        actor = principal(authorization)
        try:
            return service.promote(actor, connector_id, command)
        except ControlPlaneError as exc:
            fail(exc)

    @router.post("/mcp/validate", response_model=MCPValidationReport)
    async def validate_mcp(
        command: MCPValidationCommand,
        authorization: str | None = Header(default=None),
    ):
        actor = principal(authorization)
        try:
            return await service.validate_mcp_candidate(actor, command)
        except ControlPlaneError as exc:
            fail(exc)

    return router
