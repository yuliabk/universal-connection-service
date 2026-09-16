from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from fastapi import APIRouter, Header, HTTPException, Query
from pydantic import Field, SecretStr

from .approvals import ApprovalRecord, ApprovalStore, approval_ref_hash
from .contracts import Model
from .control_plane import ControlPlaneError, ControlPlanePrincipal, StaticBearerAuthenticator
from .mcpb_sandbox import SandboxedMCPConnector
from .persistence import EvidenceRecord, EvidenceStore
from .registry import ConnectorRegistry
from .sandbox_policy import SandboxCapabilityProfile, SandboxMountCatalog

_SANDBOX_TOOL_POLICY_SERVICE = "ucs-sandbox-tool-policy"


class SandboxToolProfileApprovalCommand(Model):
    organization_id: str = Field(alias="organizationId", min_length=1)
    version: str = Field(min_length=1)
    capability: str = Field(min_length=1)
    change_id: str = Field(alias="changeId", min_length=8, max_length=200)
    profile: SandboxCapabilityProfile
    expires_in_seconds: int = Field(alias="expiresInSeconds", default=900, ge=60, le=3600)


class SandboxToolProfileApprovalIssued(Model):
    change_id: str = Field(alias="changeId")
    connector_id: str = Field(alias="connectorId")
    version: str
    organization_id: str = Field(alias="organizationId")
    capability: str
    profile_hash: str = Field(alias="profileHash")
    approval_id: str = Field(alias="approvalId")
    expires_at: datetime = Field(alias="expiresAt")


class SandboxToolProfileApplyCommand(Model):
    organization_id: str = Field(alias="organizationId", min_length=1)
    version: str = Field(min_length=1)
    capability: str = Field(min_length=1)
    change_id: str = Field(alias="changeId", min_length=8, max_length=200)
    profile: SandboxCapabilityProfile
    approval_id: SecretStr = Field(alias="approvalId")


class SandboxToolProfileResult(Model):
    organization_id: str = Field(alias="organizationId")
    connector_id: str = Field(alias="connectorId")
    version: str
    capability: str
    profile: SandboxCapabilityProfile
    profile_hash: str = Field(alias="profileHash")
    approval_ref_hash: str | None = Field(alias="approvalRefHash", default=None)


class SandboxToolPolicyService:
    """Version- and capability-scoped sandbox privileges for trusted MCPB connectors."""

    def __init__(
        self,
        *,
        registry: ConnectorRegistry,
        evidence_store: EvidenceStore | None,
        approval_store: ApprovalStore | None,
        mount_catalog: SandboxMountCatalog | None = None,
        require_distinct_approver: bool = False,
    ) -> None:
        self.registry = registry
        self.evidence_store = evidence_store
        self.approval_store = approval_store
        self.mount_catalog = mount_catalog or SandboxMountCatalog()
        self.require_distinct_approver = require_distinct_approver

    @staticmethod
    def _require(principal: ControlPlanePrincipal, scope: str, organization_id: str) -> None:
        if scope not in principal.scopes or ("*" not in principal.organizations and organization_id not in principal.organizations):
            raise ControlPlaneError(
                "CONTROL_PLANE_FORBIDDEN",
                "Control-plane principal is not authorized for sandbox tool policy",
                status_code=403,
            )

    def _trusted_connector(self, organization_id: str, connector_id: str, version: str):
        registration = self.registry.exact(organization_id, connector_id, version)
        if registration is None or registration.status != "trusted" or not isinstance(registration.connector, SandboxedMCPConnector):
            # Tool-scoped runtime wrappers expose the same config/manifest but are not necessarily the base class.
            if registration is None or registration.status != "trusted" or not hasattr(registration.connector, "config"):
                raise ControlPlaneError(
                    "SANDBOX_PROFILE_NOT_APPLICABLE",
                    "Sandbox tool profile requires a trusted sandboxed MCP connector",
                )
        return registration

    def _require_capability(self, organization_id: str, connector_id: str, version: str, capability: str):
        registration = self._trusted_connector(organization_id, connector_id, version)
        if capability not in registration.manifest.capabilities:
            raise ControlPlaneError(
                "SANDBOX_CAPABILITY_NOT_FOUND",
                "Sandbox tool profile capability is not exposed by this connector",
                status_code=404,
            )
        return registration

    @staticmethod
    def _approval_capability(connector_id: str, version: str, capability: str, profile_hash: str) -> str:
        material = hashlib.sha256(capability.encode("utf-8")).hexdigest()[:16]
        return f"sandbox.tool-profile:{connector_id}:{version}:{material}:{profile_hash}"

    def active_profile(
        self,
        organization_id: str,
        connector_id: str,
        version: str,
        capability: str | None = None,
    ) -> SandboxCapabilityProfile:
        # Introspection and health checks intentionally receive no capability and therefore no privileges.
        if capability is None or self.evidence_store is None:
            return SandboxCapabilityProfile()
        matches = [
            item
            for item in self.evidence_store.list_evidence(organization_id, kind="approval_verification")
            if item.connector_id == connector_id
            and item.payload.get("type") == "sandbox_tool_profile_activated"
            and item.payload.get("version") == version
            and item.payload.get("capability") == capability
            and isinstance(item.payload.get("profile"), dict)
        ]
        if not matches:
            return SandboxCapabilityProfile()
        matches.sort(key=lambda item: (item.created_at, item.evidence_id))
        try:
            return SandboxCapabilityProfile.model_validate(matches[-1].payload["profile"])
        except Exception:
            return SandboxCapabilityProfile()

    def issue_approval(
        self,
        principal: ControlPlanePrincipal,
        connector_id: str,
        command: SandboxToolProfileApprovalCommand,
    ) -> SandboxToolProfileApprovalIssued:
        self._require(principal, "approvals:issue", command.organization_id)
        if self.approval_store is None:
            raise ControlPlaneError("APPROVAL_STORE_UNAVAILABLE", "Persistent approval storage is not configured", status_code=503)
        self._require_capability(command.organization_id, connector_id, command.version, command.capability)
        self.mount_catalog.validate_profile(command.organization_id, command.profile)
        profile_hash = command.profile.digest()
        raw = secrets.token_urlsafe(32)
        ref = approval_ref_hash(raw)
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=command.expires_in_seconds)
        self.approval_store.put_approval(
            ApprovalRecord(
                approvalRefHash=ref,
                requestId=command.change_id,
                organizationId=command.organization_id,
                userId=principal.subject,
                agentId=principal.token_id,
                serviceId=_SANDBOX_TOOL_POLICY_SERVICE,
                capability=self._approval_capability(connector_id, command.version, command.capability, profile_hash),
                operation="update",
                expiresAt=expires_at,
            )
        )
        if self.evidence_store is not None:
            self.evidence_store.append_evidence(
                EvidenceRecord(
                    evidenceId=str(uuid4()),
                    organizationId=command.organization_id,
                    kind="approval_verification",
                    phase="execution",
                    requestId=command.change_id,
                    connectorId=connector_id,
                    payload={
                        "type": "sandbox_tool_profile_approval_issued",
                        "version": command.version,
                        "capability": command.capability,
                        "profileHash": profile_hash,
                        "approvalRefHash": ref,
                        "approverSubject": principal.subject,
                        "expiresAt": expires_at.isoformat(),
                    },
                )
            )
        return SandboxToolProfileApprovalIssued(
            changeId=command.change_id,
            connectorId=connector_id,
            version=command.version,
            organizationId=command.organization_id,
            capability=command.capability,
            profileHash=profile_hash,
            approvalId=raw,
            expiresAt=expires_at,
        )

    def apply(
        self,
        principal: ControlPlanePrincipal,
        connector_id: str,
        command: SandboxToolProfileApplyCommand,
    ) -> SandboxToolProfileResult:
        self._require(principal, "connectors:promote", command.organization_id)
        if self.approval_store is None:
            raise ControlPlaneError("APPROVAL_STORE_UNAVAILABLE", "Persistent approval storage is not configured", status_code=503)
        self._require_capability(command.organization_id, connector_id, command.version, command.capability)
        self.mount_catalog.validate_profile(command.organization_id, command.profile)
        profile_hash = command.profile.digest()
        ref = approval_ref_hash(command.approval_id.get_secret_value())
        record = self.approval_store.get_approval(ref)
        now = datetime.now(timezone.utc)
        if record is None:
            raise ControlPlaneError("APPROVAL_INVALID", "Sandbox tool profile approval is invalid")
        if record.consumed_at is not None:
            raise ControlPlaneError("APPROVAL_ALREADY_USED", "Sandbox tool profile approval has already been used")
        expires_at = record.expires_at if record.expires_at.tzinfo else record.expires_at.replace(tzinfo=timezone.utc)
        if expires_at <= now:
            raise ControlPlaneError("APPROVAL_EXPIRED", "Sandbox tool profile approval has expired")
        expected = (
            record.request_id == command.change_id
            and record.organization_id == command.organization_id
            and record.service_id == _SANDBOX_TOOL_POLICY_SERVICE
            and record.capability == self._approval_capability(
                connector_id, command.version, command.capability, profile_hash
            )
            and record.operation == "update"
        )
        if not expected:
            raise ControlPlaneError("APPROVAL_SCOPE_MISMATCH", "Sandbox tool profile approval does not match this change")
        if self.require_distinct_approver and record.user_id == principal.subject:
            raise ControlPlaneError(
                "SEPARATION_OF_DUTIES_REQUIRED",
                "Sandbox tool profile approver and applier must be different principals",
            )
        if not self.approval_store.consume_approval(ref, now):
            raise ControlPlaneError("APPROVAL_ALREADY_USED", "Sandbox tool profile approval could not be consumed")
        if self.evidence_store is not None:
            self.evidence_store.append_evidence(
                EvidenceRecord(
                    evidenceId=str(uuid4()),
                    organizationId=command.organization_id,
                    kind="approval_verification",
                    phase="execution",
                    requestId=command.change_id,
                    connectorId=connector_id,
                    payload={
                        "type": "sandbox_tool_profile_activated",
                        "version": command.version,
                        "capability": command.capability,
                        "profileHash": profile_hash,
                        "approvalRefHash": ref,
                        "appliedBy": principal.subject,
                        "profile": command.profile.model_dump(by_alias=True, mode="json"),
                    },
                )
            )
        return SandboxToolProfileResult(
            organizationId=command.organization_id,
            connectorId=connector_id,
            version=command.version,
            capability=command.capability,
            profile=command.profile,
            profileHash=profile_hash,
            approvalRefHash=ref,
        )

    def status(
        self,
        principal: ControlPlanePrincipal,
        organization_id: str,
        connector_id: str,
        version: str,
        capability: str,
    ) -> SandboxToolProfileResult:
        self._require(principal, "connectors:review", organization_id)
        self._require_capability(organization_id, connector_id, version, capability)
        profile = self.active_profile(organization_id, connector_id, version, capability)
        return SandboxToolProfileResult(
            organizationId=organization_id,
            connectorId=connector_id,
            version=version,
            capability=capability,
            profile=profile,
            profileHash=profile.digest(),
        )


def build_sandbox_tool_policy_router(
    service: SandboxToolPolicyService | None,
    authenticator: StaticBearerAuthenticator | None,
) -> APIRouter:
    router = APIRouter(prefix="/v1/control-plane/connectors", tags=["sandbox-tool-policy"])

    def principal(authorization: str | None) -> ControlPlanePrincipal:
        if service is None or authenticator is None:
            raise HTTPException(
                status_code=503,
                detail={"code": "SANDBOX_POLICY_DISABLED", "message": "Sandbox tool policy control plane is not configured"},
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
        if isinstance(exc, ControlPlaneError):
            raise HTTPException(status_code=exc.status_code, detail={"code": exc.code, "message": exc.safe_message})
        raise exc

    @router.get("/{connector_id}/sandbox-profile", response_model=SandboxToolProfileResult)
    def status(
        connector_id: str,
        organization_id: str = Query(alias="organizationId"),
        version: str = Query(),
        capability: str = Query(),
        authorization: str | None = Header(default=None),
    ):
        try:
            assert service is not None
            return service.status(principal(authorization), organization_id, connector_id, version, capability)
        except Exception as exc:
            fail(exc)

    @router.post("/{connector_id}/sandbox-profile-approval", response_model=SandboxToolProfileApprovalIssued)
    def issue(
        connector_id: str,
        command: SandboxToolProfileApprovalCommand,
        authorization: str | None = Header(default=None),
    ):
        try:
            assert service is not None
            return service.issue_approval(principal(authorization), connector_id, command)
        except Exception as exc:
            fail(exc)

    @router.post("/{connector_id}/sandbox-profile", response_model=SandboxToolProfileResult)
    def apply(
        connector_id: str,
        command: SandboxToolProfileApplyCommand,
        authorization: str | None = Header(default=None),
    ):
        try:
            assert service is not None
            return service.apply(principal(authorization), connector_id, command)
        except Exception as exc:
            fail(exc)

    return router
