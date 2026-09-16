from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Literal
from uuid import uuid4

from fastapi import APIRouter, Header, HTTPException, Query
from pydantic import Field, SecretStr, field_validator, model_validator

from .approvals import ApprovalRecord, ApprovalStore, approval_ref_hash
from .contracts import Model
from .control_plane import ControlPlaneError, ControlPlanePrincipal, StaticBearerAuthenticator
from .mcpb_sandbox import SandboxedMCPConnector
from .persistence import EvidenceRecord, EvidenceStore
from .registry import ConnectorRegistry


_SANDBOX_POLICY_SERVICE = "ucs-sandbox-policy"


class SandboxMountGrant(Model):
    mount_id: str = Field(alias="mountId", min_length=1)
    access: Literal["read_only", "read_write"] = "read_only"


class SandboxCapabilityProfile(Model):
    egress_hosts: tuple[str, ...] = Field(alias="egressHosts", default=())
    mounts: tuple[SandboxMountGrant, ...] = ()
    brokered_credentials: bool = Field(alias="brokeredCredentials", default=False)

    @field_validator("egress_hosts")
    @classmethod
    def normalize_hosts(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalized = tuple(sorted({host.strip().lower().rstrip(".") for host in value if host.strip()}))
        for host in normalized:
            if "/" in host or ":" in host or " " in host or host in {"localhost", "127.0.0.1", "::1"}:
                raise ValueError("sandbox egress hosts must be DNS hostnames")
        return normalized

    @model_validator(mode="after")
    def broker_required_for_egress(self):
        if self.egress_hosts and not self.brokered_credentials:
            raise ValueError("sandbox egress requires brokeredCredentials=true")
        mount_ids = [item.mount_id for item in self.mounts]
        if len(mount_ids) != len(set(mount_ids)):
            raise ValueError("sandbox mount grants must be unique")
        return self

    def digest(self) -> str:
        raw = json.dumps(
            self.model_dump(by_alias=True, mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()


class SandboxMountBinding(Model):
    organization_id: str = Field(alias="organizationId", min_length=1)
    mount_id: str = Field(alias="mountId", min_length=1)
    host_path: str = Field(alias="hostPath", min_length=1)
    container_path: str = Field(alias="containerPath", min_length=6)
    max_access: Literal["read_only", "read_write"] = Field(alias="maxAccess", default="read_only")

    @field_validator("host_path")
    @classmethod
    def absolute_host_path(cls, value: str) -> str:
        path = Path(value)
        if not path.is_absolute():
            raise ValueError("sandbox hostPath must be absolute")
        if str(path) in {"/", "/proc", "/sys", "/dev", "/run", "/var/run"}:
            raise ValueError("sandbox hostPath is too broad")
        return str(path)

    @field_validator("container_path")
    @classmethod
    def safe_container_path(cls, value: str) -> str:
        path = PurePosixPath(value)
        if not path.is_absolute() or ".." in path.parts or not str(path).startswith("/data/"):
            raise ValueError("sandbox containerPath must be under /data/")
        return str(path)


class SandboxMountCatalog:
    def __init__(self, bindings: tuple[SandboxMountBinding, ...] = ()) -> None:
        keys = [(item.organization_id, item.mount_id) for item in bindings]
        if len(keys) != len(set(keys)):
            raise ValueError("sandbox mount bindings must be unique per organization")
        self._bindings = {(item.organization_id, item.mount_id): item for item in bindings}

    @classmethod
    def from_json(cls, value: str | None) -> "SandboxMountCatalog":
        if not value:
            return cls()
        try:
            payload = json.loads(value)
        except json.JSONDecodeError:
            raise ValueError("sandbox mount catalog JSON is invalid") from None
        if not isinstance(payload, list):
            raise ValueError("sandbox mount catalog must be an array")
        return cls(tuple(SandboxMountBinding.model_validate(item) for item in payload))

    def resolve(self, organization_id: str, grant: SandboxMountGrant) -> SandboxMountBinding:
        binding = self._bindings.get((organization_id, grant.mount_id))
        if binding is None:
            raise ControlPlaneError("SANDBOX_MOUNT_NOT_ALLOWED", "Sandbox mount is not configured for this organization")
        if grant.access == "read_write" and binding.max_access != "read_write":
            raise ControlPlaneError("SANDBOX_MOUNT_ACCESS_DENIED", "Sandbox mount does not permit read-write access")
        path = Path(binding.host_path)
        if not path.exists() or path.is_socket():
            raise ControlPlaneError("SANDBOX_MOUNT_UNAVAILABLE", "Sandbox mount source is unavailable")
        return binding

    def validate_profile(self, organization_id: str, profile: SandboxCapabilityProfile) -> None:
        for grant in profile.mounts:
            self.resolve(organization_id, grant)


class SandboxProfileApprovalCommand(Model):
    organization_id: str = Field(alias="organizationId", min_length=1)
    version: str = Field(min_length=1)
    change_id: str = Field(alias="changeId", min_length=8, max_length=200)
    profile: SandboxCapabilityProfile
    expires_in_seconds: int = Field(alias="expiresInSeconds", default=900, ge=60, le=3600)


class SandboxProfileApprovalIssued(Model):
    change_id: str = Field(alias="changeId")
    connector_id: str = Field(alias="connectorId")
    version: str
    organization_id: str = Field(alias="organizationId")
    profile_hash: str = Field(alias="profileHash")
    approval_id: str = Field(alias="approvalId")
    expires_at: datetime = Field(alias="expiresAt")


class SandboxProfileApplyCommand(Model):
    organization_id: str = Field(alias="organizationId", min_length=1)
    version: str = Field(min_length=1)
    change_id: str = Field(alias="changeId", min_length=8, max_length=200)
    profile: SandboxCapabilityProfile
    approval_id: SecretStr = Field(alias="approvalId")


class SandboxProfileResult(Model):
    organization_id: str = Field(alias="organizationId")
    connector_id: str = Field(alias="connectorId")
    version: str
    profile: SandboxCapabilityProfile
    profile_hash: str = Field(alias="profileHash")
    approval_ref_hash: str | None = Field(alias="approvalRefHash", default=None)


class SandboxPolicyService:
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
            raise ControlPlaneError("CONTROL_PLANE_FORBIDDEN", "Control-plane principal is not authorized for sandbox policy", status_code=403)

    def _trusted_connector(self, organization_id: str, connector_id: str, version: str):
        registration = self.registry.exact(organization_id, connector_id, version)
        if registration is None or registration.status != "trusted" or not isinstance(registration.connector, SandboxedMCPConnector):
            raise ControlPlaneError("SANDBOX_PROFILE_NOT_APPLICABLE", "Sandbox profile requires a trusted sandboxed MCP connector")
        return registration

    @staticmethod
    def _approval_capability(connector_id: str, version: str, profile_hash: str) -> str:
        return f"sandbox.profile:{connector_id}:{version}:{profile_hash}"

    def active_profile(self, organization_id: str, connector_id: str, version: str) -> SandboxCapabilityProfile:
        if self.evidence_store is None:
            return SandboxCapabilityProfile()
        matches = [
            item for item in self.evidence_store.list_evidence(organization_id, kind="approval_verification")
            if item.connector_id == connector_id
            and item.payload.get("type") == "sandbox_profile_activated"
            and item.payload.get("version") == version
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
        command: SandboxProfileApprovalCommand,
    ) -> SandboxProfileApprovalIssued:
        self._require(principal, "approvals:issue", command.organization_id)
        if self.approval_store is None:
            raise ControlPlaneError("APPROVAL_STORE_UNAVAILABLE", "Persistent approval storage is not configured", status_code=503)
        self._trusted_connector(command.organization_id, connector_id, command.version)
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
                serviceId=_SANDBOX_POLICY_SERVICE,
                capability=self._approval_capability(connector_id, command.version, profile_hash),
                operation="update",
                expiresAt=expires_at,
            )
        )
        if self.evidence_store is not None:
            self.evidence_store.append_evidence(EvidenceRecord(
                evidenceId=str(uuid4()), organizationId=command.organization_id,
                kind="approval_verification", phase="execution", requestId=command.change_id,
                connectorId=connector_id,
                payload={
                    "type": "sandbox_profile_approval_issued",
                    "version": command.version,
                    "profileHash": profile_hash,
                    "approvalRefHash": ref,
                    "approverSubject": principal.subject,
                    "expiresAt": expires_at.isoformat(),
                },
            ))
        return SandboxProfileApprovalIssued(
            changeId=command.change_id, connectorId=connector_id, version=command.version,
            organizationId=command.organization_id, profileHash=profile_hash,
            approvalId=raw, expiresAt=expires_at,
        )

    def apply(
        self,
        principal: ControlPlanePrincipal,
        connector_id: str,
        command: SandboxProfileApplyCommand,
    ) -> SandboxProfileResult:
        self._require(principal, "sandbox:manage", command.organization_id)
        if self.approval_store is None:
            raise ControlPlaneError("APPROVAL_STORE_UNAVAILABLE", "Persistent approval storage is not configured", status_code=503)
        self._trusted_connector(command.organization_id, connector_id, command.version)
        self.mount_catalog.validate_profile(command.organization_id, command.profile)
        profile_hash = command.profile.digest()
        raw = command.approval_id.get_secret_value()
        ref = approval_ref_hash(raw)
        record = self.approval_store.get_approval(ref)
        now = datetime.now(timezone.utc)
        if record is None:
            raise ControlPlaneError("APPROVAL_INVALID", "Sandbox profile approval is invalid")
        if record.consumed_at is not None:
            raise ControlPlaneError("APPROVAL_ALREADY_USED", "Sandbox profile approval has already been used")
        expires_at = record.expires_at if record.expires_at.tzinfo else record.expires_at.replace(tzinfo=timezone.utc)
        if expires_at <= now:
            raise ControlPlaneError("APPROVAL_EXPIRED", "Sandbox profile approval has expired")
        expected = (
            record.request_id == command.change_id
            and record.organization_id == command.organization_id
            and record.service_id == _SANDBOX_POLICY_SERVICE
            and record.capability == self._approval_capability(connector_id, command.version, profile_hash)
            and record.operation == "update"
        )
        if not expected:
            raise ControlPlaneError("APPROVAL_SCOPE_MISMATCH", "Sandbox profile approval does not match this change")
        if self.require_distinct_approver and record.user_id == principal.subject:
            raise ControlPlaneError("SEPARATION_OF_DUTIES_REQUIRED", "Sandbox profile approver and applier must be different principals")
        if not self.approval_store.consume_approval(ref, now):
            raise ControlPlaneError("APPROVAL_ALREADY_USED", "Sandbox profile approval could not be consumed")
        if self.evidence_store is not None:
            self.evidence_store.append_evidence(EvidenceRecord(
                evidenceId=str(uuid4()), organizationId=command.organization_id,
                kind="approval_verification", phase="execution", requestId=command.change_id,
                connectorId=connector_id,
                payload={
                    "type": "sandbox_profile_activated",
                    "version": command.version,
                    "profileHash": profile_hash,
                    "approvalRefHash": ref,
                    "appliedBy": principal.subject,
                    "profile": command.profile.model_dump(by_alias=True, mode="json"),
                },
            ))
        return SandboxProfileResult(
            organizationId=command.organization_id, connectorId=connector_id, version=command.version,
            profile=command.profile, profileHash=profile_hash, approvalRefHash=ref,
        )

    def status(self, principal: ControlPlanePrincipal, organization_id: str, connector_id: str, version: str) -> SandboxProfileResult:
        self._require(principal, "connectors:review", organization_id)
        self._trusted_connector(organization_id, connector_id, version)
        profile = self.active_profile(organization_id, connector_id, version)
        return SandboxProfileResult(
            organizationId=organization_id, connectorId=connector_id, version=version,
            profile=profile, profileHash=profile.digest(),
        )


def build_sandbox_policy_router(
    service: SandboxPolicyService | None,
    authenticator: StaticBearerAuthenticator | None,
) -> APIRouter:
    router = APIRouter(prefix="/v1/control-plane/connectors", tags=["sandbox-policy"])

    def principal(authorization: str | None) -> ControlPlanePrincipal:
        if service is None or authenticator is None:
            raise HTTPException(status_code=503, detail={"code": "SANDBOX_POLICY_DISABLED", "message": "Sandbox policy control plane is not configured"})
        actor = authenticator.authenticate(authorization)
        if actor is None:
            raise HTTPException(status_code=401, detail={"code": "CONTROL_PLANE_UNAUTHENTICATED", "message": "Valid control-plane bearer token required"}, headers={"WWW-Authenticate": "Bearer"})
        return actor

    def fail(exc: Exception):
        if isinstance(exc, ControlPlaneError):
            raise HTTPException(status_code=exc.status_code, detail={"code": exc.code, "message": exc.safe_message})
        raise exc

    @router.get("/{connector_id}/sandbox-profile", response_model=SandboxProfileResult)
    def status(connector_id: str, organization_id: str = Query(alias="organizationId"), version: str = Query(), authorization: str | None = Header(default=None)):
        try:
            assert service is not None
            return service.status(principal(authorization), organization_id, connector_id, version)
        except Exception as exc:
            fail(exc)

    @router.post("/{connector_id}/sandbox-profile-approval", response_model=SandboxProfileApprovalIssued)
    def issue(connector_id: str, command: SandboxProfileApprovalCommand, authorization: str | None = Header(default=None)):
        try:
            assert service is not None
            return service.issue_approval(principal(authorization), connector_id, command)
        except Exception as exc:
            fail(exc)

    @router.post("/{connector_id}/sandbox-profile", response_model=SandboxProfileResult)
    def apply(connector_id: str, command: SandboxProfileApplyCommand, authorization: str | None = Header(default=None)):
        try:
            assert service is not None
            return service.apply(principal(authorization), connector_id, command)
        except Exception as exc:
            fail(exc)

    return router
