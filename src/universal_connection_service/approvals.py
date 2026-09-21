from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
from typing import Protocol, runtime_checkable

from pydantic import Field

from .contracts import ConnectionRequest, Model, Operation
from .policy import ApprovalGrant, ApprovalVerification, approval_input_digest


def approval_ref_hash(approval_id: str) -> str:
    """Return a stable non-reversible reference for an opaque approval id."""
    return sha256(approval_id.encode("utf-8")).hexdigest()


class ApprovalRecord(Model):
    approval_ref_hash: str = Field(alias="approvalRefHash", min_length=64, max_length=64)
    request_id: str = Field(alias="requestId", min_length=1)
    organization_id: str = Field(alias="organizationId", min_length=1)
    user_id: str = Field(alias="userId", min_length=1)
    agent_id: str = Field(alias="agentId", min_length=1)
    service_id: str = Field(alias="serviceId", min_length=1)
    capability: str = Field(min_length=1)
    operation: Operation
    expires_at: datetime = Field(alias="expiresAt")
    input_digest: str | None = Field(alias="inputDigest", default=None, min_length=64, max_length=64)
    consumed_at: datetime | None = Field(alias="consumedAt", default=None)
    created_at: datetime = Field(alias="createdAt", default_factory=lambda: datetime.now(timezone.utc))

    @classmethod
    def from_grant(cls, grant: ApprovalGrant) -> "ApprovalRecord":
        return cls(
            approvalRefHash=approval_ref_hash(grant.approval_id),
            requestId=grant.request_id,
            organizationId=grant.organization_id,
            userId=grant.user_id,
            agentId=grant.agent_id,
            serviceId=grant.service_id,
            capability=grant.capability,
            operation=grant.operation,
            expiresAt=grant.expires_at,
            inputDigest=grant.input_digest,
        )


@runtime_checkable
class ApprovalStore(Protocol):
    def put_approval(self, record: ApprovalRecord) -> None: ...

    def get_approval(self, approval_ref_hash: str) -> ApprovalRecord | None: ...

    def consume_approval(self, approval_ref_hash: str, consumed_at: datetime) -> bool: ...


class ApprovalConsumeError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.safe_message = message


class PersistentApprovalVerifier:
    """ApprovalVerifier backed by a persistent ApprovalStore.

    Raw approval ids are hashed before touching persistence. The underlying
    store must implement consume_approval atomically so one grant cannot be
    consumed concurrently by multiple UCS instances.
    """

    def __init__(self, store: ApprovalStore, *, require_input_binding: bool = True) -> None:
        self.store = store
        # A grant without an input digest authorizes any payload for that
        # request. That is refused by default: an approval for "send 10" must
        # not execute "send 1,000,000".
        self.require_input_binding = require_input_binding

    def register(self, grant: ApprovalGrant) -> ApprovalRecord:
        record = ApprovalRecord.from_grant(grant)
        self.store.put_approval(record)
        return record

    async def verify(self, approval_id: str, request: ConnectionRequest) -> ApprovalVerification:
        record = self.store.get_approval(approval_ref_hash(approval_id))
        if record is None:
            return ApprovalVerification(valid=False)
        if record.consumed_at is not None:
            return ApprovalVerification(
                valid=False,
                code="APPROVAL_ALREADY_USED",
                message="Approval has already been used",
            )

        now = datetime.now(timezone.utc)
        expires_at = record.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at <= now:
            return ApprovalVerification(
                valid=False,
                code="APPROVAL_EXPIRED",
                message="Approval has expired",
            )

        service_id = request.service.id or request.service.name.lower().replace(" ", "-")
        matches = (
            record.request_id == request.request_id
            and record.organization_id == request.actor.organization_id
            and record.user_id == request.actor.user_id
            and record.agent_id == request.actor.agent_id
            and record.service_id == service_id
            and record.capability == request.capability
            and record.operation == request.operation
        )
        if not matches:
            return ApprovalVerification(
                valid=False,
                code="APPROVAL_SCOPE_MISMATCH",
                message="Approval does not match this request",
            )

        if record.input_digest is None:
            if self.require_input_binding:
                return ApprovalVerification(
                    valid=False,
                    code="APPROVAL_INPUT_UNBOUND",
                    message="Approval is not bound to a request payload",
                )
        elif record.input_digest != approval_input_digest(request.input):
            return ApprovalVerification(
                valid=False,
                code="APPROVAL_INPUT_MISMATCH",
                message="Approval was granted for a different request payload",
            )
        return ApprovalVerification(valid=True, code="APPROVAL_VALID", message="Approval is valid")

    async def consume(self, approval_id: str) -> None:
        ref_hash = approval_ref_hash(approval_id)
        consumed_at = datetime.now(timezone.utc)
        if self.store.consume_approval(ref_hash, consumed_at):
            return

        record = self.store.get_approval(ref_hash)
        if record is None:
            raise ApprovalConsumeError("APPROVAL_INVALID", "Approval is invalid or unavailable")
        if record.consumed_at is not None:
            raise ApprovalConsumeError("APPROVAL_ALREADY_USED", "Approval has already been used")
        expires_at = record.expires_at
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at <= consumed_at:
            raise ApprovalConsumeError("APPROVAL_EXPIRED", "Approval has expired")
        raise ApprovalConsumeError("APPROVAL_INVALID", "Approval could not be consumed")
