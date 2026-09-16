"""Provider-neutral durable execution contracts. No credentials or raw payloads."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Literal, Protocol, runtime_checkable
from uuid import uuid4

from pydantic import Field, field_validator

from .contracts import ConnectionRequest, Model, Operation

ReceiptState = Literal["prepared", "dispatching", "pending", "unknown", "succeeded", "failed_no_effect"]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def execution_binding(request: ConnectionRequest, provider_account_id: str, *, schema_version: int = 1) -> str:
    """Versioned canonical binding; rejects ambiguous/non-JSON values."""
    if type(schema_version) is not int or schema_version != 1:
        raise ReceiptError("BINDING_SCHEMA_UNSUPPORTED")
    def validate(value):
        if isinstance(value, dict):
            if any(not isinstance(key, str) for key in value):
                raise ValueError("execution input keys must be strings")
            for child in value.values():
                validate(child)
        elif isinstance(value, list):
            for child in value:
                validate(child)
        elif value is not None and type(value) not in (str, bool, int, float):
            raise ValueError("execution input must be JSON")

    validate(request.input)
    body = {
        "schemaVersion": 1,
        "actor": request.actor.model_dump(by_alias=True),
        "serviceId": request.service.id or request.service.name.lower().replace(" ", "-"),
        "providerAccountId": provider_account_id,
        "capability": request.capability,
        "operation": request.operation,
        "input": request.input,
    }
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class ReceiptError(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class ExecutionIntent(Model):
    # Missing on historical receipts means v1; never silently reinterpret v1.
    binding_schema_version: Literal[1] = Field(alias="bindingSchemaVersion", default=1)
    organization_id: str = Field(alias="organizationId", min_length=1)
    operation_id: str = Field(alias="operationId", min_length=1, max_length=200)
    request_id: str = Field(alias="requestId", min_length=1)
    user_id: str = Field(alias="userId", min_length=1)
    agent_id: str = Field(alias="agentId", min_length=1)
    service_id: str = Field(alias="serviceId", min_length=1)
    provider_account_id: str = Field(alias="providerAccountId", min_length=1)
    capability: str = Field(min_length=1)
    operation: Operation
    binding_digest: str = Field(alias="bindingDigest", pattern=r"^[a-f0-9]{64}$")
    connector_id: str = Field(alias="connectorId", min_length=1)
    connector_version: str = Field(alias="connectorVersion", min_length=1)
    approval_ref_hash: str | None = Field(alias="approvalRefHash", default=None, pattern=r"^[a-f0-9]{64}$")
    recovery_contract_digest: str | None = Field(alias="recoveryContractDigest", default=None, pattern=r"^[a-f0-9]{64}$")


class ExecutionReceipt(ExecutionIntent):
    receipt_id: str = Field(alias="receiptId", default_factory=lambda: str(uuid4()))
    provider_key: str = Field(alias="providerKey", default_factory=lambda: str(uuid4()))
    provider_not_after: datetime | None = Field(alias="providerNotAfter", default=None)
    state: ReceiptState = "prepared"
    version: int = Field(default=0, ge=0)
    attempt_count: int = Field(alias="attemptCount", default=0, ge=0)
    lookup_count: int = Field(alias="lookupCount", default=0, ge=0)
    recovery_not_before: datetime | None = Field(alias="recoveryNotBefore", default=None)
    outcome_conflicted: bool = Field(alias="outcomeConflicted", default=False)
    attempt_id: str | None = Field(alias="attemptId", default=None)
    result_ref: str | None = Field(alias="resultRef", default=None)
    provider_reference: str | None = Field(alias="providerReference", default=None)
    audit_id: str | None = Field(alias="auditId", default=None)
    result_purged_at: datetime | None = Field(alias="resultPurgedAt", default=None)
    created_at: datetime = Field(alias="createdAt", default_factory=utc_now)
    updated_at: datetime = Field(alias="updatedAt", default_factory=utc_now)

    @field_validator("created_at", "updated_at", "recovery_not_before")
    @classmethod
    def aware(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("receipt timestamps must include timezone")
        return value.astimezone(timezone.utc)


class ReceiptAudit(Model):
    """Allow-listed audit body; deliberately cannot contain input, output or secrets."""
    event_id: str = Field(alias="eventId", default_factory=lambda: str(uuid4()))
    organization_id: str = Field(alias="organizationId")
    receipt_id: str = Field(alias="receiptId")
    operation_id: str = Field(alias="operationId")
    request_id: str = Field(alias="requestId")
    user_id: str = Field(alias="userId")
    agent_id: str = Field(alias="agentId")
    service_id: str = Field(alias="serviceId")
    capability: str
    operation: Operation
    connector_id: str = Field(alias="connectorId")
    connector_version: str = Field(alias="connectorVersion")
    decision: Literal["execution_completed", "reconciled"] = "execution_completed"
    state: Literal["succeeded", "failed_no_effect"]
    created_at: datetime = Field(alias="createdAt", default_factory=utc_now)


@runtime_checkable
class ReceiptStore(Protocol):
    def quarantine_conflicting_outcome(self, organization_id: str, operation_id: str, observed_state: str) -> ExecutionReceipt: ...
    def record_execution_notice(self, organization_id: str, receipt_id: str, code: str) -> None: ...
    def execution_notices(self, organization_id: str, *, after: str = "", limit: int = 100) -> list[dict]: ...
    def execution_metrics(self, organization_id: str) -> dict: ...
    @property
    def receipts_durable(self) -> bool: ...
    def prepare_receipt(self, intent: ExecutionIntent) -> ExecutionReceipt: ...
    def get_receipt(self, organization_id: str, operation_id: str) -> ExecutionReceipt | None: ...
    def begin_dispatch(self, organization_id: str, operation_id: str, expected_version: int, request_id: str, *, require_approval: bool = False, approval_ref_hash: str | None = None, replay_window_seconds: int | None = None) -> ExecutionReceipt: ...
    def mark_unresolved(self, organization_id: str, operation_id: str, expected_version: int, state: Literal["unknown", "pending"]) -> ExecutionReceipt: ...
    def complete_receipt(self, organization_id: str, operation_id: str, expected_version: int, state: Literal["succeeded", "failed_no_effect"], *, result_ref: str | None = None, provider_reference: str | None = None, result_ciphertext: str | None = None) -> ExecutionReceipt: ...
    def get_receipt_result(self, organization_id: str, operation_id: str) -> str | None: ...
    def revoke_execution_approval(self, organization_id: str, ref_hash: str) -> bool: ...
    def pending_receipt_audit(self, organization_id: str, limit: int = 100) -> list[ReceiptAudit]: ...
    def acknowledge_receipt_audit(self, organization_id: str, event_id: str) -> bool: ...
    def receipt_audit_organizations(self, limit: int = 100, *, after: str = "") -> list[str]: ...
    def deliver_receipt_audit(self, organization_id: str, limit: int = 100) -> int: ...
    def receipt_result_page(self, after: str = "", limit: int = 10) -> list[tuple[ExecutionReceipt, str]]: ...
    def purge_receipt_result(self, organization_id: str, operation_id: str, expected_version: int, ciphertext: str) -> bool: ...
    def begin_receipt_lookup(self, organization_id: str, operation_id: str, expected_version: int, contract_digest: str, max_lookups: int, deadline: datetime, *, backoff_ms: int = 1000) -> ExecutionReceipt: ...
    def begin_receipt_replay(self, organization_id: str, operation_id: str, expected_version: int, request_id: str, contract_digest: str, max_attempts: int, approval_ref_hash: str, *, backoff_ms: int = 1000, clock_margin_ms: int = 1000) -> ExecutionReceipt: ...
