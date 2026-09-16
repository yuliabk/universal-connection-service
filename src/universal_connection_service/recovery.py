"""Operator-pinned provider recovery contract, independent of transport hints."""
import hashlib
import json
from datetime import datetime
from typing import Literal, Protocol

from pydantic import Field, model_validator

from .contracts import Model, ConnectorResult, ExecutionContext


class ReplayPolicy(Model):
    deduplication_window_seconds: int = Field(alias="deduplicationWindowSeconds", ge=1, le=31_536_000)
    max_attempts: int = Field(alias="maxAttempts", ge=2, le=10)
    # Reviewed provider guarantee: concurrent equal keys share one effect, and
    # delayed requests past notAfter cannot create an effect after key eviction.
    provider_enforces_not_after: Literal[True] = Field(alias="providerEnforcesNotAfter")
    concurrent_deduplication: Literal[True] = Field(alias="concurrentDeduplication")


class RecoveryContract(Model):
    contract_id: str = Field(alias="contractId", min_length=1)
    revision: str = Field(min_length=1)
    evidence_sha256: str = Field(alias="evidenceSha256", pattern=r"^[a-f0-9]{64}$")
    approval_reference: str = Field(alias="approvalReference", min_length=1)
    lookup_window_seconds: int = Field(alias="lookupWindowSeconds", ge=1, le=31_536_000)
    max_lookups: int = Field(alias="maxLookups", ge=1, le=100)
    lookup_timeout_ms: int = Field(alias="lookupTimeoutMs", ge=1, le=60_000)
    replay: ReplayPolicy | None = None
    dispatch_outcomes: bool = Field(alias="dispatchOutcomes", default=False)

    def digest(self) -> str:
        return hashlib.sha256(json.dumps(self.model_dump(mode="json", by_alias=True, exclude_defaults=True),
            sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class ProviderExecutionKey(Model):
    provider_key: str = Field(alias="providerKey")
    provider_account_id: str = Field(alias="providerAccountId")
    binding_digest: str = Field(alias="bindingDigest")
    contract_digest: str = Field(alias="contractDigest")
    not_after: datetime | None = Field(alias="notAfter", default=None)


class ProviderOutcome(ProviderExecutionKey):
    state: Literal["succeeded", "failed_no_effect", "pending", "unknown", "not_found"]
    result: ConnectorResult | None = None
    # failed_no_effect includes a provider guarantee that late dispatch cannot act.
    late_execution_prevented: bool = Field(alias="lateExecutionPrevented", default=False)

    @model_validator(mode="after")
    def finality(self):
        if self.state == "succeeded" and (self.result is None or self.result.status != "success"):
            raise ValueError("success requires a final result")
        if self.state == "failed_no_effect" and (not self.late_execution_prevented or
                self.result is None or self.result.status != "failed"):
            raise ValueError("no-effect requires final failure and late-execution prevention")
        if self.state in {"pending", "unknown", "not_found"} and self.result is not None:
            raise ValueError("unresolved outcome cannot carry a final result")
        return self


class RecoveryConnector(Protocol):
    """Trusted adapter must implement the pinned provider semantics end to end."""
    def recovery_contract_digest(self) -> str: ...
    async def execute_keyed(self, capability: str, input: dict, ctx: ExecutionContext,
                            key: ProviderExecutionKey) -> ConnectorResult | ProviderOutcome: ...
    async def lookup_execution(self, capability: str, ctx: ExecutionContext,
                               key: ProviderExecutionKey) -> ProviderOutcome: ...
