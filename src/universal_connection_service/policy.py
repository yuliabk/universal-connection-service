from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal, Protocol, runtime_checkable
from urllib.parse import urlsplit

import httpx
from pydantic import Field, field_validator

from .contracts import ConnectionRequest, Model, Operation, RiskAssessment

PolicyOutcome = Literal["ALLOW", "DENY", "REQUIRE_APPROVAL"]


class PolicyFacts(Model):
    request_id: str = Field(alias="requestId", min_length=1)
    organization_id: str = Field(alias="organizationId", min_length=1)
    user_id: str = Field(alias="userId", min_length=1)
    agent_id: str = Field(alias="agentId", min_length=1)
    service_id: str = Field(alias="serviceId", min_length=1)
    capability: str = Field(min_length=1)
    operation: Operation
    read_only: bool = Field(alias="readOnly")
    trusted_connector: bool = Field(alias="trustedConnector")
    destructive: bool = False
    financial: bool = False
    permission_increase: bool = Field(alias="permissionIncrease", default=False)


class PolicyEvaluation(Model):
    decision: PolicyOutcome
    reasons: tuple[str, ...] = ()
    risk: RiskAssessment


@runtime_checkable
class PolicyEngine(Protocol):
    def evaluate(self, facts: PolicyFacts) -> PolicyEvaluation: ...


class DefaultPolicyEngine:
    """Deterministic bootstrap policy.

    This engine is intentionally conservative and stateless. Deployments can
    replace it with OPA or another policy provider without changing UCS core
    contracts.
    """

    def __init__(
        self,
        *,
        denied_services: tuple[str, ...] = (),
        denied_capabilities: tuple[str, ...] = (),
    ) -> None:
        self.denied_services = set(denied_services)
        self.denied_capabilities = set(denied_capabilities)

    def evaluate(self, facts: PolicyFacts) -> PolicyEvaluation:
        if facts.service_id in self.denied_services:
            return PolicyEvaluation(
                decision="DENY",
                reasons=("service denied by policy",),
                risk=RiskAssessment(level="HIGH", reasons=("service denied by policy",)),
            )
        if facts.capability in self.denied_capabilities:
            return PolicyEvaluation(
                decision="DENY",
                reasons=("capability denied by policy",),
                risk=RiskAssessment(level="HIGH", reasons=("capability denied by policy",)),
            )

        destructive = facts.destructive or facts.operation == "delete"
        reasons: list[str] = []
        if not facts.trusted_connector:
            reasons.append("untrusted implementation")
        if destructive:
            reasons.append("destructive operation")
        if facts.financial:
            reasons.append("financial operation")
        if facts.permission_increase:
            reasons.append("permission increase")

        if destructive or facts.financial or facts.permission_increase:
            return PolicyEvaluation(
                decision="REQUIRE_APPROVAL",
                reasons=tuple(reasons),
                risk=RiskAssessment(
                    level="HIGH",
                    reasons=tuple(reasons),
                    destructive=destructive,
                    financial=facts.financial,
                    permissionIncrease=facts.permission_increase,
                ),
            )

        write = facts.operation != "read" or not facts.read_only
        if write or not facts.trusted_connector:
            if write:
                reasons.append("write or side-effecting operation")
            return PolicyEvaluation(
                decision="REQUIRE_APPROVAL",
                reasons=tuple(reasons),
                risk=RiskAssessment(level="MEDIUM", reasons=tuple(reasons)),
            )

        return PolicyEvaluation(
            decision="ALLOW",
            reasons=(),
            risk=RiskAssessment(level="LOW"),
        )


class OPAConfig(Model):
    address: str = Field(min_length=1)
    decision_path: str = Field(alias="decisionPath", default="ucs/policy/decision", min_length=1)
    timeout_seconds: float = Field(alias="timeoutSeconds", default=3.0, gt=0, le=30)

    @field_validator("address")
    @classmethod
    def validate_address(cls, value: str) -> str:
        parsed = urlsplit(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("OPA address must be an absolute HTTP(S) URL")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("OPA address must not contain credentials, query parameters or fragments")
        local_hosts = {"localhost", "127.0.0.1", "::1"}
        if parsed.scheme == "http" and parsed.hostname not in local_hosts:
            raise ValueError("remote OPA endpoints must use HTTPS")
        return value.rstrip("/")

    @field_validator("decision_path")
    @classmethod
    def normalize_path(cls, value: str) -> str:
        normalized = value.strip("/")
        if not normalized or ".." in normalized.split("/"):
            raise ValueError("invalid OPA decision path")
        return normalized


class OPAPolicyEngine:
    """OPA Data API policy adapter.

    Expected result shape:
      {"result": {"decision": "ALLOW|DENY|REQUIRE_APPROVAL",
                  "reasons": [...],
                  "risk": {"level": "LOW|MEDIUM|HIGH", ...}}}

    Any network, HTTP, or schema failure denies execution by policy.
    """

    def __init__(
        self,
        config: OPAConfig,
        *,
        client_factory=None,
    ) -> None:
        self.config = config
        self._client_factory = client_factory

    def _client(self) -> httpx.Client:
        if self._client_factory is not None:
            return self._client_factory()
        return httpx.Client(
            base_url=self.config.address,
            timeout=self.config.timeout_seconds,
            follow_redirects=False,
            trust_env=False,
        )

    @staticmethod
    def _fail_closed(reason: str) -> PolicyEvaluation:
        return PolicyEvaluation(
            decision="DENY",
            reasons=(reason,),
            risk=RiskAssessment(level="HIGH", reasons=(reason,)),
        )

    def evaluate(self, facts: PolicyFacts) -> PolicyEvaluation:
        try:
            with self._client() as client:
                response = client.post(
                    f"/v1/data/{self.config.decision_path}",
                    json={"input": facts.model_dump(by_alias=True, mode="json")},
                )
            if response.status_code >= 400:
                return self._fail_closed("policy provider unavailable")
            payload = response.json()
            result = payload.get("result")
            if not isinstance(result, dict):
                return self._fail_closed("policy provider returned no decision")
            return PolicyEvaluation.model_validate(result)
        except Exception:
            return self._fail_closed("policy provider evaluation failed")


class ApprovalGrant(Model):
    approval_id: str = Field(alias="approvalId", min_length=1)
    request_id: str = Field(alias="requestId", min_length=1)
    organization_id: str = Field(alias="organizationId", min_length=1)
    user_id: str = Field(alias="userId", min_length=1)
    agent_id: str = Field(alias="agentId", min_length=1)
    service_id: str = Field(alias="serviceId", min_length=1)
    capability: str = Field(min_length=1)
    operation: Operation
    expires_at: datetime = Field(alias="expiresAt")
    operation_id: str | None = Field(alias="operationId", default=None, min_length=1, max_length=200)
    binding_digest: str | None = Field(alias="bindingDigest", default=None, pattern=r"^[a-f0-9]{64}$")


class ApprovalVerification(Model):
    valid: bool
    code: str = "APPROVAL_INVALID"
    message: str = "Approval is invalid or unavailable"


@runtime_checkable
class ApprovalVerifier(Protocol):
    async def verify(
        self,
        approval_id: str,
        request: ConnectionRequest,
    ) -> ApprovalVerification: ...

    async def consume(self, approval_id: str) -> None: ...


class InMemoryApprovalVerifier:
    """Reference verifier for tests and single-process development.

    Grants are one-time use and request-bound. Production deployments should
    replace this with a persistent approval service/store.
    """

    def __init__(self, grants: tuple[ApprovalGrant, ...] = ()) -> None:
        self._grants = {grant.approval_id: grant for grant in grants}
        self._consumed: set[str] = set()

    async def verify(self, approval_id: str, request: ConnectionRequest) -> ApprovalVerification:
        if approval_id in self._consumed:
            return ApprovalVerification(
                valid=False,
                code="APPROVAL_ALREADY_USED",
                message="Approval has already been used",
            )
        grant = self._grants.get(approval_id)
        if grant is None:
            return ApprovalVerification(valid=False)
        now = datetime.now(timezone.utc)
        expires_at = grant.expires_at
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
            grant.request_id == request.request_id
            and grant.organization_id == request.actor.organization_id
            and grant.user_id == request.actor.user_id
            and grant.agent_id == request.actor.agent_id
            and grant.service_id == service_id
            and grant.capability == request.capability
            and grant.operation == request.operation
        )
        if not matches:
            return ApprovalVerification(
                valid=False,
                code="APPROVAL_SCOPE_MISMATCH",
                message="Approval does not match this request",
            )
        return ApprovalVerification(valid=True, code="APPROVAL_VALID", message="Approval is valid")

    async def consume(self, approval_id: str) -> None:
        if approval_id in self._grants:
            self._consumed.add(approval_id)
