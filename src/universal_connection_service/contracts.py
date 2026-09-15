from __future__ import annotations

from typing import Any, Literal, Protocol, runtime_checkable
from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator

Strategy = Literal["trusted_connector", "official_api", "oauth", "mcp", "generated_api_adapter", "browser"]
Operation = Literal["read", "create", "update", "delete", "execute"]
Status = Literal["success", "partial", "failed"]
Lifecycle = Literal["discovered", "generated", "sandboxed", "validated", "awaiting_approval", "trusted", "degraded", "repairing", "disabled", "rejected"]

class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

class ActorRef(Model):
    user_id: str = Field(alias="userId", min_length=1)
    organization_id: str = Field(alias="organizationId", min_length=1)
    agent_id: str = Field(alias="agentId", min_length=1)

class ServiceRef(Model):
    id: str | None = None
    name: str = Field(min_length=1)
    base_url: str | None = Field(alias="baseUrl", default=None)

class ConnectionRequest(Model):
    request_id: str = Field(alias="requestId", min_length=1)
    actor: ActorRef
    service: ServiceRef
    capability: str = Field(min_length=1)
    operation: Operation
    input: dict[str, Any] = Field(default_factory=dict)
    read_only: bool = Field(alias="readOnly", default=True)

class AuthRequirement(Model):
    type: Literal["none", "api_key", "oauth2", "session", "certificate", "other"] = "none"
    scopes: tuple[str, ...] = ()

class RiskAssessment(Model):
    level: Literal["LOW", "MEDIUM", "HIGH"]
    reasons: tuple[str, ...] = ()
    destructive: bool = False
    financial: bool = False

class ConnectionPlan(Model):
    plan_id: str = Field(alias="planId")
    request_id: str = Field(alias="requestId")
    service_id: str = Field(alias="serviceId")
    capability: str
    connector_id: str | None = Field(alias="connectorId", default=None)
    strategy: Strategy
    auth_requirement: AuthRequirement = Field(alias="authRequirement")
    risk: RiskAssessment
    requires_build: bool = Field(alias="requiresBuild")
    requires_validation: bool = Field(alias="requiresValidation")
    requires_human_approval: bool = Field(alias="requiresHumanApproval")

class ConnectorManifest(Model):
    connector_id: str = Field(alias="connectorId")
    service_id: str = Field(alias="serviceId")
    name: str
    version: str
    strategy: Literal["api", "oauth", "mcp", "browser"]
    capabilities: tuple[str, ...]
    auth: AuthRequirement = AuthRequirement()

class ExecutionContext(Model):
    request_id: str = Field(alias="requestId")
    user_id: str = Field(alias="userId")
    organization_id: str = Field(alias="organizationId")
    credential_handle: SecretStr | None = Field(alias="credentialHandle", default=None)
    approval_id: str | None = Field(alias="approvalId", default=None)
    deadline_ms: int = Field(alias="deadlineMs", default=15000, ge=1)

class ConnectionError(Model):
    code: str
    message: str
    retryable: bool = False
    user_action_required: bool = Field(alias="userActionRequired", default=False)

class ConnectorResult(Model):
    status: Status
    data: Any | None = None
    error: ConnectionError | None = None
    @model_validator(mode="after")
    def consistent(self):
        if self.status == "success" and self.error: raise ValueError("success cannot contain error")
        if self.status == "failed" and not self.error: raise ValueError("failed requires error")
        return self

class ConnectionResult(Model):
    request_id: str = Field(alias="requestId")
    status: Status
    service_id: str = Field(alias="serviceId")
    capability: str
    connector_id: str | None = Field(alias="connectorId", default=None)
    data: Any | None = None
    error: ConnectionError | None = None
    audit_id: str = Field(alias="auditId")

@runtime_checkable
class ConnectorContract(Protocol):
    def manifest(self) -> ConnectorManifest: ...
    async def health_check(self, ctx: ExecutionContext) -> bool: ...
    async def execute(self, capability: str, input: dict[str, Any], ctx: ExecutionContext) -> ConnectorResult: ...
