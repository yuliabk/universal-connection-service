from __future__ import annotations

import hashlib
import json
from typing import Any, Literal
from uuid import uuid4

from fastapi import APIRouter, Header, HTTPException, Query
from pydantic import Field, field_validator

from .contracts import Model
from .control_plane import ControlPlaneError, ControlPlanePrincipal, StaticBearerAuthenticator
from .credentials import AgentVaultCredentialResolver
from .mcp_validation import MAX_LIST_PAGES, MAX_TOOL_METADATA_BYTES
from .mcpb_sandbox import SandboxedMCPConnector
from .persistence import EvidenceRecord, EvidenceStore
from .registry import ConnectorRegistry
from .sandbox_policy import SandboxCapabilityProfile, SandboxMountCatalog


ProposalConfidence = Literal["LOW", "MEDIUM", "HIGH"]


class SandboxPolicyRule(Model):
    organization_id: str = Field(alias="organizationId", min_length=1)
    service_id: str = Field(alias="serviceId", min_length=1)
    capability: str | None = Field(default=None)
    tool_name: str | None = Field(alias="toolName", default=None)
    profile: SandboxCapabilityProfile
    reason: str = Field(min_length=1, max_length=500)

    @field_validator("organization_id", "service_id", "capability", "tool_name")
    @classmethod
    def strip_values(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if not normalized:
            raise ValueError("policy rule identifiers must be non-empty")
        return normalized


class SandboxPolicyCatalog:
    def __init__(self, rules: tuple[SandboxPolicyRule, ...] = ()) -> None:
        self.rules = rules

    @classmethod
    def from_json(cls, value: str | None) -> "SandboxPolicyCatalog":
        if not value:
            return cls()
        try:
            payload = json.loads(value)
        except json.JSONDecodeError:
            raise ValueError("sandbox policy catalog JSON is invalid") from None
        if not isinstance(payload, list):
            raise ValueError("sandbox policy catalog must be an array")
        return cls(tuple(SandboxPolicyRule.model_validate(item) for item in payload))

    @staticmethod
    def _specificity(rule: SandboxPolicyRule, organization_id: str, capability: str, tool_name: str) -> int:
        if rule.organization_id not in {"*", organization_id}:
            return -1
        if rule.capability is not None and rule.capability != capability:
            return -1
        if rule.tool_name is not None and rule.tool_name != tool_name:
            return -1
        score = 0
        if rule.organization_id == organization_id:
            score += 4
        if rule.capability is not None:
            score += 2
        if rule.tool_name is not None:
            score += 1
        return score

    def best_matches(
        self,
        organization_id: str,
        service_id: str,
        capability: str,
        tool_name: str,
    ) -> tuple[SandboxPolicyRule, ...]:
        candidates: list[tuple[int, SandboxPolicyRule]] = []
        for rule in self.rules:
            if rule.service_id != service_id:
                continue
            score = self._specificity(rule, organization_id, capability, tool_name)
            if score >= 0:
                candidates.append((score, rule))
        if not candidates:
            return ()
        top = max(score for score, _ in candidates)
        return tuple(rule for score, rule in candidates if score == top)


class ToolRiskHints(Model):
    read_only_hint: bool | None = Field(alias="readOnlyHint", default=None)
    destructive_hint: bool | None = Field(alias="destructiveHint", default=None)
    idempotent_hint: bool | None = Field(alias="idempotentHint", default=None)
    open_world_hint: bool | None = Field(alias="openWorldHint", default=None)


class SandboxPolicyProposal(Model):
    proposal_id: str = Field(alias="proposalId")
    organization_id: str = Field(alias="organizationId")
    connector_id: str = Field(alias="connectorId")
    version: str
    service_id: str = Field(alias="serviceId")
    capability: str
    tool_name: str = Field(alias="toolName")
    profile: SandboxCapabilityProfile
    profile_hash: str = Field(alias="profileHash")
    confidence: ProposalConfidence
    reasons: tuple[str, ...] = ()
    unresolved_requirements: tuple[str, ...] = Field(alias="unresolvedRequirements", default=())
    tool_risk: ToolRiskHints = Field(alias="toolRisk")
    requires_human_approval: bool = Field(alias="requiresHumanApproval", default=True)


class LeastPrivilegePolicyCompiler:
    """Compile a reviewable sandbox profile proposal from trusted local facts.

    MCP annotations are advisory only. They may influence explanations and whether
    a network requirement appears likely, but they never directly grant egress,
    mounts, or credentials. Concrete privileges come only from the operator
    catalog or an already configured Agent Vault binding scope.
    """

    def __init__(
        self,
        *,
        registry: ConnectorRegistry,
        evidence_store: EvidenceStore | None,
        mount_catalog: SandboxMountCatalog,
        policy_catalog: SandboxPolicyCatalog | None = None,
        credential_resolver: AgentVaultCredentialResolver | None = None,
    ) -> None:
        self.registry = registry
        self.evidence_store = evidence_store
        self.mount_catalog = mount_catalog
        self.policy_catalog = policy_catalog or SandboxPolicyCatalog()
        self.credential_resolver = credential_resolver

    @staticmethod
    def _require_review(principal: ControlPlanePrincipal, organization_id: str) -> None:
        if not principal.allows("connectors:review", organization_id):
            raise ControlPlaneError(
                "CONTROL_PLANE_FORBIDDEN",
                "Control-plane principal is not authorized to compile sandbox policy for this organization",
                status_code=403,
            )

    def _registration(self, organization_id: str, connector_id: str, version: str):
        registration = self.registry.exact(organization_id, connector_id, version)
        if (
            registration is None
            or registration.status != "trusted"
            or not isinstance(registration.connector, SandboxedMCPConnector)
        ):
            raise ControlPlaneError(
                "SANDBOX_POLICY_COMPILER_NOT_APPLICABLE",
                "Least-privilege policy compilation requires a trusted sandboxed MCP connector",
                status_code=409,
            )
        return registration

    @staticmethod
    def _binding_tool(registration, capability: str) -> str:
        binding = next(
            (item for item in registration.connector.config.bindings if item.capability == capability),
            None,
        )
        if binding is None:
            raise ControlPlaneError(
                "SANDBOX_CAPABILITY_NOT_FOUND",
                "Capability is not exposed by this connector",
                status_code=404,
            )
        return binding.tool

    async def _tool_risk(self, registration, tool_name: str) -> ToolRiskHints:
        runner = getattr(registration.connector, "runner", None)
        if runner is None:
            return ToolRiskHints()
        cursor: str | None = None
        seen = 0
        try:
            async with runner.client(registration.connector.config.bundle_digest) as client:
                for _ in range(MAX_LIST_PAGES):
                    page = await client.list_tools(cursor=cursor) if cursor else await client.list_tools()
                    for tool in page.tools:
                        seen += 1
                        if seen > 100:
                            return ToolRiskHints()
                        payload = tool.model_dump(by_alias=True, mode="json", exclude_none=True)
                        if len(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")) > MAX_TOOL_METADATA_BYTES:
                            continue
                        if payload.get("name") != tool_name:
                            continue
                        annotations = payload.get("annotations") if isinstance(payload.get("annotations"), dict) else {}

                        def optional_bool(key: str) -> bool | None:
                            value = annotations.get(key)
                            return value if isinstance(value, bool) else None

                        return ToolRiskHints(
                            readOnlyHint=optional_bool("readOnlyHint"),
                            destructiveHint=optional_bool("destructiveHint"),
                            idempotentHint=optional_bool("idempotentHint"),
                            openWorldHint=optional_bool("openWorldHint"),
                        )
                    cursor = page.next_cursor
                    if cursor is None:
                        break
        except Exception:
            return ToolRiskHints()
        return ToolRiskHints()

    def _vault_host_sets(self, organization_id: str, service_id: str) -> tuple[tuple[str, ...], ...]:
        if self.credential_resolver is None:
            return ()
        host_sets = {
            tuple(sorted(binding.allowed_hosts))
            for binding in self.credential_resolver.config.bindings
            if binding.organization_id == organization_id and binding.service_id == service_id
        }
        return tuple(sorted(host_sets))

    @staticmethod
    def _same_profile(rules: tuple[SandboxPolicyRule, ...]) -> bool:
        if not rules:
            return False
        hashes = {rule.profile.digest() for rule in rules}
        return len(hashes) == 1

    def _persist(self, proposal: SandboxPolicyProposal) -> None:
        if self.evidence_store is None:
            return
        self.evidence_store.append_evidence(
            EvidenceRecord(
                evidenceId=proposal.proposal_id,
                organizationId=proposal.organization_id,
                kind="policy_decision",
                phase="validation",
                connectorId=proposal.connector_id,
                payload={
                    "type": "sandbox_policy_proposal",
                    "version": proposal.version,
                    "serviceId": proposal.service_id,
                    "capability": proposal.capability,
                    "toolName": proposal.tool_name,
                    "profile": proposal.profile.model_dump(by_alias=True, mode="json"),
                    "profileHash": proposal.profile_hash,
                    "confidence": proposal.confidence,
                    "reasons": list(proposal.reasons),
                    "unresolvedRequirements": list(proposal.unresolved_requirements),
                    "toolRisk": proposal.tool_risk.model_dump(by_alias=True, mode="json"),
                    "requiresHumanApproval": True,
                },
            )
        )

    async def compile(
        self,
        principal: ControlPlanePrincipal,
        *,
        organization_id: str,
        connector_id: str,
        version: str,
        capability: str,
    ) -> SandboxPolicyProposal:
        self._require_review(principal, organization_id)
        registration = self._registration(organization_id, connector_id, version)
        tool_name = self._binding_tool(registration, capability)
        service_id = registration.manifest.service_id
        risk = await self._tool_risk(registration, tool_name)

        reasons: list[str] = []
        unresolved: list[str] = []
        profile = SandboxCapabilityProfile()
        confidence: ProposalConfidence = "LOW"

        rules = self.policy_catalog.best_matches(organization_id, service_id, capability, tool_name)
        if rules:
            if not self._same_profile(rules):
                unresolved.append("operator_policy_conflict")
                reasons.append("equally specific operator rules propose different profiles")
            else:
                candidate = rules[0].profile
                try:
                    self.mount_catalog.validate_profile(organization_id, candidate)
                except Exception:
                    unresolved.append("operator_mount_policy_unavailable")
                    reasons.append("operator policy references a mount that is not currently available")
                else:
                    profile = candidate
                    confidence = "HIGH"
                    reasons.extend(rule.reason for rule in rules)
                    reasons.append("concrete privileges originate from operator-controlled policy")

        if not rules and risk.open_world_hint is True:
            host_sets = self._vault_host_sets(organization_id, service_id)
            if len(host_sets) == 1:
                profile = SandboxCapabilityProfile(
                    egressHosts=host_sets[0],
                    brokeredCredentials=True,
                )
                confidence = "MEDIUM"
                reasons.append("tool advertises open-world behavior")
                reasons.append("egress targets come from the unique Agent Vault binding scope for this service")
            elif len(host_sets) > 1:
                unresolved.append("credential_scope_selection_required")
                reasons.append("multiple Agent Vault host scopes exist for this service")
            else:
                unresolved.append("egress_targets_unknown")
                reasons.append("tool advertises open-world behavior but no operator-controlled egress scope is available")
        elif not rules and risk.open_world_hint is None:
            unresolved.append("open_world_behavior_unverified")
            reasons.append("tool does not provide a trustworthy-enough open-world signal; zero privilege retained")
        elif not rules and risk.open_world_hint is False:
            reasons.append("tool advertises closed-world behavior; zero network privilege proposed")
            confidence = "MEDIUM"

        if risk.read_only_hint is True:
            reasons.append("tool advertises read-only behavior")
        elif risk.read_only_hint is False:
            reasons.append("tool advertises mutating behavior")
        else:
            reasons.append("tool read-only behavior is unspecified")
        if risk.destructive_hint is True:
            reasons.append("tool advertises potentially destructive behavior")
        if risk.idempotent_hint is True:
            reasons.append("tool advertises idempotent behavior")

        if unresolved:
            confidence = "LOW"

        proposal_id = str(uuid4())
        proposal = SandboxPolicyProposal(
            proposalId=proposal_id,
            organizationId=organization_id,
            connectorId=connector_id,
            version=version,
            serviceId=service_id,
            capability=capability,
            toolName=tool_name,
            profile=profile,
            profileHash=profile.digest(),
            confidence=confidence,
            reasons=tuple(dict.fromkeys(reasons)),
            unresolvedRequirements=tuple(dict.fromkeys(unresolved)),
            toolRisk=risk,
            requiresHumanApproval=True,
        )
        self._persist(proposal)
        return proposal


def build_sandbox_policy_compiler_router(
    compiler: LeastPrivilegePolicyCompiler | None,
    authenticator: StaticBearerAuthenticator | None,
) -> APIRouter:
    router = APIRouter(prefix="/v1/control-plane/connectors", tags=["sandbox-policy-compiler"])

    def principal(authorization: str | None) -> ControlPlanePrincipal:
        if compiler is None or authenticator is None:
            raise HTTPException(
                status_code=503,
                detail={"code": "SANDBOX_POLICY_COMPILER_DISABLED", "message": "Sandbox policy compiler is not configured"},
            )
        actor = authenticator.authenticate(authorization)
        if actor is None:
            raise HTTPException(
                status_code=401,
                detail={"code": "CONTROL_PLANE_UNAUTHENTICATED", "message": "Valid control-plane bearer token required"},
                headers={"WWW-Authenticate": "Bearer"},
            )
        return actor

    @router.get("/{connector_id}/sandbox-profile-proposal", response_model=SandboxPolicyProposal)
    async def propose(
        connector_id: str,
        organization_id: str = Query(alias="organizationId"),
        version: str = Query(),
        capability: str = Query(),
        authorization: str | None = Header(default=None),
    ):
        try:
            assert compiler is not None
            return await compiler.compile(
                principal(authorization),
                organization_id=organization_id,
                connector_id=connector_id,
                version=version,
                capability=capability,
            )
        except ControlPlaneError as exc:
            raise HTTPException(status_code=exc.status_code, detail={"code": exc.code, "message": exc.safe_message}) from None

    return router
