from uuid import uuid4

from .contracts import AuthRequirement, ConnectionPlan, ConnectionRequest
from .persistence import EvidenceRecord, EvidenceStore
from .policy import DefaultPolicyEngine, PolicyEngine, PolicyFacts
from .registry import ConnectorRegistry


class ConnectionCompiler:
    def __init__(
        self,
        registry: ConnectorRegistry,
        policy_engine: PolicyEngine | None = None,
        evidence_store: EvidenceStore | None = None,
    ):
        self.registry = registry
        self.policy_engine = policy_engine or DefaultPolicyEngine()
        self.evidence_store = evidence_store

    @staticmethod
    def service_id(req: ConnectionRequest) -> str:
        return req.service.id or req.service.name.lower().replace(" ", "-")

    def _policy_facts(self, req: ConnectionRequest, *, trusted_connector: bool) -> PolicyFacts:
        hints = req.risk_hints
        return PolicyFacts(
            requestId=req.request_id,
            organizationId=req.actor.organization_id,
            userId=req.actor.user_id,
            agentId=req.actor.agent_id,
            serviceId=self.service_id(req),
            capability=req.capability,
            operation=req.operation,
            readOnly=req.read_only,
            trustedConnector=trusted_connector,
            destructive=hints.destructive,
            financial=hints.financial,
            permissionIncrease=hints.permission_increase,
        )

    def _persist_policy_evidence(
        self,
        req: ConnectionRequest,
        *,
        phase: str,
        connector_id: str | None,
        trusted_connector: bool,
        evaluation,
    ) -> None:
        if self.evidence_store is None:
            return
        self.evidence_store.append_evidence(
            EvidenceRecord(
                evidenceId=str(uuid4()),
                organizationId=req.actor.organization_id,
                kind="policy_decision",
                phase=phase,
                requestId=req.request_id,
                connectorId=connector_id,
                payload={
                    "decision": evaluation.decision,
                    "reasons": list(evaluation.reasons),
                    "risk": evaluation.risk.model_dump(by_alias=True, mode="json"),
                    "trustedConnector": trusted_connector,
                    "serviceId": self.service_id(req),
                    "capability": req.capability,
                    "operation": req.operation,
                },
            )
        )

    def compile(self, req: ConnectionRequest, *, phase: str = "plan") -> ConnectionPlan:
        if phase not in {"plan", "execution"}:
            raise ValueError("policy evidence phase must be plan or execution")
        service_id = self.service_id(req)
        found = self.registry.trusted(
            service_id,
            req.capability,
            req.actor.organization_id,
        )
        evaluation = self.policy_engine.evaluate(
            self._policy_facts(req, trusted_connector=found is not None)
        )
        self._persist_policy_evidence(
            req,
            phase=phase,
            connector_id=found.manifest.connector_id if found else None,
            trusted_connector=found is not None,
            evaluation=evaluation,
        )

        if found:
            return ConnectionPlan(
                planId=str(uuid4()),
                requestId=req.request_id,
                serviceId=service_id,
                capability=req.capability,
                connectorId=found.manifest.connector_id,
                strategy="trusted_connector",
                authRequirement=found.manifest.auth,
                risk=evaluation.risk,
                requiresBuild=False,
                requiresValidation=False,
                requiresHumanApproval=evaluation.decision == "REQUIRE_APPROVAL",
                policyDecision=evaluation.decision,
                policyReasons=evaluation.reasons,
            )

        strategy = "official_api" if req.service.base_url else "generated_api_adapter"
        return ConnectionPlan(
            planId=str(uuid4()),
            requestId=req.request_id,
            serviceId=service_id,
            capability=req.capability,
            strategy=strategy,
            authRequirement=AuthRequirement(type="other"),
            risk=evaluation.risk,
            requiresBuild=True,
            requiresValidation=True,
            requiresHumanApproval=evaluation.decision == "REQUIRE_APPROVAL",
            policyDecision=evaluation.decision,
            policyReasons=evaluation.reasons,
        )
