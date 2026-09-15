from uuid import uuid4
from .contracts import AuthRequirement, ConnectionPlan, ConnectionRequest, RiskAssessment
from .registry import ConnectorRegistry

class ConnectionCompiler:
    def __init__(self, registry: ConnectorRegistry): self.registry = registry
    def compile(self, req: ConnectionRequest) -> ConnectionPlan:
        service_id = req.service.id or req.service.name.lower().replace(" ", "-")
        found = self.registry.trusted(service_id, req.capability)
        write = req.operation != "read"
        if found:
            return ConnectionPlan(planId=str(uuid4()), requestId=req.request_id, serviceId=service_id,
                capability=req.capability, connectorId=found.manifest.connector_id,
                strategy="trusted_connector", authRequirement=found.manifest.auth,
                risk=RiskAssessment(level="MEDIUM" if write else "LOW", reasons=(("write operation",) if write else ())),
                requiresBuild=False, requiresValidation=False, requiresHumanApproval=write)
        strategy = "official_api" if req.service.base_url else "generated_api_adapter"
        return ConnectionPlan(planId=str(uuid4()), requestId=req.request_id, serviceId=service_id,
            capability=req.capability, strategy=strategy, authRequirement=AuthRequirement(type="other"),
            risk=RiskAssessment(level="MEDIUM", reasons=("untrusted implementation",)),
            requiresBuild=True, requiresValidation=True, requiresHumanApproval=True)
