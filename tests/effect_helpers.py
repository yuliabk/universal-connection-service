"""Explicit host approvals for synthetic read fixtures only."""
from universal_connection_service.effects import EffectClassification


def approve_read(service, request, connector_id=None):
    candidates = service.registry.manifests(request.actor.organization_id)
    manifest = next(m for m in candidates if request.capability in m.capabilities
                    and (connector_id is None or m.connector_id == connector_id))
    service.effect_catalog.approve(EffectClassification(
        organizationId=request.actor.organization_id, serviceId=manifest.service_id,
        connectorId=manifest.connector_id, connectorVersion=manifest.version,
        capability=request.capability, effect="read_only", evidenceSha256="a" * 64,
        approvalReference="synthetic-reviewed-read"))
