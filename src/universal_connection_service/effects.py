"""Host-reviewed capability effects; never inferred from requests or MCP hints."""
import json
import os
from typing import Literal
from pydantic import Field
from .contracts import Model


class EffectClassification(Model):
    organization_id: str = Field(alias="organizationId", min_length=1)
    service_id: str = Field(alias="serviceId", min_length=1)
    connector_id: str = Field(alias="connectorId", min_length=1)
    connector_version: str = Field(alias="connectorVersion", min_length=1)
    capability: str = Field(min_length=1)
    effect: Literal["read_only", "side_effecting"]
    evidence_sha256: str = Field(alias="evidenceSha256", pattern=r"^[a-f0-9]{64}$")
    approval_reference: str = Field(alias="approvalReference", min_length=1)


class EffectCatalog:
    def __init__(self, entries=()):
        self._entries = {}
        for entry in entries:
            self.approve(entry)

    def approve(self, entry: EffectClassification):
        """Trusted host configuration API, deliberately not exposed over HTTP."""
        entry = EffectClassification.model_validate(entry.model_dump()).model_copy(deep=True)
        key = (entry.organization_id, entry.service_id, entry.connector_id, entry.connector_version, entry.capability)
        if key in self._entries:
            raise ValueError("duplicate effect classification")
        self._entries[key] = entry

    def classify(self, request, registration):
        manifest = registration.manifest
        entry = self._entries.get((request.actor.organization_id, manifest.service_id,
            manifest.connector_id, manifest.version, request.capability))
        return entry.effect if entry else "unknown"


def effects_from_env():
    raw = os.getenv("UCS_CAPABILITY_EFFECTS_JSON")
    if raw is None:
        return EffectCatalog()
    try:
        values = json.loads(raw)
        if not isinstance(values, list):
            raise ValueError
        return EffectCatalog(EffectClassification.model_validate(value) for value in values)
    except Exception:
        raise RuntimeError("Capability effect configuration is invalid") from None
