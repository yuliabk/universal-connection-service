from __future__ import annotations

from dataclasses import dataclass, field

from .contracts import ConnectorContract, ConnectorManifest, Lifecycle
from .persistence import ConnectorStateRecord, ConnectorStateStore


GLOBAL_ORGANIZATION = "*"


@dataclass
class Registration:
    connector: ConnectorContract
    status: Lifecycle = "discovered"
    approval_id: str | None = None
    organization_id: str = GLOBAL_ORGANIZATION
    _state_store: ConnectorStateStore | None = field(default=None, init=False, repr=False, compare=False)

    @property
    def manifest(self) -> ConnectorManifest:
        return self.connector.manifest()

    def bind_state_store(self, store: ConnectorStateStore | None) -> None:
        self._state_store = store

    def persist(self) -> None:
        if self._state_store is None:
            return
        self._state_store.upsert_connector(
            ConnectorStateRecord(
                organizationId=self.organization_id,
                manifest=self.manifest,
                status=self.status,
                approvalId=self.approval_id,
            )
        )

    def set_status(self, status: Lifecycle, *, approval_id: str | None = None) -> None:
        self.status = status
        self.approval_id = approval_id
        if self._state_store is not None:
            self._state_store.update_connector_status(
                self.organization_id,
                self.manifest.connector_id,
                self.manifest.version,
                status,
                approval_id,
            )


class ConnectorRegistry:
    def __init__(self, state_store: ConnectorStateStore | None = None):
        self._items: dict[tuple[str, str, str], Registration] = {}
        self.state_store = state_store

    def register(self, item: Registration):
        key = (
            item.organization_id,
            item.manifest.connector_id,
            item.manifest.version,
        )
        if key in self._items:
            raise ValueError("connector version already registered for organization")
        item.bind_state_store(self.state_store)
        self._items[key] = item
        item.persist()

    def exact(self, organization_id: str, connector_id: str, version: str) -> Registration | None:
        """Return one exact runtime registration without tenant/global fallback."""
        return self._items.get((organization_id, connector_id, version))

    def trusted(
        self,
        service_id: str,
        capability: str,
        organization_id: str | None = None,
    ) -> Registration | None:
        allowed_organizations = {GLOBAL_ORGANIZATION}
        if organization_id is not None:
            allowed_organizations.add(organization_id)
        items = [
            item
            for item in self._items.values()
            if item.status == "trusted"
            and item.organization_id in allowed_organizations
            and item.manifest.service_id == service_id
            and capability in item.manifest.capabilities
        ]
        if not items:
            return None
        return sorted(
            items,
            key=lambda item: (
                item.organization_id == organization_id,
                item.manifest.version,
            ),
        )[-1]

    def manifests(self, organization_id: str | None = None):
        allowed_organizations = {GLOBAL_ORGANIZATION}
        if organization_id is not None:
            allowed_organizations.add(organization_id)
        return [
            item.manifest
            for item in self._items.values()
            if item.organization_id in allowed_organizations
        ]
