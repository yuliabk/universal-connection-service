from dataclasses import dataclass
from .contracts import ConnectorContract, ConnectorManifest, Lifecycle

@dataclass
class Registration:
    connector: ConnectorContract
    status: Lifecycle = "discovered"
    approval_id: str | None = None
    @property
    def manifest(self) -> ConnectorManifest: return self.connector.manifest()

class ConnectorRegistry:
    def __init__(self): self._items: dict[tuple[str, str], Registration] = {}
    def register(self, item: Registration):
        key = (item.manifest.connector_id, item.manifest.version)
        if key in self._items: raise ValueError("connector version already registered")
        self._items[key] = item
    def trusted(self, service_id: str, capability: str) -> Registration | None:
        items = [x for x in self._items.values() if x.status == "trusted" and x.manifest.service_id == service_id and capability in x.manifest.capabilities]
        return sorted(items, key=lambda x: x.manifest.version)[-1] if items else None
    def manifests(self): return [x.manifest for x in self._items.values()]
