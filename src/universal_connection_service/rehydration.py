from __future__ import annotations

from collections.abc import Callable
from uuid import uuid4

from pydantic import Field

from .contracts import ConnectorContract, Model
from .packages import ConnectorPackageLoader, PackageVerificationError
from .persistence import ConnectorStateStore, EvidenceRecord, EvidenceStore
from .registry import ConnectorRegistry, Registration


class RehydrationItem(Model):
    organization_id: str = Field(alias="organizationId")
    connector_id: str = Field(alias="connectorId")
    version: str
    status: str
    code: str


class RehydrationReport(Model):
    loaded: int = 0
    skipped: int = 0
    failed: int = 0
    items: tuple[RehydrationItem, ...] = ()


class ConnectorPackagePinService:
    """Verify and pin a signed package digest to trusted connector metadata."""

    def __init__(self, loader: ConnectorPackageLoader, evidence_store: EvidenceStore) -> None:
        self.loader = loader
        self.evidence_store = evidence_store

    def pin(self, registration: Registration, digest: str) -> None:
        if registration.status != "trusted":
            raise ValueError("only trusted connector registrations can pin executable packages")
        loaded = self.loader.load(digest)
        if loaded.manifest.connector != registration.manifest:
            raise PackageVerificationError(
                "PACKAGE_TRUST_MISMATCH",
                "Signed package metadata does not match the trusted connector registration",
            )
        self.evidence_store.append_evidence(
            EvidenceRecord(
                evidenceId=str(uuid4()),
                organizationId=registration.organization_id,
                kind="validation",
                phase="validation",
                connectorId=registration.manifest.connector_id,
                payload={
                    "type": "package_verification",
                    "digest": loaded.digest,
                    "version": registration.manifest.version,
                    "signerRef": loaded.signer_ref,
                    "verified": True,
                },
            )
        )


RuntimeConnectorBinder = Callable[[ConnectorContract], ConnectorContract]


class ConnectorRuntimeRehydrator:
    """Rebuild runtime registry from trusted state and pinned signed packages."""

    def __init__(
        self,
        *,
        state_store: ConnectorStateStore,
        evidence_store: EvidenceStore,
        registry: ConnectorRegistry,
        loader: ConnectorPackageLoader,
        runtime_binder: RuntimeConnectorBinder | None = None,
    ) -> None:
        self.state_store = state_store
        self.evidence_store = evidence_store
        self.registry = registry
        self.loader = loader
        self.runtime_binder = runtime_binder

    def _pin_for(self, organization_id: str, connector_id: str, version: str):
        evidence = self.evidence_store.list_evidence(organization_id, kind="validation")
        matches = [
            item
            for item in evidence
            if item.connector_id == connector_id
            and item.payload.get("type") == "package_verification"
            and item.payload.get("verified") is True
            and item.payload.get("version") == version
            and isinstance(item.payload.get("digest"), str)
        ]
        if not matches:
            return None
        matches.sort(key=lambda item: (item.created_at, item.evidence_id))
        digests = {item.payload["digest"] for item in matches}
        if len(digests) != 1:
            raise PackageVerificationError(
                "PACKAGE_PIN_AMBIGUOUS",
                "Multiple signed package digests are pinned to the same connector version",
            )
        return matches[-1]

    def rehydrate(self) -> RehydrationReport:
        items: list[RehydrationItem] = []
        loaded_count = skipped_count = failed_count = 0
        for record in self.state_store.list_connectors():
            connector_id = record.manifest.connector_id
            version = record.manifest.version
            if record.status != "trusted":
                skipped_count += 1
                items.append(RehydrationItem(
                    organizationId=record.organization_id,
                    connectorId=connector_id,
                    version=version,
                    status="skipped",
                    code="CONNECTOR_NOT_TRUSTED",
                ))
                continue
            try:
                pin = self._pin_for(record.organization_id, connector_id, version)
                if pin is None:
                    raise PackageVerificationError("PACKAGE_PIN_MISSING", "Trusted connector has no verified package pin")
                loaded = self.loader.load(pin.payload["digest"])
                if loaded.manifest.connector != record.manifest:
                    raise PackageVerificationError(
                        "PACKAGE_TRUST_MISMATCH",
                        "Signed package metadata does not match persistent trusted metadata",
                    )
                connector = loaded.connector
                if self.runtime_binder is not None:
                    connector = self.runtime_binder(connector)
                if connector.manifest() != record.manifest:
                    raise PackageVerificationError(
                        "PACKAGE_RUNTIME_BINDING_MISMATCH",
                        "Runtime dependency binding changed connector metadata",
                    )
                self.registry.register(
                    Registration(
                        connector=connector,
                        status="trusted",
                        organization_id=record.organization_id,
                    )
                )
                loaded_count += 1
                code = "PACKAGE_REHYDRATED"
                status = "loaded"
            except ValueError:
                skipped_count += 1
                code = "CONNECTOR_ALREADY_LOADED"
                status = "skipped"
            except PackageVerificationError as exc:
                failed_count += 1
                code = exc.code
                status = "failed"
            except Exception:
                failed_count += 1
                code = "PACKAGE_REHYDRATION_FAILED"
                status = "failed"
            items.append(RehydrationItem(
                organizationId=record.organization_id,
                connectorId=connector_id,
                version=version,
                status=status,
                code=code,
            ))
            self.evidence_store.append_evidence(
                EvidenceRecord(
                    evidenceId=str(uuid4()),
                    organizationId=record.organization_id,
                    kind="validation",
                    phase="validation",
                    connectorId=connector_id,
                    payload={
                        "type": "package_rehydration",
                        "version": version,
                        "status": status,
                        "code": code,
                    },
                )
            )
        return RehydrationReport(
            loaded=loaded_count,
            skipped=skipped_count,
            failed=failed_count,
            items=tuple(items),
        )
