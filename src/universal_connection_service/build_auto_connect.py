from __future__ import annotations

from .auto_connect import AutoConnectAdvanceCommand, AutoConnectOrchestrator, AutoConnectResponse
from .build_pipeline import ConnectorBuildPipeline, ConnectorBuildResult
from .control_plane import ControlPlanePrincipal
from .packages import ConnectorPackageLoader, PackageVerificationError
from .persistence import EvidenceRecord, EvidenceStore
from .rehydration import ConnectorPackagePinService
from uuid import uuid4


class VerifiedBuildCoordinator:
    """Verify generated signed packages before allowing the workflow to continue."""

    def __init__(
        self,
        *,
        pipeline: ConnectorBuildPipeline,
        package_loader: ConnectorPackageLoader | None,
        evidence_store: EvidenceStore | None,
    ) -> None:
        self.pipeline = pipeline
        self.package_loader = package_loader
        self.evidence_store = evidence_store

    def build(self, candidate, request) -> ConnectorBuildResult:
        result = self.pipeline.build(candidate, request)
        if not result.passed or result.package_digest is None:
            return result
        if self.package_loader is None:
            return ConnectorBuildResult(
                passed=False,
                code="PACKAGE_VERIFIER_REQUIRED",
                candidateId=candidate.candidate_id,
                connectorId=result.connector_id,
                connectorVersion=result.connector_version,
                packageDigest=result.package_digest,
                lifecycle=result.lifecycle,
            )
        try:
            loaded = self.package_loader.load(result.package_digest)
            registration = self.pipeline.registry.exact(
                request.actor.organization_id,
                result.connector_id or "",
                result.connector_version or "",
            )
            if registration is None or loaded.manifest.connector != registration.manifest:
                raise PackageVerificationError(
                    "PACKAGE_TRUST_MISMATCH",
                    "Generated package does not match built connector metadata",
                )
        except PackageVerificationError as exc:
            return ConnectorBuildResult(
                passed=False,
                code=exc.code,
                candidateId=candidate.candidate_id,
                connectorId=result.connector_id,
                connectorVersion=result.connector_version,
                packageDigest=result.package_digest,
                lifecycle=result.lifecycle,
            )
        if self.evidence_store is not None:
            self.evidence_store.append_evidence(
                EvidenceRecord(
                    evidenceId=str(uuid4()),
                    organizationId=request.actor.organization_id,
                    kind="validation",
                    phase="validation",
                    requestId=request.request_id,
                    connectorId=result.connector_id,
                    payload={
                        "type": "generated_package_verification",
                        "candidateId": candidate.candidate_id,
                        "digest": result.package_digest,
                        "version": result.connector_version,
                        "signerRef": loaded.signer_ref,
                        "verified": True,
                    },
                )
            )
        return result

    def pin_after_trust(self, organization_id: str, connector_id: str, version: str) -> None:
        if self.package_loader is None or self.evidence_store is None:
            return
        registration = self.pipeline.registry.exact(organization_id, connector_id, version)
        if registration is None or registration.status != "trusted":
            return
        evidence = self.evidence_store.list_evidence(organization_id, kind="validation")
        matches = [
            item
            for item in evidence
            if item.connector_id == connector_id
            and item.payload.get("type") == "generated_package_verification"
            and item.payload.get("verified") is True
            and item.payload.get("version") == version
            and isinstance(item.payload.get("digest"), str)
        ]
        if not matches:
            return
        matches.sort(key=lambda item: (item.created_at, item.evidence_id))
        digest = matches[-1].payload["digest"]
        existing_pins = [
            item for item in evidence
            if item.connector_id == connector_id
            and item.payload.get("type") == "package_verification"
            and item.payload.get("version") == version
            and item.payload.get("digest") == digest
            and item.payload.get("verified") is True
        ]
        if existing_pins:
            return
        ConnectorPackagePinService(self.package_loader, self.evidence_store).pin(registration, digest)


class BuildAwareAutoConnectOrchestrator(AutoConnectOrchestrator):
    def __init__(self, *, build_coordinator: VerifiedBuildCoordinator, **kwargs) -> None:
        super().__init__(**kwargs)
        self.build_coordinator = build_coordinator

    async def _drive(self, principal: ControlPlanePrincipal, record, command: AutoConnectAdvanceCommand) -> AutoConnectResponse:
        response = await super()._drive(principal, record, command)
        if record.stage != "awaiting_build" or record.selected_candidate_id is None:
            return response
        organization_id = command.request.actor.organization_id
        if not principal.allows("connectors:validate", organization_id):
            record.last_code = "CONTROL_PLANE_BUILD_FORBIDDEN"
            return response
        plan = response.plan or self.connection_service.compiler.compile(command.request, phase="plan")
        candidate = next(
            (item for item in plan.discovery_candidates if item.candidate_id == record.selected_candidate_id),
            None,
        )
        if candidate is None:
            record.stage = "awaiting_candidate_selection"
            record.selected_candidate_id = None
            record.last_code = "DISCOVERY_CANDIDATE_STALE"
            return AutoConnectResponse(workflow=self._view(record), plan=plan, candidates=plan.discovery_candidates)

        build = self.build_coordinator.build(candidate, command.request)
        record.last_code = build.code
        if not build.passed:
            return AutoConnectResponse(workflow=self._view(record), plan=plan, candidates=plan.discovery_candidates)

        record.connector_id = build.connector_id
        record.connector_version = build.connector_version
        record.promotion_id = record.promotion_id or f"auto-connect:{record.workflow_id}"
        record.stage = "awaiting_promotion_approval"
        record.last_code = "PROMOTION_APPROVAL_REQUIRED"
        return AutoConnectResponse(workflow=self._view(record), plan=plan)

    async def promote_and_advance(self, principal: ControlPlanePrincipal, workflow_id: str, command: AutoConnectAdvanceCommand) -> AutoConnectResponse:
        response = await super().promote_and_advance(principal, workflow_id, command)
        record = self.workflow_store.get_workflow(command.request.actor.organization_id, workflow_id)
        if record is not None and record.connector_id and record.connector_version:
            self.build_coordinator.pin_after_trust(
                record.organization_id,
                record.connector_id,
                record.connector_version,
            )
        return response
