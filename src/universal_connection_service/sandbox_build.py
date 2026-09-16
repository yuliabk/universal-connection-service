from __future__ import annotations

import hashlib
import json
import zipfile
from io import BytesIO
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

import httpx

from .auto_connect import AutoConnectAdvanceCommand, AutoConnectOrchestrator, AutoConnectResponse
from .build_auto_connect import BuildAwareAutoConnectOrchestrator, VerifiedBuildCoordinator
from .build_pipeline import (
    BuildPipelineError,
    ConnectorBuildResult,
    Ed25519BuildSigner,
    FilesystemPackageWriter,
)
from .contracts import ConnectionRequest, DiscoveryCandidateRef, ExecutionContext
from .control_plane import ControlPlanePrincipal
from .mcp_adapter import MCPToolBinding
from .mcp_validation import MCPToolMapper
from .mcpb_sandbox import (
    DockerMCPBSandboxRunner,
    SandboxedMCPConnector,
    SandboxedMCPConnectorConfig,
    inspect_mcpb_archive,
)
from .packages import ConnectorPackageLoader, ConnectorPackageManifest, PackageArtifact, PACKAGE_MANIFEST_PATH
from .persistence import EvidenceRecord, EvidenceStore
from .registry import ConnectorRegistry, Registration


MAX_MCPB_BYTES = 64 * 1024 * 1024


class FilesystemMCPBArtifactStore:
    """Digest-addressed storage for already hash-verified MCPB build inputs."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _digest(value: str) -> str:
        normalized = value.lower()
        if len(normalized) != 64 or any(ch not in "0123456789abcdef" for ch in normalized):
            raise ValueError("artifact digest is invalid")
        return normalized

    def put(self, digest: str, data: bytes, suffix: str = "mcpb") -> Path:
        digest = self._digest(digest)
        if suffix != "mcpb":
            raise ValueError("unsupported MCPB artifact suffix")
        path = self.root / f"{digest}.mcpb"
        path.write_bytes(data)
        return path

    def get(self, digest: str, suffix: str = "mcpb") -> bytes:
        digest = self._digest(digest)
        if suffix != "mcpb":
            raise ValueError("unsupported MCPB artifact suffix")
        path = self.root / f"{digest}.mcpb"
        data = path.read_bytes()
        if len(data) > MAX_MCPB_BYTES or hashlib.sha256(data).hexdigest() != digest:
            raise ValueError("stored MCPB artifact failed integrity verification")
        return data


class SandboxMCPPackageAcquirer:
    def __init__(self, store: FilesystemMCPBArtifactStore, *, client_factory=None, timeout_seconds: float = 20.0) -> None:
        self.store = store
        self.client_factory = client_factory
        self.timeout_seconds = timeout_seconds

    def _client(self) -> httpx.Client:
        if self.client_factory is not None:
            return self.client_factory()
        return httpx.Client(timeout=self.timeout_seconds, follow_redirects=False, trust_env=False)

    def acquire(self, candidate: DiscoveryCandidateRef) -> str:
        if (candidate.package_registry or "").lower() != "mcpb":
            raise BuildPipelineError(
                "MCP_PACKAGE_REGISTRY_SANDBOX_REQUIRED",
                "Package registry requires a dedicated resolver and sandbox",
            )
        identifier = candidate.package_identifier
        expected = candidate.package_sha256
        if not identifier or not expected:
            raise BuildPipelineError(
                "MCP_PACKAGE_INTEGRITY_REQUIRED",
                "MCPB sandbox requires a direct HTTPS URL and SHA-256 pin",
            )
        parsed = urlsplit(identifier)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise BuildPipelineError("MCP_PACKAGE_URL_INVALID", "MCPB package URL is not an allowed HTTPS URL")
        try:
            with self._client() as client:
                response = client.get(identifier, headers={"Accept": "application/octet-stream"})
            if response.status_code != 200:
                raise BuildPipelineError(
                    "MCP_PACKAGE_UNAVAILABLE",
                    "MCPB package could not be downloaded",
                    retryable=response.status_code >= 500,
                )
            data = response.content
        except BuildPipelineError:
            raise
        except Exception:
            raise BuildPipelineError("MCP_PACKAGE_UNAVAILABLE", "MCPB package could not be downloaded", retryable=True) from None
        if len(data) > MAX_MCPB_BYTES:
            raise BuildPipelineError("MCP_PACKAGE_TOO_LARGE", "MCPB package exceeds sandbox size limit")
        actual = hashlib.sha256(data).hexdigest()
        if actual != expected:
            raise BuildPipelineError("MCP_PACKAGE_DIGEST_MISMATCH", "MCPB package does not match registry SHA-256 pin")
        inspect_mcpb_archive(data)
        self.store.put(actual, data)
        return actual


class GeneratedSandboxMCPPackageBuilder:
    def __init__(self, writer: FilesystemPackageWriter, signer: Ed25519BuildSigner) -> None:
        self.writer = writer
        self.signer = signer

    @staticmethod
    def _archive(connector: SandboxedMCPConnector) -> bytes:
        config_json = json.dumps(
            connector.config.model_dump(by_alias=True, mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        source = (
            "from universal_connection_service.mcpb_sandbox import SandboxedMCPConnector, SandboxedMCPConnectorConfig\n"
            f"CONFIG = {config_json!r}\n"
            "def build():\n"
            "    return SandboxedMCPConnector(SandboxedMCPConnectorConfig.model_validate_json(CONFIG))\n"
        )
        package_manifest = ConnectorPackageManifest(connector=connector.manifest(), entrypoint="connector:build")
        buffer = BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(PACKAGE_MANIFEST_PATH, package_manifest.model_dump_json(by_alias=True))
            archive.writestr("connector.py", source)
        return buffer.getvalue()

    def build(self, connector: SandboxedMCPConnector) -> PackageArtifact:
        archive = self._archive(connector)
        artifact = PackageArtifact(
            digest=hashlib.sha256(archive).hexdigest(),
            archive=archive,
            signature=self.signer.sign(archive),
        )
        self.writer.put(artifact)
        return artifact


class SandboxAwareBuildCoordinator:
    """Add governed MCPB sandbox validation while preserving UCS-13 OpenAPI builds."""

    def __init__(
        self,
        *,
        fallback: VerifiedBuildCoordinator,
        runner: DockerMCPBSandboxRunner,
        acquirer: SandboxMCPPackageAcquirer,
        package_builder: GeneratedSandboxMCPPackageBuilder | None,
        package_loader: ConnectorPackageLoader | None,
        registry: ConnectorRegistry,
        evidence_store: EvidenceStore | None,
        mapper: MCPToolMapper | None = None,
    ) -> None:
        self.fallback = fallback
        self.runner = runner
        self.acquirer = acquirer
        self.package_builder = package_builder
        self.package_loader = package_loader
        self.registry = registry
        self.evidence_store = evidence_store
        self.mapper = mapper or MCPToolMapper()
        self.pipeline = fallback.pipeline

    @staticmethod
    def _connector_id(candidate: DiscoveryCandidateRef, request: ConnectionRequest, tool: str) -> str:
        material = "\x1f".join((candidate.candidate_id, request.capability, tool, candidate.version)).encode("utf-8")
        return "mcpb-sandboxed-" + hashlib.sha256(material).hexdigest()[:24]

    def _evidence(
        self,
        request: ConnectionRequest,
        candidate: DiscoveryCandidateRef,
        *,
        digest: str | None,
        code: str,
        passed: bool,
        connector_id: str | None = None,
        selected_tool: str | None = None,
        tool_count: int = 0,
        package_digest: str | None = None,
    ) -> None:
        if self.evidence_store is None:
            return
        self.evidence_store.append_evidence(
            EvidenceRecord(
                evidenceId=str(uuid4()),
                organizationId=request.actor.organization_id,
                kind="validation",
                phase="validation",
                requestId=request.request_id,
                connectorId=connector_id,
                payload={
                    "type": "mcp_package_sandbox_validation",
                    "candidateId": candidate.candidate_id,
                    "sourceDigest": digest,
                    "passed": passed,
                    "code": code,
                    "selectedTool": selected_tool,
                    "toolCount": tool_count,
                    "packageDigest": package_digest,
                },
            )
        )

    async def _build_mcpb(
        self,
        candidate: DiscoveryCandidateRef,
        request: ConnectionRequest,
        *,
        selected_tool: str | None,
        deadline_ms: int,
    ) -> ConnectorBuildResult:
        digest: str | None = None
        try:
            digest = self.acquirer.acquire(candidate)
            tools = await self.runner.inspect_tools(digest, deadline_ms=deadline_ms)
            matches, chosen, mode, requires_selection = self.mapper.map(request, tools, selected_tool=selected_tool)
            if chosen is None or requires_selection:
                self._evidence(
                    request,
                    candidate,
                    digest=digest,
                    code="MCP_TOOL_SELECTION_REQUIRED",
                    passed=False,
                    tool_count=len(tools),
                )
                return ConnectorBuildResult(
                    passed=False,
                    code="MCP_TOOL_SELECTION_REQUIRED",
                    candidateId=candidate.candidate_id,
                    lifecycle="sandboxed",
                )

            connector_id = self._connector_id(candidate, request, chosen)
            config = SandboxedMCPConnectorConfig(
                connectorId=connector_id,
                serviceId=request.service.id or request.service.name.lower().replace(" ", "-"),
                name=candidate.name,
                version=candidate.version,
                bundleDigest=digest,
                bindings=(MCPToolBinding(capability=request.capability, tool=chosen),),
            )
            connector = SandboxedMCPConnector(config, runner=self.runner)
            registration = self.registry.exact(request.actor.organization_id, connector_id, candidate.version)
            if registration is None:
                registration = Registration(
                    connector=connector,
                    status="sandboxed",
                    organization_id=request.actor.organization_id,
                )
                self.registry.register(registration)
            elif registration.manifest != connector.manifest():
                raise BuildPipelineError("MCPB_BUILD_STATE_INVALID", "Existing MCPB connector metadata does not match sandbox result")

            healthy = await connector.health_check(
                ExecutionContext(
                    requestId=request.request_id,
                    userId=request.actor.user_id,
                    organizationId=request.actor.organization_id,
                    deadlineMs=deadline_ms,
                )
            )
            if not healthy:
                self._evidence(
                    request,
                    candidate,
                    digest=digest,
                    code="MCPB_SANDBOX_HEALTH_FAILED",
                    passed=False,
                    connector_id=connector_id,
                    selected_tool=chosen,
                    tool_count=len(tools),
                )
                return ConnectorBuildResult(
                    passed=False,
                    code="MCPB_SANDBOX_HEALTH_FAILED",
                    candidateId=candidate.candidate_id,
                    connectorId=connector_id,
                    connectorVersion=candidate.version,
                    lifecycle=registration.status,
                    retryable=True,
                )
            if registration.status == "sandboxed":
                registration.set_status("validated")
            elif registration.status not in {"validated", "awaiting_approval", "trusted"}:
                raise BuildPipelineError("MCPB_BUILD_STATE_INVALID", "Existing MCPB connector is not in a valid sandbox lifecycle state")

            if self.package_builder is None:
                self._evidence(
                    request,
                    candidate,
                    digest=digest,
                    code="PACKAGE_SIGNER_REQUIRED",
                    passed=False,
                    connector_id=connector_id,
                    selected_tool=chosen,
                    tool_count=len(tools),
                )
                return ConnectorBuildResult(
                    passed=False,
                    code="PACKAGE_SIGNER_REQUIRED",
                    candidateId=candidate.candidate_id,
                    connectorId=connector_id,
                    connectorVersion=candidate.version,
                    lifecycle=registration.status,
                )
            artifact = self.package_builder.build(connector)
            if self.package_loader is None:
                return ConnectorBuildResult(
                    passed=False,
                    code="PACKAGE_VERIFIER_REQUIRED",
                    candidateId=candidate.candidate_id,
                    connectorId=connector_id,
                    connectorVersion=candidate.version,
                    packageDigest=artifact.digest,
                    lifecycle=registration.status,
                )
            loaded = self.package_loader.load(artifact.digest)
            if loaded.manifest.connector != registration.manifest:
                raise BuildPipelineError("PACKAGE_TRUST_MISMATCH", "Generated sandbox connector package does not match validated metadata")

            if self.evidence_store is not None:
                self.evidence_store.append_evidence(
                    EvidenceRecord(
                        evidenceId=str(uuid4()),
                        organizationId=request.actor.organization_id,
                        kind="validation",
                        phase="validation",
                        requestId=request.request_id,
                        connectorId=connector_id,
                        payload={
                            "type": "generated_package_verification",
                            "candidateId": candidate.candidate_id,
                            "digest": artifact.digest,
                            "version": candidate.version,
                            "signerRef": loaded.signer_ref,
                            "verified": True,
                        },
                    )
                )
            self._evidence(
                request,
                candidate,
                digest=digest,
                code="MCP_PACKAGE_SANDBOX_VALIDATED",
                passed=True,
                connector_id=connector_id,
                selected_tool=chosen,
                tool_count=len(tools),
                package_digest=artifact.digest,
            )
            return ConnectorBuildResult(
                passed=True,
                code="MCP_PACKAGE_SANDBOX_VALIDATED",
                candidateId=candidate.candidate_id,
                connectorId=connector_id,
                connectorVersion=candidate.version,
                packageDigest=artifact.digest,
                lifecycle="validated",
            )
        except BuildPipelineError as exc:
            self._evidence(request, candidate, digest=digest, code=exc.code, passed=False)
            return ConnectorBuildResult(
                passed=False,
                code=exc.code,
                candidateId=candidate.candidate_id,
                retryable=exc.retryable,
            )
        except Exception as exc:
            code = getattr(exc, "code", "MCPB_SANDBOX_VALIDATION_FAILED")
            retryable = bool(getattr(exc, "retryable", False))
            self._evidence(request, candidate, digest=digest, code=code, passed=False)
            return ConnectorBuildResult(
                passed=False,
                code=code,
                candidateId=candidate.candidate_id,
                retryable=retryable,
            )

    async def build_async(
        self,
        candidate: DiscoveryCandidateRef,
        request: ConnectionRequest,
        *,
        selected_tool: str | None = None,
        deadline_ms: int = 15000,
    ) -> ConnectorBuildResult:
        if candidate.strategy == "mcp" and (candidate.package_registry or "").lower() == "mcpb":
            return await self._build_mcpb(
                candidate,
                request,
                selected_tool=selected_tool,
                deadline_ms=deadline_ms,
            )
        return self.fallback.build(candidate, request)

    def build(self, candidate: DiscoveryCandidateRef, request: ConnectionRequest) -> ConnectorBuildResult:
        return self.fallback.build(candidate, request)

    def pin_after_trust(self, organization_id: str, connector_id: str, version: str) -> None:
        self.fallback.pin_after_trust(organization_id, connector_id, version)


class SandboxBuildAwareAutoConnectOrchestrator(BuildAwareAutoConnectOrchestrator):
    def __init__(self, *, build_coordinator: SandboxAwareBuildCoordinator, **kwargs) -> None:
        super().__init__(build_coordinator=build_coordinator, **kwargs)
        self.build_coordinator = build_coordinator

    async def _drive(self, principal: ControlPlanePrincipal, record, command: AutoConnectAdvanceCommand) -> AutoConnectResponse:
        response = await AutoConnectOrchestrator._drive(self, principal, record, command)
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

        build = await self.build_coordinator.build_async(
            candidate,
            command.request,
            selected_tool=command.selected_tool or record.selected_tool,
            deadline_ms=command.deadline_ms,
        )
        record.last_code = build.code
        if not build.passed:
            if build.code == "MCP_TOOL_SELECTION_REQUIRED":
                record.stage = "awaiting_tool_selection"
            return AutoConnectResponse(workflow=self._view(record), plan=plan, candidates=plan.discovery_candidates)

        record.selected_tool = command.selected_tool or record.selected_tool
        record.connector_id = build.connector_id
        record.connector_version = build.connector_version
        record.promotion_id = record.promotion_id or f"auto-connect:{record.workflow_id}"
        record.stage = "awaiting_promotion_approval"
        record.last_code = "PROMOTION_APPROVAL_REQUIRED"
        return AutoConnectResponse(workflow=self._view(record), plan=plan)
