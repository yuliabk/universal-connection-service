from __future__ import annotations

import base64
import hashlib
import json
import zipfile
from io import BytesIO
from pathlib import Path
from typing import Any, Protocol, runtime_checkable
from urllib.parse import urlsplit
from uuid import uuid4

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import Field, SecretStr, field_validator, model_validator

from .contracts import AuthRequirement, ConnectionRequest, DiscoveryCandidateRef, Model
from .credentials import CredentialResolver
from .openapi_adapter import OpenAPIConnectorAdapter, compile_openapi_connector
from .openapi_validation import OpenAPIValidationService
from .packages import ConnectorPackageManifest, PackageArtifact, PackageSignature, PACKAGE_MANIFEST_PATH
from .persistence import EvidenceRecord, EvidenceStore
from .registry import ConnectorRegistry, Registration

MAX_OPENAPI_BYTES = 2 * 1024 * 1024
MAX_MCP_PACKAGE_BYTES = 64 * 1024 * 1024


class BuildPipelineError(RuntimeError):
    def __init__(self, code: str, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.code = code
        self.safe_message = message
        self.retryable = retryable


class OpenAPIBuildDescriptor(Model):
    service_id: str = Field(alias="serviceId", min_length=1)
    service_name: str = Field(alias="serviceName", min_length=1)
    version: str = Field(min_length=1)
    schema_url: str = Field(alias="schemaUrl", min_length=1)
    schema_sha256: str = Field(alias="schemaSha256", min_length=64, max_length=64)
    base_url: str = Field(alias="baseUrl", min_length=1)
    sandbox_url: str | None = Field(alias="sandboxUrl", default=None)
    auth_requirement: AuthRequirement = Field(alias="authRequirement", default_factory=AuthRequirement)

    @field_validator("schema_sha256")
    @classmethod
    def validate_digest(cls, value: str) -> str:
        normalized = value.lower()
        if len(normalized) != 64 or any(ch not in "0123456789abcdef" for ch in normalized):
            raise ValueError("schemaSha256 must be lowercase SHA-256 hex")
        return normalized

    @field_validator("schema_url", "base_url")
    @classmethod
    def validate_remote_url(cls, value: str) -> str:
        parsed = urlsplit(value)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("remote build URLs must use HTTPS")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("build URLs must not contain credentials, query parameters or fragments")
        return value.rstrip("/")

    @model_validator(mode="after")
    def schema_host_matches_base_host(self):
        schema_host = (urlsplit(self.schema_url).hostname or "").lower().rstrip(".")
        base_host = (urlsplit(self.base_url).hostname or "").lower().rstrip(".")
        if schema_host != base_host:
            raise ValueError("schemaUrl and baseUrl must use the same host in UCS-13")
        return self


@runtime_checkable
class OpenAPIBuildDescriptorProvider(Protocol):
    def descriptor_for(self, candidate_id: str) -> OpenAPIBuildDescriptor | None: ...


class OpenAPICatalogProvider:
    """Operator-configured OpenAPI discovery + build descriptor source."""

    def __init__(self, descriptors: tuple[OpenAPIBuildDescriptor, ...]) -> None:
        self._descriptors: dict[str, OpenAPIBuildDescriptor] = {}
        for descriptor in descriptors:
            candidate_id = self._candidate_id(descriptor)
            if candidate_id in self._descriptors:
                raise ValueError("duplicate OpenAPI catalog candidate")
            self._descriptors[candidate_id] = descriptor

    @staticmethod
    def _candidate_id(descriptor: OpenAPIBuildDescriptor) -> str:
        material = "\x1f".join((descriptor.service_id, descriptor.version, descriptor.schema_sha256, descriptor.base_url)).encode()
        return "openapi-catalog:" + hashlib.sha256(material).hexdigest()[:24]

    @classmethod
    def from_json(cls, value: str) -> "OpenAPICatalogProvider":
        try:
            payload = json.loads(value)
        except json.JSONDecodeError:
            raise ValueError("OpenAPI catalog JSON is invalid") from None
        if not isinstance(payload, list) or not payload:
            raise ValueError("OpenAPI catalog must be a non-empty array")
        return cls(tuple(OpenAPIBuildDescriptor.model_validate(item) for item in payload))

    @staticmethod
    def _normalized(value: str) -> str:
        return "".join(ch.lower() for ch in value if ch.isalnum())

    def discover(self, query) -> tuple[DiscoveryCandidateRef, ...]:
        wanted_id = self._normalized(query.service_id)
        wanted_name = self._normalized(query.service_name)
        results: list[DiscoveryCandidateRef] = []
        for candidate_id, descriptor in self._descriptors.items():
            descriptor_id = self._normalized(descriptor.service_id)
            descriptor_name = self._normalized(descriptor.service_name)
            if descriptor_id == wanted_id or descriptor_name == wanted_name:
                confidence = 100
            elif wanted_name and wanted_name in descriptor_name:
                confidence = 85
            elif wanted_id and wanted_id in descriptor_id:
                confidence = 85
            else:
                continue
            results.append(
                DiscoveryCandidateRef(
                    candidateId=candidate_id,
                    source="openapi",
                    name=descriptor.service_name,
                    version=descriptor.version,
                    strategy="api",
                    endpoint=descriptor.base_url,
                    authRequirement=descriptor.auth_requirement,
                    confidence=confidence,
                    actionable=False,
                    requiresBuild=True,
                )
            )
        results.sort(key=lambda item: (-item.confidence, item.name, item.candidate_id))
        return tuple(results)

    def descriptor_for(self, candidate_id: str) -> OpenAPIBuildDescriptor | None:
        return self._descriptors.get(candidate_id)


class PinnedOpenAPIDocumentFetcher:
    def __init__(self, *, client_factory=None, timeout_seconds: float = 10.0) -> None:
        self.client_factory = client_factory
        self.timeout_seconds = timeout_seconds

    def _client(self) -> httpx.Client:
        if self.client_factory is not None:
            return self.client_factory()
        return httpx.Client(timeout=self.timeout_seconds, follow_redirects=False, trust_env=False)

    def fetch(self, descriptor: OpenAPIBuildDescriptor) -> dict[str, Any]:
        try:
            with self._client() as client:
                response = client.get(descriptor.schema_url, headers={"Accept": "application/json"})
            if response.status_code != 200:
                raise BuildPipelineError("OPENAPI_SCHEMA_UNAVAILABLE", "Pinned OpenAPI schema could not be fetched", retryable=response.status_code >= 500)
            raw = response.content
        except BuildPipelineError:
            raise
        except Exception:
            raise BuildPipelineError("OPENAPI_SCHEMA_UNAVAILABLE", "Pinned OpenAPI schema could not be fetched", retryable=True) from None
        if len(raw) > MAX_OPENAPI_BYTES:
            raise BuildPipelineError("OPENAPI_SCHEMA_TOO_LARGE", "OpenAPI schema exceeds build size limit")
        if hashlib.sha256(raw).hexdigest() != descriptor.schema_sha256:
            raise BuildPipelineError("OPENAPI_SCHEMA_DIGEST_MISMATCH", "OpenAPI schema digest does not match catalog pin")
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise BuildPipelineError("OPENAPI_SCHEMA_INVALID", "Pinned OpenAPI schema is not valid JSON") from None
        if not isinstance(payload, dict):
            raise BuildPipelineError("OPENAPI_SCHEMA_INVALID", "Pinned OpenAPI schema must be a JSON object")
        return payload


class Ed25519BuildSigner:
    def __init__(self, *, signer_ref: str, private_key: SecretStr | str | bytes) -> None:
        self.signer_ref = signer_ref
        raw_value = private_key.get_secret_value() if isinstance(private_key, SecretStr) else private_key
        try:
            raw = base64.b64decode(raw_value, validate=True) if isinstance(raw_value, str) else raw_value
            self.private_key = Ed25519PrivateKey.from_private_bytes(raw)
        except Exception:
            raise ValueError("invalid Ed25519 build signing key") from None

    def sign(self, archive: bytes) -> PackageSignature:
        return PackageSignature(
            scheme="ed25519",
            signerRef=self.signer_ref,
            signature=base64.b64encode(self.private_key.sign(archive)).decode("ascii"),
        )


class FilesystemPackageWriter:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def put(self, artifact: PackageArtifact) -> None:
        digest = artifact.digest.lower()
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            raise BuildPipelineError("PACKAGE_DIGEST_INVALID", "Generated package digest is invalid")
        (self.root / f"{digest}.zip").write_bytes(artifact.archive)
        (self.root / f"{digest}.sig.json").write_text(
            artifact.signature.model_dump_json(by_alias=True, exclude_none=True), encoding="utf-8"
        )


class GeneratedOpenAPIPackageBuilder:
    def __init__(self, writer: FilesystemPackageWriter, signer: Ed25519BuildSigner) -> None:
        self.writer = writer
        self.signer = signer

    @staticmethod
    def _archive(connector: OpenAPIConnectorAdapter) -> bytes:
        config_json = json.dumps(connector.config.model_dump(by_alias=True, mode="json"), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        source = (
            "from universal_connection_service.openapi_adapter import OpenAPIConnectorAdapter, OpenAPIConnectorConfig\n"
            f"CONFIG = {config_json!r}\n"
            "def build():\n"
            "    return OpenAPIConnectorAdapter(OpenAPIConnectorConfig.model_validate_json(CONFIG))\n"
        )
        package_manifest = ConnectorPackageManifest(connector=connector.manifest(), entrypoint="connector:build")
        buffer = BytesIO()
        with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(PACKAGE_MANIFEST_PATH, package_manifest.model_dump_json(by_alias=True))
            zf.writestr("connector.py", source)
        return buffer.getvalue()

    def build(self, connector: OpenAPIConnectorAdapter) -> PackageArtifact:
        archive = self._archive(connector)
        artifact = PackageArtifact(
            digest=hashlib.sha256(archive).hexdigest(),
            archive=archive,
            signature=self.signer.sign(archive),
        )
        self.writer.put(artifact)
        return artifact


class FilesystemBuildArtifactStore:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def put(self, digest: str, data: bytes, suffix: str) -> Path:
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest.lower()):
            raise BuildPipelineError("BUILD_ARTIFACT_DIGEST_INVALID", "Build artifact digest is invalid")
        safe_suffix = "".join(ch for ch in suffix.lower() if ch.isalnum())[:12] or "bin"
        path = self.root / f"{digest.lower()}.{safe_suffix}"
        path.write_bytes(data)
        return path


class MCPPackageAcquirer:
    """Acquire MCPB packages by pinned digest; never execute or extract them."""

    def __init__(self, artifact_store: FilesystemBuildArtifactStore | None = None, *, client_factory=None) -> None:
        self.artifact_store = artifact_store
        self.client_factory = client_factory

    def _client(self) -> httpx.Client:
        if self.client_factory is not None:
            return self.client_factory()
        return httpx.Client(timeout=20.0, follow_redirects=False, trust_env=False)

    def acquire(self, candidate: DiscoveryCandidateRef) -> str:
        registry = (candidate.package_registry or "").lower()
        if registry != "mcpb":
            raise BuildPipelineError("MCP_PACKAGE_REGISTRY_SANDBOX_REQUIRED", "Package registry requires a dedicated resolver and sandbox before execution")
        identifier, digest = candidate.package_identifier, candidate.package_sha256
        if not identifier or not digest:
            raise BuildPipelineError("MCP_PACKAGE_INTEGRITY_REQUIRED", "MCPB build requires a direct package URL and SHA-256 pin")
        parsed = urlsplit(identifier)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise BuildPipelineError("MCP_PACKAGE_URL_INVALID", "MCPB package URL is not an allowed HTTPS URL")
        try:
            with self._client() as client:
                response = client.get(identifier)
            if response.status_code != 200:
                raise BuildPipelineError("MCP_PACKAGE_UNAVAILABLE", "MCPB package could not be downloaded", retryable=response.status_code >= 500)
            data = response.content
        except BuildPipelineError:
            raise
        except Exception:
            raise BuildPipelineError("MCP_PACKAGE_UNAVAILABLE", "MCPB package could not be downloaded", retryable=True) from None
        if len(data) > MAX_MCP_PACKAGE_BYTES:
            raise BuildPipelineError("MCP_PACKAGE_TOO_LARGE", "MCPB package exceeds acquisition size limit")
        actual = hashlib.sha256(data).hexdigest()
        if actual != digest:
            raise BuildPipelineError("MCP_PACKAGE_DIGEST_MISMATCH", "MCPB package does not match registry SHA-256 pin")
        if self.artifact_store is not None:
            self.artifact_store.put(actual, data, "mcpb")
        return actual


class ConnectorBuildResult(Model):
    passed: bool
    code: str
    candidate_id: str = Field(alias="candidateId")
    connector_id: str | None = Field(alias="connectorId", default=None)
    connector_version: str | None = Field(alias="connectorVersion", default=None)
    package_digest: str | None = Field(alias="packageDigest", default=None)
    lifecycle: str | None = None
    retryable: bool = False


class ConnectorBuildPipeline:
    def __init__(self, *, registry: ConnectorRegistry, evidence_store: EvidenceStore | None, openapi_descriptors: tuple[OpenAPIBuildDescriptorProvider, ...] = (), openapi_fetcher: PinnedOpenAPIDocumentFetcher | None = None, openapi_validator: OpenAPIValidationService | None = None, package_builder: GeneratedOpenAPIPackageBuilder | None = None, mcp_package_acquirer: MCPPackageAcquirer | None = None, credential_resolver: CredentialResolver | None = None) -> None:
        self.registry = registry
        self.evidence_store = evidence_store
        self.openapi_descriptors = openapi_descriptors
        self.openapi_fetcher = openapi_fetcher or PinnedOpenAPIDocumentFetcher()
        self.openapi_validator = openapi_validator or OpenAPIValidationService(evidence_store=evidence_store)
        self.package_builder = package_builder
        self.mcp_package_acquirer = mcp_package_acquirer or MCPPackageAcquirer()
        self.credential_resolver = credential_resolver

    @staticmethod
    def _connector_id(candidate: DiscoveryCandidateRef, request: ConnectionRequest) -> str:
        material = "\x1f".join((candidate.candidate_id, request.capability, candidate.version)).encode()
        return "openapi-built-" + hashlib.sha256(material).hexdigest()[:24]

    def _evidence(self, request: ConnectionRequest, result: ConnectorBuildResult, *, source_digest: str | None = None) -> None:
        if self.evidence_store is None:
            return
        payload: dict[str, Any] = {
            "type": "connector_build",
            "candidateId": result.candidate_id,
            "passed": result.passed,
            "code": result.code,
            "connectorVersion": result.connector_version,
            "packageDigest": result.package_digest,
            "lifecycle": result.lifecycle,
            "retryable": result.retryable,
        }
        if source_digest is not None:
            payload["sourceDigest"] = source_digest
        self.evidence_store.append_evidence(
            EvidenceRecord(
                evidenceId=str(uuid4()), organizationId=request.actor.organization_id, kind="validation", phase="validation",
                requestId=request.request_id, connectorId=result.connector_id, payload=payload,
            )
        )

    def _descriptor(self, candidate_id: str) -> OpenAPIBuildDescriptor | None:
        for provider in self.openapi_descriptors:
            descriptor = provider.descriptor_for(candidate_id)
            if descriptor is not None:
                return descriptor
        return None

    def _build_openapi(self, candidate: DiscoveryCandidateRef, request: ConnectionRequest) -> ConnectorBuildResult:
        descriptor = self._descriptor(candidate.candidate_id)
        if descriptor is None:
            raise BuildPipelineError("OPENAPI_BUILD_DESCRIPTOR_MISSING", "OpenAPI candidate has no server-side build descriptor")
        if descriptor.service_id != (request.service.id or request.service.name.lower().replace(" ", "-")):
            raise BuildPipelineError("OPENAPI_BUILD_SCOPE_MISMATCH", "OpenAPI build descriptor does not match requested service")
        schema = self.openapi_fetcher.fetch(descriptor)
        connector_id = self._connector_id(candidate, request)
        compiled = compile_openapi_connector(schema, connector_id=connector_id, service_id=descriptor.service_id, name=descriptor.service_name, version=descriptor.version, base_url=descriptor.base_url, credential_resolver=self.credential_resolver)
        if request.capability not in compiled.connector.manifest().capabilities:
            raise BuildPipelineError("OPENAPI_CAPABILITY_NOT_FOUND", "Pinned OpenAPI document does not expose the requested capability")
        registration = Registration(connector=compiled.connector, status="generated", organization_id=request.actor.organization_id)
        try:
            self.registry.register(registration)
        except ValueError:
            existing = self.registry.exact(request.actor.organization_id, connector_id, descriptor.version)
            if existing is None:
                raise
            registration = existing
        if descriptor.sandbox_url is None:
            result = ConnectorBuildResult(passed=False, code="OPENAPI_SANDBOX_REQUIRED", candidateId=candidate.candidate_id, connectorId=connector_id, connectorVersion=descriptor.version, lifecycle=registration.status)
            self._evidence(request, result, source_digest=descriptor.schema_sha256)
            return result
        if registration.status in {"generated", "sandboxed"}:
            report = self.openapi_validator.validate_registration(registration, schema=schema, sandbox_url=descriptor.sandbox_url)
            if not report.passed:
                result = ConnectorBuildResult(passed=False, code="OPENAPI_VALIDATION_FAILED", candidateId=candidate.candidate_id, connectorId=connector_id, connectorVersion=descriptor.version, lifecycle=registration.status)
                self._evidence(request, result, source_digest=descriptor.schema_sha256)
                return result
        elif registration.status != "validated":
            raise BuildPipelineError("OPENAPI_BUILD_STATE_INVALID", "Existing generated connector is not buildable")
        if self.package_builder is None:
            result = ConnectorBuildResult(passed=False, code="PACKAGE_SIGNER_REQUIRED", candidateId=candidate.candidate_id, connectorId=connector_id, connectorVersion=descriptor.version, lifecycle=registration.status)
            self._evidence(request, result, source_digest=descriptor.schema_sha256)
            return result
        artifact = self.package_builder.build(compiled.connector)
        result = ConnectorBuildResult(passed=True, code="OPENAPI_CONNECTOR_BUILT", candidateId=candidate.candidate_id, connectorId=connector_id, connectorVersion=descriptor.version, packageDigest=artifact.digest, lifecycle="validated")
        self._evidence(request, result, source_digest=descriptor.schema_sha256)
        if self.evidence_store is not None:
            self.evidence_store.append_evidence(EvidenceRecord(evidenceId=str(uuid4()), organizationId=request.actor.organization_id, kind="validation", phase="validation", requestId=request.request_id, connectorId=connector_id, payload={"type": "generated_package", "candidateId": candidate.candidate_id, "digest": artifact.digest, "version": descriptor.version, "signerRef": artifact.signature.signer_ref, "verified": False}))
        return result

    def _acquire_mcp_package(self, candidate: DiscoveryCandidateRef, request: ConnectionRequest) -> ConnectorBuildResult:
        digest = self.mcp_package_acquirer.acquire(candidate)
        result = ConnectorBuildResult(passed=False, code="MCP_PACKAGE_SANDBOX_REQUIRED", candidateId=candidate.candidate_id, packageDigest=digest, lifecycle="sandboxed")
        self._evidence(request, result, source_digest=digest)
        return result

    def build(self, candidate: DiscoveryCandidateRef, request: ConnectionRequest) -> ConnectorBuildResult:
        try:
            if candidate.strategy == "api":
                return self._build_openapi(candidate, request)
            if candidate.strategy == "mcp" and candidate.package_identifier:
                return self._acquire_mcp_package(candidate, request)
            raise BuildPipelineError("BUILD_STRATEGY_UNSUPPORTED", "Candidate build strategy is not supported")
        except BuildPipelineError as exc:
            result = ConnectorBuildResult(passed=False, code=exc.code, candidateId=candidate.candidate_id, retryable=exc.retryable)
            self._evidence(request, result)
            return result
        except Exception:
            result = ConnectorBuildResult(passed=False, code="CONNECTOR_BUILD_FAILED", candidateId=candidate.candidate_id)
            self._evidence(request, result)
            return result
