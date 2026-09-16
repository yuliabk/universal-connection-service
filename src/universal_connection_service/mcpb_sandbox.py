from __future__ import annotations

import asyncio
import os
import stat
import subprocess
import tempfile
import zipfile
from contextlib import asynccontextmanager
from io import BytesIO
from pathlib import Path, PurePosixPath
from typing import Any, Literal, Protocol, runtime_checkable
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .contracts import AuthRequirement, ConnectionError, ConnectorManifest, ConnectorResult, ExecutionContext, Model
from .mcp_adapter import MCPConnectorAdapter, MCPConnectorConfig, MCPToolBinding
from .mcp_validation import MAX_INTROSPECTION_TOOLS, MAX_LIST_PAGES, MCPToolSnapshot, _snapshot_tool

try:
    from mcp import Client, StdioServerParameters
except ImportError:  # pragma: no cover
    Client = None  # type: ignore[assignment]
    StdioServerParameters = None  # type: ignore[assignment]


MAX_MCPB_MEMBERS = 4096
MAX_MCPB_MEMBER_BYTES = 64 * 1024 * 1024
MAX_MCPB_UNCOMPRESSED_BYTES = 256 * 1024 * 1024
MAX_MCPB_MANIFEST_BYTES = 256 * 1024


class MCPBSandboxError(RuntimeError):
    def __init__(self, code: str, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.code = code
        self.safe_message = message
        self.retryable = retryable


class MCPBServerConfig(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)
    type: Literal["python", "node", "binary", "uv"]
    entry_point: str = Field(alias="entry_point", min_length=1)
    mcp_config: dict[str, Any] | None = Field(alias="mcp_config", default=None)

    @field_validator("entry_point")
    @classmethod
    def safe_entrypoint(cls, value: str) -> str:
        _safe_relative_path(value)
        return value


class MCPBManifest(BaseModel):
    model_config = ConfigDict(extra="allow", populate_by_name=True)
    manifest_version: str = Field(alias="manifest_version", min_length=1)
    name: str = Field(min_length=1)
    version: str = Field(min_length=1)
    server: MCPBServerConfig


class DockerMCPBSandboxConfig(Model):
    docker_executable: str = Field(alias="dockerExecutable", default="docker", min_length=1)
    python_image: str = Field(alias="pythonImage", default="python:3.12-slim", min_length=1)
    node_image: str = Field(alias="nodeImage", default="node:22-bookworm-slim", min_length=1)
    memory_limit: str = Field(alias="memoryLimit", default="256m", min_length=2)
    cpu_limit: float = Field(alias="cpuLimit", default=1.0, gt=0, le=4)
    pids_limit: int = Field(alias="pidsLimit", default=64, ge=8, le=512)
    tmpfs_bytes: int = Field(alias="tmpfsBytes", default=64 * 1024 * 1024, ge=1024 * 1024, le=512 * 1024 * 1024)
    startup_timeout_seconds: float = Field(alias="startupTimeoutSeconds", default=5.0, gt=0, le=30)
    egress_network: str | None = Field(alias="egressNetwork", default=None)
    egress_proxy_host: str | None = Field(alias="egressProxyHost", default=None)


@runtime_checkable
class SandboxArtifactSource(Protocol):
    def get(self, digest: str, suffix: str) -> bytes: ...


@runtime_checkable
class SandboxProfileProvider(Protocol):
    def active_profile(self, organization_id: str, connector_id: str, version: str) -> Any: ...


@runtime_checkable
class SandboxMountResolver(Protocol):
    def resolve(self, organization_id: str, grant: Any) -> Any: ...


@runtime_checkable
class SandboxCredentialBroker(Protocol):
    async def sandbox_session(self, service_id: str, allowed_hosts: tuple[str, ...], ctx: ExecutionContext) -> Any: ...


def _safe_relative_path(value: str) -> PurePosixPath:
    if not value or "\x00" in value or "\\" in value:
        raise ValueError("MCPB path is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise ValueError("MCPB path escapes the bundle root")
    return path


def _member_is_symlink(info: zipfile.ZipInfo) -> bool:
    mode = (info.external_attr >> 16) & 0o170000
    return mode == stat.S_IFLNK


def inspect_mcpb_archive(data: bytes) -> MCPBManifest:
    try:
        with zipfile.ZipFile(BytesIO(data), "r") as archive:
            members = archive.infolist()
            if len(members) > MAX_MCPB_MEMBERS:
                raise MCPBSandboxError("MCPB_LAYOUT_INVALID", "MCPB contains too many files")
            total = 0
            names: set[str] = set()
            for member in members:
                try:
                    path = _safe_relative_path(member.filename)
                except ValueError:
                    raise MCPBSandboxError("MCPB_LAYOUT_INVALID", "MCPB contains an unsafe path") from None
                if str(path) in names:
                    raise MCPBSandboxError("MCPB_LAYOUT_INVALID", "MCPB contains duplicate paths")
                names.add(str(path))
                if _member_is_symlink(member):
                    raise MCPBSandboxError("MCPB_LAYOUT_INVALID", "MCPB symlinks are not allowed")
                if member.file_size > MAX_MCPB_MEMBER_BYTES:
                    raise MCPBSandboxError("MCPB_LAYOUT_INVALID", "MCPB member exceeds the size limit")
                total += member.file_size
                if total > MAX_MCPB_UNCOMPRESSED_BYTES:
                    raise MCPBSandboxError("MCPB_LAYOUT_INVALID", "MCPB uncompressed size exceeds the limit")
            try:
                manifest_raw = archive.read("manifest.json")
            except KeyError:
                raise MCPBSandboxError("MCPB_MANIFEST_INVALID", "MCPB manifest.json is missing") from None
            if len(manifest_raw) > MAX_MCPB_MANIFEST_BYTES:
                raise MCPBSandboxError("MCPB_MANIFEST_INVALID", "MCPB manifest exceeds the size limit")
            try:
                manifest = MCPBManifest.model_validate_json(manifest_raw)
            except Exception:
                raise MCPBSandboxError("MCPB_MANIFEST_INVALID", "MCPB manifest failed validation") from None
            if manifest.server.entry_point not in names:
                raise MCPBSandboxError("MCPB_ENTRYPOINT_INVALID", "MCPB server entry point is missing")
            return manifest
    except MCPBSandboxError:
        raise
    except zipfile.BadZipFile:
        raise MCPBSandboxError("MCPB_ARCHIVE_INVALID", "MCPB is not a valid ZIP archive") from None


def _extract_mcpb(data: bytes, root: Path) -> MCPBManifest:
    manifest = inspect_mcpb_archive(data)
    with zipfile.ZipFile(BytesIO(data), "r") as archive:
        for member in archive.infolist():
            path = _safe_relative_path(member.filename)
            target = root.joinpath(*path.parts)
            if member.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                target.chmod(0o755)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.parent.chmod(0o755)
            target.write_bytes(archive.read(member))
            target.chmod(0o644)
    root.chmod(0o755)
    return manifest


class DockerMCPBSandboxRunner:
    def __init__(
        self,
        artifact_source: SandboxArtifactSource,
        config: DockerMCPBSandboxConfig | None = None,
        *,
        profile_provider: SandboxProfileProvider | None = None,
        mount_resolver: SandboxMountResolver | None = None,
        credential_broker: SandboxCredentialBroker | None = None,
    ) -> None:
        self.artifact_source = artifact_source
        self.config = config or DockerMCPBSandboxConfig()
        self.profile_provider = profile_provider
        self.mount_resolver = mount_resolver
        self.credential_broker = credential_broker

    def available(self) -> bool:
        try:
            completed = subprocess.run(
                [self.config.docker_executable, "version", "--format", "{{.Server.Version}}"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=self.config.startup_timeout_seconds,
                check=False,
            )
            return completed.returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            return False

    def resolve_image(self, image: str) -> str:
        try:
            completed = subprocess.run(
                [self.config.docker_executable, "image", "inspect", image, "--format", "{{.Id}}"],
                capture_output=True,
                text=True,
                timeout=self.config.startup_timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise MCPBSandboxError("MCPB_SANDBOX_IMAGE_UNAVAILABLE", "Approved sandbox runtime image is unavailable", retryable=True) from None
        image_id = completed.stdout.strip().lower() if completed.returncode == 0 else ""
        if not image_id.startswith("sha256:") or len(image_id) != 71 or any(ch not in "0123456789abcdef" for ch in image_id[7:]):
            raise MCPBSandboxError("MCPB_SANDBOX_IMAGE_UNAVAILABLE", "Approved sandbox runtime image is unavailable", retryable=True)
        return image_id

    def _runtime(self, manifest: MCPBManifest) -> tuple[str, str, tuple[str, ...], tuple[str, ...]]:
        entry = "/bundle/" + str(_safe_relative_path(manifest.server.entry_point))
        if manifest.server.type == "python":
            return self.config.python_image, "python", (entry,), ("PYTHONPATH=/bundle/server/lib",)
        if manifest.server.type == "node":
            return self.config.node_image, "node", (entry,), ()
        if manifest.server.type == "uv":
            raise MCPBSandboxError("MCPB_UV_BUILD_REQUIRED", "UV MCPB packages require a separate dependency build sandbox before execution")
        raise MCPBSandboxError("MCPB_BINARY_POLICY_REQUIRED", "Binary MCPB execution requires an explicit platform/image policy")

    def _require_internal_network(self) -> str:
        network = self.config.egress_network
        if not network:
            raise MCPBSandboxError("SANDBOX_EGRESS_NETWORK_REQUIRED", "Approved internal sandbox egress network is not configured")
        try:
            completed = subprocess.run(
                [self.config.docker_executable, "network", "inspect", network, "--format", "{{.Internal}}"],
                capture_output=True,
                text=True,
                timeout=self.config.startup_timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise MCPBSandboxError("SANDBOX_EGRESS_NETWORK_INVALID", "Sandbox egress network could not be verified") from None
        if completed.returncode != 0 or completed.stdout.strip().lower() != "true":
            raise MCPBSandboxError("SANDBOX_EGRESS_NETWORK_INVALID", "Sandbox egress network must be a Docker internal network")
        return network

    def _proxy_url_for_sandbox(self, proxy_url: str) -> str:
        host = self.config.egress_proxy_host
        if not host or any(ch in host for ch in "/:@ "):
            raise MCPBSandboxError("SANDBOX_EGRESS_PROXY_REQUIRED", "Sandbox egress proxy host is not configured")
        parsed = urlsplit(proxy_url)
        if parsed.scheme != "http" or parsed.port is None:
            raise MCPBSandboxError("SANDBOX_EGRESS_PROXY_INVALID", "Credential broker returned unsupported proxy metadata")
        userinfo = parsed.netloc.rsplit("@", 1)[0] if "@" in parsed.netloc else ""
        netloc = f"{userinfo}@{host}:{parsed.port}" if userinfo else f"{host}:{parsed.port}"
        return urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))

    def docker_args(
        self,
        bundle_root: Path,
        manifest: MCPBManifest,
        *,
        image_override: str | None = None,
        network: str = "none",
        extra_mounts: tuple[str, ...] = (),
        extra_env: tuple[str, ...] = (),
        secret_root: Path | None = None,
    ) -> list[str]:
        image, runtime, runtime_args, runtime_env = self._runtime(manifest)
        if image_override is not None:
            image = image_override
        args = [
            "run", "--rm", "-i", "--pull=never", f"--network={network}", "--read-only",
            "--cap-drop=ALL", "--security-opt=no-new-privileges",
            f"--pids-limit={self.config.pids_limit}", f"--memory={self.config.memory_limit}",
            f"--cpus={self.config.cpu_limit}", "--user=65534:65534",
            f"--tmpfs=/tmp:rw,nosuid,nodev,noexec,size={self.config.tmpfs_bytes}",
            "--mount", f"type=bind,src={bundle_root},dst=/bundle,readonly",
            "--workdir=/bundle", "--env=HOME=/tmp",
        ]
        if secret_root is not None:
            args.extend(("--mount", f"type=bind,src={secret_root},dst=/run/ucs,readonly"))
        for mount in extra_mounts:
            args.extend(("--mount", mount))
        args.extend(f"--env={item}" for item in (*runtime_env, *extra_env))
        args.extend((image, runtime, *runtime_args))
        return args

    async def _execution_capabilities(
        self,
        *,
        service_id: str | None,
        connector_id: str | None,
        version: str | None,
        ctx: ExecutionContext | None,
        secret_root: Path,
    ) -> tuple[str, tuple[str, ...], tuple[str, ...], bool]:
        if self.profile_provider is None or ctx is None or connector_id is None or version is None:
            return "none", (), (), False
        profile = self.profile_provider.active_profile(ctx.organization_id, connector_id, version)
        extra_mounts: list[str] = []
        if getattr(profile, "mounts", ()):
            if self.mount_resolver is None:
                raise MCPBSandboxError("SANDBOX_MOUNT_POLICY_UNAVAILABLE", "Sandbox mount policy resolver is unavailable")
            for grant in profile.mounts:
                binding = self.mount_resolver.resolve(ctx.organization_id, grant)
                read_only = ",readonly" if grant.access == "read_only" else ""
                extra_mounts.append(f"type=bind,src={binding.host_path},dst={binding.container_path}{read_only}")

        hosts = tuple(getattr(profile, "egress_hosts", ()))
        if not hosts:
            return "none", tuple(extra_mounts), (), False
        if not getattr(profile, "brokered_credentials", False):
            raise MCPBSandboxError("SANDBOX_EGRESS_BROKER_REQUIRED", "Sandbox egress requires brokered credentials")
        if self.credential_broker is None or service_id is None:
            raise MCPBSandboxError("CREDENTIAL_BROKER_UNAVAILABLE", "Sandbox credential broker is unavailable")
        try:
            session = await self.credential_broker.sandbox_session(service_id, hosts, ctx)
        except Exception as exc:
            code = getattr(exc, "code", "CREDENTIAL_BROKER_UNAVAILABLE")
            message = getattr(exc, "safe_message", "Sandbox credential broker is unavailable")
            raise MCPBSandboxError(code, message, retryable=code == "CREDENTIAL_BROKER_UNAVAILABLE") from None
        proxy_url = self._proxy_url_for_sandbox(session.proxy_url.get_secret_value())
        ca_path = secret_root / "ca.pem"
        ca_path.write_text(session.ca_certificate, encoding="utf-8")
        ca_path.chmod(0o444)
        network = self._require_internal_network()
        env = (
            f"HTTP_PROXY={proxy_url}", f"HTTPS_PROXY={proxy_url}",
            "NO_PROXY=", "SSL_CERT_FILE=/run/ucs/ca.pem", "REQUESTS_CA_BUNDLE=/run/ucs/ca.pem",
        )
        return network, tuple(extra_mounts), env, True

    @asynccontextmanager
    async def client(
        self,
        digest: str,
        *,
        service_id: str | None = None,
        connector_id: str | None = None,
        version: str | None = None,
        ctx: ExecutionContext | None = None,
    ):
        if Client is None or StdioServerParameters is None:
            raise MCPBSandboxError("MCP_RUNTIME_UNAVAILABLE", "MCP SDK is not installed")
        if not self.available():
            raise MCPBSandboxError("MCPB_SANDBOX_UNAVAILABLE", "Docker sandbox runtime is unavailable", retryable=True)
        try:
            data = self.artifact_source.get(digest, "mcpb")
        except Exception:
            raise MCPBSandboxError("MCPB_ARTIFACT_UNAVAILABLE", "Pinned MCPB artifact is unavailable") from None
        with tempfile.TemporaryDirectory(prefix="ucs-mcpb-") as temporary, tempfile.TemporaryDirectory(prefix="ucs-secrets-") as secret_temp:
            root = Path(temporary).resolve()
            secret_root = Path(secret_temp).resolve()
            secret_root.chmod(0o755)
            manifest = _extract_mcpb(data, root)
            configured_image, _, _, _ = self._runtime(manifest)
            image_id = self.resolve_image(configured_image)
            network, mounts, env, has_secrets = await self._execution_capabilities(
                service_id=service_id, connector_id=connector_id, version=version, ctx=ctx, secret_root=secret_root
            )
            params = StdioServerParameters(
                command=self.config.docker_executable,
                args=self.docker_args(
                    root, manifest, image_override=image_id, network=network,
                    extra_mounts=mounts, extra_env=env, secret_root=secret_root if has_secrets else None,
                ),
                env={},
            )
            try:
                async with Client(params, mode="legacy") as client:
                    yield client
            except MCPBSandboxError:
                raise
            except Exception:
                raise MCPBSandboxError("MCPB_SANDBOX_PROTOCOL_ERROR", "Sandboxed MCPB server failed MCP stdio negotiation", retryable=True) from None

    async def inspect_tools(self, digest: str, *, deadline_ms: int = 15000) -> tuple[MCPToolSnapshot, ...]:
        tools: list[MCPToolSnapshot] = []
        cursor: str | None = None
        try:
            async with asyncio.timeout(deadline_ms / 1000):
                async with self.client(digest) as client:
                    for _ in range(MAX_LIST_PAGES):
                        page = await client.list_tools(cursor=cursor) if cursor else await client.list_tools()
                        for tool in page.tools:
                            tools.append(_snapshot_tool(tool))
                            if len(tools) > MAX_INTROSPECTION_TOOLS:
                                raise MCPBSandboxError("MCP_TOOL_LIMIT_EXCEEDED", "Sandboxed MCPB exposes too many tools")
                        cursor = page.next_cursor
                        if cursor is None:
                            break
                    else:
                        if cursor is not None:
                            raise MCPBSandboxError("MCP_TOOL_PAGE_LIMIT_EXCEEDED", "Sandboxed MCPB tool pagination exceeds limits")
        except TimeoutError:
            raise MCPBSandboxError("MCPB_SANDBOX_TIMEOUT", "Sandboxed MCPB introspection timed out", retryable=True) from None
        return tuple(tools)


class SandboxedMCPConnectorConfig(Model):
    connector_id: str = Field(alias="connectorId", min_length=1)
    service_id: str = Field(alias="serviceId", min_length=1)
    name: str = Field(min_length=1)
    version: str = Field(min_length=1)
    bundle_digest: str = Field(alias="bundleDigest", min_length=64, max_length=64)
    bindings: tuple[MCPToolBinding, ...] = Field(min_length=1)

    @field_validator("bundle_digest")
    @classmethod
    def digest_is_sha256(cls, value: str) -> str:
        normalized = value.lower()
        if len(normalized) != 64 or any(ch not in "0123456789abcdef" for ch in normalized):
            raise ValueError("bundleDigest must be SHA-256 hex")
        return normalized


class SandboxedMCPConnector:
    def __init__(self, config: SandboxedMCPConnectorConfig, *, runner: DockerMCPBSandboxRunner | None = None) -> None:
        self.config = config
        self.runner = runner

    def with_runner(self, runner: DockerMCPBSandboxRunner) -> "SandboxedMCPConnector":
        return SandboxedMCPConnector(self.config, runner=runner)

    def manifest(self) -> ConnectorManifest:
        return ConnectorManifest(
            connectorId=self.config.connector_id, serviceId=self.config.service_id,
            name=self.config.name, version=self.config.version, strategy="mcp",
            capabilities=tuple(binding.capability for binding in self.config.bindings), auth=AuthRequirement(type="none"),
        )

    def _adapter(self, ctx: ExecutionContext) -> MCPConnectorAdapter:
        if self.runner is None:
            raise MCPBSandboxError("MCPB_SANDBOX_UNAVAILABLE", "Sandbox runtime is not bound to this connector")
        return MCPConnectorAdapter(
            MCPConnectorConfig(
                connectorId=self.config.connector_id, serviceId=self.config.service_id,
                name=self.config.name, version=self.config.version,
                bindings=self.config.bindings, auth=AuthRequirement(type="none"),
            ),
            client_factory=lambda: self.runner.client(
                self.config.bundle_digest,
                service_id=self.config.service_id,
                connector_id=self.config.connector_id,
                version=self.config.version,
                ctx=ctx,
            ),
        )

    async def health_check(self, ctx: ExecutionContext) -> bool:
        try:
            return await self._adapter(ctx).health_check(ctx)
        except Exception:
            return False

    async def execute(self, capability: str, input: dict[str, Any], ctx: ExecutionContext) -> ConnectorResult:
        try:
            return await self._adapter(ctx).execute(capability, input, ctx)
        except MCPBSandboxError as exc:
            return ConnectorResult(status="failed", error=ConnectionError(code=exc.code, message=exc.safe_message, retryable=exc.retryable))
        except Exception:
            return ConnectorResult(status="failed", error=ConnectionError(code="MCPB_SANDBOX_EXECUTION_FAILED", message="Sandboxed MCPB execution failed"))
