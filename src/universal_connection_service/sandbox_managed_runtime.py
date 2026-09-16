from __future__ import annotations

import contextvars
import json
import subprocess
from contextlib import asynccontextmanager
from typing import Any

from pydantic import Field, field_validator

from .contracts import AuthRequirement, ConnectionError, ConnectorManifest, ConnectorResult, ExecutionContext, Model
from .mcp_adapter import MCPConnectorAdapter, MCPConnectorConfig, MCPToolBinding
from .mcpb_sandbox import DockerMCPBSandboxConfig, DockerMCPBSandboxRunner, MCPBSandboxError, SandboxedMCPConnector
from .registry import ConnectorRegistry
from .sandbox_build import SandboxAwareBuildCoordinator
from .sandbox_tool_policy import SandboxToolPolicyService


class SandboxGatewayError(RuntimeError):
    def __init__(self, code: str, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.code = code
        self.safe_message = message
        self.retryable = retryable


class DockerSandboxGatewayConfig(Model):
    docker_executable: str = Field(alias="dockerExecutable", default="docker", min_length=1)
    network_name: str = Field(alias="networkName", default="ucs-sandbox-egress", min_length=1)
    gateway_container: str = Field(alias="gatewayContainer", min_length=1)
    gateway_alias: str = Field(alias="gatewayAlias", default="agent-vault-proxy", min_length=1)
    startup_timeout_seconds: float = Field(alias="startupTimeoutSeconds", default=5.0, gt=0, le=30)

    @field_validator("network_name", "gateway_container", "gateway_alias")
    @classmethod
    def safe_docker_identifier(cls, value: str) -> str:
        if any(ch.isspace() or ch in "/:@" for ch in value):
            raise ValueError("managed sandbox gateway identifiers contain unsupported characters")
        return value


class SandboxGatewayStatus(Model):
    ready: bool
    network: str
    gateway_alias: str = Field(alias="gatewayAlias")
    code: str


class DockerSandboxGatewayManager:
    """Idempotently create an internal bridge and attach an existing broker container."""

    NETWORK_LABEL = "io.universal-connection-service.sandbox-gateway"

    def __init__(self, config: DockerSandboxGatewayConfig) -> None:
        self.config = config

    def _run(self, args: list[str]) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(
                [self.config.docker_executable, *args],
                capture_output=True,
                text=True,
                timeout=self.config.startup_timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise SandboxGatewayError(
                "SANDBOX_GATEWAY_DOCKER_UNAVAILABLE",
                "Docker sandbox gateway runtime is unavailable",
                retryable=True,
            ) from None

    def _network_exists(self) -> bool:
        return self._run(["network", "inspect", self.config.network_name]).returncode == 0

    def _create_network(self) -> None:
        completed = self._run([
            "network", "create",
            "--driver", "bridge",
            "--internal",
            "--label", f"{self.NETWORK_LABEL}=true",
            self.config.network_name,
        ])
        if completed.returncode != 0:
            # A concurrent UCS instance may have created the same network after our existence check.
            if not self._network_exists():
                raise SandboxGatewayError(
                    "SANDBOX_GATEWAY_NETWORK_CREATE_FAILED",
                    "Managed sandbox gateway network could not be created",
                    retryable=True,
                )

    def _verify_network(self) -> None:
        internal = self._run([
            "network", "inspect", self.config.network_name,
            "--format", "{{.Internal}}",
        ])
        driver = self._run([
            "network", "inspect", self.config.network_name,
            "--format", "{{.Driver}}",
        ])
        if internal.returncode != 0 or internal.stdout.strip().lower() != "true":
            raise SandboxGatewayError(
                "SANDBOX_GATEWAY_NETWORK_INVALID",
                "Managed sandbox gateway network must be internal",
            )
        if driver.returncode != 0 or driver.stdout.strip().lower() != "bridge":
            raise SandboxGatewayError(
                "SANDBOX_GATEWAY_NETWORK_INVALID",
                "Managed sandbox gateway network must use the bridge driver",
            )

    def _container_networks(self) -> dict[str, Any]:
        running = self._run([
            "inspect", self.config.gateway_container,
            "--format", "{{.State.Running}}",
        ])
        if running.returncode != 0 or running.stdout.strip().lower() != "true":
            raise SandboxGatewayError(
                "SANDBOX_GATEWAY_CONTAINER_UNAVAILABLE",
                "Configured sandbox gateway container is not running",
                retryable=True,
            )
        networks = self._run([
            "inspect", self.config.gateway_container,
            "--format", "{{json .NetworkSettings.Networks}}",
        ])
        if networks.returncode != 0:
            raise SandboxGatewayError(
                "SANDBOX_GATEWAY_CONTAINER_UNAVAILABLE",
                "Configured sandbox gateway container network state is unavailable",
                retryable=True,
            )
        try:
            payload = json.loads(networks.stdout)
        except json.JSONDecodeError:
            raise SandboxGatewayError(
                "SANDBOX_GATEWAY_CONTAINER_INVALID",
                "Configured sandbox gateway container returned invalid network metadata",
            ) from None
        return payload if isinstance(payload, dict) else {}

    def _attach_gateway(self) -> None:
        networks = self._container_networks()
        current = networks.get(self.config.network_name)
        if current is None:
            connected = self._run([
                "network", "connect",
                "--alias", self.config.gateway_alias,
                self.config.network_name,
                self.config.gateway_container,
            ])
            if connected.returncode != 0:
                # Re-read state to tolerate another UCS instance connecting it concurrently.
                networks = self._container_networks()
                current = networks.get(self.config.network_name)
                if current is None:
                    raise SandboxGatewayError(
                        "SANDBOX_GATEWAY_CONNECT_FAILED",
                        "Sandbox gateway container could not be attached to the managed network",
                        retryable=True,
                    )
            else:
                networks = self._container_networks()
                current = networks.get(self.config.network_name)
        if not isinstance(current, dict):
            raise SandboxGatewayError(
                "SANDBOX_GATEWAY_CONNECT_FAILED",
                "Sandbox gateway container is not attached to the managed network",
                retryable=True,
            )
        aliases = current.get("Aliases")
        aliases = aliases if isinstance(aliases, list) else []
        # Docker DNS always exposes the container name; an explicit different alias must be present.
        if self.config.gateway_alias != self.config.gateway_container and self.config.gateway_alias not in aliases:
            raise SandboxGatewayError(
                "SANDBOX_GATEWAY_ALIAS_MISMATCH",
                "Sandbox gateway container is attached without the configured network alias",
            )

    def ensure(self) -> SandboxGatewayStatus:
        if not self._network_exists():
            self._create_network()
        self._verify_network()
        self._attach_gateway()
        return SandboxGatewayStatus(
            ready=True,
            network=self.config.network_name,
            gatewayAlias=self.config.gateway_alias,
            code="SANDBOX_GATEWAY_READY",
        )


class _ToolScopedProfileAdapter:
    def __init__(self, service: SandboxToolPolicyService) -> None:
        self.service = service
        self._capability: contextvars.ContextVar[str | None] = contextvars.ContextVar(
            "ucs_sandbox_capability",
            default=None,
        )

    def active_profile(self, organization_id: str, connector_id: str, version: str):
        return self.service.active_profile(
            organization_id,
            connector_id,
            version,
            self._capability.get(),
        )

    @asynccontextmanager
    async def capability(self, value: str):
        token = self._capability.set(value)
        try:
            yield
        finally:
            self._capability.reset(token)


class ManagedPolicyDockerMCPBSandboxRunner(DockerMCPBSandboxRunner):
    """UCS-15 runner plus managed gateway repair and per-capability profile selection."""

    def __init__(
        self,
        artifact_source,
        config: DockerMCPBSandboxConfig,
        *,
        policy_service: SandboxToolPolicyService,
        mount_resolver,
        credential_broker,
        gateway_manager: DockerSandboxGatewayManager | None = None,
    ) -> None:
        self.tool_profile_adapter = _ToolScopedProfileAdapter(policy_service)
        self.gateway_manager = gateway_manager
        super().__init__(
            artifact_source,
            config,
            profile_provider=self.tool_profile_adapter,
            mount_resolver=mount_resolver,
            credential_broker=credential_broker,
        )

    def _require_internal_network(self) -> str:
        if self.gateway_manager is not None:
            try:
                status = self.gateway_manager.ensure()
            except SandboxGatewayError as exc:
                raise MCPBSandboxError(exc.code, exc.safe_message, retryable=exc.retryable) from None
            if self.config.egress_network != status.network:
                raise MCPBSandboxError(
                    "SANDBOX_GATEWAY_CONFIG_MISMATCH",
                    "Managed sandbox gateway network does not match runner configuration",
                )
            return status.network
        return super()._require_internal_network()

    @asynccontextmanager
    async def client_for_capability(
        self,
        digest: str,
        *,
        capability: str,
        service_id: str,
        connector_id: str,
        version: str,
        ctx: ExecutionContext,
    ):
        async with self.tool_profile_adapter.capability(capability):
            async with self.client(
                digest,
                service_id=service_id,
                connector_id=connector_id,
                version=version,
                ctx=ctx,
            ) as client:
                yield client


class ToolScopedSandboxedMCPConnector(SandboxedMCPConnector):
    """Preserve zero-privilege health checks while applying profile only to the requested capability."""

    def __init__(self, config, *, runner: ManagedPolicyDockerMCPBSandboxRunner | None = None) -> None:
        super().__init__(config, runner=runner)
        self.runner = runner

    def with_runner(self, runner: ManagedPolicyDockerMCPBSandboxRunner) -> "ToolScopedSandboxedMCPConnector":
        return ToolScopedSandboxedMCPConnector(self.config, runner=runner)

    def manifest(self) -> ConnectorManifest:
        return ConnectorManifest(
            connectorId=self.config.connector_id,
            serviceId=self.config.service_id,
            name=self.config.name,
            version=self.config.version,
            strategy="mcp",
            capabilities=tuple(binding.capability for binding in self.config.bindings),
            auth=AuthRequirement(type="none"),
        )

    def _binding(self, capability: str) -> MCPToolBinding | None:
        return next((item for item in self.config.bindings if item.capability == capability), None)

    async def health_check(self, ctx: ExecutionContext) -> bool:
        if self.runner is None:
            return False
        adapter = MCPConnectorAdapter(
            MCPConnectorConfig(
                connectorId=self.config.connector_id,
                serviceId=self.config.service_id,
                name=self.config.name,
                version=self.config.version,
                bindings=self.config.bindings,
                auth=AuthRequirement(type="none"),
            ),
            client_factory=lambda: self.runner.client(
                self.config.bundle_digest,
                service_id=self.config.service_id,
                connector_id=self.config.connector_id,
                version=self.config.version,
                ctx=ctx,
            ),
        )
        return await adapter.health_check(ctx)

    async def execute(self, capability: str, input: dict[str, Any], ctx: ExecutionContext) -> ConnectorResult:
        binding = self._binding(capability)
        if binding is None:
            return ConnectorResult(
                status="failed",
                error=ConnectionError(
                    code="CAPABILITY_UNAVAILABLE",
                    message="Connector does not expose the requested capability",
                ),
            )
        if self.runner is None:
            return ConnectorResult(
                status="failed",
                error=ConnectionError(
                    code="MCPB_SANDBOX_UNAVAILABLE",
                    message="Sandbox runtime is not bound to this connector",
                ),
            )
        adapter = MCPConnectorAdapter(
            MCPConnectorConfig(
                connectorId=self.config.connector_id,
                serviceId=self.config.service_id,
                name=self.config.name,
                version=self.config.version,
                bindings=(binding,),
                auth=AuthRequirement(type="none"),
            ),
            client_factory=lambda: self.runner.client_for_capability(
                self.config.bundle_digest,
                capability=capability,
                service_id=self.config.service_id,
                connector_id=self.config.connector_id,
                version=self.config.version,
                ctx=ctx,
            ),
        )
        return await adapter.execute(capability, input, ctx)


class ToolScopedSandboxAwareBuildCoordinator:
    """Wrap newly validated MCPB registrations immediately with the tool-scoped runtime."""

    def __init__(
        self,
        base: SandboxAwareBuildCoordinator,
        *,
        runner: ManagedPolicyDockerMCPBSandboxRunner,
        registry: ConnectorRegistry,
    ) -> None:
        self.base = base
        self.runner = runner
        self.registry = registry
        self.pipeline = base.pipeline

    async def build_async(self, candidate, request, *, selected_tool=None, deadline_ms: int = 15000):
        result = await self.base.build_async(
            candidate,
            request,
            selected_tool=selected_tool,
            deadline_ms=deadline_ms,
        )
        if result.passed and result.connector_id and result.connector_version:
            registration = self.registry.exact(
                request.actor.organization_id,
                result.connector_id,
                result.connector_version,
            )
            if registration is not None and isinstance(registration.connector, SandboxedMCPConnector):
                registration.connector = ToolScopedSandboxedMCPConnector(
                    registration.connector.config,
                    runner=self.runner,
                )
        return result

    def build(self, candidate, request):
        return self.base.build(candidate, request)

    def pin_after_trust(self, organization_id: str, connector_id: str, version: str) -> None:
        self.base.pin_after_trust(organization_id, connector_id, version)
