import asyncio
import base64
import hashlib
import json
import shutil
import stat
import subprocess
import zipfile
from io import BytesIO

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from universal_connection_service.build_auto_connect import VerifiedBuildCoordinator
from universal_connection_service.build_pipeline import (
    ConnectorBuildPipeline,
    Ed25519BuildSigner,
    FilesystemPackageWriter,
)
from universal_connection_service.contracts import (
    ActorRef,
    AuthRequirement,
    ConnectionRequest,
    DiscoveryCandidateRef,
    ExecutionContext,
    ServiceRef,
)
from universal_connection_service.mcpb_sandbox import (
    DockerMCPBSandboxConfig,
    DockerMCPBSandboxRunner,
    MCPBSandboxError,
    SandboxedMCPConnector,
    inspect_mcpb_archive,
)
from universal_connection_service.packages import ConnectorPackageLoader, Ed25519PackageVerifier, FilesystemPackageSource
from universal_connection_service.persistence import SQLiteStateStore
from universal_connection_service.registry import ConnectorRegistry
from universal_connection_service.rehydration import ConnectorRuntimeRehydrator
from universal_connection_service.sandbox_build import (
    FilesystemMCPBArtifactStore,
    GeneratedSandboxMCPPackageBuilder,
    SandboxAwareBuildCoordinator,
    SandboxMCPPackageAcquirer,
)


SERVER_SOURCE = r'''
import json
import sys


def send(payload):
    sys.stdout.write(json.dumps(payload, separators=(",", ":")) + "\n")
    sys.stdout.flush()


for line in sys.stdin:
    try:
        message = json.loads(line)
    except Exception:
        continue
    method = message.get("method")
    request_id = message.get("id")
    if request_id is None:
        continue
    if method == "initialize":
        send({
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "Sandbox Fixture", "version": "1.0.0"}
            }
        })
    elif method == "ping":
        send({"jsonrpc": "2.0", "id": request_id, "result": {}})
    elif method == "tools/list":
        send({
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "tools": [{
                    "name": "records_read",
                    "description": "Read records",
                    "inputSchema": {"type": "object", "properties": {}},
                    "annotations": {"readOnlyHint": True, "destructiveHint": False}
                }]
            }
        })
    elif method == "tools/call":
        send({
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "content": [{"type": "text", "text": "sandbox-ok"}],
                "isError": False
            }
        })
    else:
        send({"jsonrpc": "2.0", "id": request_id, "error": {"code": -32601, "message": "method not found"}})
'''


def mcpb_bytes(*, entry_point="server/main.py", extra_members=None):
    manifest = {
        "manifest_version": "0.3",
        "name": "sandbox-fixture",
        "version": "1.0.0",
        "description": "fixture",
        "author": {"name": "UCS"},
        "server": {
            "type": "python",
            "entry_point": entry_point,
            "mcp_config": {
                "command": "python",
                "args": ["${__dirname}/server/main.py"],
                "env": {"HOST_SECRET": "${HOME}"}
            }
        }
    }
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("manifest.json", json.dumps(manifest))
        archive.writestr("server/main.py", SERVER_SOURCE)
        for name, value in extra_members or []:
            if isinstance(value, zipfile.ZipInfo):
                archive.writestr(value, b"target")
            else:
                archive.writestr(name, value)
    return buffer.getvalue()


def docker_ready():
    if shutil.which("docker") is None:
        return False
    try:
        return subprocess.run(
            ["docker", "image", "inspect", "python:3.12-slim"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
        ).returncode == 0
    except Exception:
        return False


def request():
    return ConnectionRequest(
        requestId="sandbox-build-request",
        actor=ActorRef(userId="u1", organizationId="org-1", agentId="a1"),
        service=ServiceRef(id="records", name="Records"),
        capability="records.read",
        operation="read",
        input={"secret": "do-not-persist"},
        readOnly=True,
    )


def candidate(digest):
    return DiscoveryCandidateRef(
        candidateId="mcpb-candidate-1",
        source="mcp_registry",
        name="Records MCPB",
        version="1.0.0",
        strategy="mcp",
        transport="stdio",
        packageRegistry="mcpb",
        packageIdentifier="https://packages.example/records.mcpb",
        packageVersion="1.0.0",
        packageSha256=digest,
        authRequirement=AuthRequirement(type="none"),
        confidence=100,
        actionable=False,
        requiresBuild=True,
    )


def package_runtime(tmp_path):
    private = Ed25519PrivateKey.generate()
    raw_private = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    raw_public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    package_dir = tmp_path / "packages"
    writer = FilesystemPackageWriter(package_dir)
    signer = Ed25519BuildSigner(
        signer_ref="ucs-test-builder",
        private_key=base64.b64encode(raw_private).decode("ascii"),
    )
    builder = GeneratedSandboxMCPPackageBuilder(writer, signer)
    loader = ConnectorPackageLoader(
        FilesystemPackageSource(package_dir),
        Ed25519PackageVerifier({"ucs-test-builder": raw_public}),
    )
    return builder, loader


def test_mcpb_manifest_and_archive_reject_unsafe_layouts():
    manifest = inspect_mcpb_archive(mcpb_bytes())
    assert manifest.server.type == "python"
    assert manifest.server.entry_point == "server/main.py"

    bad = BytesIO()
    with zipfile.ZipFile(bad, "w") as archive:
        archive.writestr("manifest.json", json.dumps({
            "manifest_version": "0.3",
            "name": "bad",
            "version": "1.0.0",
            "server": {"type": "python", "entry_point": "server/main.py"},
        }))
        archive.writestr("../escape.py", "x")
        archive.writestr("server/main.py", SERVER_SOURCE)
    with pytest.raises(MCPBSandboxError) as exc:
        inspect_mcpb_archive(bad.getvalue())
    assert exc.value.code == "MCPB_LAYOUT_INVALID"

    symlink = zipfile.ZipInfo("server/link.py")
    symlink.create_system = 3
    symlink.external_attr = (stat.S_IFLNK | 0o777) << 16
    linked = mcpb_bytes(extra_members=[("server/link.py", symlink)])
    with pytest.raises(MCPBSandboxError) as exc:
        inspect_mcpb_archive(linked)
    assert exc.value.code == "MCPB_LAYOUT_INVALID"


def test_docker_command_is_fail_closed_and_does_not_use_manifest_command(tmp_path):
    data = mcpb_bytes()
    digest = hashlib.sha256(data).hexdigest()
    store = FilesystemMCPBArtifactStore(tmp_path)
    store.put(digest, data)
    runner = DockerMCPBSandboxRunner(store, DockerMCPBSandboxConfig())
    manifest = inspect_mcpb_archive(data)
    args = runner.docker_args(tmp_path, manifest)
    joined = " ".join(args)
    assert "--network=none" in args
    assert "--read-only" in args
    assert "--cap-drop=ALL" in args
    assert "--security-opt=no-new-privileges" in args
    assert "--pull=never" in args
    assert "--user=65534:65534" in args
    assert "HOST_SECRET" not in joined
    assert "${HOME}" not in joined
    assert args[-2:] == ["python", "/bundle/server/main.py"]


@pytest.mark.skipif(not docker_ready(), reason="Docker sandbox test image is unavailable")
def test_real_docker_sandbox_lists_tools_and_executes_through_stdio(tmp_path):
    data = mcpb_bytes()
    digest = hashlib.sha256(data).hexdigest()
    store = FilesystemMCPBArtifactStore(tmp_path)
    store.put(digest, data)
    runner = DockerMCPBSandboxRunner(store)

    tools = asyncio.run(runner.inspect_tools(digest, deadline_ms=15000))
    assert [tool.name for tool in tools] == ["records_read"]
    assert tools[0].read_only_hint is True

    from universal_connection_service.mcp_adapter import MCPToolBinding
    from universal_connection_service.mcpb_sandbox import SandboxedMCPConnectorConfig

    connector = SandboxedMCPConnector(
        SandboxedMCPConnectorConfig(
            connectorId="sandbox-runtime",
            serviceId="records",
            name="Records MCPB",
            version="1.0.0",
            bundleDigest=digest,
            bindings=(MCPToolBinding(capability="records.read", tool="records_read"),),
        ),
        runner=runner,
    )
    result = asyncio.run(
        connector.execute(
            "records.read",
            {},
            ExecutionContext(requestId="req", userId="u1", organizationId="org-1", deadlineMs=15000),
        )
    )
    assert result.status == "success"


@pytest.mark.skipif(not docker_ready(), reason="Docker sandbox test image is unavailable")
def test_mcpb_build_is_signed_validated_pinnable_and_restart_safe(tmp_path):
    data = mcpb_bytes()
    digest = hashlib.sha256(data).hexdigest()
    artifact_store = FilesystemMCPBArtifactStore(tmp_path / "artifacts")
    runner = DockerMCPBSandboxRunner(artifact_store)

    def handler(http_request):
        assert str(http_request.url) == "https://packages.example/records.mcpb"
        return httpx.Response(200, content=data)

    acquirer = SandboxMCPPackageAcquirer(
        artifact_store,
        client_factory=lambda: httpx.Client(transport=httpx.MockTransport(handler)),
    )
    package_builder, package_loader = package_runtime(tmp_path)
    store = SQLiteStateStore(":memory:")
    registry = ConnectorRegistry(state_store=store)
    pipeline = ConnectorBuildPipeline(registry=registry, evidence_store=store)
    fallback = VerifiedBuildCoordinator(
        pipeline=pipeline,
        package_loader=package_loader,
        evidence_store=store,
    )
    coordinator = SandboxAwareBuildCoordinator(
        fallback=fallback,
        runner=runner,
        acquirer=acquirer,
        package_builder=package_builder,
        package_loader=package_loader,
        registry=registry,
        evidence_store=store,
    )

    result = asyncio.run(
        coordinator.build_async(candidate(digest), request(), deadline_ms=15000)
    )
    assert result.passed is True
    assert result.code == "MCP_PACKAGE_SANDBOX_VALIDATED"
    assert result.connector_id
    assert result.package_digest

    registration = registry.exact("org-1", result.connector_id, "1.0.0")
    assert registration is not None
    assert registration.status == "validated"
    assert registry.trusted("records", "records.read", "org-1") is None

    serialized_evidence = " ".join(
        item.model_dump_json(by_alias=True) for item in store.list_evidence("org-1")
    )
    assert "do-not-persist" not in serialized_evidence
    assert "packages.example" not in serialized_evidence

    registration.set_status("trusted", approval_id="a" * 64)
    coordinator.pin_after_trust("org-1", result.connector_id, "1.0.0")
    pins = [
        item for item in store.list_evidence("org-1", kind="validation")
        if item.payload.get("type") == "package_verification"
    ]
    assert len(pins) == 1
    assert pins[0].payload["digest"] == result.package_digest

    restarted_registry = ConnectorRegistry(state_store=store)
    report = ConnectorRuntimeRehydrator(
        state_store=store,
        evidence_store=store,
        registry=restarted_registry,
        loader=package_loader,
        runtime_binder=lambda connector: connector.with_runner(runner)
        if isinstance(connector, SandboxedMCPConnector)
        else connector,
    ).rehydrate()
    assert report.loaded == 1
    trusted = restarted_registry.trusted("records", "records.read", "org-1")
    assert trusted is not None
    execution = asyncio.run(
        trusted.connector.execute(
            "records.read",
            {},
            ExecutionContext(requestId="req2", userId="u1", organizationId="org-1", deadlineMs=15000),
        )
    )
    assert execution.status == "success"
    store.close()
