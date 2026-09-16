import asyncio
import base64
import hashlib
import json
import zipfile
from io import BytesIO

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from universal_connection_service.contracts import (
    AuthRequirement,
    ConnectorManifest,
    ExecutionContext,
)
from universal_connection_service.packages import (
    ConnectorPackageLoader,
    Ed25519PackageVerifier,
    FilesystemPackageSource,
    PackageVerificationError,
)
from universal_connection_service.persistence import SQLiteStateStore
from universal_connection_service.registry import ConnectorRegistry, Registration
from universal_connection_service.rehydration import (
    ConnectorPackagePinService,
    ConnectorRuntimeRehydrator,
)


CONNECTOR_SOURCE = '''
from universal_connection_service.contracts import AuthRequirement, ConnectorManifest, ConnectorResult

class PackagedConnector:
    def manifest(self):
        return ConnectorManifest(
            connectorId="pkg-records",
            serviceId="records",
            name="Packaged Records",
            version="1.0.0",
            strategy="api",
            capabilities=("records.read",),
            auth=AuthRequirement(type="none"),
        )

    async def health_check(self, ctx):
        return True

    async def execute(self, capability, input, ctx):
        return ConnectorResult(status="success", data={"source": "package", "input": input})

def build():
    return PackagedConnector()
'''


class StubConnector:
    def manifest(self):
        return ConnectorManifest(
            connectorId="pkg-records",
            serviceId="records",
            name="Packaged Records",
            version="1.0.0",
            strategy="api",
            capabilities=("records.read",),
            auth=AuthRequirement(type="none"),
        )

    async def health_check(self, ctx):
        return True

    async def execute(self, capability, input, ctx):
        raise AssertionError("bootstrap stub must not execute after restart")


def make_archive(*, connector_id="pkg-records", version="1.0.0", extra_file=None):
    manifest = {
        "formatVersion": 1,
        "connector": {
            "connectorId": connector_id,
            "serviceId": "records",
            "name": "Packaged Records",
            "version": version,
            "strategy": "api",
            "capabilities": ["records.read"],
            "auth": {"type": "none", "scopes": []},
        },
        "entrypoint": "connector:build",
    }
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("ucs-package.json", json.dumps(manifest, sort_keys=True))
        zf.writestr("connector.py", CONNECTOR_SOURCE)
        if extra_file:
            zf.writestr(extra_file[0], extra_file[1])
    return buffer.getvalue()


def write_signed_package(root, archive, private_key, *, signer="release-key"):
    digest = hashlib.sha256(archive).hexdigest()
    signature = private_key.sign(archive)
    (root / f"{digest}.zip").write_bytes(archive)
    (root / f"{digest}.sig.json").write_text(
        json.dumps(
            {
                "scheme": "ed25519",
                "signerRef": signer,
                "signature": base64.b64encode(signature).decode(),
            }
        ),
        encoding="utf-8",
    )
    return digest


def verifier_for(private_key, *, signer="release-key"):
    public = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return Ed25519PackageVerifier({signer: public})


def test_verified_signed_package_loads_and_executes(tmp_path):
    key = Ed25519PrivateKey.generate()
    archive = make_archive()
    digest = write_signed_package(tmp_path, archive, key)
    loader = ConnectorPackageLoader(FilesystemPackageSource(tmp_path), verifier_for(key))

    loaded = loader.load(digest)
    assert loaded.manifest.connector.connector_id == "pkg-records"

    ctx = ExecutionContext(requestId="r1", userId="u1", organizationId="org-1")
    result = asyncio.run(loaded.connector.execute("records.read", {"x": 1}, ctx))
    assert result.status == "success"
    assert result.data == {"source": "package", "input": {"x": 1}}


def test_tampered_archive_fails_before_import(tmp_path):
    key = Ed25519PrivateKey.generate()
    archive = make_archive()
    digest = write_signed_package(tmp_path, archive, key)
    (tmp_path / f"{digest}.zip").write_bytes(archive + b"tampered")
    loader = ConnectorPackageLoader(FilesystemPackageSource(tmp_path), verifier_for(key))

    with pytest.raises(PackageVerificationError) as exc:
        loader.load(digest)
    assert exc.value.code == "PACKAGE_DIGEST_MISMATCH"


def test_untrusted_signer_is_rejected(tmp_path):
    signing_key = Ed25519PrivateKey.generate()
    trusted_key = Ed25519PrivateKey.generate()
    archive = make_archive()
    digest = write_signed_package(tmp_path, archive, signing_key, signer="unknown")
    loader = ConnectorPackageLoader(
        FilesystemPackageSource(tmp_path),
        verifier_for(trusted_key, signer="release-key"),
    )

    with pytest.raises(PackageVerificationError) as exc:
        loader.load(digest)
    assert exc.value.code == "PACKAGE_SIGNER_UNTRUSTED"


def test_unsafe_zip_member_is_rejected_after_signature_verification(tmp_path):
    key = Ed25519PrivateKey.generate()
    archive = make_archive(extra_file=("../escape.py", "x = 1"))
    digest = write_signed_package(tmp_path, archive, key)
    loader = ConnectorPackageLoader(FilesystemPackageSource(tmp_path), verifier_for(key))

    with pytest.raises(PackageVerificationError) as exc:
        loader.load(digest)
    assert exc.value.code == "PACKAGE_LAYOUT_INVALID"


def test_trusted_connector_rehydrates_after_restart_from_pinned_package(tmp_path):
    key = Ed25519PrivateKey.generate()
    archive = make_archive()
    digest = write_signed_package(tmp_path, archive, key)
    loader = ConnectorPackageLoader(FilesystemPackageSource(tmp_path), verifier_for(key))

    db_path = tmp_path / "state.sqlite3"
    first_store = SQLiteStateStore(db_path)
    first_registry = ConnectorRegistry(state_store=first_store)
    registration = Registration(
        connector=StubConnector(),
        status="trusted",
        organization_id="org-1",
    )
    first_registry.register(registration)
    ConnectorPackagePinService(loader, first_store).pin(registration, digest)
    first_store.close()

    second_store = SQLiteStateStore(db_path)
    second_registry = ConnectorRegistry(state_store=second_store)
    report = ConnectorRuntimeRehydrator(
        state_store=second_store,
        evidence_store=second_store,
        registry=second_registry,
        loader=loader,
    ).rehydrate()

    assert report.loaded == 1
    item = second_registry.trusted("records", "records.read", "org-1")
    assert item is not None
    ctx = ExecutionContext(requestId="r2", userId="u1", organizationId="org-1")
    result = asyncio.run(item.connector.execute("records.read", {}, ctx))
    assert result.status == "success"
    assert result.data["source"] == "package"

    evidence = second_store.list_evidence("org-1", kind="validation")
    subtypes = {entry.payload.get("type") for entry in evidence}
    assert {"package_verification", "package_rehydration"}.issubset(subtypes)
    second_store.close()


def test_untrusted_persistent_metadata_is_not_rehydrated(tmp_path):
    key = Ed25519PrivateKey.generate()
    archive = make_archive()
    digest = write_signed_package(tmp_path, archive, key)
    loader = ConnectorPackageLoader(FilesystemPackageSource(tmp_path), verifier_for(key))
    store = SQLiteStateStore(":memory:")
    registry = ConnectorRegistry(state_store=store)
    registration = Registration(
        connector=StubConnector(),
        status="validated",
        organization_id="org-1",
    )
    registry.register(registration)

    # A package cannot be pinned to a connector that has not crossed the trust gate.
    with pytest.raises(ValueError):
        ConnectorPackagePinService(loader, store).pin(registration, digest)

    restarted_registry = ConnectorRegistry(state_store=store)
    report = ConnectorRuntimeRehydrator(
        state_store=store,
        evidence_store=store,
        registry=restarted_registry,
        loader=loader,
    ).rehydrate()
    assert report.loaded == 0
    assert report.skipped == 1
    assert restarted_registry.trusted("records", "records.read", "org-1") is None
    store.close()


def test_signed_manifest_must_match_trusted_persistent_metadata(tmp_path):
    key = Ed25519PrivateKey.generate()
    archive = make_archive(version="2.0.0")
    digest = write_signed_package(tmp_path, archive, key)
    loader = ConnectorPackageLoader(FilesystemPackageSource(tmp_path), verifier_for(key))
    store = SQLiteStateStore(":memory:")
    registry = ConnectorRegistry(state_store=store)
    registration = Registration(
        connector=StubConnector(),
        status="trusted",
        organization_id="org-1",
    )
    registry.register(registration)

    with pytest.raises(PackageVerificationError) as exc:
        ConnectorPackagePinService(loader, store).pin(registration, digest)
    assert exc.value.code in {"PACKAGE_MANIFEST_MISMATCH", "PACKAGE_TRUST_MISMATCH"}
    store.close()
