from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import types
import zipfile
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path, PurePosixPath
from typing import Any, Literal, Protocol, runtime_checkable

from pydantic import Field, field_validator

from .contracts import ConnectorContract, ConnectorManifest, Model

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except ImportError:  # pragma: no cover
    InvalidSignature = Exception  # type: ignore[assignment]
    Ed25519PublicKey = None  # type: ignore[assignment]


PACKAGE_FORMAT_VERSION = 1
PACKAGE_MANIFEST_PATH = "ucs-package.json"
MAX_PACKAGE_BYTES = 10 * 1024 * 1024
MAX_MEMBER_BYTES = 2 * 1024 * 1024
MAX_MEMBERS = 128


class ConnectorPackageManifest(Model):
    format_version: int = Field(alias="formatVersion", default=PACKAGE_FORMAT_VERSION)
    connector: ConnectorManifest
    entrypoint: str = Field(min_length=3)

    @field_validator("format_version")
    @classmethod
    def supported_format(cls, value: int) -> int:
        if value != PACKAGE_FORMAT_VERSION:
            raise ValueError("unsupported connector package format version")
        return value

    @field_validator("entrypoint")
    @classmethod
    def valid_entrypoint(cls, value: str) -> str:
        if value.count(":") != 1:
            raise ValueError("entrypoint must use module:function syntax")
        module, function = value.split(":", 1)
        if not module or not function:
            raise ValueError("entrypoint must include module and function")
        for component in module.split("."):
            if not component.isidentifier():
                raise ValueError("entrypoint module is invalid")
        if not function.isidentifier():
            raise ValueError("entrypoint function is invalid")
        return value


class PackageSignature(Model):
    scheme: Literal["ed25519", "sigstore"]
    signer_ref: str = Field(alias="signerRef", min_length=1)
    signature: str | None = None
    bundle: dict[str, Any] | None = None


class PackageArtifact(Model):
    digest: str = Field(min_length=64, max_length=64)
    archive: bytes
    signature: PackageSignature


class PackageVerificationError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.safe_message = message


@runtime_checkable
class PackageSource(Protocol):
    def get(self, digest: str) -> PackageArtifact: ...


@runtime_checkable
class PackageSignatureVerifier(Protocol):
    def verify(self, artifact: PackageArtifact) -> None: ...


class FilesystemPackageSource:
    """Digest-addressed package source.

    Archives are stored as <sha256>.zip and signatures as <sha256>.sig.json.
    Paths are derived only from validated hexadecimal digests, so package
    metadata cannot redirect UCS to arbitrary filesystem paths.
    """

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).resolve()

    @staticmethod
    def _validate_digest(digest: str) -> str:
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest.lower()):
            raise PackageVerificationError("PACKAGE_DIGEST_INVALID", "Package digest is invalid")
        return digest.lower()

    def get(self, digest: str) -> PackageArtifact:
        digest = self._validate_digest(digest)
        archive_path = self.root / f"{digest}.zip"
        signature_path = self.root / f"{digest}.sig.json"
        try:
            archive = archive_path.read_bytes()
            signature_payload = json.loads(signature_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError):
            raise PackageVerificationError(
                "PACKAGE_UNAVAILABLE",
                "Connector package or signature is unavailable",
            ) from None
        if len(archive) > MAX_PACKAGE_BYTES:
            raise PackageVerificationError("PACKAGE_TOO_LARGE", "Connector package exceeds the size limit")
        return PackageArtifact(
            digest=digest,
            archive=archive,
            signature=PackageSignature.model_validate(signature_payload),
        )


class Ed25519PackageVerifier:
    def __init__(self, trusted_public_keys: dict[str, bytes | str]) -> None:
        if Ed25519PublicKey is None:
            raise RuntimeError("cryptography is required for Ed25519 package verification")
        self._keys: dict[str, Any] = {}
        for signer_ref, value in trusted_public_keys.items():
            try:
                raw = base64.b64decode(value, validate=True) if isinstance(value, str) else value
                self._keys[signer_ref] = Ed25519PublicKey.from_public_bytes(raw)
            except Exception:
                raise ValueError(f"invalid Ed25519 public key for signer {signer_ref}") from None

    def verify(self, artifact: PackageArtifact) -> None:
        actual = hashlib.sha256(artifact.archive).hexdigest()
        if actual != artifact.digest:
            raise PackageVerificationError("PACKAGE_DIGEST_MISMATCH", "Connector package digest does not match")
        if artifact.signature.scheme != "ed25519":
            raise PackageVerificationError("PACKAGE_SIGNATURE_SCHEME_UNSUPPORTED", "Package signature scheme is unsupported")
        key = self._keys.get(artifact.signature.signer_ref)
        if key is None:
            raise PackageVerificationError("PACKAGE_SIGNER_UNTRUSTED", "Connector package signer is not trusted")
        if not artifact.signature.signature:
            raise PackageVerificationError("PACKAGE_SIGNATURE_INVALID", "Connector package signature is missing")
        try:
            signature = base64.b64decode(artifact.signature.signature, validate=True)
            key.verify(signature, artifact.archive)
        except (ValueError, InvalidSignature):
            raise PackageVerificationError("PACKAGE_SIGNATURE_INVALID", "Connector package signature is invalid") from None


class CosignBundleVerifier:
    """Sigstore/Cosign verifier for signed package blobs.

    Verification uses a local cosign binary and a stored Sigstore bundle. The
    signer identity and issuer are configuration, never package-controlled.
    """

    def __init__(
        self,
        *,
        certificate_identity: str,
        certificate_oidc_issuer: str,
        executable: str = "cosign",
        timeout_seconds: int = 30,
    ) -> None:
        self.identity = certificate_identity
        self.issuer = certificate_oidc_issuer
        self.executable = executable
        self.timeout_seconds = timeout_seconds

    def verify(self, artifact: PackageArtifact) -> None:
        actual = hashlib.sha256(artifact.archive).hexdigest()
        if actual != artifact.digest:
            raise PackageVerificationError("PACKAGE_DIGEST_MISMATCH", "Connector package digest does not match")
        if artifact.signature.scheme != "sigstore" or artifact.signature.bundle is None:
            raise PackageVerificationError("PACKAGE_SIGNATURE_SCHEME_UNSUPPORTED", "Package is not a Sigstore bundle")
        if artifact.signature.signer_ref != self.identity:
            raise PackageVerificationError("PACKAGE_SIGNER_UNTRUSTED", "Connector package signer identity is not trusted")
        with tempfile.TemporaryDirectory(prefix="ucs-sigstore-") as tmp:
            archive_path = Path(tmp) / "connector.zip"
            bundle_path = Path(tmp) / "bundle.sigstore.json"
            archive_path.write_bytes(artifact.archive)
            bundle_path.write_text(json.dumps(artifact.signature.bundle), encoding="utf-8")
            try:
                completed = subprocess.run(
                    [
                        self.executable,
                        "verify-blob",
                        str(archive_path),
                        "--bundle",
                        str(bundle_path),
                        "--certificate-identity",
                        self.identity,
                        "--certificate-oidc-issuer",
                        self.issuer,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_seconds,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired):
                raise PackageVerificationError("PACKAGE_VERIFIER_UNAVAILABLE", "Sigstore verifier is unavailable") from None
        if completed.returncode != 0:
            raise PackageVerificationError("PACKAGE_SIGNATURE_INVALID", "Sigstore package verification failed")


def _safe_archive_members(archive: bytes) -> list[zipfile.ZipInfo]:
    try:
        with zipfile.ZipFile(BytesIO(archive), "r") as zf:
            members = zf.infolist()
            if len(members) > MAX_MEMBERS:
                raise PackageVerificationError("PACKAGE_LAYOUT_INVALID", "Connector package contains too many files")
            for member in members:
                path = PurePosixPath(member.filename)
                if path.is_absolute() or ".." in path.parts or "\\" in member.filename:
                    raise PackageVerificationError("PACKAGE_LAYOUT_INVALID", "Connector package contains an unsafe path")
                if member.file_size > MAX_MEMBER_BYTES:
                    raise PackageVerificationError("PACKAGE_LAYOUT_INVALID", "Connector package member exceeds size limit")
                if member.is_dir():
                    continue
                if path.suffix not in {".py", ".json"}:
                    raise PackageVerificationError("PACKAGE_LAYOUT_INVALID", "Connector package contains an unsupported file type")
                mode = (member.external_attr >> 16) & 0o170000
                if mode == 0o120000:
                    raise PackageVerificationError("PACKAGE_LAYOUT_INVALID", "Connector package symlinks are not allowed")
            return members
    except zipfile.BadZipFile:
        raise PackageVerificationError("PACKAGE_ARCHIVE_INVALID", "Connector package is not a valid ZIP archive") from None


def read_package_manifest(archive: bytes) -> ConnectorPackageManifest:
    _safe_archive_members(archive)
    try:
        with zipfile.ZipFile(BytesIO(archive), "r") as zf:
            payload = json.loads(zf.read(PACKAGE_MANIFEST_PATH).decode("utf-8"))
    except (KeyError, UnicodeDecodeError, ValueError, json.JSONDecodeError):
        raise PackageVerificationError("PACKAGE_MANIFEST_INVALID", "Connector package manifest is invalid or missing") from None
    try:
        return ConnectorPackageManifest.model_validate(payload)
    except Exception:
        raise PackageVerificationError("PACKAGE_MANIFEST_INVALID", "Connector package manifest failed validation") from None


def _load_entrypoint(archive: bytes, manifest: ConnectorPackageManifest, digest: str) -> ConnectorContract:
    module_name, function_name = manifest.entrypoint.split(":", 1)
    module_path = module_name.replace(".", "/") + ".py"
    try:
        with zipfile.ZipFile(BytesIO(archive), "r") as zf:
            source = zf.read(module_path)
    except KeyError:
        raise PackageVerificationError("PACKAGE_ENTRYPOINT_INVALID", "Connector entrypoint module is missing") from None
    if len(source) > MAX_MEMBER_BYTES:
        raise PackageVerificationError("PACKAGE_ENTRYPOINT_INVALID", "Connector entrypoint exceeds size limit")

    unique_name = f"_ucs_connector_{digest[:16]}_{module_name.replace('.', '_')}"
    module = types.ModuleType(unique_name)
    module.__file__ = f"<ucs-package:{digest}/{module_path}>"
    module.__package__ = ""
    try:
        code = compile(source, module.__file__, "exec")
        sys.modules[unique_name] = module
        exec(code, module.__dict__)
        factory = getattr(module, function_name)
        connector = factory()
    except PackageVerificationError:
        raise
    except Exception:
        raise PackageVerificationError("PACKAGE_ENTRYPOINT_FAILED", "Connector package entrypoint failed") from None
    finally:
        sys.modules.pop(unique_name, None)

    if not isinstance(connector, ConnectorContract):
        raise PackageVerificationError("PACKAGE_CONTRACT_INVALID", "Loaded connector does not implement ConnectorContract")
    return connector


@dataclass(frozen=True)
class LoadedConnectorPackage:
    connector: ConnectorContract
    manifest: ConnectorPackageManifest
    digest: str
    signer_ref: str


class ConnectorPackageLoader:
    def __init__(self, source: PackageSource, verifier: PackageSignatureVerifier) -> None:
        self.source = source
        self.verifier = verifier

    def load(self, digest: str) -> LoadedConnectorPackage:
        artifact = self.source.get(digest)
        self.verifier.verify(artifact)
        manifest = read_package_manifest(artifact.archive)
        connector = _load_entrypoint(artifact.archive, manifest, artifact.digest)
        runtime_manifest = connector.manifest()
        if runtime_manifest != manifest.connector:
            raise PackageVerificationError(
                "PACKAGE_MANIFEST_MISMATCH",
                "Runtime connector manifest does not match the signed package manifest",
            )
        return LoadedConnectorPackage(
            connector=connector,
            manifest=manifest,
            digest=artifact.digest,
            signer_ref=artifact.signature.signer_ref,
        )
