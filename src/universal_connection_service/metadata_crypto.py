"""Encryption primitives for persisted metadata and opaque equality indexes.

This module does not itself enable encryption on a StateStore. Store integration
must verify the persisted index-key tag before any read or write: a changed index
key must never make an existing execution look like a new operation.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
from collections.abc import Mapping

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


MAX_METADATA_BYTES = 4_000_000
_KEY_ID = re.compile(r"[A-Za-z0-9_.-]{1,64}\Z")


class MetadataCryptoError(ValueError):
    """Safe to translate to an unavailable-store response; contains no inputs."""


def _frame(parts: list[str | int]) -> bytes:
    return json.dumps(parts, ensure_ascii=True, separators=(",", ":")).encode("ascii")


def _scope(namespace: str, organization_id: str, identity: tuple[str, ...]) -> None:
    if (not isinstance(namespace, str) or not _KEY_ID.fullmatch(namespace)
        or not isinstance(organization_id, str) or not 1 <= len(organization_id) <= 4096
        or not isinstance(identity, tuple) or not identity or len(identity) > 8
        or any(not isinstance(part, str) or not 1 <= len(part) <= 4096 for part in identity)):
        raise MetadataCryptoError("METADATA_SCOPE_INVALID")


class MetadataCipher:
    """Tenant/domain-separated AEAD with an independently managed index key.

    Data keys rotate by adding a key and changing active_key. The index key is
    stable for the lifetime of the execution keyspace; changing it requires an
    offline, complete migration of primary and witness identities.
    """

    def __init__(self, keys: Mapping[str, bytes], active_key: str, index_key: bytes):
        if (not isinstance(keys, Mapping) or not keys
            or not isinstance(active_key, str) or active_key not in keys
            or any(not isinstance(name, str) or not _KEY_ID.fullmatch(name)
                   or not isinstance(key, bytes) or len(key) != 32
                   for name, key in keys.items())
            or not isinstance(index_key, bytes) or len(index_key) != 32
            or any(hmac.compare_digest(index_key, key) for key in keys.values())):
            raise MetadataCryptoError("METADATA_KEYRING_INVALID")
        self._keys = dict(keys)
        self._index_key = index_key
        self.active_key = active_key

    def index(self, namespace: str, organization_id: str, *identity: str) -> str:
        """Opaque equality token; leaks equality within this exact domain only."""
        _scope(namespace, organization_id, identity)
        message = _frame(["ucs-metadata-index", 1, namespace, organization_id, *identity])
        return hmac.new(self._index_key, message, hashlib.sha256).hexdigest()

    def configuration_tag(self) -> str:
        """Persist once during provisioning; never overwrite during startup."""
        return hmac.new(self._index_key, b"ucs-metadata-index-configuration-v1", hashlib.sha256).hexdigest()

    def verify_configuration(self, persisted_tag: str) -> None:
        if (not isinstance(persisted_tag, str)
            or not re.fullmatch(r"[0-9a-f]{64}", persisted_tag)
            or not hmac.compare_digest(persisted_tag, self.configuration_tag())):
            raise MetadataCryptoError("METADATA_INDEX_KEY_MISMATCH")

    def _cipher(self, key_id: str, organization_id: str) -> AESGCM:
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                   info=_frame(["ucs-metadata-data-key", 1, organization_id])).derive(self._keys[key_id])
        return AESGCM(key)

    def _aad(self, key_id: str, namespace: str, organization_id: str, identity: tuple[str, ...]) -> bytes:
        return _frame(["ucs-metadata-envelope", 1, key_id, namespace, organization_id, *identity])

    def seal(self, namespace: str, organization_id: str, identity: tuple[str, ...], payload: bytes) -> str:
        _scope(namespace, organization_id, identity)
        if not isinstance(payload, bytes) or len(payload) > MAX_METADATA_BYTES:
            raise MetadataCryptoError("METADATA_PAYLOAD_INVALID")
        nonce = os.urandom(12)
        ciphertext = self._cipher(self.active_key, organization_id).encrypt(
            nonce, payload, self._aad(self.active_key, namespace, organization_id, identity))
        return json.dumps({"v": 1, "keyId": self.active_key,
                           "sealed": base64.b64encode(nonce + ciphertext).decode("ascii")},
                          separators=(",", ":"))

    def open(self, namespace: str, organization_id: str, identity: tuple[str, ...], envelope: str) -> bytes:
        _scope(namespace, organization_id, identity)
        try:
            if not isinstance(envelope, str) or len(envelope) > 4 * ((MAX_METADATA_BYTES + 30) // 3) + 256:
                raise ValueError
            packet = json.loads(envelope)
            if (not isinstance(packet, dict) or set(packet) != {"v", "keyId", "sealed"}
                or type(packet["v"]) is not int or packet["v"] != 1
                or not isinstance(packet["keyId"], str) or packet["keyId"] not in self._keys
                or not isinstance(packet["sealed"], str)):
                raise ValueError
            sealed = base64.b64decode(packet["sealed"], validate=True)
            if not 28 <= len(sealed) <= MAX_METADATA_BYTES + 28:
                raise ValueError
            return self._cipher(packet["keyId"], organization_id).decrypt(
                sealed[:12], sealed[12:], self._aad(packet["keyId"], namespace, organization_id, identity))
        except Exception:
            raise MetadataCryptoError("METADATA_UNAVAILABLE") from None
