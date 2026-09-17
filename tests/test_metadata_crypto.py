import base64
import json

import pytest

from universal_connection_service.metadata_crypto import MAX_METADATA_BYTES, MetadataCipher, MetadataCryptoError


def cipher(**updates):
    return MetadataCipher(**(dict(keys={"old": b"d" * 32}, active_key="old", index_key=b"i" * 32) | updates))


def test_encryption_is_randomized_and_survives_reconstruction():
    first, restarted = cipher(), cipher()
    body = b'{"organizationId":"tenant-private","providerAccountId":"sensitive-account"}'
    args = ("execution_receipt", "tenant-private", ("op-private",))
    packets = [first.seal(*args, body) for _ in range(2)]
    assert packets[0] != packets[1]
    assert all("sensitive-account" not in packet and "tenant-private" not in packet for packet in packets)
    assert all(restarted.open(*args, packet) == body for packet in packets)
    assert first.index("operation", "tenant-private", "op-private") == restarted.index("operation", "tenant-private", "op-private")


@pytest.mark.parametrize("namespace,org,identity", [
    ("execution_outbox", "org", ("op",)),
    ("execution_receipt", "other-org", ("op",)),
    ("execution_receipt", "org", ("other-op",)),
    ("execution_receipt", "org", ("op", "extra")),
])
def test_envelope_cannot_be_transplanted(namespace, org, identity):
    crypto = cipher()
    packet = crypto.seal("execution_receipt", "org", ("op",), b"private")
    with pytest.raises(MetadataCryptoError, match="^METADATA_UNAVAILABLE$"):
        crypto.open(namespace, org, identity, packet)


def test_rotation_preserves_indexes_and_reads_old_records():
    old = cipher()
    rotated = cipher(keys={"old": b"d" * 32, "new": b"n" * 32}, active_key="new")
    args = ("receipt", "org", ("op",))
    previous = old.seal(*args, b"previous")
    assert rotated.open(*args, previous) == b"previous"
    assert rotated.index("operation", "org", "op") == old.index("operation", "org", "op")
    rotated.verify_configuration(old.configuration_tag())
    fresh = rotated.seal(*args, b"fresh")
    assert json.loads(fresh)["keyId"] == "new"
    assert rotated.open(*args, fresh) == b"fresh"
    with pytest.raises(MetadataCryptoError, match="^METADATA_UNAVAILABLE$"):
        old.open(*args, fresh)


def test_index_key_change_cannot_pass_existing_configuration_check():
    original = cipher()
    changed = cipher(index_key=b"j" * 32)
    assert changed.index("operation", "org", "op") != original.index("operation", "org", "op")
    with pytest.raises(MetadataCryptoError, match="^METADATA_INDEX_KEY_MISMATCH$"):
        changed.verify_configuration(original.configuration_tag())
    with pytest.raises(MetadataCryptoError):
        changed.verify_configuration(None)


def test_indexes_are_framed_and_domain_and_tenant_separated():
    crypto = cipher()
    tokens = [crypto.index("operation", "org", "a", "bc"),
              crypto.index("operation", "org", "ab", "c"),
              crypto.index("operation", "other", "a", "bc"),
              crypto.index("approval", "org", "a", "bc"),
              crypto.index("operation", "org", 'a","bc')]
    assert len(set(tokens)) == len(tokens)
    assert all(len(token) == 64 for token in tokens)


@pytest.mark.parametrize("damage", ["nonce", "tag", "key", "version", "bool_version", "extra", "base64", "plaintext"])
def test_modified_or_plaintext_envelopes_fail_closed(damage):
    crypto = cipher(keys={"old": b"d" * 32, "alias": b"d" * 32})
    args = ("receipt", "org", ("op",))
    packet = json.loads(crypto.seal(*args, b"private"))
    if damage in {"nonce", "tag"}:
        raw = bytearray(base64.b64decode(packet["sealed"]))
        raw[0 if damage == "nonce" else -1] ^= 1
        packet["sealed"] = base64.b64encode(raw).decode()
    elif damage == "key":
        # Even two key IDs referring to the same key are bound by AAD.
        packet["keyId"] = "alias"
    elif damage == "version":
        packet["v"] = 2
    elif damage == "bool_version":
        packet["v"] = True
    elif damage == "extra":
        packet["payload"] = "private"
    elif damage == "base64":
        packet["sealed"] = "!"
    else:
        packet = {"organizationId": "org", "operationId": "op"}
    with pytest.raises(MetadataCryptoError, match="^METADATA_UNAVAILABLE$"):
        crypto.open(*args, json.dumps(packet))


@pytest.mark.parametrize("updates", [
    {"keys": {}}, {"active_key": "missing"}, {"keys": {"old": b"short"}},
    {"index_key": b"short"}, {"index_key": b"d" * 32},
    {"keys": {"private key name with spaces": b"d" * 32}},
])
def test_invalid_key_configuration_is_rejected(updates):
    with pytest.raises(MetadataCryptoError, match="^METADATA_KEYRING_INVALID$"):
        cipher(**updates)


def test_plaintext_size_limit_and_keyring_copy():
    keys = {"old": b"d" * 32}
    crypto = cipher(keys=keys)
    keys.clear()
    args = ("receipt", "org", ("op",))
    payload = b"x" * MAX_METADATA_BYTES
    assert crypto.open(*args, crypto.seal(*args, payload)) == payload
    with pytest.raises(MetadataCryptoError, match="^METADATA_PAYLOAD_INVALID$"):
        crypto.seal(*args, payload + b"x")
    with pytest.raises(MetadataCryptoError):
        crypto.index("receipt", "", "op")
