"""Open pre-provisioned synthetic stores in independent crash-test processes."""
import json
import os

from universal_connection_service.persistence import SQLiteStateStore


def open_process_store(location, backend, witness_path):
    if backend == "sqlite":
        physical = SQLiteStateStore(location, must_exist=True)
    else:
        from pydantic import SecretStr
        from universal_connection_service.postgres_store import PostgresStateStore, PostgresStoreConfig
        physical = PostgresStateStore(PostgresStoreConfig(
            dsn=SecretStr(os.environ["UCS_TEST_POSTGRES_URL"]), sslmode="disable"))
        physical.test_witness_path = witness_path
    packet = os.getenv("UCS_TEST_ENCRYPTED_PROCESS_JSON")
    if packet is None:
        return physical
    from test_metadata_storage import cipher
    from universal_connection_service.metadata_storage import MetadataRepository
    from universal_connection_service.encrypted_receipt_store import EncryptedStateStore
    from universal_connection_service.encrypted_witness import EncryptedDispatchWitness
    config = json.loads(packet)
    primary = EncryptedStateStore(MetadataRepository(physical, cipher(), config["primaryProfile"]))
    if backend == "sqlite":
        witness = SQLiteStateStore(config["witnessPath"], must_exist=True)
    else:
        witness = PostgresStateStore(PostgresStoreConfig(
            dsn=SecretStr(config["witnessDsn"]), sslmode="disable"))
    primary._test_witness = EncryptedDispatchWitness(
        MetadataRepository(witness, cipher(), config["witnessProfile"]), config["witnessId"])
    return primary
