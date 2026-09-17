"""The same real-process fault matrix against both encrypted databases."""
import json

import pytest

from test_encrypted_receipt_store import encrypted_stores
from test_metadata_storage import repositories, stores
from test_execution_crash_matrix import test_crash_boundary_never_duplicates_provider_effect as crash_boundary
from test_execution_recovery import test_process_crash_after_provider_commit_then_keyed_lookup_recovers as provider_crash
from test_dispatch_outcomes import test_process_exit_after_pending_commit_recovers_by_lookup as pending_crash
from test_stale_execution_process import test_live_old_process_cannot_overwrite_replay_or_duplicate_effect as stale_worker


@pytest.fixture
def process_stores(encrypted_stores, monkeypatch):
    primary = encrypted_stores()
    witness = primary._test_witness
    packet = dict(primaryProfile=primary.repository.profile_id,
                  witnessProfile=witness.repository.profile_id, witnessId=witness.witness_id)
    if hasattr(witness.store, "config"):
        packet["witnessDsn"] = witness.store.config.dsn.get_secret_value()
    else:
        packet["witnessPath"] = witness.store.path
    # Synthetic credentials stay out of process arguments and test reports.
    monkeypatch.setenv("UCS_TEST_ENCRYPTED_PROCESS_JSON", json.dumps(packet))
    return encrypted_stores


@pytest.mark.parametrize("phase", ["before_intent", "after_intent", "after_dispatch", "after_witness", "after_result", "after_audit_ack"])
def test_encrypted_process_crash_boundaries(process_stores, tmp_path, phase):
    crash_boundary(process_stores, tmp_path, phase)


def test_encrypted_provider_commit_before_crash(process_stores, tmp_path):
    provider_crash(tmp_path, process_stores)


def test_encrypted_pending_commit_before_crash(process_stores, tmp_path):
    pending_crash(process_stores, tmp_path)


@pytest.mark.parametrize("pause", ["before_effect", "after_effect"])
def test_encrypted_live_stale_worker(process_stores, tmp_path, pause):
    stale_worker(process_stores, tmp_path, pause)
