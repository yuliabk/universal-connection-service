"""Workflow recovery uses the same encrypted receipt after workflow-save loss."""
import pytest

from test_metadata_rotation import stores  # Isolated database per scenario.
from test_metadata_storage import repositories
from test_encrypted_receipt_store import encrypted_stores
from test_auto_connect import test_receipt_resumes_after_workflow_save_failure_without_new_approval as resume_case


@pytest.mark.parametrize("uncertain", [False, True])
def test_encrypted_workflow_resumes_without_new_approval(encrypted_stores, tmp_path, monkeypatch, uncertain):
    resume_case(tmp_path, monkeypatch, uncertain, store_factory=lambda path: encrypted_stores())
