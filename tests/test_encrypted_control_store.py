import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from uuid import uuid4

import pytest

from test_metadata_storage import repositories, stores
from test_persistence import StubConnector
from universal_connection_service.approvals import ApprovalConsumeError, ApprovalRecord, ApprovalStore, PersistentApprovalVerifier, approval_ref_hash
from universal_connection_service.encrypted_control_store import EncryptedControlStore
from universal_connection_service.persistence import (
    AuditEvent, AuditStore, ConnectorStateStore, EvidenceRecord, EvidenceStore,
    ConnectionWorkflowRecord, WorkflowStore, utc_now,
)
from universal_connection_service.policy import ApprovalGrant
from universal_connection_service.receipts import ReceiptStore
from universal_connection_service.registry import ConnectorRegistry, Registration


@pytest.fixture
def controls(repositories):
    return lambda: EncryptedControlStore(repositories())


def grant(org, raw=None, **updates):
    return ApprovalGrant(**(dict(approvalId=raw or uuid4().hex, requestId="private-request",
        organizationId=org, userId="private-user", agentId="private-agent", serviceId="private-service",
        capability="private.write", operation="update", expiresAt=utc_now() + timedelta(minutes=5)) | updates))


def workflow(org, **updates):
    return ConnectionWorkflowRecord(**(dict(workflowId=uuid4().hex, requestId=uuid4().hex,
        organizationId=org, requestFingerprint="f" * 64, serviceId="private-service",
        capability="private.write", operation="update") | updates))


def test_control_ports_and_registry_use_encrypted_documents_after_restart(controls):
    store = controls()
    for port in (ConnectorStateStore, EvidenceStore, AuditStore, WorkflowStore, ApprovalStore):
        assert isinstance(store, port)
    assert not isinstance(store, ReceiptStore)  # No silent plaintext delegation.
    org = uuid4().hex
    registry = ConnectorRegistry(state_store=store)
    registration = Registration(connector=StubConnector("private-connector"), status="generated", organization_id=org)
    registry.register(registration)
    registration.set_status("validated")
    reopened = controls()
    rows = reopened.list_connectors(org)
    assert len(rows) == 1 and rows[0].status == "validated"
    assert reopened.list_connectors(org + "-other") == []
    assert any(r.organization_id == org for r in reopened.list_connectors())
    with store.repository.transaction() as conn:
        assert store.repository.store._receipt_query(conn, "SELECT 1 FROM connector_state WHERE organization_id = ?", (org,)).fetchone() is None


def test_audit_and_evidence_filtering_preserve_tenant_and_request_boundaries(controls):
    store = controls()
    org, other = uuid4().hex, uuid4().hex
    for tenant in (org, other):
        for request_id in ("request-a", "request-b"):
            store.append_evidence(EvidenceRecord(evidenceId=uuid4().hex, organizationId=tenant,
                kind="validation", phase="validation", requestId=request_id,
                payload={"private": "private-evidence-marker"}))
            store.append_audit(AuditEvent(auditId=uuid4().hex, organizationId=tenant, requestId=request_id,
                userId="private-user", agentId="private-agent", serviceId="private-service",
                capability="private.read", operation="read", status="success"))
    reopened = controls()
    assert len(reopened.list_audit(org)) == 2
    assert len(reopened.list_audit(org, request_id="request-a")) == 1
    assert all(r.organization_id == org for r in reopened.list_evidence(org))
    assert len(reopened.list_evidence(org, kind="validation", request_id="request-b")) == 1
    assert reopened.list_evidence(org, kind="policy_decision") == []
    with store.repository.transaction() as conn:
        rows = store.repository.store._receipt_query(conn, "SELECT * FROM metadata_document").fetchall()
    physical = repr([dict(r) for r in rows])
    assert all(marker not in physical for marker in (org, other, "private-user", "private-evidence-marker"))


def test_persistent_verifier_consumes_once_across_encrypted_instances(controls):
    first, second = controls(), controls()
    g = grant(uuid4().hex)
    first_verifier = PersistentApprovalVerifier(first)
    first_verifier.register(g)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda s: s.consume_approval(approval_ref_hash(g.approval_id), utc_now()), [first, second]))
    assert sorted(results) == [False, True]
    assert controls().get_approval(approval_ref_hash(g.approval_id)).consumed_at is not None
    with pytest.raises(ApprovalConsumeError) as error:
        asyncio.run(PersistentApprovalVerifier(second).consume(g.approval_id))
    assert error.value.code == "APPROVAL_ALREADY_USED"


def test_approval_revocation_expiry_and_original_binding_survive_restart(controls):
    store = controls()
    org = uuid4().hex
    g = grant(org)
    original = ApprovalRecord.from_grant(g)
    store.put_approval(original)
    store.put_approval(original.model_copy(update={"organization_id": "attacker", "user_id": "attacker"}))
    assert store.get_approval(original.approval_ref_hash) == original
    assert not store.revoke_execution_approval("other", original.approval_ref_hash)
    assert store.revoke_execution_approval(org, original.approval_ref_hash)
    assert not controls().consume_approval(original.approval_ref_hash, utc_now())
    expired = ApprovalRecord.from_grant(grant(org, expiresAt=utc_now() - timedelta(seconds=1)))
    store.put_approval(expired)
    assert not controls().consume_approval(expired.approval_ref_hash, utc_now())


def test_workflow_lease_persists_and_only_current_owner_can_update(controls):
    first, second = controls(), controls()
    org = uuid4().hex
    record = workflow(org)
    first.create_workflow(record)
    now = utc_now()
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda pair: pair[0].claim_workflow(org, record.workflow_id, pair[1], now + timedelta(seconds=5), now),
                                [(first, "worker-a"), (second, "worker-b")]))
    assert sorted(results) == [False, True]
    reopened = controls()
    current = reopened.get_workflow_by_request(org, record.request_id)
    assert current.lease_token == ("worker-a" if results[0] else "worker-b")
    assert current.lease_expires_at == now + timedelta(seconds=5)
    assert "leaseToken" not in current.model_dump(by_alias=True)
    assert reopened.get_workflow("other-org", record.workflow_id) is None
    assert not reopened.update_claimed_workflow(current, expected_revision=0, lease_token=None)
    assert reopened.claim_workflow(org, record.workflow_id, "new-worker", now + timedelta(seconds=20), now + timedelta(seconds=6))
    assert not first.update_claimed_workflow(current, expected_revision=0, lease_token=current.lease_token)
    first.release_workflow(org, record.workflow_id, current.lease_token)
    candidate = current.model_copy(update={"request_id": "must-not-change", "request_fingerprint": "a" * 64, "stage": "completed"})
    assert reopened.update_claimed_workflow(candidate, expected_revision=0, lease_token="new-worker")
    final = first.get_workflow(org, record.workflow_id)
    assert final.stage == "completed" and final.revision == 1 and final.lease_token is None
    assert final.request_id == record.request_id and final.request_fingerprint == record.request_fingerprint


def test_duplicate_workflow_request_rolls_back_document_and_global_locator(controls):
    store = controls()
    org = uuid4().hex
    original = workflow(org)
    store.create_workflow(original)
    duplicate = workflow(org, requestId=original.request_id)
    with pytest.raises(ValueError, match="DUPLICATE_WORKFLOW_REQUEST"):
        store.create_workflow(duplicate)
    assert controls().get_workflow(org, duplicate.workflow_id) is None
    # Reusing the failed insert's ID for a distinct request succeeds only if its
    # global locator was rolled back in the same transaction.
    replacement = duplicate.model_copy(update={"request_id": uuid4().hex})
    assert store.create_workflow(replacement).workflow_id == duplicate.workflow_id
    assert store.get_workflow_by_request(org, original.request_id).workflow_id == original.workflow_id


def test_global_audit_id_cannot_be_reassigned_to_another_tenant(controls):
    store = controls()
    original = AuditEvent(auditId=uuid4().hex, organizationId=uuid4().hex, requestId="request",
        userId="user", agentId="agent", serviceId="service", capability="read", operation="read", status="success")
    store.append_audit(original)
    other = original.model_copy(update={"organization_id": uuid4().hex})
    with pytest.raises(ValueError, match="DUPLICATE_RECORD"):
        store.append_audit(other)
    assert store.list_audit(other.organization_id) == []
    assert store.list_audit(original.organization_id) == [original]
