"""Encrypted implementations of control-plane persistence ports.

Receipt coordination and runtime activation are separate integration steps. This
class deliberately does not inherit a plaintext StateStore or delegate unknown
methods to it: an unimplemented encrypted port must not silently write plaintext.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

from .approvals import ApprovalRecord
from .metadata_crypto import MetadataCryptoError
from .metadata_storage import MetadataRepository
from .persistence import AuditEvent, ConnectionWorkflowRecord, ConnectorStateRecord, EvidenceRecord, utc_now


_DIRECTORY = "ucs:private-locators:v1"


def _body(record):
    fields = record.model_dump(mode="json", by_alias=True)
    if isinstance(record, ConnectionWorkflowRecord):
        # These internal fields are intentionally excluded from API serialization,
        # but must survive process restart inside the encrypted document.
        fields["leaseToken"] = record.lease_token
        fields["leaseExpiresAt"] = record.lease_expires_at.isoformat() if record.lease_expires_at else None
    type(record).model_validate(fields)
    return json.dumps(fields, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _aware(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


class EncryptedControlStore:
    def __init__(self, repository: MetadataRepository):
        self.repository = repository

    def close(self):
        self.repository.store.close()

    def _model(self, conn, domain, org, identity, model, *, lock=False):
        doc = self.repository.get(conn, domain, org, identity, lock=lock)
        if doc is None:
            return None, None
        record = model.model_validate_json(doc.body)
        if record.organization_id != org:
            raise MetadataCryptoError("METADATA_TENANT_MISMATCH")
        return doc, record

    def _save_model(self, conn, domain, org, identity, document, record):
        if not self.repository.compare_and_swap(conn, domain, org, identity, document.revision, _body(record)):
            raise MetadataCryptoError("METADATA_STATE_CONFLICT")

    def _records(self, conn, domain, org, model):
        after = ""
        while page := self.repository.page(conn, domain, org, after=after):
            for doc in page:
                record = model.model_validate_json(doc.body)
                if record.organization_id != org:
                    raise MetadataCryptoError("METADATA_TENANT_MISMATCH")
                yield record
            after = page[-1].cursor

    def _reserve_global(self, conn, kind, record_id, org):
        # Existing APIs look up approvals by opaque reference without an org.
        # The encrypted locator is host-internal, never a cross-tenant API.
        return self.repository.insert(conn, "locator-" + kind, _DIRECTORY, (record_id,), org.encode("utf-8"))

    def _global_owner(self, conn, kind, record_id):
        doc = self.repository.get(conn, "locator-" + kind, _DIRECTORY, (record_id,))
        return doc.body.decode("utf-8") if doc else None

    def upsert_connector(self, record: ConnectorStateRecord):
        identity = (record.manifest.connector_id, record.manifest.version)
        with self.repository.transaction() as conn:
            if self.repository.insert(conn, "connector", record.organization_id, identity, _body(record)):
                return
            doc, _ = self._model(conn, "connector", record.organization_id, identity, ConnectorStateRecord, lock=True)
            self._save_model(conn, "connector", record.organization_id, identity, doc, record)

    def update_connector_status(self, organization_id, connector_id, version, status, approval_id=None):
        identity = (connector_id, version)
        with self.repository.transaction() as conn:
            doc, record = self._model(conn, "connector", organization_id, identity, ConnectorStateRecord, lock=True)
            if record is None:
                raise KeyError("connector metadata is not registered")
            record.status, record.approval_id, record.updated_at = status, approval_id, utc_now()
            self._save_model(conn, "connector", organization_id, identity, doc, record)

    def list_connectors(self, organization_id=None):
        with self.repository.transaction() as conn:
            if organization_id is not None:
                records = list(self._records(conn, "connector", organization_id, ConnectorStateRecord))
            else:
                records, after = [], ""
                while page := self.repository.tenant_page(conn, after=after):
                    for _, org in page:
                        records.extend(self._records(conn, "connector", org, ConnectorStateRecord))
                    after = page[-1][0]
        return sorted(records, key=lambda r: (r.organization_id, r.manifest.connector_id, r.manifest.version))

    def _append_unique(self, conn, domain, record_id, record):
        if not self._reserve_global(conn, domain, record_id, record.organization_id):
            raise ValueError("DUPLICATE_RECORD")
        if not self.repository.insert(conn, domain, record.organization_id, (record_id,), _body(record)):
            raise MetadataCryptoError("METADATA_IDENTITY_CONFLICT")

    def append_evidence(self, record: EvidenceRecord):
        with self.repository.transaction() as conn:
            self._append_unique(conn, "evidence", record.evidence_id, record)

    def list_evidence(self, organization_id, *, request_id=None, kind=None):
        with self.repository.transaction() as conn:
            records = [r for r in self._records(conn, "evidence", organization_id, EvidenceRecord)
                       if (request_id is None or r.request_id == request_id) and (kind is None or r.kind == kind)]
        return sorted(records, key=lambda r: (_aware(r.created_at), r.evidence_id))

    def append_audit(self, event: AuditEvent):
        with self.repository.transaction() as conn:
            self._append_unique(conn, "audit", event.audit_id, event)

    def list_audit(self, organization_id, *, request_id=None):
        with self.repository.transaction() as conn:
            records = [r for r in self._records(conn, "audit", organization_id, AuditEvent)
                       if request_id is None or r.request_id == request_id]
        return sorted(records, key=lambda r: (_aware(r.created_at), r.audit_id))

    def put_approval(self, record: ApprovalRecord):
        with self.repository.transaction() as conn:
            if not self._reserve_global(conn, "approval", record.approval_ref_hash, record.organization_id):
                return  # Preserve original immutable grant, as the existing stores do.
            if not self.repository.insert(conn, "approval", record.organization_id, (record.approval_ref_hash,), _body(record)):
                raise MetadataCryptoError("METADATA_IDENTITY_CONFLICT")

    def _approval(self, conn, ref_hash, *, lock=False):
        org = self._global_owner(conn, "approval", ref_hash)
        if org is None:
            return None, None
        doc, record = self._model(conn, "approval", org, (ref_hash,), ApprovalRecord, lock=lock)
        if record is None or record.approval_ref_hash != ref_hash:
            raise MetadataCryptoError("METADATA_IDENTITY_CONFLICT")
        return doc, record

    def get_approval(self, approval_ref_hash):
        with self.repository.transaction() as conn:
            return self._approval(conn, approval_ref_hash)[1]

    def consume_approval(self, approval_ref_hash, consumed_at):
        with self.repository.transaction() as conn:
            doc, record = self._approval(conn, approval_ref_hash, lock=True)
            if (record is None or record.consumed_at is not None or record.revoked_at is not None
                or _aware(record.expires_at) <= _aware(consumed_at)):
                return False
            record.consumed_at = consumed_at
            self._save_model(conn, "approval", record.organization_id, (approval_ref_hash,), doc, record)
            return True

    def revoke_execution_approval(self, organization_id, ref_hash):
        with self.repository.transaction() as conn:
            doc, record = self._approval(conn, ref_hash, lock=True)
            if record is None or record.organization_id != organization_id or record.revoked_at is not None:
                return False
            record.revoked_at = utc_now()
            self._save_model(conn, "approval", organization_id, (ref_hash,), doc, record)
            return True

    def create_workflow(self, record: ConnectionWorkflowRecord):
        record = record.model_copy(deep=True)
        record.lease_token, record.lease_expires_at = None, None
        with self.repository.transaction() as conn:
            self._append_unique(conn, "workflow", record.workflow_id, record)
            if not self.repository.insert(conn, "workflow-request", record.organization_id, (record.request_id,),
                                          record.workflow_id.encode("utf-8")):
                raise ValueError("DUPLICATE_WORKFLOW_REQUEST")
        return record

    def get_workflow(self, organization_id, workflow_id):
        with self.repository.transaction() as conn:
            return self._model(conn, "workflow", organization_id, (workflow_id,), ConnectionWorkflowRecord)[1]

    def get_workflow_by_request(self, organization_id, request_id):
        with self.repository.transaction() as conn:
            alias = self.repository.get(conn, "workflow-request", organization_id, (request_id,))
            if alias is None:
                return None
            record = self._model(conn, "workflow", organization_id, (alias.body.decode("utf-8"),), ConnectionWorkflowRecord)[1]
            if record is None or record.request_id != request_id:
                raise MetadataCryptoError("METADATA_IDENTITY_CONFLICT")
            return record

    def claim_workflow(self, organization_id, workflow_id, lease_token, lease_expires_at, now):
        if not isinstance(lease_token, str) or not lease_token:
            raise ValueError("lease token is required")
        with self.repository.transaction() as conn:
            doc, record = self._model(conn, "workflow", organization_id, (workflow_id,), ConnectionWorkflowRecord, lock=True)
            if record is None or (record.lease_token is not None and record.lease_expires_at is not None
                                  and _aware(record.lease_expires_at) > _aware(now)):
                return False
            record.lease_token, record.lease_expires_at = lease_token, lease_expires_at
            self._save_model(conn, "workflow", organization_id, (workflow_id,), doc, record)
            return True

    def update_claimed_workflow(self, record, *, expected_revision, lease_token):
        if not isinstance(lease_token, str) or not lease_token or type(expected_revision) is not int:
            return False
        with self.repository.transaction() as conn:
            doc, current = self._model(conn, "workflow", record.organization_id, (record.workflow_id,), ConnectionWorkflowRecord, lock=True)
            if current is None or current.revision != expected_revision or current.lease_token != lease_token:
                return False
            for field in ("stage", "selected_candidate_id", "selected_tool", "connector_id", "connector_version",
                          "promotion_id", "last_code", "result_audit_id"):
                setattr(current, field, getattr(record, field))
            current.revision += 1
            current.lease_token, current.lease_expires_at, current.updated_at = None, None, utc_now()
            self._save_model(conn, "workflow", current.organization_id, (current.workflow_id,), doc, current)
            return True

    def release_workflow(self, organization_id, workflow_id, lease_token):
        with self.repository.transaction() as conn:
            doc, record = self._model(conn, "workflow", organization_id, (workflow_id,), ConnectionWorkflowRecord, lock=True)
            if record is None or record.lease_token != lease_token:
                return
            record.lease_token, record.lease_expires_at = None, None
            self._save_model(conn, "workflow", organization_id, (workflow_id,), doc, record)
