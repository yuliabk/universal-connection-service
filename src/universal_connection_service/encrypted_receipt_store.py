"""Encrypted StateStore, reusing the established receipt state machine.

All SQL receipt persistence hooks are overridden. Unknown SQL paths fail closed;
there is no delegation to the physical store's plaintext domain tables.
"""
from __future__ import annotations

import heapq
import json
from collections import Counter
from uuid import uuid4

from .encrypted_control_store import EncryptedControlStore, _DIRECTORY, _body, _aware
from .execution_observability import NOTICE_CODES
from .metadata_crypto import MetadataCryptoError
from .persistence import AuditEvent
from .receipt_store import SQLReceiptStore
from .receipts import ExecutionReceipt, ReceiptAudit, ReceiptError, utc_now


def _json(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


class EncryptedStateStore(EncryptedControlStore, SQLReceiptStore):
    def __init__(self, repository):
        super().__init__(repository)
        # Physical identity is needed by the independent-witness check. No
        # arbitrary backend method forwarding is permitted.
        for name in ("path", "config", "test_witness_path"):
            if hasattr(repository.store, name):
                setattr(self, name, getattr(repository.store, name))

    @property
    def receipts_durable(self):
        return self.repository.store.receipts_durable

    def _receipt_transaction(self):
        return self.repository.transaction()

    def _receipt_query(self, conn, sql, args=()):
        raise MetadataCryptoError("PLAINTEXT_RECEIPT_ACCESS_FORBIDDEN")

    def _approval_row(self, conn, ref_hash):
        if ref_hash is None:
            return None
        record = self._approval(conn, ref_hash)[1]
        return record.model_dump() if record else None

    def _consume_execution_approval(self, conn, receipt, now):
        doc, record = self._approval(conn, receipt.approval_ref_hash, lock=True)
        if (record is None or record.organization_id != receipt.organization_id
            or record.consumed_at is not None or record.revoked_at is not None or _aware(record.expires_at) <= now):
            return False
        record.consumed_at = now
        self._save_model(conn, "approval", record.organization_id, (record.approval_ref_hash,), doc, record)
        return True

    def _lock_execution_approval(self, conn, receipt):
        _, record = self._approval(conn, receipt.approval_ref_hash, lock=True)
        return (record is not None and record.organization_id == receipt.organization_id
                and record.consumed_at is not None and record.revoked_at is None)

    def _load_receipt(self, conn, organization_id, operation_id):
        _, receipt = self._model(conn, "receipt", organization_id, (operation_id,), ExecutionReceipt)
        if receipt is not None and receipt.operation_id != operation_id:
            raise ReceiptError("RECEIPT_IDENTITY_CONFLICT")
        return receipt

    def _insert_receipt(self, conn, receipt):
        if self.repository.insert(conn, "receipt", receipt.organization_id, (receipt.operation_id,), _body(receipt)):
            if (not self._reserve_global(conn, "receipt", receipt.receipt_id, receipt.organization_id)
                or not self.repository.insert(conn, "receipt-id", receipt.organization_id, (receipt.receipt_id,), receipt.operation_id.encode())):
                raise ReceiptError("RECEIPT_IDENTITY_CONFLICT")

    def _save(self, conn, receipt, expected_version):
        doc, current = self._model(conn, "receipt", receipt.organization_id, (receipt.operation_id,), ExecutionReceipt)
        if current is None or current.version != expected_version:
            raise ReceiptError("RECEIPT_STATE_CONFLICT")
        receipt.version, receipt.updated_at = expected_version + 1, utc_now()
        if not self.repository.compare_and_swap(conn, "receipt", receipt.organization_id,
                                               (receipt.operation_id,), doc.revision, _body(receipt)):
            raise ReceiptError("RECEIPT_STATE_CONFLICT")

    def _lock_receipt_row(self, conn, organization_id, operation_id):
        self.repository.get(conn, "receipt", organization_id, (operation_id,), lock=True)

    def _append_execution_attempt(self, conn, receipt, request_id):
        body = _json(dict(organizationId=receipt.organization_id, operationId=receipt.operation_id,
            attemptId=receipt.attempt_id, requestId=request_id, receiptVersion=receipt.version,
            createdAt=receipt.updated_at.isoformat()))
        if not self.repository.insert(conn, "attempt", receipt.organization_id, (receipt.attempt_id,), body):
            raise ReceiptError("RECEIPT_ATTEMPT_CONFLICT")

    def _write_completion(self, conn, receipt, event, result_ciphertext):
        org, op = receipt.organization_id, receipt.operation_id
        if result_ciphertext is not None:
            if not self.repository.insert(conn, "result", org, (op,), result_ciphertext.encode()):
                raise ReceiptError("RESULT_IDENTITY_CONFLICT")
            if not self.repository.insert(conn, "result-scan", _DIRECTORY, (receipt.receipt_id,),
                _json(dict(organizationId=org, operationId=op, receiptId=receipt.receipt_id))):
                raise ReceiptError("RESULT_IDENTITY_CONFLICT")
        if (not self.repository.insert(conn, "outbox", org, (event.event_id,), _body(event))
            or not self.repository.insert(conn, "pending-outbox", org, (event.event_id,), _body(event))):
            raise ReceiptError("AUDIT_OUTBOX_CONFLICT")

    def get_receipt_result(self, organization_id, operation_id):
        with self._receipt_transaction() as conn:
            doc = self.repository.get(conn, "result", organization_id, (operation_id,))
            return doc.body.decode() if doc else None

    def _documents(self, conn, domain, org):
        after = ""
        while page := self.repository.page(conn, domain, org, after=after):
            yield from page
            after = page[-1].cursor

    @staticmethod
    def _limit(limit, maximum=100):
        if type(limit) is not int or not 1 <= limit <= maximum:
            raise ValueError("invalid page limit")

    def _pending_events(self, conn, org, limit):
        return heapq.nsmallest(limit, self._records(conn, "pending-outbox", org, ReceiptAudit), key=lambda e: e.event_id)

    def pending_receipt_audit(self, organization_id, limit=100):
        self._limit(limit, 1000)
        with self._receipt_transaction() as conn:
            return self._pending_events(conn, organization_id, limit)

    def _acknowledge_audit(self, conn, org, event_id):
        if self.repository.get(conn, "outbox", org, (event_id,)) is None:
            return False
        pending = self.repository.get(conn, "pending-outbox", org, (event_id,), lock=True)
        if pending and not self.repository.delete(conn, "pending-outbox", org, (event_id,), pending.revision):
            raise ReceiptError("AUDIT_OUTBOX_CONFLICT")
        return True

    def acknowledge_receipt_audit(self, organization_id, event_id):
        with self._receipt_transaction() as conn:
            return self._acknowledge_audit(conn, organization_id, event_id)

    def receipt_audit_organizations(self, limit=100, *, after=""):
        self._limit(limit, 1000)
        with self._receipt_transaction() as conn:
            def pending_orgs():
                cursor = ""
                while page := self.repository.tenant_page(conn, after=cursor):
                    for _, org in page:
                        if org > after and self.repository.page(conn, "pending-outbox", org, limit=1):
                            yield org
                    cursor = page[-1][0]
            return heapq.nsmallest(limit, pending_orgs())

    def deliver_receipt_audit(self, organization_id, limit=100):
        self._limit(limit, 1000)
        with self._receipt_transaction() as conn:
            events = self._pending_events(conn, organization_id, limit)
            for event in events:
                receipt = self._load_receipt(conn, organization_id, event.operation_id)
                if (receipt is None or receipt.audit_id != event.event_id or receipt.receipt_id != event.receipt_id
                    or receipt.state != event.state or event.organization_id != organization_id):
                    raise ReceiptError("AUDIT_OUTBOX_CONFLICT")
                audit = AuditEvent(auditId=event.event_id, requestId=event.request_id, organizationId=organization_id,
                    userId=event.user_id, agentId=event.agent_id, serviceId=event.service_id,
                    capability=event.capability, operation=event.operation,
                    status="success" if event.state == "succeeded" else "failed", connectorId=event.connector_id,
                    policyDecision=None, errorCode=None if event.state == "succeeded" else "EXECUTION_FAILED_NO_EFFECT",
                    approvalRefHash=receipt.approval_ref_hash, createdAt=event.created_at)
                if self._reserve_global(conn, "audit", event.event_id, organization_id):
                    if not self.repository.insert(conn, "audit", organization_id, (event.event_id,), _body(audit)):
                        raise ReceiptError("AUDIT_EVENT_CONFLICT")
                owner = self._global_owner(conn, "audit", event.event_id)
                existing = self._model(conn, "audit", organization_id, (event.event_id,), AuditEvent)[1]
                if owner != organization_id or existing != audit:
                    raise ReceiptError("AUDIT_EVENT_CONFLICT")
                self._acknowledge_audit(conn, organization_id, event.event_id)
            return len(events)

    def receipt_result_page(self, after="", limit=10):
        self._limit(limit)
        with self._receipt_transaction() as conn:
            references = (json.loads(doc.body) for doc in self._documents(conn, "result-scan", _DIRECTORY))
            chosen = heapq.nsmallest(limit, (r for r in references if r["receiptId"] > after), key=lambda r: r["receiptId"])
            result = []
            for ref in chosen:
                receipt = self.repository.get(conn, "receipt", ref["organizationId"], (ref["operationId"],))
                payload = self.repository.get(conn, "result", ref["organizationId"], (ref["operationId"],))
                if receipt is None or payload is None:
                    raise ReceiptError("RESULT_IDENTITY_CONFLICT")
                result.append((ref["receiptId"], receipt.body.decode(), payload.body.decode()))
            return result

    def purge_receipt_result(self, organization_id, operation_id, expected_version, ciphertext):
        with self._receipt_transaction() as conn:
            doc = self.repository.get(conn, "result", organization_id, (operation_id,), lock=True)
            if doc is None or doc.body.decode() != ciphertext:
                return False
            receipt = self._expected(conn, organization_id, operation_id, expected_version, {"succeeded", "failed_no_effect"})
            reference = self.repository.get(conn, "result-scan", _DIRECTORY, (receipt.receipt_id,), lock=True)
            if reference is None:
                raise ReceiptError("RESULT_IDENTITY_CONFLICT")
            if (not self.repository.delete(conn, "result", organization_id, (operation_id,), doc.revision)
                or not self.repository.delete(conn, "result-scan", _DIRECTORY, (receipt.receipt_id,), reference.revision)):
                raise ReceiptError("RECEIPT_STATE_CONFLICT")
            receipt.result_purged_at = utc_now()
            self._save(conn, receipt, expected_version)
            return True

    def _record_execution_notice(self, conn, organization_id, receipt_id, code):
        if code not in NOTICE_CODES:
            raise ValueError("unsupported execution notice")
        alias = self.repository.get(conn, "receipt-id", organization_id, (receipt_id,))
        if alias is None:
            return
        receipt = self._load_receipt(conn, organization_id, alias.body.decode())
        if receipt is None or receipt.receipt_id != receipt_id:
            raise ReceiptError("RECEIPT_IDENTITY_CONFLICT")
        identity = (receipt_id, code)
        now = utc_now().isoformat()
        notice = dict(notice_id=str(uuid4()), receipt_id=receipt_id, code=code, first_seen=now, last_seen=now, observations=1)
        if self.repository.insert(conn, "notice", organization_id, identity, _json(notice)):
            return
        doc = self.repository.get(conn, "notice", organization_id, identity, lock=True)
        notice = json.loads(doc.body)
        notice["last_seen"], notice["observations"] = now, notice["observations"] + 1
        if not self.repository.compare_and_swap(conn, "notice", organization_id, identity, doc.revision, _json(notice)):
            raise ReceiptError("NOTICE_STATE_CONFLICT")

    def execution_notices(self, organization_id, *, after="", limit=100):
        self._limit(limit)
        with self._receipt_transaction() as conn:
            rows = (json.loads(doc.body) for doc in self._documents(conn, "notice", organization_id))
            return heapq.nsmallest(limit, (r for r in rows if r["notice_id"] > after), key=lambda r: r["notice_id"])

    def execution_metrics(self, organization_id):
        with self._receipt_transaction() as conn:
            counts, observations, oldest = Counter(), Counter(), None
            for receipt in self._records(conn, "receipt", organization_id, ExecutionReceipt):
                counts[receipt.state] += 1
                if receipt.state in {"dispatching", "unknown", "pending"}:
                    oldest = min(oldest, receipt.created_at) if oldest else receipt.created_at
            for doc in self._documents(conn, "notice", organization_id):
                notice = json.loads(doc.body)
                observations[notice["code"]] += notice["observations"]
            backlog = sum(1 for _ in self._documents(conn, "pending-outbox", organization_id))
        return dict(receiptStates=dict(counts), unknownReceipts=counts["unknown"] + counts["dispatching"],
            outboxBacklog=backlog, oldestUnresolvedAgeSeconds=max(0, (utc_now() - oldest).total_seconds()) if oldest else 0,
            noticeObservations=dict(observations))
