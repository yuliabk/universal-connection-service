"""Encrypted append-only witness, retaining the existing restore checks."""
from .dispatch_witness import DispatchWitness
from .receipts import ExecutionReceipt, ReceiptError


_WITNESS = "ucs:encrypted-witness:v1"


class EncryptedDispatchWitness(DispatchWitness):
    def __init__(self, repository, witness_id):
        self.repository = repository
        super().__init__(repository.store, witness_id)

    @staticmethod
    def initialize(repository, witness_id):
        if not isinstance(witness_id, str) or not witness_id:
            raise ValueError("witness identity required")
        with repository.transaction() as conn:
            # Provision only a fresh encrypted area. Never reset existing witness
            # attempts or accidentally designate an encrypted primary as witness.
            postgres = hasattr(repository.store, "config")
            prefix = "ucs_internal." if postgres else ""
            for table in ("metadata_document", "metadata_tenant", "execution_receipt", "approval_grant",
                          "audit_event", "evidence", "connector_state", "connection_workflow"):
                if conn.execute(f"SELECT 1 FROM {prefix}{table} LIMIT 1").fetchone():
                    raise ReceiptError("EXECUTION_WITNESS_NOT_EMPTY")
            legacy = (conn.execute("SELECT to_regclass('ucs_internal.dispatch_witness_identity') AS existing").fetchone()["existing"]
                      if postgres else conn.execute("SELECT 1 FROM sqlite_master WHERE name = 'dispatch_witness_identity'").fetchone())
            if legacy:
                raise ReceiptError("EXECUTION_WITNESS_NOT_EMPTY")
            if not repository.insert(conn, "witness-identity", _WITNESS, ("identity",), witness_id.encode()):
                raise ReceiptError("EXECUTION_WITNESS_IDENTITY_MISMATCH")

    def _transaction(self):
        return self.repository.transaction()

    def _identity(self, conn):
        doc = self.repository.get(conn, "witness-identity", _WITNESS, ("identity",))
        if doc is None or doc.body.decode() != self.witness_id:
            raise ReceiptError("EXECUTION_WITNESS_IDENTITY_MISMATCH")

    def _domain(self, organization_id, operation_id):
        # The equality index is opaque even in the domain column. Each operation
        # has its own bounded-attempt log; no mutable 'latest' pointer can hide a
        # newer append-only record if that pointer is restored or deleted.
        return self.repository.cipher.index("witness-operation", organization_id,
                                             self.repository.profile_id, operation_id)

    def _latest(self, conn, organization_id, operation_id):
        domain, cursor, latest = self._domain(organization_id, operation_id), "", None
        while page := self.repository.page(conn, domain, organization_id, after=cursor):
            for doc in page:
                receipt = ExecutionReceipt.model_validate_json(doc.body)
                if receipt.organization_id != organization_id or receipt.operation_id != operation_id:
                    raise ReceiptError("EXECUTION_WITNESS_IDENTITY_MISMATCH")
                if latest is None or receipt.attempt_count > latest.attempt_count:
                    latest = receipt
            cursor = page[-1].cursor
        return latest

    def _insert_attempt(self, conn, receipt):
        return self.repository.insert(conn, self._domain(receipt.organization_id, receipt.operation_id),
            receipt.organization_id, (str(receipt.attempt_count),), receipt.model_dump_json().encode())
