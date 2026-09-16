"""Trusted execution coordinator; connectors never own receipt transitions."""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
from datetime import timedelta
from uuid import uuid4

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pydantic import Field

from .approvals import approval_ref_hash
from .contracts import ConnectionError, ConnectionRequest, ConnectionResult, ConnectorResult, Model, Operation
from .receipts import ExecutionIntent, ReceiptError, execution_binding, utc_now


class ExecutionTarget(Model):
    """Operator-authored capability/account binding, never inferred from risk hints."""
    organization_id: str = Field(alias="organizationId", min_length=1)
    service_id: str = Field(alias="serviceId", min_length=1)
    capability: str = Field(min_length=1)
    provider_account_id: str = Field(alias="providerAccountId", min_length=1)
    connector_id: str = Field(alias="connectorId", min_length=1)
    connector_version: str = Field(alias="connectorVersion", min_length=1)
    operations: tuple[Operation, ...] = Field(min_length=1)
    user_ids: tuple[str, ...] = Field(alias="userIds", min_length=1)
    agent_ids: tuple[str, ...] = Field(alias="agentIds", min_length=1)
    credential_handle_hashes: tuple[str, ...] = Field(alias="credentialHandleHashes", default=())
    allow_no_credentials: bool = Field(alias="allowNoCredentials", default=False)
    success_is_final: bool = Field(alias="successIsFinal", default=False)
    result_retention_seconds: int = Field(alias="resultRetentionSeconds", ge=1, le=31_536_000)


class ResultCipher:
    """Tenant-derived AES-GCM keys and receipt-bound AAD; supports key rotation."""
    def __init__(self, keys: dict[str, bytes], active_key: str):
        if active_key not in keys or not keys or any(not k or len(v) != 32 for k, v in keys.items()):
            raise ValueError("receipt keyring requires named 256-bit keys")
        self._keys = dict(keys)
        self.active_key = active_key

    def _cipher(self, key_id, organization_id):
        key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                   info=b"ucs-receipt-result-v1:" + organization_id.encode()).derive(self._keys[key_id])
        return AESGCM(key)

    @staticmethod
    def _aad(receipt):
        return json.dumps(["ucs-result-v1", receipt.organization_id, receipt.operation_id,
                           receipt.receipt_id, receipt.binding_digest], separators=(",", ":")).encode()

    def seal(self, receipt, result: ConnectorResult, retention_seconds: int) -> str:
        body = json.dumps({"expiresAt": (utc_now() + timedelta(seconds=retention_seconds)).isoformat(),
                           "result": result.model_dump(mode="json", by_alias=True)}, allow_nan=False).encode()
        if len(body) > 1_000_000:
            raise ReceiptError("RESULT_TOO_LARGE")
        nonce = os.urandom(12)
        ciphertext = self._cipher(self.active_key, receipt.organization_id).encrypt(nonce, body, self._aad(receipt))
        return json.dumps({"keyId": self.active_key, "sealed": base64.b64encode(nonce + ciphertext).decode()})

    def open(self, receipt, envelope: str) -> ConnectorResult:
        from datetime import datetime
        try:
            packet = json.loads(envelope)
            sealed = base64.b64decode(packet["sealed"], validate=True)
            body = json.loads(self._cipher(packet["keyId"], receipt.organization_id).decrypt(sealed[:12], sealed[12:], self._aad(receipt)))
            if datetime.fromisoformat(body["expiresAt"]) <= utc_now():
                raise ReceiptError("RESULT_EXPIRED")
            return ConnectorResult.model_validate(body["result"])
        except ReceiptError:
            raise
        except Exception:
            raise ReceiptError("RESULT_UNAVAILABLE") from None


class DurableExecutor:
    def __init__(self, store, cipher: ResultCipher, targets: tuple[ExecutionTarget, ...]):
        self.store = store
        self.cipher = cipher
        self.targets = tuple(target.model_copy(deep=True) for target in targets)
        keys = [(t.organization_id, t.service_id, t.capability) for t in self.targets]
        if len(keys) != len(set(keys)):
            raise ValueError("ambiguous execution target")

    def target(self, request: ConnectionRequest) -> ExecutionTarget:
        service_id = request.service.id or request.service.name.lower().replace(" ", "-")
        match = next((t for t in self.targets if (t.organization_id, t.service_id, t.capability) ==
                      (request.actor.organization_id, service_id, request.capability)), None)
        if match is None or request.actor.user_id not in match.user_ids or request.actor.agent_id not in match.agent_ids:
            raise ReceiptError("EXECUTION_TARGET_DENIED")
        if request.operation not in match.operations:
            raise ReceiptError("EXECUTION_TARGET_DENIED")
        return match

    def protects(self, request: ConnectionRequest) -> bool:
        service_id = request.service.id or request.service.name.lower().replace(" ", "-")
        return any((t.organization_id, t.service_id, t.capability) ==
                   (request.actor.organization_id, service_id, request.capability) for t in self.targets)

    def approval_binding(self, request):
        if not request.operation_id:
            raise ReceiptError("OPERATION_ID_REQUIRED")
        return execution_binding(request, self.target(request).provider_account_id)

    def _error(self, req, code, receipt=None, *, unknown=False):
        return ConnectionResult(requestId=req.request_id, status="failed",
            serviceId=req.service.id or req.service.name.lower().replace(" ", "-"), capability=req.capability,
            auditId=receipt.audit_id or receipt.receipt_id if receipt else str(uuid4()),
            receiptId=receipt.receipt_id if receipt else None,
            executionState="unknown" if unknown else receipt.state if receipt else None,
            error=ConnectionError(code=code, message=code.replace("_", " ").lower(), retryable=False, userActionRequired=True))

    def _cached(self, req, receipt):
        if receipt.state not in {"succeeded", "failed_no_effect"}:
            return self._error(req, "EXECUTION_PENDING" if receipt.state == "pending" else "OUTCOME_UNKNOWN", receipt,
                               unknown=receipt.state == "dispatching")
        try:
            ciphertext = self.store.get_receipt_result(receipt.organization_id, receipt.operation_id)
            if ciphertext is None:
                raise ReceiptError("RESULT_UNAVAILABLE")
            result = self.cipher.open(receipt, ciphertext)
            return ConnectionResult(requestId=req.request_id, status=result.status, serviceId=receipt.service_id,
                capability=receipt.capability, connectorId=receipt.connector_id, data=result.data, error=result.error,
                auditId=receipt.audit_id, receiptId=receipt.receipt_id, executionState=receipt.state)
        except ReceiptError as exc:
            return self._error(req, exc.code, receipt)

    async def execute(self, req, ctx, registration):
        receipt = None
        dispatched = False
        dispatch_started = False
        try:
            target = self.target(req)
            if not req.operation_id:
                raise ReceiptError("OPERATION_ID_REQUIRED")
            if not self.store.receipts_durable:
                raise ReceiptError("RECEIPT_STORE_NOT_DURABLE")
            # Account binding is verified before both dispatch and result access.
            if ctx.credential_handle is None:
                if not target.allow_no_credentials or registration.manifest.auth.type != "none":
                    raise ReceiptError("EXECUTION_ACCOUNT_MISMATCH")
            elif hashlib.sha256(ctx.credential_handle.get_secret_value().encode()).hexdigest() not in target.credential_handle_hashes:
                raise ReceiptError("EXECUTION_ACCOUNT_MISMATCH")
            digest = execution_binding(req, target.provider_account_id)
            receipt = self.store.get_receipt(req.actor.organization_id, req.operation_id)
            if receipt:
                if (receipt.user_id, receipt.agent_id) != (req.actor.user_id, req.actor.agent_id):
                    receipt = None
                    raise ReceiptError("EXECUTION_TARGET_DENIED")
                if receipt.binding_digest != digest:
                    raise ReceiptError("IDEMPOTENCY_CONFLICT")
                if receipt.state != "prepared":
                    return self._cached(req, receipt)
            if (registration.manifest.connector_id, registration.manifest.version) != (target.connector_id, target.connector_version):
                raise ReceiptError("EXECUTION_CONNECTOR_MISMATCH")
            if not ctx.approval_id:
                raise ReceiptError("APPROVAL_REQUIRED")
            if not target.success_is_final:
                raise ReceiptError("EXECUTION_OUTCOME_CONTRACT_REQUIRED")
            intent = ExecutionIntent(organizationId=req.actor.organization_id, operationId=req.operation_id,
                requestId=req.request_id, userId=req.actor.user_id, agentId=req.actor.agent_id,
                serviceId=target.service_id, providerAccountId=target.provider_account_id, capability=req.capability,
                operation=req.operation, bindingDigest=digest, connectorId=target.connector_id,
                connectorVersion=target.connector_version, approvalRefHash=approval_ref_hash(ctx.approval_id))
            receipt = self.store.prepare_receipt(intent)
            if receipt.state != "prepared":
                return self._cached(req, receipt)
            dispatch_started = True
            receipt = self.store.begin_dispatch(receipt.organization_id, receipt.operation_id, receipt.version,
                                                req.request_id, require_approval=True,
                                                approval_ref_hash=approval_ref_hash(ctx.approval_id))
            dispatched = True
            # Context is copied so caller mutation cannot affect the dispatched request.
            result = await asyncio.wait_for(registration.connector.execute(req.capability, req.model_copy(deep=True).input,
                                            ctx.model_copy(deep=True)), timeout=ctx.deadline_ms / 1000)
            if not isinstance(result, ConnectorResult) or result.status != "success":
                receipt = self.store.mark_unresolved(receipt.organization_id, receipt.operation_id, receipt.version, "unknown")
                return self._error(req, "OUTCOME_UNKNOWN", receipt)
            sealed = self.cipher.seal(receipt, result, target.result_retention_seconds)
            receipt = self.store.complete_receipt(receipt.organization_id, receipt.operation_id, receipt.version,
                                                  "succeeded", result_ciphertext=sealed)
            return self._cached(req, receipt)
        except asyncio.CancelledError:
            # The committed dispatch remains uncertain for a future caller.
            raise
        except Exception as exc:
            if dispatched or (dispatch_started and not isinstance(exc, ReceiptError)):
                return self._error(req, "OUTCOME_UNKNOWN", receipt, unknown=True)
            code = exc.code if isinstance(exc, ReceiptError) else "RECEIPT_STORE_UNAVAILABLE"
            return self._error(req, code, receipt)


def executor_from_env(store) -> DurableExecutor | None:
    target_json = os.getenv("UCS_EXECUTION_TARGETS_JSON")
    keyring_json = os.getenv("UCS_RECEIPT_KEYRING_JSON")
    if not target_json and not keyring_json:
        return None
    try:
        if not target_json or not keyring_json or store is None or not store.receipts_durable:
            raise ValueError("incomplete durable execution configuration")
        config = json.loads(keyring_json)
        keys = {name: base64.b64decode(value, validate=True) for name, value in config["keys"].items()}
        return DurableExecutor(store, ResultCipher(keys, config["activeKey"]),
                               tuple(ExecutionTarget.model_validate(t) for t in json.loads(target_json)))
    except Exception:
        raise RuntimeError("Durable execution configuration is invalid") from None
