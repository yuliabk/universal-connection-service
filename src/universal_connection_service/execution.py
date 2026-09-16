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
from .recovery import RecoveryContract, ProviderExecutionKey, ProviderOutcome


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
    recovery: RecoveryContract | None = None


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

    def _decode(self, receipt, envelope: str):
        try:
            packet = json.loads(envelope)
            sealed = base64.b64decode(packet["sealed"], validate=True)
            body = json.loads(self._cipher(packet["keyId"], receipt.organization_id).decrypt(sealed[:12], sealed[12:], self._aad(receipt)))
            return body
        except ReceiptError:
            raise
        except Exception:
            raise ReceiptError("RESULT_UNAVAILABLE") from None

    def expires_at(self, receipt, envelope: str):
        from datetime import datetime, timezone
        try:
            expires = datetime.fromisoformat(self._decode(receipt, envelope)["expiresAt"])
            if expires.tzinfo is None:
                raise ValueError("expiry requires timezone")
            return expires.astimezone(timezone.utc)
        except Exception:
            raise ReceiptError("RESULT_UNAVAILABLE") from None

    def open(self, receipt, envelope: str) -> ConnectorResult:
        if self.expires_at(receipt, envelope) <= utc_now():
            raise ReceiptError("RESULT_EXPIRED")
        try:
            return ConnectorResult.model_validate(self._decode(receipt, envelope)["result"])
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
                current = self.store.get_receipt(receipt.organization_id, receipt.operation_id)
                raise ReceiptError("RESULT_EXPIRED" if current and current.result_purged_at else "RESULT_UNAVAILABLE")
            result = self.cipher.open(receipt, ciphertext)
            return ConnectionResult(requestId=req.request_id, status=result.status, serviceId=receipt.service_id,
                capability=receipt.capability, connectorId=receipt.connector_id, data=result.data, error=result.error,
                auditId=receipt.audit_id, receiptId=receipt.receipt_id, executionState=receipt.state)
        except ReceiptError as exc:
            return self._error(req, exc.code, receipt)

    @staticmethod
    def _recovery_contract(target, registration):
        if target.recovery is None:
            raise ReceiptError("RECOVERY_NOT_CONFIGURED")
        connector = registration.connector
        if ((registration.manifest.connector_id, registration.manifest.version) !=
                (target.connector_id, target.connector_version) or
                not callable(getattr(connector, "recovery_contract_digest", None)) or
                connector.recovery_contract_digest() != target.recovery.digest() or
                not callable(getattr(connector, "execute_keyed", None)) or
                not callable(getattr(connector, "lookup_execution", None))):
            raise ReceiptError("RECOVERY_CONTRACT_MISMATCH")
        return target.recovery

    @staticmethod
    def _provider_key(receipt):
        return ProviderExecutionKey(providerKey=receipt.provider_key,
            providerAccountId=receipt.provider_account_id, bindingDigest=receipt.binding_digest,
            contractDigest=receipt.recovery_contract_digest, notAfter=receipt.provider_not_after)

    async def _dispatch_result(self, req, ctx, registration, target, receipt, contract):
        timeout = ctx.deadline_ms / 1000
        if receipt.provider_not_after is not None:
            timeout = min(timeout, (receipt.provider_not_after - utc_now()).total_seconds())
        if timeout <= 0:
            raise ReceiptError("REPLAY_BUDGET_EXHAUSTED")
        call = (registration.connector.execute_keyed(req.capability, req.model_copy(deep=True).input,
                ctx.model_copy(deep=True), self._provider_key(receipt)) if contract else
                registration.connector.execute(req.capability, req.model_copy(deep=True).input, ctx.model_copy(deep=True)))
        result = await asyncio.wait_for(call, timeout=timeout)
        if not isinstance(result, ConnectorResult) or result.status != "success":
            receipt = self.store.mark_unresolved(receipt.organization_id, receipt.operation_id, receipt.version, "unknown")
            return self._error(req, "OUTCOME_UNKNOWN", receipt)
        sealed = self.cipher.seal(receipt, result, target.result_retention_seconds)
        receipt = self.store.complete_receipt(receipt.organization_id, receipt.operation_id, receipt.version,
                                              "succeeded", result_ciphertext=sealed)
        return self._cached(req, receipt)

    async def _replay(self, req, ctx, registration, target, receipt):
        contract = self._recovery_contract(target, registration)
        if (contract.replay is None or not target.success_is_final):
            raise ReceiptError("REPLAY_NOT_CONFIGURED")
        if (receipt.recovery_contract_digest != contract.digest() or
            (receipt.connector_id, receipt.connector_version) != (target.connector_id, target.connector_version)):
            raise ReceiptError("RECOVERY_CONTRACT_MISMATCH")
        if not ctx.approval_id:
            raise ReceiptError("APPROVAL_REQUIRED")
        try:
            receipt = self.store.begin_receipt_replay(receipt.organization_id, receipt.operation_id,
                receipt.version, req.request_id, contract.digest(), contract.replay.max_attempts,
                approval_ref_hash(ctx.approval_id))
        except ReceiptError:
            raise
        except Exception:
            # A lost replay-commit acknowledgement must not cause connector IO.
            return self._error(req, "OUTCOME_UNKNOWN", receipt, unknown=True)
        try:
            return await self._dispatch_result(req, ctx, registration, target, receipt, contract)
        except asyncio.CancelledError:
            raise
        except Exception:
            current = self.store.get_receipt(receipt.organization_id, receipt.operation_id)
            if current and current.state in {"succeeded", "failed_no_effect"}:
                return self._cached(req, current)
            return self._error(req, "OUTCOME_UNKNOWN", current or receipt, unknown=True)

    async def _reconcile(self, req, ctx, registration, target, receipt):
        contract = self._recovery_contract(target, registration)
        if (receipt.recovery_contract_digest != contract.digest() or
            (receipt.connector_id, receipt.connector_version) != (target.connector_id, target.connector_version)):
            raise ReceiptError("RECOVERY_CONTRACT_MISMATCH")
        deadline = receipt.created_at + timedelta(seconds=contract.lookup_window_seconds)
        receipt = self.store.begin_receipt_lookup(receipt.organization_id, receipt.operation_id,
            receipt.version, contract.digest(), contract.max_lookups, deadline)
        key = self._provider_key(receipt)
        try:
            timeout = min(ctx.deadline_ms, contract.lookup_timeout_ms) / 1000
            timeout = min(timeout, (deadline - utc_now()).total_seconds())
            if timeout <= 0:
                raise ReceiptError("RECOVERY_BUDGET_EXHAUSTED")
            outcome = await asyncio.wait_for(registration.connector.lookup_execution(
                req.capability, ctx.model_copy(deep=True), key.model_copy(deep=True)), timeout=timeout)
            if isinstance(outcome, ProviderOutcome):
                # Revalidate even a model instance: adapter code could mutate it.
                outcome = ProviderOutcome.model_validate(outcome.model_dump())
            if (not isinstance(outcome, ProviderOutcome) or any(getattr(outcome, name) != value
                    for name, value in key.model_dump().items())):
                raise ReceiptError("RECOVERY_OUTCOME_MISMATCH")
            if outcome.state in {"unknown", "not_found", "pending"}:
                receipt = self.store.mark_unresolved(receipt.organization_id, receipt.operation_id,
                    receipt.version, "pending" if outcome.state == "pending" else "unknown")
            else:
                sealed = self.cipher.seal(receipt, outcome.result, target.result_retention_seconds)
                receipt = self.store.complete_receipt(receipt.organization_id, receipt.operation_id,
                    receipt.version, outcome.state, result_ciphertext=sealed)
            return self._cached(req, receipt)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            # A competing lookup may have completed; never execute to recover.
            current = self.store.get_receipt(receipt.organization_id, receipt.operation_id)
            if current and current.state in {"succeeded", "failed_no_effect"}:
                return self._cached(req, current)
            return self._error(req, exc.code if isinstance(exc, ReceiptError) else "OUTCOME_UNKNOWN",
                current or receipt)

    async def execute(self, req, ctx, registration, *, allow_dispatch=True, reconcile=False, replay=False):
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
                    if replay and allow_dispatch and receipt.state not in {"succeeded", "failed_no_effect"}:
                        return await self._replay(req, ctx, registration, target, receipt)
                    if reconcile and receipt.state not in {"succeeded", "failed_no_effect"}:
                        return await self._reconcile(req, ctx, registration, target, receipt)
                    return self._cached(req, receipt)
            if not allow_dispatch or reconcile or replay:
                return self._error(req, "RECEIPT_NOT_DISPATCHED", receipt)
            if (registration.manifest.connector_id, registration.manifest.version) != (target.connector_id, target.connector_version):
                raise ReceiptError("EXECUTION_CONNECTOR_MISMATCH")
            if not ctx.approval_id:
                raise ReceiptError("APPROVAL_REQUIRED")
            if not target.success_is_final:
                raise ReceiptError("EXECUTION_OUTCOME_CONTRACT_REQUIRED")
            contract = self._recovery_contract(target, registration) if target.recovery else None
            intent = ExecutionIntent(organizationId=req.actor.organization_id, operationId=req.operation_id,
                requestId=req.request_id, userId=req.actor.user_id, agentId=req.actor.agent_id,
                serviceId=target.service_id, providerAccountId=target.provider_account_id, capability=req.capability,
                operation=req.operation, bindingDigest=digest, connectorId=target.connector_id,
                connectorVersion=target.connector_version, approvalRefHash=approval_ref_hash(ctx.approval_id),
                recoveryContractDigest=contract.digest() if contract else None)
            receipt = self.store.prepare_receipt(intent)
            if receipt.state != "prepared":
                return self._cached(req, receipt)
            if receipt.recovery_contract_digest != (contract.digest() if contract else None):
                raise ReceiptError("RECOVERY_CONTRACT_MISMATCH")
            dispatch_started = True
            receipt = self.store.begin_dispatch(receipt.organization_id, receipt.operation_id, receipt.version,
                                                req.request_id, require_approval=True,
                                                approval_ref_hash=approval_ref_hash(ctx.approval_id),
                                                replay_window_seconds=contract.replay.deduplication_window_seconds
                                                if contract and contract.replay else None)
            dispatched = True
            return await self._dispatch_result(req, ctx, registration, target, receipt, contract)
        except asyncio.CancelledError:
            # The committed dispatch remains uncertain for a future caller.
            raise
        except Exception as exc:
            if dispatched or (dispatch_started and not isinstance(exc, ReceiptError)):
                return self._error(req, "OUTCOME_UNKNOWN", receipt, unknown=True)
            code = exc.code if isinstance(exc, ReceiptError) else "RECEIPT_STORE_UNAVAILABLE"
            if code in {"RECEIPT_STATE_CONFLICT", "APPROVAL_ALREADY_USED", "APPROVAL_UNAVAILABLE"} and receipt is not None:
                try:
                    current = self.store.get_receipt(receipt.organization_id, receipt.operation_id)
                    if current is not None and current.state != "prepared":
                        return self._cached(req, current)
                except Exception:
                    return self._error(req, "OUTCOME_UNKNOWN", receipt, unknown=True)
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
