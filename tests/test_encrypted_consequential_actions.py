"""Explicit delete/payment acceptance scenarios; no real external actions."""
import pytest

from test_metadata_storage import repositories, stores
from test_encrypted_receipt_store import encrypted_stores
from test_durable_execution import request, approve, build_service, execute, make_target, WriteConnector
from universal_connection_service.contracts import ConnectorResult


@pytest.mark.parametrize("action", ["delete", "financial"])
@pytest.mark.parametrize("failure", ["provider_timeout", "completion_unavailable", "none"])
def test_delete_and_financial_effects_are_not_repeated(encrypted_stores, monkeypatch, action, failure):
    store = encrypted_stores()
    req = request()
    req.operation = "delete" if action == "delete" else "create"
    req.input = ({"value": "synthetic-record-to-delete"} if action == "delete" else
                 {"value": "synthetic-payment", "amountMinor": 12500, "currency": "ILS", "beneficiary": "synthetic-account"})
    req.risk_hints.financial = action == "financial"
    target = make_target(req).model_copy(update={"operations": (req.operation,)})
    effects = []
    class Provider(WriteConnector):
        async def execute(self, capability, input, context):
            self.calls += 1
            effects.append(dict(input))
            if failure == "provider_timeout":
                raise TimeoutError("synthetic acknowledgement lost after effect")
            return ConnectorResult(status="success", data={"effect": action})
    provider = Provider()
    service, _ = build_service(store, req, connector=provider, target=target)
    assert execute(service, req, None).error.code == "APPROVAL_REQUIRED"
    assert not effects
    raw = approve(store, req, raw=req.actor.organization_id)
    with monkeypatch.context() as patch:
        if failure == "completion_unavailable":
            def fail(*args, **kwargs):
                raise OSError("synthetic result storage unavailable")
            patch.setattr(store, "complete_receipt", fail)
        first = execute(service, req, raw)
    assert len(effects) == 1
    recovered, _ = build_service(encrypted_stores(), req, connector=provider, target=target)
    retry_request = req.model_copy(update={"request_id": "new-transport-attempt"})
    result = execute(recovered, retry_request, None)
    assert result.receipt_id == first.receipt_id
    if failure == "none":
        assert result.status == "success" and result.data == {"effect": action}
    else:
        assert first.error.code == result.error.code == "OUTCOME_UNKNOWN"
        assert result.execution_state in {"dispatching", "unknown"}
    changed = retry_request.model_copy(deep=True)
    changed.input["currency" if action == "financial" else "value"] = "different-target-or-currency"
    assert execute(recovered, changed, raw).error.code == "IDEMPOTENCY_CONFLICT"
    assert len(effects) == provider.calls == 1
