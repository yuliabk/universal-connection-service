import json
import pytest

from test_receipts import stores
from test_durable_execution import request, approve, build_service, execute
from universal_connection_service.receipts import execution_binding, ReceiptError


def test_legacy_receipt_defaults_to_original_binding_version(stores):
    store = stores()
    req = request()
    raw = approve(store, req, raw=req.actor.organization_id)
    svc, provider = build_service(store, req)
    assert execute(svc, req, raw).status == "success"
    receipt = store.get_receipt(req.actor.organization_id, req.operation_id)
    assert receipt.binding_schema_version == 1
    legacy = receipt.model_dump(mode="json", by_alias=True)
    del legacy["bindingSchemaVersion"]
    with store._receipt_transaction() as conn:
        store._receipt_query(conn, "UPDATE execution_receipt SET receipt_json = ? WHERE organization_id = ? AND operation_id = ?",
            (json.dumps(legacy), req.actor.organization_id, req.operation_id))
    reopened, _ = build_service(stores(), req, connector=provider)
    assert execute(reopened, req, None).status == "success"
    assert provider.calls == 1
    legacy["bindingSchemaVersion"] = 2
    with store._receipt_transaction() as conn:
        store._receipt_query(conn, "UPDATE execution_receipt SET receipt_json = ? WHERE organization_id = ? AND operation_id = ?",
            (json.dumps(legacy), req.actor.organization_id, req.operation_id))
    assert execute(reopened, req, None).error.code == "RECEIPT_STORE_UNAVAILABLE"
    assert provider.calls == 1


@pytest.mark.parametrize("version", [0, 2, True, "1"])
def test_unsupported_binding_version_cannot_be_silently_rehashed(version):
    with pytest.raises(ReceiptError, match="BINDING_SCHEMA_UNSUPPORTED"):
        execution_binding(request(), "account-1", schema_version=version)
