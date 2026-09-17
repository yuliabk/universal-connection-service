import hashlib
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from test_receipts import stores
from test_execution_recovery import setup, contract, reconcile
from test_durable_execution import request, approve, build_service, execute
from universal_connection_service.control_plane import ControlPlaneCredential, StaticBearerAuthenticator
from universal_connection_service.execution_api import build_execution_router


def test_budget_notice_survives_restart_with_stable_identity_and_no_payload(stores):
    store = stores()
    req, provider, svc, target = setup(store, contract(max_lookups=1))
    provider.outcome = "unknown"
    reconcile(svc, req)
    assert reconcile(svc, req).error.code == "RECOVERY_BUDGET_EXHAUSTED"
    notices = store.execution_notices(req.actor.organization_id)
    notice = next(n for n in notices if n["code"] == "RECOVERY_BUDGET_EXHAUSTED")
    reopened = stores()
    svc2, _ = build_service(reopened, req, connector=provider, target=target)
    assert reconcile(svc2, req).error.code == "RECOVERY_BUDGET_EXHAUSTED"
    updated = next(n for n in reopened.execution_notices(req.actor.organization_id) if n["code"] == notice["code"])
    assert updated["notice_id"] == notice["notice_id"] and updated["first_seen"] == notice["first_seen"]
    assert updated["observations"] == 2
    assert "synthetic-sensitive-result" not in str(notices)
    assert set(notice) == {"notice_id", "receipt_id", "code", "first_seen", "last_seen", "observations"}
    assert provider.calls == provider.lookups == 1
    metrics = reopened.execution_metrics(req.actor.organization_id)
    assert metrics["unknownReceipts"] == 1 and metrics["oldestUnresolvedAgeSeconds"] >= 0
    assert metrics["noticeObservations"]["RECOVERY_BUDGET_EXHAUSTED"] == 2
    assert req.actor.organization_id not in str(metrics) and notice["receipt_id"] not in str(metrics)


def test_notice_scope_pagination_and_concurrent_counts(stores):
    store = stores()
    req, _, _, _ = setup(store)
    receipt = store.get_receipt(req.actor.organization_id, req.operation_id)
    store.record_execution_notice("other", receipt.receipt_id, "IDEMPOTENCY_CONFLICT")
    assert store.execution_notices("other") == []
    assert store.execution_metrics("other")["unknownReceipts"] == 0
    workers = [stores(), stores()]
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(lambda worker: worker.record_execution_notice(req.actor.organization_id,
            receipt.receipt_id, "IDEMPOTENCY_CONFLICT"), workers))
    first = store.execution_notices(req.actor.organization_id, limit=1)
    second = store.execution_notices(req.actor.organization_id, after=first[0]["notice_id"], limit=1)
    assert len(first) == len(second) == 1
    assert first[0]["notice_id"] != second[0]["notice_id"]
    conflict = next(n for n in first + second if n["code"] == "IDEMPOTENCY_CONFLICT")
    assert conflict["observations"] == 2
    with pytest.raises(ValueError):
        store.record_execution_notice(req.actor.organization_id, receipt.receipt_id, "raw-secret-error")


def test_metrics_outbox_backlog_tracks_delivery_without_business_io(stores):
    store = stores()
    req = request()
    raw = approve(store, req, raw=req.actor.organization_id)
    svc, provider = build_service(store, req)
    execute(svc, req, raw)
    assert store.execution_metrics(req.actor.organization_id)["outboxBacklog"] == 1
    store.deliver_receipt_audit(req.actor.organization_id)
    metrics = store.execution_metrics(req.actor.organization_id)
    assert metrics["outboxBacklog"] == 0 and metrics["receiptStates"] == {"succeeded": 1}
    assert provider.calls == 1


def test_notice_failure_never_redispatches_or_reports_success(stores, monkeypatch):
    store = stores()
    req, provider, svc, _ = setup(store)
    def unavailable(*args):
        raise RuntimeError("must-not-leak")
    monkeypatch.setattr(store, "record_execution_notice", unavailable)
    result = execute(svc, req, None)
    assert result.error.code == "EXECUTION_NOTICE_STORE_UNAVAILABLE"
    assert result.execution_state == "unknown" and result.status == "failed"
    assert "must-not-leak" not in result.model_dump_json()
    assert provider.calls == 1


def test_observation_api_requires_distinct_scope_and_tenant(stores):
    store = stores()
    req, _, svc, _ = setup(store)
    org = req.actor.organization_id
    credentials = tuple(ControlPlaneCredential(tokenSha256=hashlib.sha256(token.encode()).hexdigest(),
        subject="synthetic", tokenId=token, organizations=orgs, scopes=scopes)
        for token, orgs, scopes in [("observer", (org,), ("executions:observe",)),
            ("executor", (org,), ("connections:execute",)), ("other", ("other",), ("executions:observe",))])
    app = FastAPI()
    app.include_router(build_execution_router(svc, StaticBearerAuthenticator(credentials)))
    with TestClient(app) as http:
        for path in ("notices", "metrics"):
            url = f"/v1/control-plane/executions/{path}"
            for token, status in [(None, 401), ("executor", 403), ("other", 403), ("observer", 200)]:
                response = http.get(url, params={"organizationId": org},
                    headers={"Authorization": "Bearer " + token} if token else {})
                assert response.status_code == status
                assert "synthetic-sensitive-result" not in response.text
            assert http.get(url, params={"organizationId": "other"},
                headers={"Authorization": "Bearer observer"}).status_code == 403
