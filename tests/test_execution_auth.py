import hashlib
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from test_receipts import stores
from test_durable_execution import request, approve, build_service, execute
from universal_connection_service.control_plane import ControlPlaneCredential, StaticBearerAuthenticator
from universal_connection_service.execution_api import build_connection_execution_router


def test_cached_receipt_requires_authenticated_exact_actor_and_scope(stores):
    store = stores()
    req = request()
    raw = approve(store, req, raw=req.actor.organization_id)
    svc, provider = build_service(store, req)
    original = execute(svc, req, raw)
    assert original.status == "success"
    actors = (req.actor,)
    credentials = tuple(ControlPlaneCredential(tokenSha256=hashlib.sha256(token.encode()).hexdigest(),
        subject="synthetic-caller", tokenId=token, organizations=orgs, scopes=scopes, executionActors=grants)
        for token, orgs, scopes, grants in [
            ("valid", (req.actor.organization_id,), ("connections:execute",), actors),
            ("wrong-org", ("other-org",), ("connections:execute",), actors),
            ("wrong-scope", (req.actor.organization_id,), ("connectors:review",), actors),
            ("no-actors", (req.actor.organization_id,), ("connections:execute",), ()),
        ])
    app = FastAPI()
    app.include_router(build_connection_execution_router(svc, StaticBearerAuthenticator(credentials)))
    def body(candidate):
        return {"request": candidate.model_dump(by_alias=True), "context": {
            "requestId": candidate.request_id, "userId": candidate.actor.user_id,
            "organizationId": candidate.actor.organization_id}}
    with TestClient(app) as http:
        for token in (None, "invalid", "wrong-org", "wrong-scope", "no-actors"):
            response = http.post("/v1/connections/execute", json=body(req),
                headers={"Authorization": "Bearer " + token} if token else {})
            assert response.status_code == (401 if token in {None, "invalid"} else 403)
            assert "synthetic-sensitive-result" not in response.text
        for field in ("user_id", "agent_id", "organization_id"):
            forged = req.model_copy(deep=True)
            setattr(forged.actor, field, "forged")
            assert http.post("/v1/connections/execute", json=body(forged),
                headers={"Authorization": "Bearer valid"}).status_code == 403
        response = http.post("/v1/connections/execute", json=body(req), headers={"Authorization": "Bearer valid"})
        assert response.status_code == 200
        assert response.json()["data"] == original.data
        assert response.json()["receiptId"] == original.receipt_id
        mismatched = body(req)
        mismatched["context"]["userId"] = "forged"
        response = http.post("/v1/connections/execute", json=mismatched, headers={"Authorization": "Bearer valid"})
        assert response.json()["error"]["code"] == "EXECUTION_CONTEXT_MISMATCH"
    assert provider.calls == 1


def test_authentication_precedes_service_or_receipt_access():
    class UnreachableService:
        async def execute(self, req, ctx):
            raise AssertionError("unauthorized request reached service")
    app = FastAPI()
    app.include_router(build_connection_execution_router(UnreachableService(), None))
    req = request()
    with TestClient(app) as http:
        response = http.post("/v1/connections/execute", json={"request": req.model_dump(by_alias=True),
            "context": {"requestId": req.request_id, "userId": req.actor.user_id, "organizationId": req.actor.organization_id}})
        assert response.status_code == 503
