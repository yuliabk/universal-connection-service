from fastapi.testclient import TestClient
from universal_connection_service.app import app

client = TestClient(app)

def request():
    return {"requestId":"r1","actor":{"userId":"u1","organizationId":"o1","agentId":"a1"},
            "service":{"name":"Example","baseUrl":"https://example.com"},
            "capability":"records.read","operation":"read","input":{}}

def test_health(): assert client.get("/health").json()["ok"] is True

def test_unknown_service_yields_safe_plan():
    body = client.post("/v1/connections/plan", json=request()).json()
    assert body["requiresBuild"] is True
    assert body["requiresHumanApproval"] is True

def test_unknown_service_fails_closed():
    payload = {"request":request(), "context":{"requestId":"r1","userId":"u1","organizationId":"o1","deadlineMs":1000}}
    body = client.post("/v1/connections/execute", json=payload).json()
    assert body["status"] == "failed"
    assert body["error"]["code"] == "CONNECTION_UNAVAILABLE"
