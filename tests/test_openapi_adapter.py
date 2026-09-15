import asyncio
from copy import deepcopy
import socket
import threading
import time
from types import SimpleNamespace

import httpx
from fastapi import FastAPI
import uvicorn

from universal_connection_service.contracts import ExecutionContext
from universal_connection_service.openapi_adapter import compile_openapi_connector
from universal_connection_service.openapi_validation import (
    OpenAPIValidationReport,
    OpenAPIValidationService,
    SchemathesisSandboxValidator,
)
from universal_connection_service.registry import Registration


SCHEMA = {
    "openapi": "3.1.0",
    "info": {"title": "Synthetic Records API", "version": "1.0.0"},
    "paths": {
        "/records/{record_id}": {
            "get": {
                "operationId": "getRecord",
                "x-ucs-capability": "records.read",
                "parameters": [
                    {
                        "name": "record_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                    }
                ],
                "responses": {
                    "200": {
                        "description": "Record",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["id"],
                                    "properties": {"id": {"type": "string"}},
                                }
                            }
                        },
                    }
                },
            }
        },
        "/records": {
            "post": {
                "operationId": "createRecord",
                "x-ucs-capability": "records.create",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "required": ["name"],
                                "properties": {"name": {"type": "string"}},
                            }
                        }
                    },
                },
                "responses": {
                    "200": {
                        "description": "Created",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["name"],
                                    "properties": {"name": {"type": "string"}},
                                }
                            }
                        },
                    }
                },
            }
        },
    },
}


app = FastAPI()


@app.get("/records/{record_id}")
async def get_record(record_id: str):
    return {"id": record_id}


@app.post("/records")
async def create_record(payload: dict):
    return payload


validation_app = FastAPI()


@validation_app.get("/healthz", response_model=dict[str, bool])
async def validation_health():
    return {"ok": True}


def context() -> ExecutionContext:
    return ExecutionContext(
        requestId="r1",
        userId="u1",
        organizationId="o1",
        deadlineMs=2000,
    )


def client_factory():
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    )


def compiled(schema=None, *, client=True):
    return compile_openapi_connector(
        schema or SCHEMA,
        connector_id="synthetic-openapi",
        service_id="synthetic",
        name="Synthetic OpenAPI",
        version="1.0.0",
        base_url="http://127.0.0.1:8000",
        client_factory=client_factory if client else None,
    )


def test_compile_uses_explicit_ucs_capability_and_operation_id_fallback():
    schema = deepcopy(SCHEMA)
    del schema["paths"]["/records"]["post"]["x-ucs-capability"]
    result = compiled(schema)

    manifest = result.connector.manifest()
    assert manifest.strategy == "api"
    assert manifest.capabilities == ("records.read", "createRecord")
    assert result.skipped_operations == ()


def test_compile_rejects_remote_refs():
    schema = deepcopy(SCHEMA)
    schema["components"] = {
        "schemas": {"Record": {"$ref": "https://example.com/record.json"}}
    }
    try:
        compiled(schema)
        assert False, "remote refs must fail closed"
    except ValueError as exc:
        assert "Remote OpenAPI $ref" in str(exc)


def test_path_renderer_percent_encodes_segment_values():
    connector = compiled().connector
    rendered, error = connector._render_path(
        "/records/{record_id}", {"record_id": "abc/123 ?"}
    )
    assert error is None
    assert rendered == "/records/abc%2F123%20%3F"


def test_generated_adapter_executes_get_and_post():
    connector = compiled().connector

    read = asyncio.run(
        connector.execute(
            "records.read",
            {"path": {"record_id": "abc-123"}},
            context(),
        )
    )
    assert read.status == "success"
    assert read.data == {"statusCode": 200, "body": {"id": "abc-123"}}

    created = asyncio.run(
        connector.execute(
            "records.create",
            {"body": {"name": "Ada"}},
            context(),
        )
    )
    assert created.status == "success"
    assert created.data == {"statusCode": 200, "body": {"name": "Ada"}}


def test_generated_adapter_rejects_missing_path_and_unknown_input_fields():
    connector = compiled().connector
    missing = asyncio.run(connector.execute("records.read", {}, context()))
    assert missing.status == "failed"
    assert missing.error is not None
    assert missing.error.code == "INVALID_INPUT"

    unknown = asyncio.run(
        connector.execute("records.read", {"headers": {"X-Token": "secret"}}, context())
    )
    assert unknown.status == "failed"
    assert unknown.error is not None
    assert unknown.error.code == "INVALID_INPUT"


def test_authenticated_operation_requires_external_credential_aware_client():
    schema = deepcopy(SCHEMA)
    schema["components"] = {
        "securitySchemes": {
            "ApiKeyAuth": {"type": "apiKey", "in": "header", "name": "X-API-Key"}
        }
    }
    schema["paths"]["/records/{record_id}"]["get"]["security"] = [{"ApiKeyAuth": []}]
    connector = compiled(schema, client=False).connector

    result = asyncio.run(
        connector.execute(
            "records.read",
            {"path": {"record_id": "1"}},
            context(),
        )
    )
    assert result.status == "failed"
    assert result.error is not None
    assert result.error.code == "CREDENTIAL_RESOLUTION_UNAVAILABLE"


def test_dynamic_validation_rejects_non_loopback_target(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/schemathesis")
    validator = SchemathesisSandboxValidator(max_examples=1)
    report = validator.validate(SCHEMA, "https://api.example.com")
    assert report.static_valid is True
    assert report.dynamic_attempted is False
    assert report.passed is False


def test_schemathesis_runner_uses_bounded_non_stateful_phases(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda _: "/usr/bin/schemathesis")
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("subprocess.run", fake_run)
    report = SchemathesisSandboxValidator(max_examples=3, timeout_seconds=10).validate(
        SCHEMA, "http://127.0.0.1:9999"
    )

    assert report.passed is True
    command = captured["command"]
    assert "--max-examples" in command
    assert command[command.index("--max-examples") + 1] == "3"
    assert "--phases=examples,coverage,fuzzing" in command
    assert "stateful" not in " ".join(command)


def test_real_schemathesis_loopback_smoke():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]

    config = uvicorn.Config(
        validation_app,
        host="127.0.0.1",
        port=port,
        log_level="error",
        access_log=False,
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{port}"

    try:
        ready = False
        for _ in range(50):
            try:
                response = httpx.get(base_url + "/healthz", timeout=0.2)
                if response.status_code == 200:
                    ready = True
                    break
            except httpx.HTTPError:
                pass
            time.sleep(0.05)
        assert ready, "synthetic validation server did not start"

        report = SchemathesisSandboxValidator(max_examples=1, timeout_seconds=30).validate(
            validation_app.openapi(), base_url
        )
        assert report.static_valid is True
        assert report.dynamic_attempted is True
        assert report.passed is True
    finally:
        server.should_exit = True
        thread.join(timeout=5)


class PassingValidator:
    def validate(self, schema, sandbox_url):
        return OpenAPIValidationReport(
            staticValid=True,
            dynamicAttempted=True,
            dynamicPassed=True,
            passed=True,
            exitCode=0,
        )


class FailingValidator:
    def validate(self, schema, sandbox_url):
        return OpenAPIValidationReport(
            staticValid=True,
            dynamicAttempted=True,
            dynamicPassed=False,
            passed=False,
            exitCode=1,
            issues=("contract violation",),
        )


def test_validation_promotes_only_successful_candidate_to_validated():
    successful = Registration(connector=compiled().connector, status="generated")
    report = OpenAPIValidationService(PassingValidator()).validate_registration(
        successful, schema=SCHEMA, sandbox_url="http://127.0.0.1:9999"
    )
    assert report.passed is True
    assert successful.status == "validated"

    failing = Registration(connector=compiled().connector, status="generated")
    report = OpenAPIValidationService(FailingValidator()).validate_registration(
        failing, schema=SCHEMA, sandbox_url="http://127.0.0.1:9999"
    )
    assert report.passed is False
    assert failing.status == "sandboxed"
