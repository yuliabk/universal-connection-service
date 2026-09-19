import pytest

from universal_connection_service.capability_schemas import (
    CapabilitySchema,
    SchemaAnnotatedConnector,
    capability_schemas_of,
    schemas_from_openapi,
)
from universal_connection_service.contracts import ConnectorManifest, ConnectorResult


SPEC = {
    "openapi": "3.0.3",
    "info": {"title": "Flights", "version": "1.0.0"},
    "paths": {
        "/offers": {
            "get": {
                "operationId": "searchOffers",
                "summary": "Search flight offers",
                "parameters": [
                    {"name": "origin", "in": "query", "required": True, "schema": {"type": "string"}},
                    {"name": "max", "in": "query", "schema": {"type": "integer"}},
                    {"name": "x-trace", "in": "header", "schema": {"type": "string"}},
                ],
                "responses": {"200": {"description": "ok"}},
            }
        },
        "/orders/{orderId}": {
            "delete": {
                "operationId": "cancelOrder",
                "x-ucs-capability": "orders.cancel",
                "responses": {"204": {"description": "gone"}},
            },
            "patch": {
                "operationId": "updateOrder",
                "requestBody": {
                    "required": True,
                    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Order"}}},
                },
                "responses": {"200": {"description": "ok"}},
            },
        },
    },
    "components": {
        "schemas": {
            "Order": {
                "type": "object",
                "properties": {"seat": {"type": "string"}, "parent": {"$ref": "#/components/schemas/Order"}},
            }
        }
    },
}


def by_capability(schemas):
    return {schema.capability: schema for schema in schemas}


def test_query_and_header_parameters():
    schemas = by_capability(schemas_from_openapi(SPEC))
    search = schemas["searchOffers"]
    query = search.input_schema["properties"]["query"]
    assert set(query["properties"]) == {"origin", "max"}  # header parameters stay out of the envelope
    assert query["required"] == ["origin"]
    assert search.read_only is True
    assert search.operation == "read"


def test_path_parameter_is_required_and_delete_is_destructive():
    schemas = by_capability(schemas_from_openapi(SPEC))
    cancel = schemas["orders.cancel"]  # x-ucs-capability wins over operationId
    assert cancel.input_schema["properties"]["path"]["required"] == ["orderId"]
    assert "path" in cancel.input_schema["required"]
    assert cancel.read_only is False
    assert cancel.risk_hints.destructive is True
    assert cancel.operation == "delete"


def test_recursive_body_ref_terminates():
    schemas = by_capability(schemas_from_openapi(SPEC))
    body = schemas["updateOrder"].input_schema["properties"]["body"]
    assert body["properties"]["seat"] == {"type": "string"}
    assert "recursive" in body["properties"]["parent"]["description"]
    assert "body" in schemas["updateOrder"].input_schema["required"]


def test_remote_ref_is_rejected():
    spec = {
        "openapi": "3.0.3",
        "paths": {
            "/x": {
                "get": {
                    "operationId": "x",
                    "parameters": [{"$ref": "https://evil.example.com/p.json#/p"}],
                    "responses": {"200": {"description": "ok"}},
                }
            }
        },
    }
    with pytest.raises(ValueError):
        schemas_from_openapi(spec)


def test_operations_without_operation_id_are_skipped():
    spec = {
        "openapi": "3.0.3",
        "paths": {"/x": {"get": {"responses": {"200": {"description": "ok"}}}}},
    }
    with pytest.raises(ValueError):
        schemas_from_openapi(spec)


class StubConnector:
    def manifest(self) -> ConnectorManifest:
        return ConnectorManifest(
            connectorId="c1",
            serviceId="svc",
            name="Stub",
            version="1.0.0",
            strategy="api",
            capabilities=("alpha", "beta"),
        )

    async def health_check(self, ctx) -> bool:
        return True

    async def execute(self, capability, input, ctx) -> ConnectorResult:
        return ConnectorResult(status="success", data={"capability": capability})


def test_annotation_rejects_unknown_capability():
    with pytest.raises(ValueError):
        SchemaAnnotatedConnector(StubConnector(), (CapabilitySchema(capability="gamma"),))


def test_unannotated_connector_falls_back_to_permissive_envelope():
    schemas = by_capability(capability_schemas_of(StubConnector()))
    assert set(schemas) == {"alpha", "beta"}
    assert set(schemas["alpha"].input_schema["properties"]) == {"path", "query", "body"}


def test_annotated_connector_delegates_manifest_and_publishes_schemas():
    annotated = SchemaAnnotatedConnector(StubConnector(), (CapabilitySchema(capability="alpha", description="A"),))
    assert annotated.manifest().connector_id == "c1"
    assert annotated.capability_schemas()[0].description == "A"
