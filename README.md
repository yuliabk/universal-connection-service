# Universal Connection Service

Provider-neutral connection module for Agent Factory, plugins and standalone agents.

## Alpha scope

- Typed Connection Request, Plan, Result and Connector contracts
- Capability-based connector registry
- Fail-closed planning and execution
- Tenant-aware execution context with opaque credential handles
- FastAPI endpoints and Docker packaging

This repository intentionally contains no credentials and performs no external calls by default.

## Run

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
uvicorn universal_connection_service.app:app --reload
```

Open `http://127.0.0.1:8000/docs`.

## API

- `GET /health`
- `GET /v1/connectors`
- `POST /v1/connections/plan`
- `POST /v1/connections/execute`

## Security baseline

- Raw credentials are never accepted by connector manifests or plans.
- Unknown connectors fail closed.
- Untrusted/generated implementations require validation and human approval.
- Tenant and actor identity are explicit in every execution context.
- Production secret storage, OAuth callbacks and persistent audit storage are intentionally deferred.

## Next milestone

Add REST/OpenAPI and MCP adapters, persistent registry, vault-backed credential resolver, policy engine and three synthetic end-to-end scenarios.
