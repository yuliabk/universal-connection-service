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
- `GET /v1/agents/{agentId}/tools` (agent tool catalog, MCP or Gemini shape)
- `POST /v1/agents/{agentId}/tools/call` (see `docs/TOOL_CATALOG.md`)

## Agent tool catalog

Agents call tools through `/v1/agents/...`, either over REST or over the native
MCP endpoint. Only `trusted` connectors are listed, and only when the agent's
allowlist names the tool. See `docs/TOOL_CATALOG.md`.

## Security baseline

- Raw credentials are never accepted by connector manifests or plans.
- Unknown connectors fail closed.
- Untrusted/generated implementations require validation and human approval.
- Tenant and actor identity are explicit in every execution context, including
  on the MCP endpoint, where identity comes from headers and never from the
  JSON-RPC payload.
- Agent tool access is default-deny: no allowlist means no tools.
- Production secret storage, OAuth callbacks and persistent audit storage are intentionally deferred.

## Next milestone

Add REST/OpenAPI and MCP adapters, persistent registry, vault-backed credential resolver, policy engine and three synthetic end-to-end scenarios.
