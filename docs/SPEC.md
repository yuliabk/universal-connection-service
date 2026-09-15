# Universal Connection Service - Alpha specification

## Goal

Expose business capabilities through one stable contract without forcing callers to know whether the implementation uses MCP, REST/OpenAPI, OAuth, a database, Machine Bridge or controlled browser automation.

## Boundary

The service resolves and executes connectors. It is not an agent-to-agent router and does not grant permissions. Calling platforms remain responsible for identity and effective policy; the service verifies the supplied execution context and fails closed.

## Core flow

1. Accept a tenant-scoped `ConnectionRequest`.
2. Compile a reviewable `ConnectionPlan`.
3. Resolve an exact trusted connector implementation.
4. Require approval when policy or risk demands it.
5. Resolve credentials only at the outbound execution boundary.
6. Validate and normalize the result.
7. Return an audit identifier with every result.

## Alpha acceptance scenarios

1. Unknown service produces a build-and-validation plan and execution fails with `CONNECTION_UNAVAILABLE`.
2. Trusted read connector can be resolved by service and capability without exposing credentials.
3. Write, destructive, financial or permission-increasing operations require human approval.

## Deferred before public production

- persistent tenant-scoped registry and audit store;
- vault-backed credential resolver and OAuth callback service;
- policy engine and approval verification;
- signed connector packages and supply-chain verification;
- REST/OpenAPI and MCP adapters with SSRF and schema-drift protection;
- rate limiting, observability, deployment and rollback evidence.
