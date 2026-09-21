# OpenSpec - Federated Travel Connectors v1

Status: approved task group
Owner approval: 2026-09-21
Scope: read-only multi-provider travel discovery through trusted connectors

## Goal

Allow an authorized agent to query several explicitly configured travel connectors in parallel while keeping MCP, REST/OpenAPI and future transports replaceable behind ConnectorContract.

## Boundaries

- Read-only search and recommendation capabilities only.
- No booking, payment, ticketing, PNR mutation, cancellation, exchange or refund.
- Only trusted connectors visible to the requesting organization may execute.
- Credentials remain opaque and are resolved only by the existing outbound boundary.
- Provider output is untrusted data and never instruction.
- Unknown commercial facts remain unknown.
- Failure of one source yields a partial result, not a false no-results conclusion.

## Contract

A federation request supplies an ordered list of service/capability sources and one provider-neutral input. The result contains normalized provider envelopes, per-source status, latency and errors. Source identity is retained for every item. Exact matching and commercial validation remain the caller's responsibility.

## Acceptance

- trusted tenant/global connectors can run concurrently;
- missing, unhealthy and failed sources are explicit;
- duplicate observations are collapsed only when their stable canonical key matches;
- partial success is distinguishable from complete success and total failure;
- no credential or provider-specific secret appears in output;
- deterministic tests cover success, partial failure, deduplication and tenant isolation.
