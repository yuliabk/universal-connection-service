"""Schema drift verification.

A published `CapabilitySchema` is the contract captured when the connector was
validated. The remote side can change underneath it: an MCP server can rename an
argument or make an optional field required, and the agent would keep calling the
old shape until the upstream rejects it.

`MCPToolSnapshot.input_schema_sha256` already makes drift detectable. What was
missing is something that re-reads the live schema, compares the digests and acts
on a difference.

Deliberate choice: this does not run inside `tools/call`. Verifying on every call
doubles the round trips and puts a remote listing on the latency path of every
agent turn. Drift verification is an operation the control plane runs on a
schedule or before promoting a connector, which is where the rest of the trust
decisions already live.

Only MCP connectors are verifiable here. An OpenAPI connector would need its
source document re-fetched, and that belongs with the build pipeline that
produced it.
"""

from __future__ import annotations

from typing import Any, Callable
from uuid import uuid4

from pydantic import Field

from .contracts import DiscoveryCandidateRef, ExecutionContext, Model
from .credentials import CredentialResolver
from .mcp_adapter import MCPConnectorAdapter
from .mcp_validation import MCPToolIntrospector, _schema_digest
from .persistence import EvidenceRecord, EvidenceStore
from .registry import ConnectorRegistry


class SchemaDriftFinding(Model):
    capability: str
    tool: str
    status: str  # unchanged | drifted | missing_tool | no_baseline
    expected_sha256: str | None = Field(alias="expectedSha256", default=None)
    observed_sha256: str | None = Field(alias="observedSha256", default=None)


class SchemaDriftReport(Model):
    connector_id: str = Field(alias="connectorId")
    version: str
    organization_id: str = Field(alias="organizationId")
    checked: bool
    drifted: bool
    code: str
    findings: tuple[SchemaDriftFinding, ...] = ()
    demoted: bool = False


class SchemaDriftError(Exception):
    def __init__(self, status_code: int, code: str, safe_message: str) -> None:
        super().__init__(code)
        self.status_code = status_code
        self.code = code
        self.safe_message = safe_message


class MCPSchemaDriftVerifier:
    def __init__(
        self,
        registry: ConnectorRegistry,
        *,
        credential_resolver: CredentialResolver | None = None,
        client_factory: Callable[[], Any] | None = None,
        evidence_store: EvidenceStore | None = None,
        demote_on_drift: bool = True,
    ) -> None:
        self.registry = registry
        self.credential_resolver = credential_resolver
        self.client_factory = client_factory
        self.evidence_store = evidence_store
        self.demote_on_drift = demote_on_drift

    async def verify(
        self,
        organization_id: str,
        connector_id: str,
        version: str,
        *,
        ctx: ExecutionContext | None = None,
        deadline_ms: int = 10000,
    ) -> SchemaDriftReport:
        registration = self.registry.exact(organization_id, connector_id, version)
        if registration is None:
            raise SchemaDriftError(404, "CONNECTOR_NOT_FOUND", "No such connector version for this organization")

        connector = registration.connector
        inner = getattr(connector, "inner", connector)
        if not isinstance(inner, MCPConnectorAdapter):
            return self._report(
                registration,
                organization_id,
                checked=False,
                drifted=False,
                code="DRIFT_CHECK_NOT_APPLICABLE",
            )

        endpoint = inner.config.endpoint
        if endpoint is None and self.client_factory is None:
            return self._report(
                registration,
                organization_id,
                checked=False,
                drifted=False,
                code="DRIFT_CHECK_UNAVAILABLE",
            )

        candidate = DiscoveryCandidateRef(
            candidateId=f"drift-{connector_id}",
            source="mcp_registry",
            name=inner.config.name,
            version=inner.config.version,
            strategy="mcp",
            transport="streamable-http",
            endpoint=endpoint.url if endpoint else "https://placeholder.invalid/mcp",
            authRequirement=inner.config.auth,
            actionable=True,
        )
        try:
            observed = await MCPToolIntrospector(
                candidate,
                service_id=inner.config.service_id,
                credential_resolver=self.credential_resolver,
                client_factory=self.client_factory,
            ).inspect(ctx=ctx, deadline_ms=deadline_ms)
        except Exception:
            # A server that cannot be listed is not evidence of drift.
            return self._report(
                registration,
                organization_id,
                checked=False,
                drifted=False,
                code="DRIFT_INTROSPECTION_FAILED",
            )

        observed_by_name = {item.name: item for item in observed}
        findings: list[SchemaDriftFinding] = []
        for binding in inner.config.bindings:
            schema = binding.capability_schema
            expected = _schema_digest(schema.input_schema) if schema is not None else None
            snapshot = observed_by_name.get(binding.tool)
            if snapshot is None:
                status = "missing_tool"
                observed_digest = None
            elif expected is None:
                status = "no_baseline"
                observed_digest = snapshot.input_schema_sha256
            else:
                observed_digest = snapshot.input_schema_sha256
                status = "unchanged" if observed_digest == expected else "drifted"
            findings.append(
                SchemaDriftFinding(
                    capability=binding.capability,
                    tool=binding.tool,
                    status=status,
                    expectedSha256=expected,
                    observedSha256=observed_digest,
                )
            )

        drifted = any(item.status in {"drifted", "missing_tool"} for item in findings)
        demoted = False
        if drifted and self.demote_on_drift and registration.status == "trusted":
            registration.set_status("degraded")
            demoted = True

        return self._report(
            registration,
            organization_id,
            checked=True,
            drifted=drifted,
            code="DRIFT_DETECTED" if drifted else "SCHEMA_STABLE",
            findings=tuple(findings),
            demoted=demoted,
        )

    def _report(
        self,
        registration,
        organization_id: str,
        *,
        checked: bool,
        drifted: bool,
        code: str,
        findings: tuple[SchemaDriftFinding, ...] = (),
        demoted: bool = False,
    ) -> SchemaDriftReport:
        manifest = registration.manifest
        report = SchemaDriftReport(
            connectorId=manifest.connector_id,
            version=manifest.version,
            organizationId=organization_id,
            checked=checked,
            drifted=drifted,
            code=code,
            findings=findings,
            demoted=demoted,
        )
        if self.evidence_store is not None:
            self.evidence_store.append_evidence(
                EvidenceRecord(
                    evidenceId=str(uuid4()),
                    organizationId=organization_id,
                    kind="validation",
                    phase="plan",
                    connectorId=manifest.connector_id,
                    payload={"type": "schema_drift", **report.model_dump(by_alias=True, mode="json")},
                )
            )
        return report
