from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

from pydantic import Field

from .contracts import Model
from .openapi_adapter import _reject_remote_refs
from .persistence import EvidenceRecord, EvidenceStore
from .registry import Registration

try:
    from openapi_spec_validator import validate as validate_openapi_spec
except ImportError:  # pragma: no cover - optional extra missing
    validate_openapi_spec = None  # type: ignore[assignment]


class OpenAPIValidationReport(Model):
    static_valid: bool = Field(alias="staticValid")
    dynamic_attempted: bool = Field(alias="dynamicAttempted")
    dynamic_passed: bool = Field(alias="dynamicPassed")
    passed: bool
    engine: str = "schemathesis"
    exit_code: int | None = Field(alias="exitCode", default=None)
    issues: tuple[str, ...] = ()


def _validate_loopback_url(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Sandbox URL must be an absolute HTTP(S) URL")
    if parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise ValueError("UCS-03 dynamic validation is restricted to loopback sandbox targets")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Sandbox URL must not contain credentials, query parameters or fragments")
    return value.rstrip("/")


class SchemathesisSandboxValidator:
    """Runs bounded contract fuzzing only against an explicit loopback sandbox.

    The runner uses the stable Schemathesis CLI surface instead of importing
    internal runner APIs. It never accepts auth headers or raw credentials.
    """

    def __init__(self, *, max_examples: int = 5, timeout_seconds: int = 45) -> None:
        if max_examples < 1 or max_examples > 100:
            raise ValueError("max_examples must be between 1 and 100")
        if timeout_seconds < 1 or timeout_seconds > 300:
            raise ValueError("timeout_seconds must be between 1 and 300")
        self.max_examples = max_examples
        self.timeout_seconds = timeout_seconds

    def validate(self, schema: dict[str, Any], sandbox_url: str) -> OpenAPIValidationReport:
        if validate_openapi_spec is None:
            return OpenAPIValidationReport(
                staticValid=False,
                dynamicAttempted=False,
                dynamicPassed=False,
                passed=False,
                issues=("OpenAPI validation dependency is not installed",),
            )

        try:
            _reject_remote_refs(schema)
            validate_openapi_spec(schema)
        except Exception:
            return OpenAPIValidationReport(
                staticValid=False,
                dynamicAttempted=False,
                dynamicPassed=False,
                passed=False,
                issues=("OpenAPI document failed structural validation",),
            )

        try:
            sandbox_url = _validate_loopback_url(sandbox_url)
        except ValueError:
            return OpenAPIValidationReport(
                staticValid=True,
                dynamicAttempted=False,
                dynamicPassed=False,
                passed=False,
                issues=("Dynamic validation target is not an allowed loopback sandbox",),
            )

        executable = shutil.which("schemathesis") or shutil.which("st")
        if executable is None:
            return OpenAPIValidationReport(
                staticValid=True,
                dynamicAttempted=False,
                dynamicPassed=False,
                passed=False,
                issues=("Schemathesis CLI is not installed",),
            )

        with tempfile.TemporaryDirectory(prefix="ucs-openapi-") as tmpdir:
            schema_path = Path(tmpdir) / "openapi.json"
            schema_path.write_text(json.dumps(schema), encoding="utf-8")
            command = [
                executable,
                "run",
                str(schema_path),
                "--url",
                sandbox_url,
                "--max-examples",
                str(self.max_examples),
                "--phases=examples,coverage,fuzzing",
                "--checks",
                "not_a_server_error,status_code_conformance,response_schema_conformance",
            ]
            try:
                completed = subprocess.run(
                    command,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_seconds,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                return OpenAPIValidationReport(
                    staticValid=True,
                    dynamicAttempted=True,
                    dynamicPassed=False,
                    passed=False,
                    issues=("Schemathesis validation exceeded its time budget",),
                )
            except OSError:
                return OpenAPIValidationReport(
                    staticValid=True,
                    dynamicAttempted=True,
                    dynamicPassed=False,
                    passed=False,
                    issues=("Schemathesis validation could not be started",),
                )

        if completed.returncode == 0:
            return OpenAPIValidationReport(
                staticValid=True,
                dynamicAttempted=True,
                dynamicPassed=True,
                passed=True,
                exitCode=0,
            )

        issue = "Schemathesis found API contract violations"
        if completed.returncode == 2:
            issue = "Schemathesis aborted because the validation configuration or schema was invalid"
        return OpenAPIValidationReport(
            staticValid=True,
            dynamicAttempted=True,
            dynamicPassed=False,
            passed=False,
            exitCode=completed.returncode,
            issues=(issue,),
        )


class OpenAPIValidationService:
    """Owns generated -> sandboxed -> validated promotion for OpenAPI connectors."""

    def __init__(
        self,
        validator: SchemathesisSandboxValidator | None = None,
        *,
        evidence_store: EvidenceStore | None = None,
    ) -> None:
        self.validator = validator or SchemathesisSandboxValidator()
        self.evidence_store = evidence_store

    def _persist_evidence(
        self,
        registration: Registration,
        report: OpenAPIValidationReport,
        sandbox_url: str,
    ) -> None:
        if self.evidence_store is None:
            return
        parsed = urlsplit(sandbox_url)
        self.evidence_store.append_evidence(
            EvidenceRecord(
                evidenceId=str(uuid4()),
                organizationId=registration.organization_id,
                kind="validation",
                phase="validation",
                connectorId=registration.manifest.connector_id,
                payload={
                    "engine": report.engine,
                    "report": report.model_dump(by_alias=True, mode="json"),
                    "sandboxHost": parsed.hostname,
                    "sandboxScheme": parsed.scheme,
                },
            )
        )

    def validate_registration(
        self,
        registration: Registration,
        *,
        schema: dict[str, Any],
        sandbox_url: str,
    ) -> OpenAPIValidationReport:
        if registration.manifest.strategy != "api":
            raise ValueError("OpenAPI validation can only promote API connectors")
        if registration.status not in {"generated", "sandboxed"}:
            raise ValueError("Only generated or sandboxed connectors can enter OpenAPI validation")

        registration.set_status("sandboxed")
        report = self.validator.validate(schema, sandbox_url)
        self._persist_evidence(registration, report, sandbox_url)
        if report.passed:
            registration.set_status("validated")
        return report
