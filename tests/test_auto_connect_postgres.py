import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest
from pydantic import SecretStr

from universal_connection_service.persistence import ConnectionWorkflowRecord
from universal_connection_service.postgres_store import LATEST_SCHEMA_VERSION, PostgresStateStore, PostgresStoreConfig


DSN = os.getenv("UCS_TEST_POSTGRES_URL")
pytestmark = pytest.mark.skipif(not DSN, reason="UCS_TEST_POSTGRES_URL is not configured")


def config(*, auto_migrate=True):
    return PostgresStoreConfig(
        dsn=SecretStr(DSN),
        minSize=1,
        maxSize=1,
        timeoutSeconds=10,
        sslmode="disable",
        autoMigrate=auto_migrate,
    )


def test_postgres_workflow_persists_and_claim_is_atomic_across_instances():
    store1 = PostgresStateStore(config(auto_migrate=True))
    store2 = PostgresStateStore(config(auto_migrate=False))
    # The point is that migration reaches the latest version, not that the
    # latest version is a particular number: pinning it made every new
    # migration break this test.
    assert store1.schema_version() == LATEST_SCHEMA_VERSION
    assert LATEST_SCHEMA_VERSION >= 3  # the workflow tables arrived in v3

    suffix = uuid4().hex
    organization_id = f"org-wf-{suffix}"
    workflow_id = f"wf-{suffix}"
    request_id = f"req-{suffix}"
    created = store1.create_workflow(
        ConnectionWorkflowRecord(
            workflowId=workflow_id,
            requestId=request_id,
            organizationId=organization_id,
            requestFingerprint="a" * 64,
            serviceId="records",
            capability="records.read",
            operation="read",
        )
    )
    assert created.stage == "planning"
    assert store2.get_workflow(organization_id, workflow_id).request_fingerprint == "a" * 64

    now = datetime.now(timezone.utc)
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(
            executor.map(
                lambda pair: pair[0].claim_workflow(
                    organization_id,
                    workflow_id,
                    pair[1],
                    now + timedelta(seconds=30),
                    now,
                ),
                ((store1, "lease-a"), (store2, "lease-b")),
            )
        )
    assert sorted(results) == [False, True]

    current = store1.get_workflow(organization_id, workflow_id)
    assert current is not None and current.lease_token in {"lease-a", "lease-b"}
    owner = current.lease_token
    current.stage = "awaiting_build"
    current.last_code = "CONNECTION_BUILD_REQUIRED"
    assert store1.update_claimed_workflow(current, expected_revision=0, lease_token=owner) is True

    updated = store2.get_workflow(organization_id, workflow_id)
    assert updated is not None
    assert updated.stage == "awaiting_build"
    assert updated.revision == 1
    assert updated.lease_token is None

    store1.close()
    store2.close()
