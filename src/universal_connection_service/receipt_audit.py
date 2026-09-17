"""Bounded host-owned delivery of durable execution audit events."""
import asyncio
import logging

logger = logging.getLogger(__name__)


def deliver_batch(store, after=""):
    organizations = store.receipt_audit_organizations(after=after)
    for organization_id in organizations:
        try:
            store.deliver_receipt_audit(organization_id)
        except Exception:
            # Do not log database exceptions, tenant identifiers or payloads.
            logger.warning("Receipt audit delivery deferred")
    return organizations[-1] if organizations else ""


async def run_receipt_audit_worker(store, stop: asyncio.Event, interval: float = 5.0):
    after = ""
    while not stop.is_set():
        try:
            after = await asyncio.to_thread(deliver_batch, store, after)
        except Exception:
            logger.warning("Receipt audit discovery deferred")
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
        except TimeoutError:
            pass
