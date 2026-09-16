"""Expiry is authenticated from the encrypted envelope, never caller metadata."""
import asyncio
import logging

from .receipts import ExecutionReceipt, utc_now

logger = logging.getLogger(__name__)


def purge_batch(store, cipher, after=""):
    page = store.receipt_result_page(after=after)
    for receipt_id, receipt_json, ciphertext in page:
        try:
            receipt = ExecutionReceipt.model_validate_json(receipt_json)
            if receipt.receipt_id != receipt_id:
                raise ValueError("Receipt index mismatch")
            if cipher.expires_at(receipt, ciphertext) <= utc_now():
                store.purge_receipt_result(receipt.organization_id, receipt.operation_id, receipt.version, ciphertext)
        except Exception:
            # A missing rotation key or corrupt envelope cannot justify deletion.
            logger.warning("Receipt result retention deferred")
    return page[-1][0] if page else ""


async def run_receipt_retention_worker(store, cipher, stop: asyncio.Event, interval: float = 5.0):
    after = ""
    while not stop.is_set():
        try:
            after = await asyncio.to_thread(purge_batch, store, cipher, after)
        except Exception:
            logger.warning("Receipt retention scan deferred")
        try:
            await asyncio.wait_for(stop.wait(), timeout=interval)
        except TimeoutError:
            pass
