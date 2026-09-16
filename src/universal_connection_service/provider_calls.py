"""Bounded waits: a connector cannot extend a deadline by swallowing cancellation."""
import asyncio
from threading import Lock

from .receipts import ReceiptError


class ProviderCalls:
    def __init__(self, max_in_flight: int = 64):
        if type(max_in_flight) is not int or max_in_flight < 1:
            raise ValueError("max_in_flight must be positive")
        self._limit = max_in_flight
        self._tasks = set()
        self._lock = Lock()

    def _finished(self, task):
        with self._lock:
            self._tasks.discard(task)
        # Consume late errors without logging provider messages or payloads.
        if not task.cancelled():
            task.exception()

    async def run(self, factory, timeout: float):
        if timeout <= 0:
            raise TimeoutError
        with self._lock:
            if len(self._tasks) >= self._limit:
                raise ReceiptError("PROVIDER_CAPACITY_EXHAUSTED")
            task = asyncio.create_task(factory())
            self._tasks.add(task)
        task.add_done_callback(self._finished)
        try:
            done, _ = await asyncio.wait({task}, timeout=timeout)
            if not done:
                task.cancel()
                raise TimeoutError
            return task.result()
        except asyncio.CancelledError:
            task.cancel()
            raise
