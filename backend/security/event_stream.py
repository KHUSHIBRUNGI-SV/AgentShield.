import asyncio
import threading
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any


_QUEUE_LIMIT = 100


class EventStream:
    def __init__(self) -> None:
        self._subscribers: set[
            tuple[asyncio.AbstractEventLoop, asyncio.Queue[dict[str, Any]]]
        ] = set()
        self._lock = threading.Lock()

    @asynccontextmanager
    async def subscribe(self) -> AsyncIterator[asyncio.Queue[dict[str, Any]]]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(
            maxsize=_QUEUE_LIMIT
        )
        subscriber = (asyncio.get_running_loop(), queue)
        with self._lock:
            self._subscribers.add(subscriber)
        try:
            yield queue
        finally:
            with self._lock:
                self._subscribers.discard(subscriber)

    def publish(self, event: dict[str, Any]) -> None:
        with self._lock:
            subscribers = tuple(self._subscribers)
        for loop, queue in subscribers:
            if loop.is_closed():
                continue
            try:
                loop.call_soon_threadsafe(self._enqueue, queue, event)
            except RuntimeError:
                continue

    @staticmethod
    def _enqueue(
        queue: asyncio.Queue[dict[str, Any]],
        event: dict[str, Any],
    ) -> None:
        if queue.full():
            try:
                queue.get_nowait()
            except asyncio.QueueEmpty:
                pass
        queue.put_nowait(event)


event_stream = EventStream()
