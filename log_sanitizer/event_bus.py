import asyncio
import threading
from typing import Callable, List, Dict, Any
from collections import defaultdict
from .models import AlertEvent


class EventBus:
    def __init__(self):
        self._subscribers: Dict[str, List[Callable]] = defaultdict(list)
        self._lock = threading.Lock()

    def subscribe(self, event_type: str, callback: Callable[[AlertEvent], None]) -> None:
        with self._lock:
            self._subscribers[event_type].append(callback)

    def unsubscribe(self, event_type: str, callback: Callable[[AlertEvent], None]) -> None:
        with self._lock:
            if event_type in self._subscribers:
                try:
                    self._subscribers[event_type].remove(callback)
                except ValueError:
                    pass

    def publish(self, event_type: str, event: AlertEvent) -> None:
        with self._lock:
            callbacks = list(self._subscribers.get(event_type, []))
            callbacks.extend(list(self._subscribers.get('*', [])))

        for callback in callbacks:
            try:
                callback(event)
            except Exception as e:
                print(f"Error in event subscriber: {e}", flush=True)

    def publish_async(self, event_type: str, event: AlertEvent, loop: asyncio.AbstractEventLoop) -> None:
        with self._lock:
            callbacks = list(self._subscribers.get(event_type, []))
            callbacks.extend(list(self._subscribers.get('*', [])))

        for callback in callbacks:
            asyncio.run_coroutine_threadsafe(self._safe_callback(callback, event), loop)

    @staticmethod
    async def _safe_callback(callback: Callable[[AlertEvent], None], event: AlertEvent) -> None:
        try:
            if asyncio.iscoroutinefunction(callback):
                await callback(event)
            else:
                callback(event)
        except Exception as e:
            print(f"Error in async event subscriber: {e}", flush=True)

    def clear(self) -> None:
        with self._lock:
            self._subscribers.clear()
