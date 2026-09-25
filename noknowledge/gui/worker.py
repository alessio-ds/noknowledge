"""Background worker: polls mailboxes, runs commands, discovers relays.

All of it happens off the GUI thread; the interface only sees Qt signals.
"""

from __future__ import annotations

import queue
import threading
import time
from typing import Any, Callable

from PyQt5.QtCore import QThread, pyqtSignal


class Worker(QThread):
    messages_received = pyqtSignal(list)
    status_changed = pyqtSignal(str)
    error_occurred = pyqtSignal(str)
    task_finished = pyqtSignal(str, object)
    #: Emitted with the new relay list when discovery adopted new relays.
    relays_changed = pyqtSignal(list)

    def __init__(
        self,
        client,
        poll_seconds: int = 2,
        auto_discover: bool = False,
        discovery_interval: int = 900,
    ) -> None:
        super().__init__()
        self.client = client
        self.poll_seconds = max(1, poll_seconds)
        self.auto_discover = auto_discover
        self.discovery_interval = max(60, int(discovery_interval))
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._next_discovery = 0.0
        self._tasks: "queue.Queue[tuple[str, Callable, tuple, Callable | None]]" = (
            queue.Queue()
        )

    # -- public API -------------------------------------------------------

    def submit(
        self,
        name: str,
        function: Callable[..., Any],
        *args: Any,
        callback: Callable[[Any], None] | None = None,
        **kwargs: Any,
    ) -> None:
        """Queue a command to run on the worker thread."""
        self._tasks.put((name, function, (args, kwargs), callback))
        self._wake.set()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()

    # -- thread body ------------------------------------------------------

    def run(self) -> None:  # noqa: D102
        self.status_changed.emit("connecting")
        while not self._stop.is_set():
            self._drain()
            if self._stop.is_set():
                break
            try:
                new_messages = self.client.sync(wait=1)
                if new_messages:
                    self.messages_received.emit(new_messages)
                self.client.flush_outbox()
                if self.auto_discover and time.monotonic() >= self._next_discovery:
                    self._discover()
                self.status_changed.emit("online")
            except Exception as exc:  # never let the worker die
                self.error_occurred.emit(str(exc))
                self.status_changed.emit("offline")
            self._drain()
            self._wake.wait(self.poll_seconds)
            self._wake.clear()

    def _discover(self) -> None:
        self._next_discovery = time.monotonic() + self.discovery_interval
        try:
            before = self.client.relay_urls()
            after = self.client.refresh_relays()
        except Exception as exc:
            self.error_occurred.emit(f"relay discovery: {exc}")
            return
        if after != before:
            self.relays_changed.emit(after)

    def _drain(self) -> None:
        while True:
            try:
                name, function, (args, kwargs), callback = self._tasks.get_nowait()
            except queue.Empty:
                return
            try:
                result = function(*args, **kwargs)
            except Exception as exc:
                self.error_occurred.emit(str(exc))
                result = None
            if callback is not None:
                try:
                    callback(result)
                except Exception as exc:
                    self.error_occurred.emit(str(exc))
            self.task_finished.emit(name, result)