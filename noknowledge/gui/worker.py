"""Background worker: polls mailboxes and runs commands off the GUI thread."""

from __future__ import annotations

import queue
import threading
from typing import Any, Callable

from PyQt5.QtCore import QThread, pyqtSignal


class Worker(QThread):
    messages_received = pyqtSignal(list)
    status_changed = pyqtSignal(str)
    error_occurred = pyqtSignal(str)
    task_finished = pyqtSignal(str, object)

    def __init__(self, client, poll_seconds: int = 2) -> None:
        super().__init__()
        self.client = client
        self.poll_seconds = max(1, poll_seconds)
        self._stop = threading.Event()
        self._wake = threading.Event()
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
                self.status_changed.emit("online")
            except Exception as exc:  # never let the worker die
                self.error_occurred.emit(str(exc))
                self.status_changed.emit("offline")
            self._drain()
            self._wake.wait(self.poll_seconds)
            self._wake.clear()

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