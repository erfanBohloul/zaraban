"""Small helpers shared by several modules. No project logic lives here."""

from __future__ import annotations

import os
import signal
from typing import Hashable, Iterable, TypeVar

T = TypeVar("T", bound=Hashable)


def unique(items: Iterable[T]) -> list[T]:
    """De-duplicate while keeping first-seen order."""
    return list(dict.fromkeys(items))


def kill_group(pgid: int) -> None:
    """SIGKILL every process left in a process group.

    Builds and runs start their command in its own session, so killing the
    group also stops anything the command started (``make``, the compiler, a
    forked child of the program). An empty or vanished group is not an error.
    """
    try:
        os.killpg(pgid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
