# SPDX-License-Identifier: GPL-2.0-only
"""Privacy-safe monotonic phase timing for Touch ID operations."""

from __future__ import annotations

from contextlib import contextmanager
import json
import math
import re
import sys
import time
from collections.abc import Iterator


_LABEL = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_FIELDS = {"schema_version", "operation", "phase", "duration_ms", "outcome"}


def emit(operation: str, phase: str, started: float, outcome: str = "ok") -> None:
    """Emit one bounded event without credentials, identities, or paths."""

    if not all(
        isinstance(value, str) and _LABEL.fullmatch(value)
        for value in (operation, phase, outcome)
    ):
        raise ValueError("performance event labels are invalid")
    elapsed = max(0.0, time.monotonic() - started)
    event = {
        "schema_version": 1,
        "operation": operation,
        "phase": phase,
        "duration_ms": round(elapsed * 1000, 3),
        "outcome": outcome,
    }
    print(
        "T2_PERF_EVENT " + json.dumps(event, separators=(",", ":"), sort_keys=True),
        file=sys.stderr,
        flush=True,
    )


def relay(record: bytes | bytearray) -> bool:
    """Relay only an exact bounded child timing record to the daemon journal."""

    prefix = b"T2_PERF_EVENT "
    if not isinstance(record, (bytes, bytearray)):
        return False
    record = bytes(record)
    if not record.startswith(prefix):
        return False
    try:
        event = json.loads(record[len(prefix) :])
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    duration = event.get("duration_ms") if type(event) is dict else None
    if (
        type(event) is not dict
        or set(event) != _FIELDS
        or event.get("schema_version") != 1
        or not all(
            isinstance(event.get(field), str)
            and _LABEL.fullmatch(event[field])
            for field in ("operation", "phase", "outcome")
        )
        or type(duration) not in (int, float)
        or not math.isfinite(duration)
        or not 0 <= duration <= 86_400_000
    ):
        return False
    print(
        prefix.decode() + json.dumps(event, separators=(",", ":"), sort_keys=True),
        flush=True,
    )
    return True


@contextmanager
def phase(operation: str, label: str) -> Iterator[None]:
    started = time.monotonic()
    try:
        yield
    except BaseException:
        emit(operation, label, started, "error")
        raise
    else:
        emit(operation, label, started)
