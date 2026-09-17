# SPDX-License-Identifier: GPL-2.0-only
"""Age- and count-bounded retention for per-match activation journals.

Cleanup is restricted to histories whose complete state machine ends in a
resolved phase. Unresolved, blocked, quarantined, malformed, and incomplete
journals are retained.
"""

from __future__ import annotations

import os
import re
import stat
import time
from pathlib import Path

import t2_mutation_journal as journal
import t2_user_activation_journal as activation_journal


DEFAULT_ROOT = Path("/var/lib/t2-touchid/activation")
JOURNAL_NAME = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.jsonl$"
)
DEFAULT_MAX_AGE_SECONDS = 7 * 24 * 60 * 60
DEFAULT_MAX_FILES = 64
DEFAULT_MIN_AGE_SECONDS = 60 * 60
DELETABLE_PHASES = frozenset(
    {
        activation_journal.UserActivationPhase.READY,
        activation_journal.UserActivationPhase.STOPPED,
        activation_journal.UserActivationPhase.RECOVERED_READY,
        activation_journal.UserActivationPhase.RECOVERED_NOT_READY,
    }
)


class ActivationJournalRetentionError(RuntimeError):
    pass


def _private_directory(path: Path) -> os.stat_result:
    try:
        info = path.stat(follow_symlinks=False)
    except OSError as error:
        raise ActivationJournalRetentionError(
            "activation journal directory is unavailable"
        ) from error
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o077
    ):
        raise ActivationJournalRetentionError(
            "activation journal directory is not private and caller-owned"
        )
    return info


def _private_journal(path: Path) -> os.stat_result | None:
    try:
        info = path.stat(follow_symlinks=False)
    except OSError:
        return None
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_nlink != 1
        or info.st_mode & 0o077
        or not JOURNAL_NAME.fullmatch(path.name)
    ):
        return None
    return info


def _is_proved_terminal(path: Path) -> bool:
    """True only after the state machine reaches a complete, resolved phase."""

    try:
        history = activation_journal.read(path)
    except (OSError, journal.JournalError, activation_journal.UserActivationJournalError):
        return False
    return history.phase in DELETABLE_PHASES


def prune(
    root: Path = DEFAULT_ROOT,
    *,
    now: float | None = None,
    max_age_seconds: int = DEFAULT_MAX_AGE_SECONDS,
    max_files: int = DEFAULT_MAX_FILES,
    min_age_seconds: int = DEFAULT_MIN_AGE_SECONDS,
) -> int:
    """Delete expired activation journals. Returns the number removed."""

    if (
        type(max_age_seconds) is not int
        or type(max_files) is not int
        or type(min_age_seconds) is not int
        or max_age_seconds < 1
        or max_files < 1
        or min_age_seconds < 0
        or min_age_seconds >= max_age_seconds
    ):
        raise ActivationJournalRetentionError("activation retention bounds are invalid")
    if not root.is_dir():
        return 0
    _private_directory(root)
    clock = time.time() if now is None else now
    entries: list[tuple[float, Path]] = []
    try:
        names = os.listdir(root)
    except OSError as error:
        raise ActivationJournalRetentionError(
            "activation journal directory is unreadable"
        ) from error
    for name in names:
        path = root / name
        info = _private_journal(path)
        if info is None:
            continue
        entries.append((info.st_mtime, path))
    entries.sort(key=lambda item: item[0], reverse=True)
    removed = 0
    for index, (mtime, path) in enumerate(entries):
        age = clock - mtime
        if age < min_age_seconds:
            continue
        if index < max_files and age <= max_age_seconds:
            continue
        if not _is_proved_terminal(path):
            continue
        try:
            os.unlink(path)
        except FileNotFoundError:
            continue
        except OSError:
            continue
        removed += 1
    return removed
