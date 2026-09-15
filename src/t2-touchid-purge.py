#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Delete all mapped T2 fingerprints after one fresh PolicyKit authorization."""

from __future__ import annotations

import argparse
import importlib.util
import os
from pathlib import Path
import re
import signal
import sys

SOURCE = Path(__file__).resolve().parent
sys.path.insert(0, str(SOURCE))


class PurgeError(RuntimeError):
    def __init__(self, message: str, *, progress: dict[str, object] | None = None):
        super().__init__(message)
        self.progress = progress


def _manager():
    spec = importlib.util.spec_from_file_location(
        "t2_purge_manager", SOURCE / "t2-touchid-manage.py"
    )
    if spec is None or spec.loader is None:
        raise PurgeError("identity manager is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def purge(*, resume: bool = False, manager_factory=_manager) -> dict[str, object]:
    if os.geteuid() != 0:
        raise PurgeError("run t2touch purge as your normal desktop account")
    uid = os.environ.get("PKEXEC_UID", "")
    if not re.fullmatch(r"[1-9][0-9]{0,9}", uid) or int(uid) >= 2**32 - 1:
        raise PurgeError("authenticated caller is unavailable")
    previous = os.environ.get("SUDO_UID")
    os.environ["SUDO_UID"] = uid
    try:
        manager = manager_factory()
        configuration = manager.runtime_configuration()
        if (
            configuration.get("linux_uid") != int(uid)
            or configuration.get("authority_mode") != "linux-native"
        ):
            raise PurgeError("authenticated caller has no native account mapping")
        try:
            with manager.operation_lock(), manager.sleep_inhibitor():
                result = manager.run_delete_batch(configuration, resume=resume)
        except Exception as error:
            try:
                progress = manager.delete_batch_progress()
            except Exception:
                progress = None
            raise PurgeError("batch deletion is incomplete", progress=progress) from error
        if (
            not isinstance(result, dict)
            or result.get("purge_succeeded") is not True
            or type(result.get("deleted_count")) is not int
            or not 0 <= result["deleted_count"] <= 5
            or type(result.get("identity_count")) is not int
            or result["identity_count"] != 0
        ):
            raise PurgeError("batch deletion did not reconcile")
        return result
    finally:
        if previous is None:
            os.environ.pop("SUDO_UID", None)
        else:
            os.environ["SUDO_UID"] = previous


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    for sig in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, signal.SIG_IGN)
    try:
        result = purge(resume=args.resume)
    except Exception as error:
        # The underlying error may contain private identity values. The outer
        # journal retains exact progress for a subsequent authorized resume.
        progress = error.progress if isinstance(error, PurgeError) else None
        if (
            isinstance(progress, dict)
            and type(progress.get("completed_count")) is int
            and type(progress.get("total_count")) is int
        ):
            state = (
                f"; {progress['completed_count']} of "
                f"{progress['total_count']} deletions completed"
            )
        else:
            state = ""
        print(
            f"t2touch: purge incomplete ({type(error).__name__}){state}; "
            "run sudo t2-touchid-doctor, then t2touch purge --resume",
            file=sys.stderr,
        )
        return 1
    count = result["deleted_count"]
    noun = "fingerprint" if count == 1 else "fingerprints"
    if count == 0:
        print("No fingerprints enrolled; nothing to delete.")
    else:
        print(f"Deleted {count} {noun}. No fingerprints remain enrolled.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
