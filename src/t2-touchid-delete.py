#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""One narrowly scoped deletion after pkexec has authenticated the operator."""

from __future__ import annotations

import argparse
import importlib.util
import os
from pathlib import Path
import re
import signal
import sys

SOURCE = Path(__file__).resolve().parent
# The installed launcher uses isolated Python. Import only our root-owned tree.
sys.path.insert(0, str(SOURCE))


class DeleteError(RuntimeError):
    pass


def _manager():
    spec = importlib.util.spec_from_file_location(
        "t2_delete_manager", SOURCE / "t2-touchid-manage.py"
    )
    if spec is None or spec.loader is None:
        raise DeleteError("identity manager is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def delete(finger: str, *, manager_factory=_manager) -> None:
    # PKEXEC_UID is supplied by pkexec's sanitized environment. It is not an
    # authorization token for unprivileged execution: root is mandatory.
    if os.geteuid() != 0:
        raise DeleteError("run t2touch delete as your normal desktop account")
    uid = os.environ.get("PKEXEC_UID", "")
    if not re.fullmatch(r"[1-9][0-9]{0,9}", uid) or int(uid) >= 2**32 - 1:
        raise DeleteError("authenticated caller is unavailable")
    if not re.fullmatch(r"finger-[1-5]", finger):
        raise DeleteError("deletion requires one numbered finger handle")
    previous = os.environ.get("SUDO_UID")
    os.environ["SUDO_UID"] = uid
    try:
        manager = manager_factory()
        configuration = manager.runtime_configuration()
        if (configuration.get("linux_uid") != int(uid)
                or configuration.get("authority_mode") != "linux-native"):
            raise DeleteError("authenticated caller has no native account mapping")
        # Reuse the administrative management entry point's exact inventory,
        # capability, mutation journal and recovery checks. Polkit has already
        # completed; never ask it again while holding these resources.
        with manager.operation_lock(), manager.sleep_inhibitor():
            result = manager.run_delete(configuration, finger_name=finger)
        if not isinstance(result, dict) or result.get("delete_succeeded") is not True:
            raise DeleteError("single-finger deletion did not reconcile")
    finally:
        if previous is None:
            os.environ.pop("SUDO_UID", None)
        else:
            os.environ["SUDO_UID"] = previous


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("finger", choices=[f"finger-{n}" for n in range(1, 6)])
    args = parser.parse_args()
    # Once accepted, terminal closure/cancellation must not interrupt a
    # potentially dispatched deletion before its journal is reconciled.
    for sig in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, signal.SIG_IGN)
    try:
        delete(args.finger)
    except Exception as error:
        # Manager errors may include private identity values. Keep them out of
        # terminal output; durable operation journals own recovery details.
        print(f"t2touch: deletion failed ({type(error).__name__}); "
              "run sudo t2-touchid-doctor for recovery status", file=sys.stderr)
        return 1
    print(f"Deleted {args.finger}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
