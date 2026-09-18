#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Keep automatic services held until explicit native-state recovery finishes."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import t2_mutation_registry  # noqa: E402
import t2_native_state_recovery  # noqa: E402


def check(state_root: Path) -> bool:
    root = state_root / "mutations"
    # Fresh installations and recovery of interrupted first-run provisioning
    # can have no biometric mutation journals yet. A dangling link is invalid.
    if not os.path.lexists(root):
        return True
    try:
        entries = t2_mutation_registry.scan(root)
    except (OSError, RuntimeError, ValueError):
        print("Cannot validate mutation journals; recovery hold preserved.", file=sys.stderr)
        return False
    pending = [entry for entry in entries
               if entry.kind == t2_native_state_recovery.KIND
               and entry.blocks_new_mutation]
    if not pending:
        return True
    phases = ", ".join(sorted({entry.phase for entry in pending}))
    print(f"Native-state recovery is unfinished ({phases}); recovery hold preserved.",
          file=sys.stderr)
    if any(
        entry.phase.endswith(("reply-rejected", "outcome-unknown", "post-state-rejected"))
        or entry.phase == "canonical-master-reply-reconciled"
        for entry in pending
    ):
        print("Recovery stopped after a rejected or ambiguous hardware operation. "
              "Do not repeat recovery or clear its journal; preserve state and "
              "inspect sudo t2-touchid-doctor before choosing a repair.", file=sys.stderr)
        return False
    if any(entry.phase in {"cold-restart-prepared", "canonical-restart-prepared"}
           for entry in pending):
        print("Recovery requires a cold T2 restart; a Linux reboot alone may leave T2 warm.",
              file=sys.stderr)
    print("Resume: sudo t2-touchid-manage recover-native-state "
          "--acknowledge-retained-master-recovery\n"
          "Rerun normal setup only after recovery reports complete.", file=sys.stderr)
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-root", type=Path, default=Path("/var/lib/t2-touchid"))
    args = parser.parse_args()
    return 0 if check(args.state_root) else 1


if __name__ == "__main__":
    raise SystemExit(main())
