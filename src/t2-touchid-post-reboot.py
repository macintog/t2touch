#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Automatically prove a completed biometric mutation survived a fresh boot."""

from __future__ import annotations

import json
import os
import sys

import t2_activation_journal_retention
import t2_native_post_reboot_reconciler
import t2_post_reboot_diagnostic
import t2_post_reboot_reconciler


def main() -> int:
    try:
        t2_activation_journal_retention.prune()
    except t2_activation_journal_retention.ActivationJournalRetentionError:
        pass
    try:
        mode = os.environ.get("T2_TOUCHID_AUTHORITY_MODE")
        if mode == "linux-native":
            result = t2_native_post_reboot_reconciler.run()
            if result.state == "no-pending-mutation":
                result = (
                    t2_native_post_reboot_reconciler.reconcile_external_deletion_if_needed()
                )
        elif mode == "macos-control-oracle":
            result = t2_post_reboot_reconciler.run()
        else:
            raise RuntimeError("configured authority mode is invalid")
    except Exception as error:
        print(
            json.dumps(
                t2_post_reboot_diagnostic.redacted_failure(error),
                sort_keys=True,
                separators=(",", ":"),
            ),
            file=sys.stderr,
        )
        return 1
    print(json.dumps(result.redacted(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
