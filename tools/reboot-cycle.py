#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Journal and verify one exact delayed reboot on the reference machine."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time


PROJECT = Path(__file__).resolve().parents[1]
STATE_ROOT = Path("/var/lib/t2-touchid/reboot-cycles")
BOOT_ID = Path("/proc/sys/kernel/random/boot_id")
CHECKPOINT_RE = re.compile(r"D[0-9]{3,}")
OBJECT_RE = re.compile(r"[0-9a-f]{40,64}")
BOOT_ID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)
DELAY = "8s"
ACCURACY = "100ms"


class CycleError(RuntimeError):
    pass


def run(*argv: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        check=check,
        capture_output=True,
        text=True,
        timeout=10,
    )


def git(*args: str) -> str:
    return run(
        "git",
        "-c",
        f"safe.directory={PROJECT}",
        "-C",
        str(PROJECT),
        *args,
    ).stdout.strip()


def unit_name(checkpoint: str) -> str:
    if not CHECKPOINT_RE.fullmatch(checkpoint):
        raise CycleError("checkpoint must be D followed by at least three digits")
    return f"t2-touchid-{checkpoint.lower()}-delayed-reboot"


def systemd_run_command(checkpoint: str) -> tuple[str, ...]:
    unit = unit_name(checkpoint)
    return (
        "/usr/bin/systemd-run",
        f"--unit={unit}",
        f"--on-active={DELAY}",
        f"--timer-property=AccuracySec={ACCURACY}",
        "/usr/bin/systemctl",
        "reboot",
    )


def reboot_request_count(journal: str, unit: str) -> int:
    return sum(
        "reboot requested from client PID" in line and unit in line
        for line in journal.splitlines()
    )


def reboot_journal_command(source_boot_id: str) -> tuple[str, ...]:
    # logind emits the attributed request from its own unit. Filtering on the
    # transient reboot service hides that record even though MESSAGE names it.
    # Query the attested source boot itself rather than journal index -1: the
    # operator may power-cycle again before Codex resumes, while the original
    # exact reboot request remains authoritative and retained.
    if not BOOT_ID_RE.fullmatch(source_boot_id):
        raise CycleError("source boot ID is invalid")
    return (
        "journalctl",
        "-b",
        source_boot_id.replace("-", ""),
        "-o",
        "cat",
        "--no-pager",
        "-u",
        "systemd-logind.service",
    )


def require_root() -> None:
    if os.geteuid() != 0:
        raise CycleError("run through sudo")


def current_git() -> tuple[str, str]:
    branch = git("symbolic-ref", "--quiet", "--short", "HEAD")
    head = git("rev-parse", "HEAD")
    if git("status", "--porcelain=v1"):
        raise CycleError("worktree is not clean")
    return branch, head


def require_post_reboot_git(
    prepared_branch: object,
    prepared_head: object,
    current_remote_head: str | None,
) -> bool:
    """Require the attested head or one explicitly verified clean descendant."""

    branch, head = current_git()
    if branch != prepared_branch:
        raise CycleError("post-reboot Git branch differs from its attestation")
    if head == prepared_head:
        if current_remote_head is not None and current_remote_head != head:
            raise CycleError("verified current remote head differs from local HEAD")
        return False
    if (
        not isinstance(prepared_head, str)
        or not OBJECT_RE.fullmatch(prepared_head)
        or current_remote_head is None
        or not OBJECT_RE.fullmatch(current_remote_head)
        or head != current_remote_head
    ):
        raise CycleError("post-reboot Git state differs from its attestation")
    ancestor = run(
        "git",
        "-c",
        f"safe.directory={PROJECT}",
        "-C",
        str(PROJECT),
        "merge-base",
        "--is-ancestor",
        prepared_head,
        head,
        check=False,
    )
    if ancestor.returncode != 0:
        raise CycleError("current Git head is not an attested-head descendant")
    return True


def active_cycle_units() -> list[str]:
    output = run(
        "systemctl",
        "list-units",
        "--all",
        "--state=active,activating,reloading,deactivating",
        "--plain",
        "--no-legend",
        "t2-touchid-d*-delayed-reboot.*",
    ).stdout
    return [line.split()[0] for line in output.splitlines() if line.split()]


def require_idle_hardware() -> None:
    holders = run(
        "/usr/bin/fuser", "/dev/t2-aks", "/dev/t2-acm", check=False
    )
    if holders.returncode not in (0, 1):
        raise CycleError("device-holder check failed")
    if holders.stdout.strip() or holders.stderr.strip():
        raise CycleError("a T2 device still has an open holder")
    for entry in Path("/proc").iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            command = (entry / "cmdline").read_bytes().replace(b"\0", b" ")
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        if b"/usr/local/sbin/t2-native-enroll" in command:
            raise CycleError("a native enrollment owner is still running")


def private_directory() -> None:
    STATE_ROOT.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = STATE_ROOT.stat(follow_symlinks=False)
    if (
        not STATE_ROOT.is_dir()
        or info.st_uid != 0
        or info.st_gid != 0
        or info.st_mode & 0o077
    ):
        raise CycleError("reboot-cycle state root is not private and root-owned")


def write_exclusive(path: Path, value: dict[str, object]) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        payload = (json.dumps(value, sort_keys=True) + "\n").encode("utf-8")
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    directory = os.open(STATE_ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def read_exact(path: Path, fields: set[str]) -> dict[str, object]:
    info = path.stat(follow_symlinks=False)
    if (
        path.is_symlink()
        or not path.is_file()
        or info.st_uid != 0
        or info.st_gid != 0
        or info.st_mode & 0o077
        or info.st_nlink != 1
    ):
        raise CycleError("reboot-cycle record is not private and root-owned")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or set(value) != fields:
        raise CycleError("reboot-cycle record has an invalid schema")
    return value


def arm(checkpoint: str, remote_head: str) -> dict[str, object]:
    require_root()
    if not OBJECT_RE.fullmatch(remote_head):
        raise CycleError("remote head is not a lowercase Git object ID")
    branch, head = current_git()
    if head != remote_head:
        raise CycleError("local HEAD differs from the verified remote head")
    if active_cycle_units():
        raise CycleError("another delayed reboot unit is active")
    require_idle_hardware()
    private_directory()
    unit = unit_name(checkpoint)
    prepared = STATE_ROOT / f"{checkpoint}.prepared.json"
    scheduled = STATE_ROOT / f"{checkpoint}.scheduled.json"
    if prepared.exists() or scheduled.exists():
        raise CycleError("this checkpoint already has a reboot-cycle record")
    record = {
        "schema_version": 1,
        "checkpoint": checkpoint,
        "unit": unit,
        "branch": branch,
        "head": head,
        "remote_head": remote_head,
        "source_boot_id": BOOT_ID.read_text(encoding="ascii").strip(),
        "delay": DELAY,
        "accuracy": ACCURACY,
        "created_monotonic_ns": time.monotonic_ns(),
        "identifiers_private": True,
    }
    write_exclusive(prepared, record)
    result = run(*systemd_run_command(checkpoint))
    write_exclusive(
        scheduled,
        {
            "schema_version": 1,
            "checkpoint": checkpoint,
            "unit": unit,
            "systemd_run_returncode": result.returncode,
            "timer_reported": f"{unit}.timer" in result.stdout,
            "service_reported": f"{unit}.service" in result.stdout,
        },
    )
    return {
        "checkpoint": checkpoint,
        "clean_pushed_head_verified": True,
        "idle_hardware_verified": True,
        "private_pre_reboot_record_written": True,
        "delay": DELAY,
        "accuracy": ACCURACY,
        "timer_armed": True,
        "identifiers_redacted": True,
    }


def status(
    checkpoint: str, current_remote_head: str | None = None
) -> dict[str, object]:
    require_root()
    private_directory()
    unit = unit_name(checkpoint)
    prepared = read_exact(
        STATE_ROOT / f"{checkpoint}.prepared.json",
        {
            "schema_version",
            "checkpoint",
            "unit",
            "branch",
            "head",
            "remote_head",
            "source_boot_id",
            "delay",
            "accuracy",
            "created_monotonic_ns",
            "identifiers_private",
        },
    )
    scheduled = read_exact(
        STATE_ROOT / f"{checkpoint}.scheduled.json",
        {
            "schema_version",
            "checkpoint",
            "unit",
            "systemd_run_returncode",
            "timer_reported",
            "service_reported",
        },
    )
    if (
        prepared["schema_version"] != 1
        or scheduled["schema_version"] != 1
        or prepared["checkpoint"] != checkpoint
        or scheduled["checkpoint"] != checkpoint
        or prepared["unit"] != unit
        or scheduled["unit"] != unit
        or prepared["head"] != prepared["remote_head"]
        or prepared["delay"] != DELAY
        or prepared["accuracy"] != ACCURACY
        or prepared["identifiers_private"] is not True
        or scheduled["systemd_run_returncode"] != 0
    ):
        raise CycleError("reboot-cycle records do not reconcile")
    current_boot = BOOT_ID.read_text(encoding="ascii").strip()
    if current_boot == prepared["source_boot_id"]:
        raise CycleError("the recorded reboot has not crossed a boot boundary")
    descendant = require_post_reboot_git(
        prepared["branch"], prepared["head"], current_remote_head
    )
    journal = run(*reboot_journal_command(prepared["source_boot_id"])).stdout
    if reboot_request_count(journal, unit) != 1:
        raise CycleError("prior journal does not contain exactly one reboot request")
    if active_cycle_units():
        raise CycleError("a delayed reboot unit remains active after reboot")
    return {
        "checkpoint": checkpoint,
        "boot_boundary_verified": True,
        "clean_pushed_head_reconciled": True,
        "verified_descendant_head_reconciled": descendant,
        "exactly_one_reboot_request": True,
        "no_delayed_reboot_unit_active": True,
        "identifiers_redacted": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)
    arm_parser = subparsers.add_parser("arm")
    arm_parser.add_argument("--checkpoint", required=True)
    arm_parser.add_argument("--remote-head", required=True)
    status_parser = subparsers.add_parser("status")
    status_parser.add_argument("--checkpoint", required=True)
    status_parser.add_argument("--current-remote-head")
    args = parser.parse_args()
    result = (
        arm(args.checkpoint, args.remote_head)
        if args.action == "arm"
        else status(args.checkpoint, args.current_remote_head)
    )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (CycleError, OSError, subprocess.SubprocessError, ValueError) as error:
        print(f"reboot-cycle: {error}", file=sys.stderr)
        sys.exit(1)
