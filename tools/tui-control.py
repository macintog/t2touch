#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Focus-independent control of the reference machine's dedicated Touch ID TUI."""
from __future__ import annotations

import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time

PROFILES = {
    "sudo-pam": {
        "class": "t2-sudo-pam",
        "title": "T2-Sudo-PAM-Authentication",
        "launcher": "/usr/local/sbin/t2-sudo-pam-test-launch",
        "backend": b"/usr/bin/sudo",
        "ready_title": "Touch the fingerprint sensor now.",
        "terminal_titles": (
            "SUDO AUTHENTICATION SUCCEEDED",
            "SUDO AUTHENTICATION FAILED",
        ),
    },
    "fprintd-enrollment": {
        "class": "t2-fprintd-enroll",
        "title": "T2-Fprintd-Enrollment",
        "launcher": "/usr/local/sbin/t2-fprintd-enroll-tui-launch",
        "backend": b"/opt/t2-touchid/src/t2-fprintd-enroll-tui.py",
        "ready_title": "Lift and touch this finger repeatedly",
        "terminal_titles": (
            "Enrollment stopped",
            "Fingerprint enrolled",
        ),
    },
    "fprintd-preview": {
        "class": "t2-fprintd-preview",
        "title": "T1Bridge-Touch-ID-Preview",
        "launcher": "/usr/local/sbin/t2-fprintd-preview-tui-launch",
        "backend": b"/opt/t2-touchid/src/t2-fprintd-enroll-tui.py",
        "ready_title": "Lift and touch this finger repeatedly",
        "terminal_titles": ("Fingerprint enrolled",),
        "preview": True,
    },
    "fprintd-verification": {
        "class": "t2-fprintd-verify",
        "title": "T2-Fprintd-Verification",
        "launcher": "/usr/local/sbin/t2-fprintd-verify-tui-launch",
        "backend": b"/opt/t2-touchid/src/t2-fprintd-enroll-tui.py",
        "ready_title": "Touch with any enrolled finger",
        "terminal_titles": (
            "Verification stopped",
            "Fingerprint matched",
        ),
    },
    "fprintd-negative": {
        "class": "t2-fprintd-negative",
        "title": "T2-Fprintd-Negative-Control",
        "launcher": "/usr/local/sbin/t2-fprintd-negative-tui-launch",
        "backend": b"/opt/t2-touchid/src/t2-fprintd-enroll-tui.py",
        "ready_title": "Touch with an unenrolled finger",
        "terminal_titles": (
            "Verification stopped",
            "Expected non-match",
        ),
    },
    "fprintd-deletion": {
        "class": "t2-fprintd-delete",
        "title": "T2-Fprintd-Deletion",
        "launcher": "/usr/local/sbin/t2-fprintd-delete-tui-launch",
        "backend": b"/usr/bin/fprintd-delete",
        "ready_title": "FINGERPRINT DELETED",
        "terminal_titles": (
            "FINGERPRINT DELETED",
            "DELETION STOPPED",
        ),
    },
    "enrollment": {
        "class": "t2-native-enroll",
        "title": "T2-Native-Enrollment",
        "launcher": "/usr/local/sbin/t2-native-enroll-tui-launch",
        "backend": b"/usr/local/sbin/t2-native-enroll",
        "ready_title": "PLACE FINGER NOW",
        "terminal_titles": (
            "ENROLLMENT STOPPED",
            "ENROLLMENT COULD NOT START",
            "FINGERPRINT ENROLLED",
        ),
    },
    "match": {
        "class": "t2-native-match",
        "title": "T2-Native-Match",
        "launcher": "/usr/local/sbin/t2-native-match-tui-launch",
        "backend": b"/usr/local/sbin/t2-native-match",
        "ready_title": "PLACE FINGER NOW",
        "terminal_titles": (
            "OPERATION FAILED",
            "MATCHED",
            "NOT MATCHED",
            "SENSOR OPERATION ENDED",
        ),
    },
    "negative": {
        "class": "t2-native-negative",
        "title": "T2-Native-Negative-Control",
        "launcher": "/usr/local/sbin/t2-native-negative-tui-launch",
        "backend": b"/usr/local/sbin/t2-native-match",
        "ready_title": "PLACE UNENROLLED FINGER NOW",
        "terminal_titles": (
            "OPERATION FAILED",
            "EXPECTED NON-MATCH",
            "UNEXPECTED MATCH",
            "SENSOR OPERATION ENDED",
        ),
    },
    "new-finger": {
        "class": "t2-native-new-finger",
        "title": "T2-Native-New-Finger-Proof",
        "launcher": "/usr/local/sbin/t2-native-new-finger-tui-launch",
        "backend": b"/usr/local/sbin/t2-native-match",
        "ready_title": "PLACE NEW FINGER NOW",
        "terminal_titles": (
            "OPERATION FAILED",
            "NEW FINGER VERIFIED",
            "WRONG ENROLLED FINGER",
            "SENSOR OPERATION ENDED",
        ),
    },
    "second": {
        "class": "t2-second-finger",
        "title": "T2-Second-Finger-Ceremony",
        "launcher": "/usr/local/sbin/t2-second-finger-tui-launch",
        "backend": b"/opt/t2-touchid/src/t2-second-finger-ceremony.py",
        "ready_title": "PLACE CURRENT FINGER NOW",
        "terminal_titles": (
            "CEREMONY STOPPED SAFELY",
            "SECOND FINGER ENROLLED AND VERIFIED",
            "CURRENT FINGER VERIFIED",
        ),
    },
}

def finger_handle(value: str) -> str:
    match = re.fullmatch(r"finger-([1-9][0-9]{0,8})", value)
    if match is None or int(match.group(1)) > 999_999_999:
        raise argparse.ArgumentTypeError("finger handle must look like finger-1")
    return value


def run(*argv: str) -> str:
    return subprocess.run(argv, check=True, capture_output=True, text=True, timeout=3).stdout


class Control:
    def __init__(
        self,
        root: Path,
        instance: str,
        profile: dict[str, object] | None = None,
        launcher_args: tuple[str, ...] = (),
    ):
        self.root = root
        self.instance = instance
        self.socket = f"unix:{root}/kitty.sock"
        self.profile = PROFILES["enrollment"] if profile is None else profile
        self.launcher_args = launcher_args

    def hypr(self, *args: str) -> str:
        return run("hyprctl", "-i", self.instance, *args)

    def remote(self, *args: str) -> str:
        return run("kitty", "@", "--to", self.socket, *args)

    def window(self) -> str:
        windows = [w for osw in json.loads(self.remote("ls"))
                   for tab in osw["tabs"] for w in tab["windows"]]
        if len(windows) != 1:
            raise RuntimeError("expected exactly one terminal on the dedicated socket")
        return str(windows[0]["id"])

    def screen(self, window: str) -> str:
        return self.remote("get-text", "--match", f"id:{window}", "--extent", "screen").strip()

    def backend_active(self) -> bool:
        backend = self.profile["backend"]
        for process in Path("/proc").iterdir():
            if not process.name.isdecimal():
                continue
            try:
                arguments = process.joinpath("cmdline").read_bytes().split(b"\0")
            except (OSError, PermissionError):
                continue
            if backend in arguments:
                return True
        return False

    def wait(self, predicate, description: str, *, timeout: float = 5):
        deadline = time.monotonic() + timeout
        while True:
            try:
                value = predicate()
                if value:
                    return value
            except (OSError, subprocess.SubprocessError, ValueError):
                pass  # Only observation is retried, never launch/input.
            if time.monotonic() >= deadline:
                raise RuntimeError(f"timed out waiting for {description}; no action was replayed")
            time.sleep(0.1)

    def wait_for_physical_readiness(self, window: str) -> str:
        """Return only after the launched TUI is ready or definitively terminal."""
        terminal_titles = self.profile["terminal_titles"]
        ready_title = self.profile["ready_title"]

        def handoff_screen() -> str | None:
            screen = self.screen(window)
            if any(title in screen for title in terminal_titles):
                return screen
            if ready_title in screen and self.backend_active():
                # Re-read once after a short stability interval so a screen
                # painted immediately before terminal cleanup is never handed
                # to the operator as a live capture state.
                time.sleep(0.25)
                stable = self.screen(window)
                if any(title in stable for title in terminal_titles):
                    return stable
                if ready_title in stable and self.backend_active():
                    return stable
            return None

        screen = self.wait(
            handoff_screen,
            "physical-readiness or terminal Touch ID state",
            timeout=60,
        )
        if ready_title not in screen:
            raise RuntimeError("Touch ID operation stopped before physical readiness")
        return screen

    def launch(self) -> str:
        clients = json.loads(self.hypr("-j", "clients"))
        window_class = self.profile["class"]
        if any(c.get("class") == window_class or c.get("initialClass") == window_class for c in clients):
            raise RuntimeError("a dedicated Touch ID terminal already exists; inspect it instead")
        workspace = json.loads(self.hypr("-j", "activeworkspace"))
        # Dwindle supports preselection; scrolling already inserts beside the
        # current column. Never send an unsupported layout command blindly.
        if workspace.get("tiledLayout") == "dwindle":
            self.hypr("dispatch", 'hl.dsp.layout("preselect r")')
        command = shlex.join(
            [
                "kitty",
                "--class",
                window_class,
                "-T",
                self.profile["title"],
                "--hold",
                "-o",
                "allow_remote_control=socket-only",
                "--listen-on",
                self.socket,
                self.profile["launcher"],
                *self.launcher_args,
            ]
        )
        self.hypr("dispatch", f"hl.dsp.exec_cmd({json.dumps(command)})")
        return self.wait(self.window, "the dedicated terminal socket")

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action",
        choices=(
            "launch",
            "status",
            "launch-fprintd-enroll",
            "fprintd-enroll-status",
            "launch-fprintd-preview",
            "fprintd-preview-status",
            "launch-fprintd-verify",
            "fprintd-verify-status",
            "launch-fprintd-negative",
            "fprintd-negative-status",
            "launch-fprintd-delete",
            "fprintd-delete-status",
            "launch-match",
            "match-status",
            "launch-negative",
            "negative-status",
            "launch-new-finger",
            "new-finger-status",
            "launch-second-finger",
            "second-finger-status",
            "launch-sudo-pam",
            "sudo-pam-status",
        ),
    )
    parser.add_argument("--instance", default="0", help="explicit Hyprland instance (default: 0)")
    parser.add_argument(
        "--finger",
        type=finger_handle,
        help="neutral numbered enrollment handle",
    )
    args = parser.parse_args()
    if os.geteuid() == 0:
        parser.error("run as the desktop user; the fixed launcher owns sudo")
    finger_actions = {"launch-fprintd-enroll", "launch-fprintd-delete"}
    if args.finger is not None and args.action not in finger_actions:
        parser.error("--finger is only valid with enrollment or deletion launch")
    if args.action == "launch-fprintd-delete" and args.finger is None:
        parser.error("deletion launch requires --finger")
    os.umask(0o077)
    runtime = Path(f"/run/user/{os.getuid()}")
    boot = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    if args.action in {"launch-fprintd-preview", "fprintd-preview-status"}:
        profile_name = "fprintd-preview"
    elif args.action in {"launch-fprintd-enroll", "fprintd-enroll-status"}:
        profile_name = "fprintd-enrollment"
    elif args.action in {"launch-sudo-pam", "sudo-pam-status"}:
        profile_name = "sudo-pam"
    elif args.action in {"launch-fprintd-verify", "fprintd-verify-status"}:
        profile_name = "fprintd-verification"
    elif args.action in {"launch-fprintd-negative", "fprintd-negative-status"}:
        profile_name = "fprintd-negative"
    elif args.action in {"launch-fprintd-delete", "fprintd-delete-status"}:
        profile_name = "fprintd-deletion"
    elif args.action in {"launch-new-finger", "new-finger-status"}:
        profile_name = "new-finger"
    elif args.action in {"launch-second-finger", "second-finger-status"}:
        profile_name = "second"
    elif args.action in {"launch-negative", "negative-status"}:
        profile_name = "negative"
    elif args.action in {"launch-match", "match-status"}:
        profile_name = "match"
    else:
        profile_name = "enrollment"
    root_prefix = {
        "fprintd-enrollment": "t2-fprintd-enroll-tui",
        "fprintd-preview": "t2-fprintd-preview-tui",
        "sudo-pam": "t2-sudo-pam-test",
        "fprintd-verification": "t2-fprintd-verify-tui",
        "fprintd-negative": "t2-fprintd-negative-tui",
        "fprintd-deletion": "t2-fprintd-delete-tui",
        "enrollment": "t2-tui",
        "match": "t2-match-tui",
        "negative": "t2-negative-tui",
        "new-finger": "t2-new-finger-tui",
        "second": "t2-second-finger-tui",
    }[profile_name]
    root = runtime / f"{root_prefix}-{boot}"
    root.mkdir(mode=0o700, exist_ok=True)
    info = root.lstat()
    if root.is_symlink() or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise RuntimeError("control directory is not private and user-owned")
    with (root / "control.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        launcher_args = (args.finger,) if args.finger is not None else ()
        control = Control(
            root,
            args.instance,
            PROFILES[profile_name],
            launcher_args,
        )
        launch = args.action in {
            "launch",
            "launch-fprintd-enroll",
            "launch-fprintd-preview",
            "launch-sudo-pam",
            "launch-fprintd-verify",
            "launch-fprintd-negative",
            "launch-fprintd-delete",
            "launch-match",
            "launch-negative",
            "launch-new-finger",
            "launch-second-finger",
        }
        window = control.launch() if launch else control.window()
        if launch and not control.profile.get("preview", False):
            screen = control.wait_for_physical_readiness(window)
        else:
            screen = control.screen(window)
        print(screen)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as error:
        print(f"tui-control: {error}", file=sys.stderr)
        sys.exit(1)
