#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Persistent event-driven terminal UI for one Linux-native enrollment."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import datetime as dt
import json
import os
from pathlib import Path
import select
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import termios
import tty


CSI = "\x1b["
ALT_ON = f"{CSI}?1049h{CSI}?25l"
ALT_OFF = f"{CSI}?25h{CSI}?1049l"
EVENT_PREFIX = b"T2_ENROLL_EVENT "
DEFAULT_BROKER = Path("/usr/local/sbin/t2-native-enroll")
DEFAULT_ARTIFACT_ROOT = Path("/var/lib/t2-touchid/research-artifacts")
MAX_CREDENTIAL_BYTES = 128


@dataclass
class View:
    title: str = "STARTING NATIVE ENROLLMENT"
    detail: str = "Preparing protected state and a stable Bridge lease."
    hint: str = "The authorized launch starts exactly one bounded operation."
    color: str = "cyan"
    phase: int = 0
    progress: int = 0
    started: bool = False
    terminal: bool = False


class EnrollmentUI:
    # Match the restrained T1Bridge Touch ID overlay palette: neutral text,
    # blue enrollment progress, green success, and explicit retry/error color.
    COLORS = {
        "cyan": "38;2;64;156;255",
        "green": "38;2;48;209;88",
        "amber": "38;2;255;184;70",
        "red": "38;2;255;69;58",
        "dim": "38;2;142;142;147",
        "white": "38;2;220;220;220",
    }

    def __init__(self) -> None:
        self.view = View()
        self.color = "NO_COLOR" not in os.environ
        self.unicode = (sys.stdout.encoding or "ascii").lower() != "ascii"

    def paint(self, text: str, color: str) -> str:
        if not self.color:
            return text
        return f"{CSI}{self.COLORS.get(color, '97')}m{text}{CSI}0m"

    @staticmethod
    def center(text: str, width: int) -> str:
        return text.center(width)[:width]

    def draw(self) -> None:
        size = shutil.get_terminal_size((76, 28))
        width = max(48, min(72, size.columns - 2))
        bar_width = min(40, width - 12)
        filled = max(0, min(bar_width, self.view.progress * bar_width // 100))
        bar = ("━" if self.unicode else "=") * filled + (
            "─" if self.unicode else "-"
        ) * (bar_width - filled)
        stage = ("PREPARING", "AUTHORIZING", "ENROLLING", "COMPLETE")[
            max(0, min(3, self.view.phase))
        ]
        control = (
            "Q / ESC  CLOSE"
            if self.view.terminal
            else "Q / ESC  CANCEL SAFELY"
        )
        lines = [
            (self.center("T2 TOUCH ID", width), "white"),
            (self.center("LINUX-NATIVE ENROLLMENT", width), "dim"),
            ("", "dim"),
            (self.center("╭──────────────╮" if self.unicode else "+--------------+", width), self.view.color),
            (self.center("│      ◎       │" if self.unicode else "|      @       |", width), self.view.color),
            (self.center("│    ◎   ◎     │" if self.unicode else "|    @   @     |", width), self.view.color),
            (self.center("╰──────────────╯" if self.unicode else "+--------------+", width), self.view.color),
            ("", "dim"),
            (self.center(self.view.title, width), self.view.color),
            (self.center(self.view.detail, width), "white"),
            ("", "dim"),
            (self.center(f"{stage}  {self.view.progress:3d}%", width), "dim"),
            (self.center(bar, width), "cyan"),
            ("", "dim"),
            (self.center(self.view.hint, width), "dim"),
            (self.center(control, width), "dim"),
        ]
        available = max(1, size.lines - 1)
        lines = lines[:available]
        top_padding = max(0, (available - len(lines)) // 2)
        left = max(0, (size.columns - width) // 2)
        output = [f"{CSI}2J{CSI}H", *("" for _ in range(top_padding))]
        output.extend(" " * left + self.paint(text, color) + f"{CSI}K" for text, color in lines)
        sys.stdout.write("\n".join(output))
        sys.stdout.flush()

    def update(self, *, audible: bool = False, **changes: object) -> None:
        for name, value in changes.items():
            setattr(self.view, name, value)
        if audible:
            sys.stdout.write("\a")
        self.draw()

    def apply(self, event: dict[str, object]) -> None:
        kind = event.get("event_kind")
        if kind == "preflight-started":
            self.update(
                title="PREPARING NATIVE FINGERPRINT STATE",
                detail="No fingerprint mutation has been sent.",
                hint="Checking the live namespace and saved authority.",
                color="amber",
                phase=0,
            )
        elif kind == "empty-baseline-verified":
            self.update(
                title="EMPTY LIVE NAMESPACE VERIFIED",
                detail="Activating the Linux-created keybag.",
                hint="No finger action is needed yet.",
                color="green",
                phase=1,
            )
        elif kind == "existing-baseline-verified":
            self.update(
                title="CURRENT FINGERPRINT STATE VERIFIED",
                detail="The committed Catacomb and live identity agree exactly.",
                hint="Preparing the additional-finger enrollment context.",
                color="green",
                phase=1,
            )
        elif kind in {
            "preclient-residual-event-drained",
            "preparation-residual-event-drained",
        }:
            self.update(
                title="FINISHING SENSOR HANDOFF",
                detail="A completed-match callback was drained before enrollment.",
                hint="Opening a fresh read-only connection automatically.",
                color="amber",
                phase=0,
            )
        elif kind == "rolling-biolockout-synchronized":
            self.update(
                title="NEW FINGERPRINT SAVED",
                detail="The Catacomb and rolling BioLockout state are synchronized.",
                hint="Immediate new-finger validation starts next.",
                color="green",
                phase=3,
                progress=100,
            )
        elif kind == "keybag-ready":
            self.update(
                title="KEYBAG READY",
                detail="Authorizing one enrollment context.",
                hint="Wait for the explicit placement cue.",
                color="green",
                phase=1,
            )
        elif kind == "enrollment-armed":
            self.update(
                title="STARTING SENSOR CAPTURE",
                detail="Enrollment authorization is ready; waiting for accepted start.",
                hint="No finger action is needed until the placement cue appears.",
                color="amber",
                phase=2,
            )
        elif kind == "enrollment-active":
            self.update(
                audible=True,
                title="PLACE FINGER NOW",
                detail="Touch the sensor briefly; lift as soon as it registers.",
                hint="Use light taps. This screen will cue every next touch.",
                color="cyan",
                phase=2,
            )
        elif kind == "enrollment-feedback":
            self._feedback(event)

    def _feedback(self, event: dict[str, object]) -> None:
        action = event.get("action")
        progress = event.get("progress_percent")
        if isinstance(progress, int):
            self.view.progress = max(self.view.progress, min(100, progress))
        if action == "finger-present":
            self.update(
                audible=True,
                title="TOUCH REGISTERED — LIFT FINGER",
                detail="Contact was detected; this does not yet claim progress.",
                hint="Lift now and wait for the next placement cue.",
                color="cyan",
                phase=2,
            )
        elif action == "finger-removed":
            self.update(
                audible=True,
                title="PLACE FINGER AGAIN",
                detail="Use a slightly different part of the same finger pad.",
                hint="Touch briefly; lift as soon as the sensor registers it.",
                color="cyan",
                phase=2,
            )
        elif action in {"continue", "progress"}:
            self.update(
                audible=True,
                title="CAPTURE ACCEPTED — LIFT FINGER",
                detail="Enrollment progress came from the sensor.",
                hint="Lift cleanly, then reposition when asked.",
                color="green",
                phase=2,
            )
        elif action in {"remove-and-retry", "retry-scan", "retry-small-coverage"}:
            detail = (
                "Cover more of the sensor with the finger pad."
                if action == "retry-small-coverage"
                else "The sensor rejected that capture; adjust slightly."
            )
            self.update(
                audible=True,
                title="LIFT, THEN TRY AGAIN",
                detail=detail,
                hint="After full release, use another brief touch at a new angle.",
                color="amber",
                phase=2,
            )
        elif action == "dirty-sensor":
            self.update(
                audible=True,
                title="LIFT AND CLEAN THE SENSOR",
                detail="The sensor reported contamination.",
                hint="The operation will not silently invent a successful capture.",
                color="red",
                phase=2,
            )


def _read_credential(descriptor: int) -> bytearray:
    if descriptor < 0:
        raise RuntimeError("credential descriptor is invalid")
    value = bytearray()
    while len(value) <= MAX_CREDENTIAL_BYTES:
        block = os.read(descriptor, MAX_CREDENTIAL_BYTES + 1 - len(value))
        if not block:
            break
        value.extend(block)
        if b"\n" in value:
            value = value[: value.index(0x0A)]
            break
    if value.endswith(b"\r"):
        value.pop()
    if not 1 <= len(value) <= MAX_CREDENTIAL_BYTES:
        value[:] = b"\0" * len(value)
        raise RuntimeError("credential length is outside policy")
    return value


def _result_root(requested: Path | None) -> Path:
    root = requested
    if root is None:
        stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
        root = DEFAULT_ARTIFACT_ROOT / f"native-enroll-result-{stamp}" / "private"
    if not root.is_absolute() or root.name in {"", ".", ".."}:
        raise RuntimeError("result directory is invalid")
    parent = root.parent
    parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent_info = parent.stat(follow_symlinks=False)
    if not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid != 0 or parent_info.st_mode & 0o077:
        raise RuntimeError("result parent is unsafe")
    root.mkdir(mode=0o700, exist_ok=False)
    return root


def _run_child(args: argparse.Namespace, ui: EnrollmentUI, credential: bytearray) -> int:
    result_root = _result_root(args.result_root)
    stdout_path = result_root / "native-enroll.stdout"
    stderr_path = result_root / "native-enroll.stderr"
    exit_path = result_root / "native-enroll.exitcode"
    read_fd = -1
    pass_fds: tuple[int, ...] = ()
    credential_arguments: list[str] = []
    if credential:
        read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
        try:
            os.write(write_fd, credential + b"\n")
        finally:
            os.close(write_fd)
            credential[:] = b"\0" * len(credential)
        credential_arguments = ["--credential-fd", str(read_fd)]
        pass_fds = (read_fd,)
    command = [
        str(args.broker),
        *credential_arguments,
        "--operator-fd",
        "0",
        "--identity-name",
        args.identity_name,
        "--acknowledge-one-shot-native-enrollment",
        "--acknowledge-password-fallback-tested",
        "--acknowledge-local-catacomb-mutation",
    ]
    if args.add_finger:
        command.append("--add-finger")
    try:
        with stdout_path.open("xb") as stdout_file, stderr_path.open("xb") as stderr_file:
            process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                pass_fds=pass_fds,
                start_new_session=True,
            )
            if read_fd >= 0:
                os.close(read_fd)
                read_fd = -1
            selector = selectors.DefaultSelector()
            assert (
                process.stdin is not None
                and process.stdout is not None
                and process.stderr is not None
            )
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")
            selector.register(sys.stdin, selectors.EVENT_READ, "keyboard")
            pending = bytearray()
            cancel_sent = False
            streams = 2
            try:
                while streams or process.poll() is None:
                    for key, _mask in selector.select(0.20):
                        if key.data == "keyboard":
                            typed = sys.stdin.read(1)
                            if (
                                typed in ("q", "Q", "\x1b")
                                and process.poll() is None
                                and not cancel_sent
                            ):
                                cancel_sent = True
                                process.send_signal(signal.SIGTERM)
                                ui.update(
                                    title="CANCEL REQUESTED",
                                    detail="Waiting for the journaled sensor cancellation boundary.",
                                    hint="Do not close the window until cleanup reports terminal.",
                                    color="amber",
                                )
                            continue
                        chunk = os.read(key.fileobj.fileno(), 65536)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            streams -= 1
                            continue
                        if key.data == "stdout":
                            stdout_file.write(chunk)
                            stdout_file.flush()
                        else:
                            stderr_file.write(chunk)
                            stderr_file.flush()
                            pending.extend(chunk)
                            while b"\n" in pending:
                                line, _, remainder = pending.partition(b"\n")
                                pending = bytearray(remainder)
                                if not line.startswith(EVENT_PREFIX):
                                    continue
                                try:
                                    event = json.loads(
                                        line[len(EVENT_PREFIX) :].decode("utf-8")
                                    )
                                except (UnicodeDecodeError, json.JSONDecodeError):
                                    continue
                                if isinstance(event, dict):
                                    ui.apply(event)
                status = process.wait()
            finally:
                selector.close()
                try:
                    process.stdin.close()
                except OSError:
                    pass
                if process.poll() is None:
                    process.send_signal(signal.SIGTERM)
                    try:
                        process.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=15)
    finally:
        if read_fd >= 0:
            os.close(read_fd)
    exit_path.write_text(f"{status}\n", encoding="ascii")
    os.chmod(exit_path, 0o600)
    success = False
    if status == 0:
        try:
            document = json.loads(stdout_path.read_text(encoding="utf-8"))
            success = document.get("enrollment_succeeded") is True
        except (OSError, UnicodeError, json.JSONDecodeError, AttributeError):
            success = False
    if success:
        ui.update(
            audible=True,
            title="FINGERPRINT ENROLLED",
            detail="Linux persisted and reconciled the updated fingerprint set.",
            hint="Evidence is retained. Press Q or Escape to close this screen.",
            color="green",
            phase=3,
            progress=100,
            terminal=True,
        )
    else:
        ui.update(
            audible=True,
            title="ENROLLMENT STOPPED",
            detail="No success was assumed; the terminal journal and evidence are retained.",
            hint="Do not retry in this boot. Press Q or Escape to close.",
            color="red",
            terminal=True,
        )
    return status


def main() -> int:
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--broker", type=Path, default=DEFAULT_BROKER)
    parser.add_argument("--credential-fd", type=int)
    parser.add_argument("--add-finger", action="store_true")
    parser.add_argument("--identity-name", default="finger-1")
    parser.add_argument("--result-root", type=Path)
    args = parser.parse_args()
    if os.geteuid() != 0 or not sys.stdin.isatty() or not sys.stdout.isatty():
        parser.error("native enrollment TUI requires a root interactive terminal")
    credential = (
        _read_credential(args.credential_fd)
        if args.credential_fd is not None
        else bytearray()
    )
    saved = termios.tcgetattr(sys.stdin.fileno())
    status = 0
    try:
        tty.setcbreak(sys.stdin.fileno())
        sys.stdout.write(ALT_ON)
        ui = EnrollmentUI()
        ui.update(
            started=True,
            title="STARTING ONE BOUNDED ENROLLMENT",
            detail="Preparing protected state and a stable Bridge lease.",
            hint="No automatic retry is possible in this boot.",
            color="amber",
        )
        try:
            status = _run_child(args, ui, credential)
        except (OSError, RuntimeError, subprocess.SubprocessError):
            status = 1
            ui.update(
                audible=True,
                terminal=True,
                title="ENROLLMENT COULD NOT START",
                detail="The failure is terminal for this screen; no retry was sent.",
                hint="Retained state must be reconciled. Q or Escape closes.",
                color="red",
            )
        while True:
            readable, _, _ = select.select([sys.stdin], [], [], 0.20)
            if not readable:
                continue
            key = sys.stdin.read(1)
            if key in ("q", "Q", "\x1b"):
                return status
    finally:
        credential[:] = b"\0" * len(credential)
        termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, saved)
        sys.stdout.write(f"{CSI}0m{ALT_OFF}")
        sys.stdout.flush()


if __name__ == "__main__":
    raise SystemExit(main())
