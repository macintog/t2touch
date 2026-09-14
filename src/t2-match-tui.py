#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Interactive terminal UI for one bounded T2 Touch ID observation."""

import argparse
import datetime
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
import time
import tty
from dataclasses import dataclass

import t2_enrollment_journal
import t2_mutation_journal
import t2_mutation_registry


CSI = "\x1b["
ALT_SCREEN_ON = f"{CSI}?1049h{CSI}?25l"
ALT_SCREEN_OFF = f"{CSI}?25h{CSI}?1049l"
MUTATION_ROOT = Path("/var/lib/t2-touchid/mutations")


def _addition_journal() -> Path:
    t2_mutation_registry.scan(MUTATION_ROOT)
    candidates = []
    for path in MUTATION_ROOT.glob("*.jsonl"):
        records = t2_mutation_journal.read(path)
        evidence = records[0].get("evidence") if records else None
        if (
            not isinstance(evidence, dict)
            or evidence.get("operation_kind") != "enroll"
        ):
            continue
        history = t2_enrollment_journal.validate_history(records)
        if (
            history.phase is t2_enrollment_journal.EnrollmentPhase.RECONCILED
            and history.baseline.get("baseline_version") == 1
            and history.terminal_identity_uuid is not None
        ):
            candidates.append(path)
    if len(candidates) != 1:
        raise RuntimeError(
            "new-finger proof requires exactly one reconciled addition journal"
        )
    return candidates[0]


@dataclass
class ViewState:
    mode: str = "starting"
    title: str = "PREPARING TOUCH ID"
    detail: str = "Verifying the saved fingerprint authority…"
    hint: str = "The sensor has not requested contact yet."
    color: str = "amber"
    phase: int = 0
    captures: int = 0
    status_code: int | None = None
    started_at: float | None = None
    awaiting_ack: bool = False
    rejected_since_removal: bool = False
    retry_advice: str = "The previous capture was rejected."
    verdict_received: bool = False
    verdict_matched: bool = False


class TerminalUI:
    COLORS = {
        "cyan": "96",
        "green": "92",
        "amber": "93",
        "red": "91",
        "white": "97",
        "dim": "2",
    }

    def __init__(
        self,
        observation_seconds: float,
        expect_no_match: bool = False,
        require_new_identity: bool = False,
    ) -> None:
        self.observation_seconds = observation_seconds
        self.expect_no_match = expect_no_match
        self.require_new_identity = require_new_identity
        self.state = ViewState()
        self.resize_pending = True
        self.last_second: int | None = None
        self.color_enabled = "NO_COLOR" not in os.environ
        self.unicode = self._supports_unicode()
        self.previous_winch: object = None

    @staticmethod
    def _supports_unicode() -> bool:
        try:
            "╭─●◉".encode(sys.stdout.encoding or "ascii")
        except UnicodeEncodeError:
            return False
        return True

    def __enter__(self) -> "TerminalUI":
        self.previous_winch = signal.getsignal(signal.SIGWINCH)
        signal.signal(signal.SIGWINCH, self._on_resize)
        sys.stdout.write(ALT_SCREEN_ON)
        sys.stdout.flush()
        self.draw(force=True)
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        signal.signal(signal.SIGWINCH, self.previous_winch)
        sys.stdout.write(f"{CSI}0m{ALT_SCREEN_OFF}")
        sys.stdout.flush()

    def _on_resize(self, _signum: int, _frame: object) -> None:
        self.resize_pending = True

    def beep(self) -> None:
        sys.stdout.write("\a")
        sys.stdout.flush()

    def paint(self, text: str, color: str) -> str:
        if not self.color_enabled:
            return text
        color_code = self.COLORS.get(color, self.COLORS["white"])
        return f"{CSI}{color_code}m{text}{CSI}0m"

    @staticmethod
    def center(text: str, width: int) -> str:
        return text.center(max(1, width))[:width]

    def sensor_art(self) -> list[str]:
        if not self.unicode:
            marks = {
                "standby": ".",
                "starting": "o",
                "waiting": "o",
                "present": "#",
                "lift": "^",
                "ready": ">",
                "rejected": "x",
                "matched": "+",
                "failed": "!",
                "complete": "-",
            }
            mark = marks.get(self.state.mode, marks["failed"])
            return [
                "+--------------+",
                f"|      {mark}       |",
                f"|    {mark} {mark}     |",
                f"|      {mark}       |",
                "+--------------+",
            ]

        art = {
            "standby": ("      ·       ", "    ·   ·     ", "      ·       "),
            "starting": ("      ◌       ", "    ◌   ◌     ", "      ◌       "),
            "waiting": ("              ", "      ◎       ", "              "),
            "present": ("     ╭──╮     ", "   ╭─╯  ╰─╮   ", "   ╰─╮  ╭─╯   "),
            "lift": ("      ↑       ", "    ↑ ↑ ↑     ", "      ◉       "),
            "ready": ("      ↻       ", "    ENTER     ", "              "),
            "rejected": ("    ╲   ╱     ", "      ×       ", "    ╱   ╲     "),
            "matched": ("      ✓       ", "    ✓ ✓ ✓     ", "      ✓       "),
            "failed": ("      !       ", "    ! ! !     ", "      !       "),
            "complete": ("      ◉       ", "    ─────     ", "              "),
        }
        inside = art.get(self.state.mode, art["failed"])
        return [
            "╭──────────────╮",
            f"│{inside[0]}│",
            f"│{inside[1]}│",
            f"│{inside[2]}│",
            "╰──────────────╯",
        ]

    def phase_line(self, width: int) -> str:
        active = max(0, min(3, self.state.phase))
        labels = ("TOUCH", "LIFT", "MATCH", "VERDICT")
        filled, empty, join = (
            ("●", "○", "──") if self.unicode else ("*", "o", "--")
        )
        pieces = [
            f"{filled if index == active else empty} {label}"
            for index, label in enumerate(labels)
        ]
        return self.center(f" {join} ".join(pieces), width)

    def metrics_line(self, width: int) -> str:
        attempts = f"ATTEMPTS  {self.state.captures:02d}"
        if self.state.started_at is None:
            timing = "EVENT-DRIVEN"
        elif self.observation_seconds == 0:
            timing = "INTERACTIVE  •  Q/ESC CANCELS"
        else:
            elapsed = max(0, int(time.monotonic() - self.state.started_at))
            limit = max(0, int(self.observation_seconds))
            timing = (
                f"ELAPSED  {elapsed // 60:02d}:{elapsed % 60:02d} / "
                f"{limit // 60:02d}:{limit % 60:02d} CEILING"
            )
        separator = "  •  " if self.unicode else "  |  "
        return self.center(attempts + separator + timing, width)

    def compact_lines(self, width: int) -> list[tuple[str, str]]:
        return [
            ("T2 TOUCH ID  /  LIVE ACQUISITION", "cyan"),
            ("-" * width, "dim"),
            (self.state.title, self.state.color),
            (self.state.detail, "white"),
            (self.phase_line(width), self.state.color),
            (self.metrics_line(width), "dim"),
            (self.state.hint, "dim"),
        ]

    def full_lines(self, width: int) -> list[tuple[str, str]]:
        border = (
            ("╭", "╮", "╰", "╯", "─", "│")
            if self.unicode
            else ("+", "+", "+", "+", "-", "|")
        )
        top_left, top_right, bottom_left, bottom_right, horizontal, vertical = border
        inner = width - 2
        lines: list[tuple[str, str]] = [
            (top_left + horizontal * inner + top_right, "cyan"),
            (
                vertical
                + self.center("T2 TOUCH ID  /  LIVE ACQUISITION", inner)
                + vertical,
                "cyan",
            ),
            (vertical + " " * inner + vertical, "cyan"),
        ]
        for art_line in self.sensor_art():
            lines.append(
                (
                    vertical + self.center(art_line, inner) + vertical,
                    self.state.color,
                )
            )
        lines.extend(
            [
                (vertical + " " * inner + vertical, "cyan"),
                (
                    vertical + self.center(self.state.title, inner) + vertical,
                    self.state.color,
                ),
                (
                    vertical + self.center(self.state.detail, inner) + vertical,
                    "white",
                ),
                (vertical + " " * inner + vertical, "cyan"),
                (
                    vertical + self.phase_line(inner) + vertical,
                    self.state.color,
                ),
                (vertical + " " * inner + vertical, "cyan"),
                (vertical + self.metrics_line(inner) + vertical, "dim"),
                (vertical + self.center(self.state.hint, inner) + vertical, "dim"),
                (bottom_left + horizontal * inner + bottom_right, "cyan"),
            ]
        )
        return lines

    def draw(self, *, force: bool = False) -> None:
        size = shutil.get_terminal_size(fallback=(72, 30))
        second = (
            int(time.monotonic() - self.state.started_at)
            if self.state.started_at is not None
            else None
        )
        if not force and not self.resize_pending and second == self.last_second:
            return
        self.resize_pending = False
        self.last_second = second
        columns, rows = max(10, size.columns), max(4, size.lines)
        width = max(8, min(72, columns - 2))
        lines = (
            self.compact_lines(width)
            if columns < 54 or rows < 22
            else self.full_lines(width)
        )
        lines = lines[: max(1, rows - 1)]
        top_padding = max(0, (rows - 1 - len(lines)) // 2)
        left_padding = max(0, (columns - width) // 2)
        output = [f"{CSI}2J{CSI}H"] + [""] * top_padding
        for text, color in lines:
            output.append(
                " " * left_padding
                + self.paint(text[:width], color)
                + f"{CSI}K"
            )
        sys.stdout.write("\n".join(output))
        sys.stdout.flush()

    def set_state(self, *, audible: bool = False, **changes: object) -> None:
        for name, value in changes.items():
            setattr(self.state, name, value)
        if audible:
            self.beep()
        self.draw(force=True)


def show_place_finger(ui: TerminalUI, *, audible: bool = True) -> None:
    ui.set_state(
        audible=audible,
        mode="waiting",
        title=(
            "PLACE UNENROLLED FINGER NOW"
            if ui.expect_no_match
            else "PLACE NEW FINGER NOW"
            if ui.require_new_identity
            else "PLACE FINGER NOW"
        ),
        detail=(
            "Briefly touch with a finger that was not enrolled."
            if ui.expect_no_match
            else "Briefly touch with the newly enrolled finger."
            if ui.require_new_identity
            else "Briefly touch the sensor with the enrolled finger."
        ),
        hint="The sensor will detect the touch in a fraction of a second.",
        color="cyan",
        phase=0,
        awaiting_ack=False,
        rejected_since_removal=False,
    )


def apply_event(ui: TerminalUI, event: dict) -> str | None:
    semantics = event.get("status_semantics")
    status_code = event.get("status_code")
    if isinstance(status_code, int):
        ui.state.status_code = status_code

    if event.get("event_kind") == "match_armed":
        show_place_finger(ui)
        return

    if event.get("event_kind") == "match_result":
        if event.get("result_valid") is not True:
            ui.set_state(
                audible=True,
                mode="failed",
                title="UNUSABLE SENSOR RESULT",
                detail="The result failed exact Apple framing or identity checks.",
                hint="No authentication decision was made.",
                color="red",
                awaiting_ack=False,
            )
            return
        matched = event.get("matched") is True
        if not matched and event.get("no_match") is True:
            quality_rejected = event.get("no_match_image_quality") is True
            if ui.expect_no_match and not quality_rejected:
                ui.set_state(
                    audible=True,
                    mode="matched",
                    title="EXPECTED NON-MATCH",
                    detail="The valid capture did not match the saved fingerprint.",
                    hint="The negative control is closing cleanly…",
                    color="green",
                    phase=3,
                    verdict_received=True,
                    verdict_matched=False,
                    awaiting_ack=False,
                )
                return
            ui.set_state(
                audible=True,
                mode="rejected",
                title=(
                    "CAPTURE QUALITY TOO LOW — LIFT AND RETRY"
                    if quality_rejected
                    else "NOT MATCHED — LIFT AND TRY AGAIN"
                ),
                detail=(
                    "The sensor classified this as an image-quality rejection."
                    if quality_rejected
                    else "The valid capture did not match the enrolled finger."
                ),
                hint="Lift promptly; the session re-arms without another keypress.",
                color="red",
                phase=2,
                rejected_since_removal=True,
                retry_advice=(
                    "Use more of the finger pad on the next placement."
                    if quality_rejected
                    else "Use the enrolled finger and place it fully next time."
                ),
                awaiting_ack=False,
            )
            return
        wrong_new_identity = (
            ui.require_new_identity
            and matched
            and event.get("matches_required_identity") is not True
        )
        unexpected_match = (ui.expect_no_match and matched) or wrong_new_identity
        ui.set_state(
            audible=True,
            mode="failed" if unexpected_match else ("matched" if matched else "rejected"),
            title=(
                "UNEXPECTED MATCH"
                if ui.expect_no_match and unexpected_match
                else "WRONG ENROLLED FINGER"
                if wrong_new_identity
                else "NEW FINGER VERIFIED"
                if ui.require_new_identity and matched
                else "MATCHED" if matched else "NOT MATCHED"
            ),
            detail="A terminal biometric verdict was received.",
            hint="The sensor operation is closing cleanly…",
            color="red" if unexpected_match else ("green" if matched else "red"),
            phase=3,
            verdict_received=True,
            verdict_matched=matched,
            awaiting_ack=False,
        )
        return
    if semantics == "finger-present":
        ui.set_state(
            audible=True,
            mode="lift",
            title="CONTACT DETECTED — LIFT NOW",
            detail="The sensor registered the brief touch.",
            hint="Lift fully while the secure match completes.",
            color="cyan",
            phase=1,
        )
    elif semantics == "capture-progress":
        # Exact 24G830 BKMatchOperation does not expose status 91 as an
        # operator callback.  Preserve the current UI state and wait for an
        # actionable status or terminal match result.
        return
    elif semantics == "finger-removed":
        if not ui.state.verdict_received:
            rejected = ui.state.rejected_since_removal
            ui.set_state(
                audible=True,
                mode="waiting",
                title="PLACE FINGER AGAIN — WAIT" if rejected else "PLACE FINGER — WAIT",
                detail=(
                    ui.state.retry_advice
                    if rejected
                    else "The sensor confirmed release and is ready for contact."
                ),
                hint="Use another brief touch; do not hold the finger down.",
                color="cyan",
                phase=0,
                awaiting_ack=False,
                rejected_since_removal=False,
            )
    elif semantics == "operation-ended":
        ui.set_state(
            audible=True,
            mode="failed",
            title="SENSOR OPERATION ENDED",
            detail=(
                f"The sensor stopped without a biometric verdict "
                f"(status {status_code}, reason {event.get('operation_end_reason')})."
            ),
            hint="Cleanup is running; no authentication decision was made.",
            color="red",
            phase=3,
            awaiting_ack=False,
        )
    elif semantics in {
        "capture-rejected",
        "capture-rejected-small-coverage",
        "lift-and-retry",
    }:
        ui.state.captures += 1
        detail = (
            "Use more of the finger pad on the next placement."
            if semantics == "capture-rejected-small-coverage"
            else "Lift promptly and adjust the next brief touch."
        )
        retry_advice = (
            "Use more of the finger pad on the next placement."
            if semantics == "capture-rejected-small-coverage"
            else "The previous capture was rejected."
        )
        ui.set_state(
            audible=True,
            mode="rejected",
            title="CAPTURE REJECTED — LIFT NOW",
            detail=detail,
            hint="Lift fully; the sensor will ask for another brief touch.",
            color="red",
            phase=1,
            rejected_since_removal=True,
            retry_advice=retry_advice,
        )
        return
    elif semantics == "sensor-dirty":
        ui.set_state(
            audible=True,
            mode="failed",
            title="CLEAN SENSOR",
            detail="Lift the finger before cleaning the sensor.",
            hint="No automatic retry will be attempted.",
            color="red",
            phase=0,
        )
    return None


def wait_for_key(ui: TerminalUI, accepted: str) -> str:
    while True:
        ui.draw()
        readable, _, _ = select.select([sys.stdin], [], [], 0.20)
        if readable:
            key = sys.stdin.read(1)
            if key in accepted:
                return key


def run_observation(args: argparse.Namespace, ui: TerminalUI) -> int:
    stamp = datetime.datetime.now(datetime.UTC).strftime("%Y%m%dT%H%M%S%fZ")
    public_path = f"/var/lib/t2-touchid/native-match/tui-match-{stamp}.json"
    private_path = f"/var/lib/t2-touchid/native-match/private-tui-match-events-{stamp}.json"
    diagnostic_path = f"/var/lib/t2-touchid/native-match/tui-match-{stamp}.stderr"
    command = [
        args.probe,
        "--observation-seconds",
        str(args.observation_seconds),
        "--private-match-events-output",
        private_path,
    ]
    if args.expect_no_match:
        command.append("--expect-no-match")
    if args.match_new_finger:
        command.extend(["--addition-journal", str(_addition_journal())])
    ui.set_state(
        mode="starting",
        title="OPENING SENSOR",
        detail="Preparing one bounded observation…",
        hint="The duration is a safety ceiling, not a capture timer.",
        color="amber",
        phase=0,
        started_at=time.monotonic(),
    )

    event_prefix = b"T2_MATCH_EVENT "
    pending = bytearray()
    process: subprocess.Popen[bytes] | None = None
    selector: selectors.BaseSelector | None = None
    status = 1
    observation_error: Exception | None = None
    cancel_requested = False
    rejection_cancel_requested = False
    termination_signal_received = False
    saved = termios.tcgetattr(sys.stdin.fileno())
    previous_sigint = signal.getsignal(signal.SIGINT)
    previous_sighup = signal.getsignal(signal.SIGHUP)
    previous_sigterm = signal.getsignal(signal.SIGTERM)

    def request_clean_termination(_signum: int, _frame: object) -> None:
        nonlocal termination_signal_received
        termination_signal_received = True

    try:
        tty.setcbreak(sys.stdin.fileno())
        # Keep terminal interrupts from bypassing the probe's bounded cleanup.
        # The child has its own process group, so an operator Ctrl-C cannot
        # interrupt its sensor cancel/finalization path either.
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGHUP, request_clean_termination)
        signal.signal(signal.SIGTERM, request_clean_termination)
        with open(public_path, "xb") as public_output, open(
            diagnostic_path, "xb"
        ) as diagnostic_output:
            process = subprocess.Popen(
                command,
                stdout=public_output,
                stderr=subprocess.PIPE,
                bufsize=0,
                start_new_session=True,
            )
            assert process.stderr is not None
            selector = selectors.DefaultSelector()
            selector.register(process.stderr, selectors.EVENT_READ, "probe")
            selector.register(sys.stdin, selectors.EVENT_READ, "keyboard")
            pipe_open = True
            while pipe_open or process.poll() is None:
                if (
                    termination_signal_received
                    and not cancel_requested
                    and process.poll() is None
                ):
                    cancel_requested = True
                    process.send_signal(signal.SIGTERM)
                for key, _mask in selector.select(timeout=0.20):
                    if key.data == "keyboard":
                        typed = sys.stdin.read(1)
                        if typed in ("q", "Q", "\x1b") and process.poll() is None:
                            cancel_requested = True
                            process.send_signal(signal.SIGTERM)
                            ui.set_state(
                                mode="complete",
                                title="CANCELING SAFELY",
                                detail="Stopping the observation and closing the sensor…",
                                hint="Evidence will be retained after clean cancellation.",
                                color="amber",
                                awaiting_ack=False,
                            )
                        continue
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        pipe_open = False
                        continue
                    diagnostic_output.write(chunk)
                    diagnostic_output.flush()
                    pending.extend(chunk)
                    while b"\n" in pending:
                        line, _, remainder = pending.partition(b"\n")
                        pending = bytearray(remainder)
                        if not line.startswith(event_prefix):
                            continue
                        try:
                            event = json.loads(
                                line[len(event_prefix) :].decode("utf-8")
                            )
                        except (UnicodeDecodeError, json.JSONDecodeError):
                            continue
                        if not isinstance(event, dict):
                            continue
                        if rejection_cancel_requested:
                            continue
                        apply_event(ui, event)
                ui.draw()
            status = process.wait()
    except Exception as error:
        observation_error = error
    finally:
        if selector is not None:
            try:
                selector.close()
            except OSError:
                pass
        if process is not None and process.poll() is None:
            try:
                process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            except (OSError, ProcessLookupError):
                pass
        signal.signal(signal.SIGINT, previous_sigint)
        signal.signal(signal.SIGHUP, previous_sighup)
        signal.signal(signal.SIGTERM, previous_sigterm)
        termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, saved)

    if status != 0:
        ui.set_state(
            mode="failed",
            title="OPERATION FAILED",
            detail=(
                f"Internal UI failure: {observation_error}"
                if observation_error is not None
                else "No authentication decision was accepted. Evidence was preserved."
            ),
            hint=f"Exit status {status}. Evidence was preserved.",
            color="red",
            awaiting_ack=False,
        )
    elif ui.state.verdict_received:
        expected_negative = args.expect_no_match and not ui.state.verdict_matched
        ui.set_state(
            title=(
                "EXPECTED NON-MATCH"
                if expected_negative
                else "NEW FINGER VERIFIED"
                if ui.require_new_identity and ui.state.verdict_matched
                else "MATCHED" if ui.state.verdict_matched else "NOT MATCHED"
            ),
            detail=(
                "The secure result resolved only the newly enrolled identity."
                if ui.require_new_identity and ui.state.verdict_matched
                else "Terminal verdict received. Evidence was preserved."
            ),
            hint="You may return to Codex; the evidence is sealed locally.",
            color="green" if (ui.state.verdict_matched or expected_negative) else "red",
            phase=3,
        )
    elif status == 0 and rejection_cancel_requested:
        ui.set_state(
            mode="rejected",
            title="CAPTURE REJECTED — LIFT NOW",
            detail="One rejected capture was saved; the sensor stopped cleanly.",
            hint="Lift fully. Evidence was preserved.",
            color="red",
            phase=1,
            awaiting_ack=False,
        )
    elif status == 0 and cancel_requested:
        ui.set_state(
            mode="complete",
            title="SESSION ENDED",
            detail="The sensor canceled cleanly. Evidence was preserved.",
            hint="Evidence was preserved.",
            color="green",
            phase=3,
            awaiting_ack=False,
        )
    elif status == 0:
        ui.set_state(
            mode="complete",
            title="OBSERVATION COMPLETE",
            detail="The safety ceiling ended. Evidence was preserved.",
            hint="Evidence was preserved.",
            color="green",
            phase=3,
            awaiting_ack=False,
        )
    return status


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--probe",
        default="/usr/local/sbin/t2-native-match",
        help="path to the native match owner",
    )
    parser.add_argument(
        "--observation-seconds",
        type=float,
        default=0.0,
        help="optional safety ceiling; 0 stays live until Q/Escape (default: 0)",
    )
    parser.add_argument("--expect-no-match", action="store_true")
    parser.add_argument("--match-new-finger", action="store_true")
    args = parser.parse_args()
    if args.observation_seconds < 0:
        parser.error("--observation-seconds cannot be negative")
    if args.expect_no_match and args.match_new_finger:
        parser.error("negative and new-finger modes are distinct")
    if os.geteuid() != 0:
        raise SystemExit("t2-match-tui must run as root")
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise SystemExit("t2-match-tui requires an interactive terminal")
    os.umask(0o077)

    with TerminalUI(
        args.observation_seconds,
        args.expect_no_match,
        args.match_new_finger,
    ) as ui:
        return run_observation(args, ui)


if __name__ == "__main__":
    raise SystemExit(main())
