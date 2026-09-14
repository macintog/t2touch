#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""One uninterrupted existing-finger, add-finger, and new-finger proof UI."""

from __future__ import annotations

import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import select
import selectors
import signal
import stat
import subprocess
import sys
import termios
import tty


SOURCE = Path(__file__).resolve().parent
STATE_ROOT = Path("/var/lib/t2-touchid")
MUTATION_ROOT = STATE_ROOT / "mutations"
ARTIFACT_ROOT = STATE_ROOT / "research-artifacts"
MATCH = Path("/usr/local/sbin/t2-native-match")
ENROLL = Path("/usr/local/sbin/t2-native-enroll")
MATCH_PREFIX = b"T2_MATCH_EVENT "
ENROLL_PREFIX = b"T2_ENROLL_EVENT "
CSI = "\x1b["
ALT_ON = f"{CSI}?1049h{CSI}?25l"
ALT_OFF = f"{CSI}?25h{CSI}?1049l"


def _load_enrollment_ui():
    path = SOURCE / "t2-native-enroll-tui.py"
    spec = importlib.util.spec_from_file_location("t2_enrollment_ui", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("enrollment UI module is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.EnrollmentUI


EnrollmentUI = _load_enrollment_ui()


def _private_result_root() -> Path:
    stamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    parent = ARTIFACT_ROOT / f"D206-second-finger-ceremony-{stamp}"
    parent.mkdir(mode=0o700, parents=True, exist_ok=False)
    root = parent / "private"
    root.mkdir(mode=0o700)
    return root


def _safe_mutation_names() -> set[str]:
    info = MUTATION_ROOT.stat(follow_symlinks=False)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
        raise RuntimeError("mutation journal root is unsafe")
    names = set()
    with os.scandir(MUTATION_ROOT) as entries:
        for entry in entries:
            if not entry.is_file(follow_symlinks=False) or not entry.name.endswith(".jsonl"):
                raise RuntimeError("mutation journal root is not canonical")
            names.add(entry.name)
    return names


def _request_cancel(process: subprocess.Popen[bytes], ui) -> None:
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
        ui.update(
            title="CANCELING SAFELY",
            detail="Waiting for the owned sensor operation to close cleanly.",
            hint="Do not close this terminal during cleanup.",
            color="amber",
        )


def _match_event(ui, event: dict[str, object], mode: str) -> None:
    kind = event.get("event_kind")
    semantics = event.get("status_semantics")
    if kind == "match_armed":
        title = {
            "current": "PLACE CURRENT FINGER NOW",
            "distinct": "PLACE THE NEW FINGER NOW",
            "new": "PLACE THE NEW FINGER TO PROVE IT",
        }[mode]
        detail = {
            "current": "Briefly touch with the fingerprint already enrolled.",
            "distinct": "One brief touch checks that this is not the enrolled finger.",
            "new": "One brief touch must resolve the newly added identity exactly.",
        }[mode]
        ui.update(
            audible=True,
            title=title,
            detail=detail,
            hint="Touch for a fraction of a second; lift when this screen changes.",
            color="cyan",
            phase=2,
        )
    elif semantics == "finger-present":
        ui.update(
            audible=True,
            title="CONTACT DETECTED — LIFT NOW",
            detail="The sensor registered the brief touch.",
            hint="Lift fully while the secure result completes.",
            color="cyan",
            phase=2,
        )
    elif semantics == "finger-removed":
        ui.update(
            audible=True,
            title="PLACE FINGER AGAIN",
            detail="The sensor is ready for another brief touch.",
            hint="Use the finger requested for this stage.",
            color="cyan",
            phase=2,
        )
    elif kind == "match_result":
        if event.get("result_valid") is not True:
            ui.update(
                audible=True,
                title="UNUSABLE SENSOR RESULT",
                detail="Exact result framing or identity validation failed.",
                hint="The ceremony is stopping safely.",
                color="red",
            )
        elif mode == "distinct" and event.get("no_match_matcher") is True:
            ui.update(
                audible=True,
                title="NEW FINGER CONFIRMED DISTINCT",
                detail="It did not match the existing saved fingerprint.",
                hint="Enrollment begins automatically next.",
                color="green",
                phase=2,
            )
        elif event.get("matched") is True:
            required_ok = mode != "new" or event.get("matches_required_identity") is True
            ui.update(
                audible=True,
                title=(
                    "NEW FINGER VERIFIED"
                    if mode == "new" and required_ok
                    else "CURRENT FINGER VERIFIED"
                    if mode == "current"
                    else "WRONG FINGER"
                ),
                detail=(
                    "The secure result resolved the newly added identity."
                    if mode == "new" and required_ok
                    else "The secure result resolved the existing identity."
                ),
                hint=(
                    "The ceremony is sealing its evidence."
                    if required_ok
                    else "This did not prove the new fingerprint."
                ),
                color="green" if required_ok else "red",
                phase=3 if required_ok else 2,
            )
        elif mode == "current" and event.get("no_match") is True:
            ui.update(
                audible=True,
                title="NOT THE CURRENT FINGER — TRY AGAIN",
                detail="That valid capture did not match the saved fingerprint.",
                hint="Lift fully, then use the currently enrolled finger.",
                color="amber",
                phase=2,
            )
        elif mode == "distinct" and event.get("matched") is True:
            ui.update(
                audible=True,
                title="THAT FINGER IS ALREADY ENROLLED",
                detail="No duplicate enrollment will be attempted.",
                hint="The ceremony is stopping safely.",
                color="red",
            )


def _run_child(
    *,
    command: list[str],
    ui,
    event_prefix: bytes,
    stdout_path: Path,
    stderr_path: Path,
    event_handler,
    pass_fds: tuple[int, ...] = (),
) -> tuple[int, dict[str, object] | None]:
    pending = bytearray()
    document = None
    with stdout_path.open("xb") as stdout_file, stderr_path.open("xb") as stderr_file:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=pass_fds,
            start_new_session=True,
        )
        assert process.stdout is not None and process.stderr is not None
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        selector.register(sys.stdin, selectors.EVENT_READ, "keyboard")
        streams = 2
        canceled = False
        stdout_data = bytearray()
        try:
            while streams or process.poll() is None:
                for key, _mask in selector.select(0.20):
                    if key.data == "keyboard":
                        typed = sys.stdin.read(1)
                        if typed in ("q", "Q", "\x1b") and not canceled:
                            canceled = True
                            _request_cancel(process, ui)
                        continue
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        streams -= 1
                        continue
                    if key.data == "stdout":
                        stdout_file.write(chunk)
                        stdout_file.flush()
                        stdout_data.extend(chunk)
                    else:
                        stderr_file.write(chunk)
                        stderr_file.flush()
                        pending.extend(chunk)
                        while b"\n" in pending:
                            line, _, remainder = pending.partition(b"\n")
                            pending = bytearray(remainder)
                            if not line.startswith(event_prefix):
                                continue
                            try:
                                event = json.loads(line[len(event_prefix):].decode("utf-8"))
                            except (UnicodeError, json.JSONDecodeError):
                                continue
                            if isinstance(event, dict):
                                event_handler(event)
            status = process.wait()
        finally:
            selector.close()
            if process.poll() is None:
                _request_cancel(process, ui)
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=15)
        if status == 0:
            try:
                parsed = json.loads(stdout_data)
                document = parsed if isinstance(parsed, dict) else None
            except (UnicodeError, json.JSONDecodeError):
                document = None
        return status, document


def _run_match(root: Path, ui, stage: str, addition: Path | None = None) -> bool:
    command = [
        str(MATCH),
        "--observation-seconds",
        "0",
        "--private-match-events-output",
        str(root / f"{stage}-match-private-events.json"),
    ]
    if stage == "distinct":
        command.append("--expect-no-match")
    if addition is not None:
        command.extend(["--addition-journal", str(addition)])
    ui.update(
        title="OPENING SENSOR",
        detail={
            "current": "Preparing the existing-fingerprint proof.",
            "distinct": "Preparing the duplicate-finger safeguard.",
            "new": "Preparing the new-identity proof.",
        }[stage],
        hint="No contact is needed until the placement cue.",
        color="amber",
        phase=0,
    )
    status, document = _run_child(
        command=command,
        ui=ui,
        event_prefix=MATCH_PREFIX,
        stdout_path=root / f"{stage}-match.json",
        stderr_path=root / f"{stage}-match.stderr",
        event_handler=lambda event: _match_event(ui, event, stage),
    )
    return status == 0 and isinstance(document, dict)


def _menu(ui) -> bool:
    ui.update(
        audible=True,
        title="CURRENT FINGER ACCEPTED",
        detail="A  ADD AND VALIDATE A SECOND FINGER     Q  FINISH",
        hint="Press A once to continue. Enrollment capture itself uses no keys.",
        color="green",
        phase=1,
    )
    while True:
        readable, _, _ = select.select([sys.stdin], [], [], 0.20)
        if readable:
            key = sys.stdin.read(1)
            if key in ("a", "A"):
                return True
            if key in ("q", "Q", "\x1b"):
                return False


def _run_enrollment(root: Path, ui) -> tuple[bool, Path | None]:
    before = _safe_mutation_names()
    read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
    try:
        os.write(write_fd, b"test\n")
    finally:
        os.close(write_fd)
    command = [
        str(ENROLL),
        "--credential-fd", str(read_fd),
        "--operator-fd", "0",
        "--identity-name", "Linux second finger",
        "--add-finger",
        "--acknowledge-one-shot-native-enrollment",
        "--acknowledge-password-fallback-tested",
        "--acknowledge-local-catacomb-mutation",
    ]
    try:
        status, document = _run_child(
            command=command,
            ui=ui,
            event_prefix=ENROLL_PREFIX,
            stdout_path=root / "add-finger-enroll.json",
            stderr_path=root / "add-finger-enroll.stderr",
            event_handler=ui.apply,
            pass_fds=(read_fd,),
        )
    finally:
        os.close(read_fd)
    after = _safe_mutation_names()
    added = after - before
    success = (
        status == 0
        and isinstance(document, dict)
        and document.get("enrollment_succeeded") is True
        and document.get("additional_fingerprint") is True
        and len(added) == 1
    )
    return success, MUTATION_ROOT / next(iter(added)) if success else None


def main() -> int:
    if os.geteuid() != 0 or not sys.stdin.isatty() or not sys.stdout.isatty():
        raise SystemExit("second-finger ceremony requires a root interactive terminal")
    os.umask(0o077)
    root = _private_result_root()
    saved = termios.tcgetattr(sys.stdin.fileno())
    status = 1
    try:
        tty.setcbreak(sys.stdin.fileno())
        sys.stdout.write(ALT_ON)
        ui = EnrollmentUI()
        ui.update(
            title="STARTING SECOND-FINGER CEREMONY",
            detail="First, prove the fingerprint already saved.",
            hint="No contact is needed until the placement cue.",
            color="amber",
            phase=0,
        )
        if not _run_match(root, ui, "current"):
            raise RuntimeError("existing fingerprint proof failed")
        if not _menu(ui):
            ui.update(
                title="CURRENT FINGER VERIFIED",
                detail="No new fingerprint was requested.",
                hint="Press Q or Escape to close.",
                color="green",
                terminal=True,
            )
            status = 0
        else:
            if not _run_match(root, ui, "distinct"):
                raise RuntimeError("candidate finger was not proven distinct")
            enrolled, journal = _run_enrollment(root, ui)
            if not enrolled or journal is None:
                raise RuntimeError("additional fingerprint enrollment failed")
            if not _run_match(root, ui, "new", journal):
                raise RuntimeError("new fingerprint proof failed")
            ui.update(
                audible=True,
                title="SECOND FINGER ENROLLED AND VERIFIED",
                detail="The final secure result resolved only the new identity.",
                hint="All phases completed in this boot. Evidence is retained. Q closes.",
                color="green",
                phase=3,
                progress=100,
                terminal=True,
            )
            status = 0
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        ui.update(
            audible=True,
            title="CEREMONY STOPPED SAFELY",
            detail=str(error),
            hint="No automatic retry will run. Evidence is retained. Q closes.",
            color="red",
            terminal=True,
        )
        status = 1
    finally:
        while True:
            readable, _, _ = select.select([sys.stdin], [], [], 0.20)
            if readable and sys.stdin.read(1) in ("q", "Q", "\x1b"):
                break
        termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, saved)
        sys.stdout.write(f"{CSI}0m{ALT_OFF}")
        sys.stdout.flush()
    return status


if __name__ == "__main__":
    raise SystemExit(main())
