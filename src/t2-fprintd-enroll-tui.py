#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Persistent event-driven presentation for standard fprintd operations."""

from __future__ import annotations

import argparse
import asyncio
import os
import re
import shutil
import signal
import sys
from pathlib import Path

from dbus_next import BusType, Message, MessageType
from dbus_next.aio import MessageBus

LOCAL_SOURCE = Path(__file__).resolve().parent
if str(LOCAL_SOURCE) not in sys.path:
    sys.path.insert(0, str(LOCAL_SOURCE))

import t2_fprint_identity


BUS_NAME = "net.reactivated.Fprint"
CLEANUP_CALL_TIMEOUT_SECONDS = 10
DEVICE_PATH = "/net/reactivated/Fprint/Device/0"
DEVICE_INTERFACE = "net.reactivated.Fprint.Device"
PROPERTIES_INTERFACE = "org.freedesktop.DBus.Properties"
CSI = "\x1b["
ALT_ON = f"{CSI}?1049h{CSI}?25l"
ALT_OFF = f"{CSI}?25h{CSI}?1049l"


class EnrollmentUIError(RuntimeError):
    pass


def _property_bool(properties: object, name: str) -> bool:
    if not isinstance(properties, dict):
        return False
    value = properties.get(name)
    return bool(getattr(value, "value", False) is True)


def _property_progress(properties: object, name: str) -> int | None:
    if not isinstance(properties, dict):
        return None
    value = getattr(properties.get(name), "value", None)
    return value if type(value) is int and 0 <= value <= 100 else None


class EnrollmentUI:
    # Adapt the supplied early T1 terminal enrollment reference: centered
    # fingerprint art, live percentage, thin progress bar, and short event
    # prompts. T2's live presence/need signals remain the sole prompt authority.
    COLORS = {
        "blue": "38;2;126;164;255",
        "track": "38;2;62;64;88",
        "green": "38;2;48;209;88",
        "amber": "38;2;255;184;70",
        "red": "38;2;255;69;58",
        "dim": "38;2;153;153;178",
        "white": "38;2;218;218;232",
    }
    # Fixed artwork in terminal cells. A taller window adds surrounding space,
    # not a different mask with a taller aspect ratio.
    COMPACT_FINGERPRINT_MASK = (
        "         #######         ",
        "      ###       ###      ",
        "    ##   #######   ##    ",
        "   #  ###       ###  #   ",
        "  # ##   #######   ## #  ",
        " # #  ###       ###  # # ",
        "# # ##   #######   ## # #",
        "# ##  ###       ###  ## #",
        "# # # ###     ###  # # # ",
        "# # ##   #####  ## # # # ",
        "# ##  ###   ### ## # # # ",
        "# # # ## # # # # ## # # ",
        "# # # #  # # # # #  # # ",
        "# # ##  ## # # ##  ## #  ",
        " #  ##   ### ###    ##    ",
        "  ##   ###     ### ##     ",
        "    ###           ##      ",
        "      ####   ####         ",
        "          ###             ",
    )

    def __init__(
        self,
        finger: str,
        username: str,
        *,
        operation: str = "enroll",
        expect_no_match: bool = False,
    ) -> None:
        self.finger = finger
        self.username = username
        self.operation = operation
        self.expect_no_match = expect_no_match
        self.finger_present = False
        self.finger_needed = False
        self.progress_percent: int | None = None
        self.retry = False
        self.terminal: str | None = None
        self.terminal_detail: str | None = None
        self.bus: MessageBus | None = None
        self.done = asyncio.Event()
        self.operation_result = 1
        self.service_available = True
        self.enrolled_before: tuple[str, ...] = ()
        self.assigned_finger: str | None = None
        self.presenting = False
        self.color = "NO_COLOR" not in os.environ
        encoding = sys.stdout.encoding or "ascii"
        try:
            "╭─●◉".encode(encoding)
        except (LookupError, UnicodeEncodeError):
            self.unicode = False
        else:
            self.unicode = True

    def paint(self, text: str, color: str) -> str:
        if not self.color:
            return text
        # Reset only the foreground so the dark reference canvas survives
        # adjacent colored spans.
        return f"{CSI}{self.COLORS[color]}m{text}{CSI}39m"

    @staticmethod
    def center(text: str, width: int) -> str:
        return text.center(width)[:width]

    def _view(self) -> tuple[str, str, str, str, str]:
        if self.operation == "verify":
            return self._verification_view()
        if self.terminal == "FINGERPRINT ENROLLED":
            return (
                "SUCCESS",
                "FINGERPRINT ENROLLED",
                "The standard fprintd enrollment completed.",
                "green",
                "✓" if self.unicode else "+",
            )
        if self.terminal is not None:
            return (
                "STOPPED",
                "ENROLLMENT STOPPED",
                self.terminal_detail
                or "No successful enrollment was reported.",
                "red",
                "×" if self.unicode else "x",
            )
        if self.finger_present:
            return (
                (
                    "VERIFY NEW PRINT"
                    if self.progress_percent == 100
                    else "ENROLLMENT"
                ),
                "TOUCH REGISTERED — LIFT FINGER"
                if self.unicode
                else "TOUCH REGISTERED - LIFT FINGER",
                (
                    "Remove your finger while the new identity is validated."
                    if self.progress_percent == 100
                    else "Remove your finger completely; presence is not accepted progress."
                ),
                "blue",
                "↑" if self.unicode else "^",
            )
        if self.retry:
            return (
                "RETRY",
                "LIFT, THEN TRY AGAIN",
                "Reposition the same finger for one brief touch.",
                "amber",
                "↻" if self.unicode else "~",
            )
        if self.finger_needed:
            return (
                (
                    "VERIFY NEW PRINT"
                    if self.progress_percent == 100
                    else "ENROLLMENT"
                ),
                (
                    "TOUCH NEW FINGERPRINT ONCE"
                    if self.progress_percent == 100
                    else "TOUCH SENSOR BRIEFLY"
                ),
                (
                    "Touch once more with the same finger to complete enrollment."
                    if self.progress_percent == 100
                    else "Touch with the finger you are adding and lift as soon as it registers."
                ),
                "blue",
                "→" if self.unicode else ">",
            )
        if self.progress_percent == 100:
            return (
                "ENROLLMENT",
                "SAVING FINGERPRINT",
                "Finalizing secure enrollment for immediate use.",
                "blue",
                "…" if self.unicode else ".",
            )
        return (
            "ENROLLMENT",
            "PREPARING SENSOR — DO NOT TOUCH"
            if self.unicode
            else "PREPARING SENSOR - DO NOT TOUCH",
            "The standard fprintd client will start automatically.",
            "dim",
            "→" if self.unicode else ">",
        )

    def _verification_view(self) -> tuple[str, str, str, str, str]:
        successful = {
            "FINGERPRINT MATCHED": (
                "FINGERPRINT MATCHED",
                "The standard fprintd verification succeeded.",
            ),
            "EXPECTED NON-MATCH": (
                "EXPECTED NON-MATCH",
                "The unenrolled-finger control was rejected correctly.",
            ),
        }
        if self.terminal in successful:
            title, detail = successful[self.terminal]
            return (
                "SUCCESS",
                title,
                detail,
                "green",
                "✓" if self.unicode else "+",
            )
        if self.terminal is not None:
            return (
                "STOPPED",
                self.terminal,
                self.terminal_detail
                or "No expected verification result was reported.",
                "red",
                "×" if self.unicode else "x",
            )
        if self.finger_present:
            return (
                "VERIFY",
                "TOUCH REGISTERED — LIFT FINGER"
                if self.unicode
                else "TOUCH REGISTERED - LIFT FINGER",
                "Remove your finger completely while fprintd resolves the match.",
                "blue",
                "↑" if self.unicode else "^",
            )
        if self.retry:
            return (
                "RETRY",
                "LIFT, THEN TRY AGAIN",
                "Reposition the finger for one brief touch.",
                "amber",
                "↻" if self.unicode else "~",
            )
        if self.finger_needed:
            detail = (
                "Briefly touch with a finger that is not enrolled."
                if self.expect_no_match
                else "Briefly touch with any enrolled finger."
            )
            return (
                "VERIFY",
                "TOUCH SENSOR BRIEFLY",
                detail,
                "blue",
                "→" if self.unicode else ">",
            )
        return (
            "VERIFY",
            "PREPARING SENSOR — DO NOT TOUCH"
            if self.unicode
            else "PREPARING SENSOR - DO NOT TOUCH",
            "The standard fprintd verification client will start automatically.",
            "dim",
            "→" if self.unicode else ">",
        )

    def _reference_view(self) -> tuple[str, str, str | None]:
        """Map T2 events onto the supplied terminal-enrollment reference."""

        successful = self.terminal in {
            "FINGERPRINT ENROLLED",
            "FINGERPRINT MATCHED",
            "EXPECTED NON-MATCH",
        }
        if successful:
            if self.terminal == "FINGERPRINT ENROLLED":
                return "Fingerprint enrolled", "white", "Enrollment complete · press Ctrl+C to return"
            if self.terminal == "FINGERPRINT MATCHED":
                return "Fingerprint matched", "white", "Authentication complete · press Ctrl+C to return"
            return "Expected non-match", "white", "Control complete · press Ctrl+C to return"
        if self.terminal is not None:
            label = (
                "Enrollment stopped"
                if self.operation == "enroll"
                else "Verification stopped"
            )
            detail = (
                "No fingerprint was saved."
                if self.operation == "enroll"
                else "No authentication was accepted."
            )
            return label, "red", detail

        if self.finger_present:
            return "Lift finger", "white", None
        if self.retry:
            return "Try again — lift, then touch", "amber", None
        if self.finger_needed:
            if self.operation == "verify":
                return (
                    "Touch with an unenrolled finger"
                    if self.expect_no_match
                    else "Touch with any enrolled finger",
                    "white",
                    None,
                )
            if (self.progress_percent or 0) > 0:
                return "Good scan — lift and touch again", "white", None
            return "Lift and touch this finger repeatedly", "white", None
        if self.progress_percent == 100:
            return "Saving fingerprint", "blue", "Finalizing for immediate use"
        return "Preparing sensor", "dim", None

    def _finger_heading(self) -> str:
        if self.operation == "verify":
            return (
                "UNENROLLED CONTROL"
                if self.expect_no_match
                else "ANY ENROLLED FINGER"
            )
        if self.assigned_finger is None:
            return "NEW FINGER"
        return t2_fprint_identity.display_name(self.assigned_finger).upper()

    def _fingerprint(self, progress: int, mask: tuple[str, ...]) -> list[str]:
        points = [
            (y, x)
            for y, mask_row in enumerate(mask)
            for x, cell in enumerate(mask_row)
            if cell == "#"
        ]
        # SEP/Mesa supplies the percentage; it is not inferred from a capture
        # count. Give exactly that share of the fingerprint cells the active
        # color, with a stable scattered order that resembles acquired area.
        points.sort(
            key=lambda point: (
                (
                    point[1] * 73
                    + point[0] * 151
                    + point[1] * point[0] * 29
                )
                % 1009,
                point,
            )
        )
        active_count = (len(points) * max(0, min(100, progress)) + 50) // 100
        active = set(points[:active_count])
        rows: list[str] = []
        glyph = "▪" if self.unicode else "#"
        for y, mask_row in enumerate(mask):
            row: list[str] = []
            for x, cell in enumerate(mask_row):
                if cell != "#":
                    row.append(" ")
                    continue
                row.append(self.paint(glyph, "blue" if (y, x) in active else "track"))
            rows.append("".join(row))
        return rows

    def render(self, *, bell: bool = False) -> None:
        if not self.presenting and sys.stdout.isatty():
            sys.stdout.write(ALT_ON)
            self.presenting = True
        size = shutil.get_terminal_size((76, 28))
        message, message_color, detail = self._reference_view()
        panel_width = min(58, max(24, size.columns))
        bar_width = max(8, panel_width - 10)
        compact = size.columns < 50
        # Keep the artwork's size and proportions stable across window heights.
        mask = () if compact else self.COMPACT_FINGERPRINT_MASK
        # A terminal failure must never make an incomplete capture look like a
        # durable partly-filled fingerprint slot.  Keep the last percentage
        # internally for diagnostics, but clear it from the finished view.
        successful = self.terminal in {
            "FINGERPRINT ENROLLED",
            "FINGERPRINT MATCHED",
            "EXPECTED NON-MATCH",
        }
        progress = (
            100
            if successful
            else 0
            if (
                self.terminal is not None
                or self.progress_percent is None
                or not (self.finger_needed or self.finger_present or self.retry)
            )
            else self.progress_percent
        )
        art_progress = 100 if successful else progress
        operation = "VERIFY" if self.operation == "verify" else "ENROLL"
        header = f"TOUCH ID  ·  {operation}"
        filled = min(bar_width, progress * bar_width // 100)
        lines = [
            self.paint(header.center(panel_width), "dim"),
            self.paint(self._finger_heading().center(panel_width), "blue"),
            "",
        ]
        if mask:
            lines.extend(
                " " * ((panel_width - len(mask[0])) // 2) + row
                for row in self._fingerprint(art_progress, mask)
            )
            lines.append("")
        lines.append(self.paint(message.center(panel_width), message_color))
        if self.terminal is None or successful:
            bar = self.paint("━" * filled, "blue") + self.paint(
                "━" * (bar_width - filled), "track"
            )
            lines.append(" " * 2 + bar + f"  {progress:3d}%")
        if detail is not None:
            lines.extend(("", self.paint(detail.center(panel_width), "dim")))

        available = max(1, size.lines - 1)
        top_padding = max(0, (available - len(lines)) // 2)
        left = max(0, (size.columns - panel_width) // 2)
        clear = f"{CSI}2J{CSI}H"
        if self.color:
            clear += f"{CSI}48;2;18;18;28m"
        output = [clear, *("" for _ in range(top_padding))]
        for text in lines:
            output.append(" " * left + text + f"{CSI}K")
        if bell:
            output.append("\a")
        sys.stdout.write("\n".join(output))
        sys.stdout.flush()

    def _finger_label(self) -> str:
        if self.operation == "verify":
            return (
                "UNENROLLED FINGER CONTROL"
                if self.expect_no_match
                else "ANY ENROLLED FINGER"
            )
        if self.assigned_finger is None:
            return "NEW FINGER"
        return t2_fprint_identity.display_name(self.assigned_finger).upper()

    def close_screen(self) -> None:
        if self.presenting:
            sys.stdout.write(f"{CSI}0m{ALT_OFF}")
            sys.stdout.flush()
            self.presenting = False

    def _properties_changed(self, message: Message) -> bool:
        if (
            message.message_type != MessageType.SIGNAL
            or message.path != DEVICE_PATH
            or message.interface != PROPERTIES_INTERFACE
            or message.member != "PropertiesChanged"
            or len(message.body) != 3
            or message.body[0] != DEVICE_INTERFACE
        ):
            return False
        changed = message.body[1]
        before = (
            self.finger_present,
            self.finger_needed,
            self.progress_percent,
        )
        if isinstance(changed, dict):
            if "finger-present" in changed:
                self.finger_present = _property_bool(changed, "finger-present")
            if "finger-needed" in changed:
                self.finger_needed = _property_bool(changed, "finger-needed")
            if "t2-enroll-progress" in changed:
                self.progress_percent = _property_progress(
                    changed, "t2-enroll-progress"
                )
        after = (
            self.finger_present,
            self.finger_needed,
            self.progress_percent,
        )
        if after != before:
            if after[0]:
                self.retry = False
            self.render(bell=after[0] or (after[1] and not before[1]))
        return False

    def _service_lost(self) -> None:
        self.service_available = False
        if self.done.is_set():
            return
        self.terminal = (
            "VERIFICATION STOPPED" if self.operation == "verify" else "ENROLLMENT STOPPED"
        )
        self.terminal_detail = "The fingerprint service disconnected. Preserve the current enrollment state."
        self.finger_needed = self.finger_present = False
        self.operation_result = 1
        self.done.set()
        self.render(bell=True)

    def _message(self, message: Message) -> bool:
        if (
            message.message_type == MessageType.SIGNAL
            and message.sender == "org.freedesktop.DBus"
            and message.path == "/org/freedesktop/DBus"
            and message.interface == "org.freedesktop.DBus"
            and message.member == "NameOwnerChanged"
            and len(message.body) == 3
            and message.body[0] == BUS_NAME
            and isinstance(message.body[1], str)
            and bool(message.body[1])
            and message.body[1] != message.body[2]
        ):
            self._service_lost()
            return False
        if self.done.is_set():
            return False
        self._properties_changed(message)
        if (
            message.message_type != MessageType.SIGNAL
            or message.path != DEVICE_PATH
            or message.interface != DEVICE_INTERFACE
            or message.member != ("VerifyStatus" if self.operation == "verify" else "EnrollStatus")
            or len(message.body) != 2
            or not isinstance(message.body[0], str)
            or type(message.body[1]) is not bool
        ):
            return False
        status, done = message.body
        changed = self._consume_line(
            f"{status}{' (done)' if done else ''}",
            (
                "enroll-retry-scan",
                "enroll-swipe-too-short",
                "enroll-finger-not-centered",
                "enroll-remove-and-retry",
            ),
            (
                "failed",
                "disconnected",
                "data-full",
                "unknown-error",
                "duplicate",
            ),
        )
        if changed:
            self.render(bell=self.terminal is not None or self.retry)
        if done:
            self.operation_result = 0 if self.terminal in {
                "FINGERPRINT ENROLLED",
                "FINGERPRINT MATCHED",
                "EXPECTED NON-MATCH",
            } else 1
            self.done.set()
        return False

    async def _wait_for_completion(self) -> None:
        assert self.bus is not None
        # Shield the bus's shared disconnect future from cancellation when a
        # normal verdict wins. Waiting for a finger remains deadline-free.
        async def disconnected() -> None:
            try:
                await asyncio.shield(self.bus.wait_for_disconnect())
            except Exception:
                pass
            self._service_lost()

        verdict = asyncio.create_task(self.done.wait())
        connection = asyncio.create_task(disconnected())
        try:
            await asyncio.wait((verdict, connection), return_when=asyncio.FIRST_COMPLETED)
        finally:
            for task in (verdict, connection):
                if not task.done():
                    task.cancel()
            await asyncio.gather(verdict, connection, return_exceptions=True)

    async def _call(
        self, member: str, signature: str = "", body: list[object] | None = None
    ) -> Message:
        assert self.bus is not None
        reply = await self.bus.call(
            Message(
                destination=BUS_NAME,
                path=DEVICE_PATH,
                interface=DEVICE_INTERFACE,
                member=member,
                signature=signature,
                body=[] if body is None else body,
            )
        )
        if reply.message_type != MessageType.METHOD_RETURN:
            detail = reply.body[0] if reply.body and isinstance(reply.body[0], str) else member
            raise EnrollmentUIError(f"fprintd {member} failed: {detail[:160]}")
        return reply

    async def _finish_client(self, started: bool, claimed: bool) -> None:
        if self.bus is None or not self.service_available:
            return
        if started:
            try:
                await asyncio.wait_for(
                    self._call("VerifyStop" if self.operation == "verify" else "EnrollStop"),
                    CLEANUP_CALL_TIMEOUT_SECONDS,
                )
            except (EnrollmentUIError, OSError):
                pass
        if claimed and self.service_available:
            try:
                await asyncio.wait_for(self._call("Release"), CLEANUP_CALL_TIMEOUT_SECONDS)
            except (EnrollmentUIError, OSError):
                pass

    async def _initial_properties(self) -> None:
        assert self.bus is not None
        reply = await self.bus.call(
            Message(
                destination=BUS_NAME,
                path=DEVICE_PATH,
                interface=PROPERTIES_INTERFACE,
                member="GetAll",
                signature="s",
                body=[DEVICE_INTERFACE],
            )
        )
        if (
            reply.message_type != MessageType.METHOD_RETURN
            or len(reply.body) != 1
        ):
            raise EnrollmentUIError("fprintd device properties are unavailable")
        properties = reply.body[0]
        self.finger_present = _property_bool(properties, "finger-present")
        self.finger_needed = _property_bool(properties, "finger-needed")
        self.progress_percent = _property_progress(
            properties, "t2-enroll-progress"
        )

    async def _list_fingers(self) -> tuple[str, ...]:
        assert self.bus is not None
        reply = await self.bus.call(
            Message(
                destination=BUS_NAME,
                path=DEVICE_PATH,
                interface=DEVICE_INTERFACE,
                member="ListEnrolledFingers",
                signature="s",
                body=[self.username],
            )
        )
        if reply.message_type == MessageType.ERROR:
            if reply.error_name == "net.reactivated.Fprint.Error.NoEnrolledPrints":
                return ()
            raise EnrollmentUIError("fprintd identity list is unavailable")
        if (
            reply.message_type != MessageType.METHOD_RETURN
            or len(reply.body) != 1
            or not isinstance(reply.body[0], list)
            or any(not t2_fprint_identity.is_handle(item) for item in reply.body[0])
            or len(reply.body[0]) != len(set(reply.body[0]))
        ):
            raise EnrollmentUIError("fprintd identity list is malformed")
        return tuple(reply.body[0])

    def _consume_line(
        self,
        line: str,
        retry_markers: tuple[str, ...] = (),
        terminal_errors: tuple[str, ...] = (),
    ) -> bool:
        if self.operation == "verify":
            if "verify-no-match" in line:
                self.terminal = (
                    "EXPECTED NON-MATCH"
                    if self.expect_no_match
                    else "VERIFICATION FAILED"
                )
                return True
            if "verify-match" in line:
                self.terminal = (
                    "UNEXPECTED MATCH"
                    if self.expect_no_match
                    else "FINGERPRINT MATCHED"
                )
                return True
            if "verify-retry" in line:
                self.retry = True
                return True
            if "verify-" in line and "(done)" in line:
                self.terminal = "VERIFICATION STOPPED"
                result = re.search(r"\b(verify-[a-z-]+)\b", line)
                if result is not None:
                    self.terminal_detail = (
                        f"fprintd reported {result.group(1)}."
                    )
                return True
            return False
        changed = False
        if "enroll-stage-passed" in line:
            self.retry = False
            changed = True
        elif any(marker in line for marker in retry_markers):
            self.retry = True
            changed = True
        if "enroll-completed" in line:
            self.terminal = "FINGERPRINT ENROLLED"
            self.progress_percent = 100
            changed = True
        elif "enroll-" in line and any(
            marker in line for marker in terminal_errors
        ):
            self.terminal = "ENROLLMENT STOPPED"
            if "enroll-failed" in line:
                self.terminal_detail = (
                    "The incomplete capture was discarded; no fingerprint slot was created."
                )
            elif "data-full" in line:
                self.terminal_detail = (
                    "All five fingerprint slots are in use. "
                    "Delete one with `t2touch delete finger-N`."
                )
            else:
                self.terminal_detail = (
                    "Enrollment did not complete; run `sudo t2-touchid-doctor`."
                )
            changed = True
        return changed

    async def run(self) -> int:
        started = False
        claimed = False
        try:
            self.bus = await MessageBus(bus_type=BusType.SYSTEM).connect()
            self.bus.add_message_handler(self._message)
            match_reply = await self.bus.call(
                Message(
                    destination="org.freedesktop.DBus",
                    path="/org/freedesktop/DBus",
                    interface="org.freedesktop.DBus",
                    member="AddMatch",
                    signature="s",
                    body=[
                        "type='signal',"
                        f"sender='{BUS_NAME}',"
                        f"path='{DEVICE_PATH}'"
                    ],
                )
            )
            if match_reply.message_type != MessageType.METHOD_RETURN:
                raise EnrollmentUIError(
                    "fprintd property signal subscription failed"
                )
            owner_reply = await self.bus.call(Message(
                destination="org.freedesktop.DBus",
                path="/org/freedesktop/DBus",
                interface="org.freedesktop.DBus",
                member="AddMatch", signature="s",
                body=["type='signal',sender='org.freedesktop.DBus',"
                      "interface='org.freedesktop.DBus',member='NameOwnerChanged',"
                      f"arg0='{BUS_NAME}'"],
            ))
            if owner_reply.message_type != MessageType.METHOD_RETURN:
                raise EnrollmentUIError("fprintd service-loss subscription failed")
            await self._initial_properties()
            self.render()
            self.enrolled_before = await self._list_fingers()
            await self._call("Claim", "s", [self.username])
            claimed = True
            if self.done.is_set():
                raise EnrollmentUIError("fprintd service changed during setup")
            await self._call(
                "VerifyStart" if self.operation == "verify" else "EnrollStart",
                "s",
                ["any" if self.operation == "verify" else self.finger],
            )
            started = True
            await self._wait_for_completion()
            if self.operation == "enroll" and self.operation_result == 0:
                enrolled_after = await self._list_fingers()
                added = set(enrolled_after) - set(self.enrolled_before)
                if len(added) != 1:
                    raise EnrollmentUIError(
                        "completed enrollment did not add one numbered identity"
                    )
                self.assigned_finger = added.pop()
                self.render()
        finally:
            await self._finish_client(started, claimed)
            if self.bus is not None:
                self.bus.disconnect()
        if self.terminal is None:
            self.terminal = (
                "FINGERPRINT ENROLLED"
                if self.operation == "enroll" and self.operation_result == 0
                else "ENROLLMENT STOPPED"
                if self.operation == "enroll"
                else "VERIFICATION STOPPED"
            )
            self.render(bell=True)
        if self.terminal in {
            "FINGERPRINT ENROLLED",
            "FINGERPRINT MATCHED",
            "EXPECTED NON-MATCH",
        }:
            return 0
        return self.operation_result or 1


async def _present_until_closed(
    ui: EnrollmentUI, stop: asyncio.Event
) -> int:
    operation = asyncio.create_task(ui.run())
    stopped = asyncio.create_task(stop.wait())
    try:
        done, _pending = await asyncio.wait(
            (operation, stopped), return_when=asyncio.FIRST_COMPLETED
        )
        if stopped in done and not operation.done():
            operation.cancel()
            try:
                await operation
            except asyncio.CancelledError:
                pass
            return 130
        try:
            result = await operation
        except (EnrollmentUIError, OSError):
            ui.terminal = "ENROLLMENT STOPPED"
            ui.render(bell=True)
            result = 1
        if sys.stdout.isatty() and not stop.is_set():
            await stop.wait()
        return result
    finally:
        stopped.cancel()


async def _main_async(ui: EnrollmentUI) -> int:
    loop = asyncio.get_running_loop()
    stop = asyncio.Event()
    watched = (signal.SIGINT, signal.SIGHUP, signal.SIGTERM)
    for watched_signal in watched:
        loop.add_signal_handler(watched_signal, stop.set)
    try:
        return await _present_until_closed(ui, stop)
    finally:
        for watched_signal in watched:
            loop.remove_signal_handler(watched_signal)
        ui.close_screen()


async def _preview_async(ui: EnrollmentUI) -> int:
    """Cycle the visible states without opening D-Bus or touching hardware."""

    loop = asyncio.get_running_loop()
    stop = asyncio.Event()
    watched = (signal.SIGINT, signal.SIGHUP, signal.SIGTERM)
    for watched_signal in watched:
        loop.add_signal_handler(watched_signal, stop.set)
    states = (
        (0, False, False, False, None, 0.8),
        (12, True, False, False, None, 1.5),
        (12, False, True, False, None, 0.8),
        (38, True, False, False, None, 1.5),
        (38, False, False, True, None, 1.0),
        (38, True, False, False, None, 1.5),
        (67, False, True, False, None, 0.8),
        (82, True, False, False, None, 1.5),
        (82, False, True, False, None, 0.8),
        (100, False, False, False, "FINGERPRINT ENROLLED", 1.8),
    )
    try:
        while not stop.is_set():
            for progress, needed, present, retry, terminal, duration in states:
                ui.progress_percent = progress
                ui.finger_needed = needed
                ui.finger_present = present
                ui.retry = retry
                ui.terminal = terminal
                ui.render()
                try:
                    await asyncio.wait_for(stop.wait(), timeout=duration)
                except asyncio.TimeoutError:
                    continue
                break
        return 0
    finally:
        for watched_signal in watched:
            loop.remove_signal_handler(watched_signal)
        ui.close_screen()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--finger", default="finger-1")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--verify", action="store_true")
    mode.add_argument("--expect-no-match", action="store_true")
    mode.add_argument(
        "--preview",
        action="store_true",
        help="cycle the T1Bridge-style presentation without D-Bus or hardware",
    )
    args = parser.parse_args()
    if os.geteuid() == 0:
        parser.error("run the standard fprintd client as the desktop user")
    if not t2_fprint_identity.is_handle(args.finger):
        parser.error("finger must be a neutral numbered handle")
    username = os.environ.get("USER", "")
    if not username or not re.fullmatch(
        r"[a-z_][a-z0-9_-]{0,31}", username
    ):
        parser.error("desktop username is unavailable")
    ui = EnrollmentUI(
        args.finger,
        username,
        operation=(
            "verify" if args.verify or args.expect_no_match else "enroll"
        ),
        expect_no_match=args.expect_no_match,
    )
    return asyncio.run(_preview_async(ui) if args.preview else _main_async(ui))


if __name__ == "__main__":
    raise SystemExit(main())
