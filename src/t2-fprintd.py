#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Minimal fprintd-compatible D-Bus facade for Apple T2 Touch ID.

Verification is always available after the ordinary readiness gates. Native
enrollment and single-name deletion have separately gated worker paths and
remain disabled unless the daemon receives their explicit research activation
flags. Bulk deletion remains disabled. Authentication stays fail-closed and
accepts only an identity
selected from the scoped Apple-user identity list.
"""

import argparse
import asyncio
from collections.abc import Callable
import json
import os
from pathlib import Path
import pwd
import signal as process_signal
import stat
import sys
import time

LOCAL_SOURCE = Path(__file__).resolve().parent
if str(LOCAL_SOURCE) not in sys.path:
    sys.path.insert(0, str(LOCAL_SOURCE))

from dbus_next import BusType, DBusError, Message, MessageType, Variant
from dbus_next.constants import PropertyAccess
from dbus_next import introspection as dbus_introspection
from dbus_next.service import ServiceInterface, dbus_property, method, signal

import t2_fprint_projection
import t2_fprint_result
import t2_fprint_identity
import t2_fprint_runtime
import t2_fprint_enrollment_runtime
import t2_fprint_deletion_runtime
import t2_fprint_worker_client
import t2_fprint_worker
import t2_fprint_delete_worker_client
import t2_dbus_identity
import t2_fprint_claim
import t2_performance
import t2_user_authority
from t2_dbus_sender import (
    DBusSenderError,
    SenderAwareMessageBus,
    current_sender as current_dbus_sender,
)


BUS_NAME = "net.reactivated.Fprint"
MANAGER_PATH = "/net/reactivated/Fprint/Manager"
DEVICE_PATH = "/net/reactivated/Fprint/Device/0"
FPRINT_ERROR = "net.reactivated.Fprint.Error"
UNSET_ENROLLMENT_PROGRESS = object()
LINUX_USER = os.environ.get("T2_TOUCHID_USER", "")
AUTO_SYNC_ADAPTIVE_VALUE = os.environ.get(
    "T2_TOUCHID_AUTO_SYNC_ADAPTIVE", "0"
)
ALLOWED_PAM_USERS = (LINUX_USER,)
UNSTARTED_CLAIM_SECONDS = 5.0
COMPLETED_CLAIM_SECONDS = 2.0
NATIVE_CANCEL_SECONDS = 5.0
MAX_MATCH_SECONDS = 120.0
METHOD_RATE_LIMIT = 8
METHOD_RATE_WINDOW_SECONDS = 10.0
METHOD_RATE_MAX_SENDERS = 64
DESKTOP_FEEDBACK_UNITS = frozenset(
    {
        "t2-touchid-alert.service",
        "t2-touchid-success.service",
        "t2-touchid-failure.service",
    }
)

if AUTO_SYNC_ADAPTIVE_VALUE not in {"0", "1"}:
    raise RuntimeError("T2_TOUCHID_AUTO_SYNC_ADAPTIVE is invalid")
AUTO_SYNC_ADAPTIVE = AUTO_SYNC_ADAPTIVE_VALUE == "1"
NATIVE_AUTHORITY = "linux-native-e4"
COMPATIBILITY_AUTHORITY = "macos-control-oracle-v1"


def cancelled_method_error(name: str, message: str) -> DBusError:
    """Turn a method-task cancel into a typed D-Bus error reply."""

    task = asyncio.current_task()
    if task is not None:
        task.uncancel()
    return DBusError(f"{FPRINT_ERROR}.{name}", message)


def public_verification_failure(error: BaseException) -> str:
    """Return a bounded diagnostic without paths or stable identifiers."""
    message = " ".join(str(error).split())
    if (
        not message
        or len(message) > 300
        or "/" in message
        or "\\" in message
        or any(ord(character) < 32 for character in message)
    ):
        return type(error).__name__
    for token in message.replace("(", " ").replace(")", " ").split():
        candidate = token.strip("[]{}<>,.;:")
        if len(candidate) >= 16 and all(
            character in "0123456789abcdefABCDEF-" for character in candidate
        ):
            return type(error).__name__
    return message


def verdict_from_result(
    result: object, target_finger: str | None = None
) -> str:
    """Translate privacy-safe probe JSON into a fail-closed fprintd verdict."""
    if type(result) is dict and set(result) == {
        "schema_version", "selector", "verdict", "finger_name"
    }:
        return t2_fprint_result.validate_worker_terminal_result(
            result, target_finger, False
        )[0]
    if not isinstance(result, dict):
        raise RuntimeError("malformed T2 probe result")
    if target_finger is not None:
        gate = result.get("targeted_match_gate")
        post = result.get("targeted_match_post_attestation")
        if (
            target_finger == "any"
            or not isinstance(gate, dict)
            or gate.get("finger_name") != target_finger
            or gate.get("single_identity_selected") is not True
            or gate.get("same_connection_inventory_stable") is not True
            or gate.get("local_live_reconciled") is not True
            or gate.get("identifiers_redacted") is not True
            or not isinstance(post, dict)
            or post.get("identity_state_unchanged") is not True
            or post.get("local_components_unchanged") is not True
            or post.get("per_user_inventory_unchanged") is not True
            or post.get("global_inventory_unchanged") is not True
            or post.get("identifiers_redacted") is not True
        ):
            raise RuntimeError("named T2 match attestation is incomplete")
    events = result.get("match_events", [])
    if not isinstance(events, list):
        raise RuntimeError("malformed T2 match event list")
    if result.get("match_cleanup_valid") is not True:
        raise RuntimeError("the T2 match did not close cleanly")
    if result.get("match_rejected") is True:
        raise RuntimeError("the T2 rejected match startup")
    verdict = None
    image_quality_rejected = False
    for event in events:
        if not isinstance(event, dict):
            raise RuntimeError("malformed T2 match event")
        if event.get("event_kind") != "match_result":
            continue
        if verdict is not None:
            raise RuntimeError("the T2 returned multiple terminal match results")
        if event.get("result_valid") is not True:
            raise RuntimeError("the T2 returned an invalid or unknown match result")
        if (
            event.get("matched") is True
            and event.get("no_match", False) is False
            and event.get("no_match_image_quality", False) is False
            and event.get("matches_enrolled_identity") is True
            and (
                target_finger is None
                or event.get("matches_selected_identity") is True
            )
        ):
            verdict = "verify-match"
            continue
        if event.get("no_match") is True and event.get("matched") is False:
            if event.get("no_match_image_quality") is True:
                image_quality_rejected = True
                continue
            verdict = "verify-no-match"
            continue
        raise RuntimeError("the T2 returned an unclassifiable match result")
    if verdict is not None:
        return verdict
    if image_quality_rejected:
        raise RuntimeError(
            "the T2 match ended after image-quality retries without a verdict"
        )
    raise RuntimeError("the T2 match ended without a terminal verdict")


def resolved_any_finger_from_result(result: object) -> str | None:
    """Return the canonical identity selected by an attested `any` match."""
    if type(result) is dict and set(result) == {
        "schema_version", "selector", "verdict", "finger_name"
    }:
        verdict, finger_name = t2_fprint_result.validate_worker_terminal_result(
            result, None, True
        )
        return finger_name if verdict == "verify-match" else None
    if not isinstance(result, dict):
        raise RuntimeError("malformed T2 probe result")
    gate = result.get("resolved_any_match_gate")
    post = result.get("resolved_any_match_post_attestation")
    if (
        not isinstance(gate, dict)
        or type(gate.get("identity_count")) is not int
        or not 1 <= gate["identity_count"] <= t2_fprint_identity.MAX_ENROLLED_IDENTITIES
        or gate.get("complete_named_inventory") is not True
        or gate.get("all_identities_selected") is not True
        or gate.get("same_connection_inventory_stable") is not True
        or gate.get("local_live_reconciled") is not True
        or gate.get("identifiers_redacted") is not True
        or not isinstance(post, dict)
        or post.get("identity_state_unchanged") is not True
        or post.get("local_components_unchanged") is not True
        or post.get("per_user_inventory_unchanged") is not True
        or post.get("global_inventory_unchanged") is not True
        or post.get("identifiers_redacted") is not True
    ):
        raise RuntimeError("resolved-any T2 match attestation is incomplete")
    # Use the same fail-closed terminal checks as named verification. A
    # placement/image-quality retry is not a terminal negative verdict.
    if verdict_from_result(result) == "verify-no-match":
        return None
    for event in result["match_events"]:
        if not isinstance(event, dict) or event.get("event_kind") != "match_result":
            continue
        if event.get("matched") is not True:
            continue
        finger_name = event.get("matched_finger_name")
        if (
            event.get("matches_enrolled_identity") is not True
            or event.get("matched_finger_name_present") is not True
            or not t2_fprint_projection.is_finger_name(finger_name)
        ):
            raise RuntimeError("resolved-any T2 match result is incomplete")
        return finger_name
    raise RuntimeError("resolved-any T2 match result has no terminal identity")


def desktop_user_unit_command(unit: object) -> tuple[str, ...] | None:
    """Return a command bound to the configured desktop user's live bus.

    The fprint facade is a root system service.  Root's environment is not a
    desktop user session, and ``systemctl --machine=... --user`` is not a
    reliable substitute for the target user's runtime bus.  Refuse an absent,
    replaced, or wrong-owner socket and let feedback remain best-effort.
    """

    if unit not in DESKTOP_FEEDBACK_UNITS or not LINUX_USER:
        return None
    try:
        account = pwd.getpwnam(LINUX_USER)
    except (KeyError, OSError):
        return None
    if account.pw_uid <= 0:
        return None
    runtime_dir = Path(f"/run/user/{account.pw_uid}")
    bus = runtime_dir / "bus"
    try:
        runtime_info = runtime_dir.stat(follow_symlinks=False)
        bus_info = bus.stat(follow_symlinks=False)
    except OSError:
        return None
    if (
        not stat.S_ISDIR(runtime_info.st_mode)
        or runtime_info.st_uid != account.pw_uid
        or runtime_info.st_nlink < 1
        or runtime_info.st_mode & 0o077
        or not stat.S_ISSOCK(bus_info.st_mode)
        or bus_info.st_uid != account.pw_uid
        or bus_info.st_nlink != 1
    ):
        return None
    return (
        "/usr/bin/runuser",
        "-u",
        LINUX_USER,
        "--",
        "/usr/bin/env",
        f"XDG_RUNTIME_DIR={runtime_dir}",
        f"DBUS_SESSION_BUS_ADDRESS=unix:path={bus}",
        "/usr/bin/systemctl",
        "--user",
        "start",
        "--no-block",
        unit,
    )


class T2Backend:
    def __init__(
        self,
        project_dir: Path,
        match_seconds: float,
        auto_sync_adaptive: bool = AUTO_SYNC_ADAPTIVE,
    ) -> None:
        if not LINUX_USER:
            raise RuntimeError("T2_TOUCHID_USER is not configured")
        try:
            account = pwd.getpwnam(LINUX_USER)
        except KeyError as error:
            raise RuntimeError("configured Linux user does not exist") from error
        if account.pw_uid == 0:
            raise RuntimeError("configured Linux user must be non-root")
        self.linux_uid = account.pw_uid
        self.project_dir = project_dir
        if (
            type(match_seconds) is bool
            or type(match_seconds) not in (int, float)
            or match_seconds != match_seconds
            or match_seconds < 0
            or match_seconds == float("inf")
        ):
            raise RuntimeError("match observation deadline is invalid")
        self.match_seconds = float(match_seconds)
        self.sleep_generation = 0
        self._cached_runtime_authority = None
        self._cached_runtime_authority_token = None
        self.biolockout_state_dir = Path(
            os.environ.get(
                "T2_TOUCHID_BIOLOCKOUT_STATE_DIR",
                "/var/lib/t2-touchid/biolockout",
            )
        )
        if not self.biolockout_state_dir.is_absolute():
            raise RuntimeError("bio-lockout state directory must be absolute")
        self.catacomb_root = Path("/var/lib/t2-touchid/catacomb")
        self.process: asyncio.subprocess.Process | None = None
        self.process_owner = None
        self.native_worker: asyncio.subprocess.Process | None = None
        self.native_worker_stderr_task: asyncio.Task | None = None
        self.native_worker_feedback: Callable[[dict], None] | None = None
        self.native_worker_cue_sent = False
        self.native_worker_request_id = 0
        self.native_worker_expected_boundary: int | None = None
        self.native_worker_boundary_event: asyncio.Event | None = None
        self.native_worker_start_lock = asyncio.Lock()
        self.native_worker_warm_task: asyncio.Task | None = None
        self.native_worker_sleep_task: asyncio.Task | None = None
        self.runtime_warm_task: asyncio.Task | None = None
        # Startup is fail-closed until authenticated login1 monitoring has
        # reconciled the current PreparingForSleep state.
        self.system_sleeping = True
        self.operation_lock = asyncio.Lock()
        self.inventory_task: asyncio.Task | None = None
        self.inventory_projection: t2_fprint_runtime.RuntimeProjection | None = None
        self.inventory_authority_token: tuple[object, ...] | None = None
        self.inventory_state_token: tuple[object, ...] | None = None
        self.inventory_generation = 0
        if type(auto_sync_adaptive) is not bool:
            raise RuntimeError("adaptive Catacomb sync activation is invalid")
        self.auto_sync_adaptive = auto_sync_adaptive
        self.adaptive_sync_tasks: set[asyncio.Task] = set()
        self.feedback_tasks: set[asyncio.Task] = set()
        self.port: int | None = None
        self.port_from_cache = False
        port_file = Path(
            os.environ.get(
                "T2_TOUCHID_PORT_FILE", "/var/lib/t2-touchid/biometric-port"
            )
        )
        try:
            cached_port = int(port_file.read_text().strip())
            if 49152 <= cached_port <= 65535:
                self.port = cached_port
                self.port_from_cache = True
        except (OSError, ValueError):
            pass

    @staticmethod
    def _signal_process_group(process, sig) -> None:
        # All supervised commands below start their own session. Include a
        # wrapper's descendants, which may still hold the output pipes open.
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            pass

    async def _reap_process(self, process) -> None:
        async def discard(stream):
            if stream is not None:
                while await stream.read(65536):
                    pass

        self._signal_process_group(
            process, process_signal.SIGTERM
        )
        drained = asyncio.gather(
            discard(process.stdout), discard(process.stderr), process.wait()
        )
        try:
            # Keep draining through the deadline: cancelling pipe readers
            # before waiting for exit can deadlock even after SIGKILL.
            await asyncio.wait_for(asyncio.shield(drained), timeout=10)
        except asyncio.TimeoutError:
            self._signal_process_group(process, process_signal.SIGKILL)
            await drained

    async def _collect_process(self, process, live_feedback=None, *, probe=False):
        """Retain ownership and drain both pipes through failure/cancellation."""
        self.process = process
        self.process_owner = asyncio.current_task()
        if probe:
            readers = (
                asyncio.create_task(process.stdout.read()),
                asyncio.create_task(self._read_probe_stderr(process.stderr, live_feedback)),
                asyncio.create_task(process.wait()),
            )
        else:
            readers = (asyncio.create_task(process.communicate()),)
        try:
            output = await asyncio.gather(*readers)
            return (output[0], output[1]) if probe else output[0]
        except BaseException:
            async def finish():
                for reader in readers:
                    reader.cancel()
                await asyncio.gather(*readers, return_exceptions=True)
                await self._reap_process(process)

            cleanup = asyncio.create_task(finish())
            # A second Stop/disconnect must not detach an unreaped helper.
            while not cleanup.done():
                try:
                    await asyncio.shield(cleanup)
                except asyncio.CancelledError:
                    continue
            cleanup.result()
            raise
        finally:
            if self.process is process:
                self.process = None
                self.process_owner = None

    async def _bounded_communication(self, process):
        """Timeout/cancellation cleanup for best-effort feedback commands."""
        communication = asyncio.create_task(process.communicate())
        try:
            return await asyncio.wait_for(asyncio.shield(communication), timeout=3)
        except BaseException:
            self._signal_process_group(process, process_signal.SIGKILL)
            # The original readers remain alive, so wrappers cannot leave
            # blocked pipes, unconsumed exceptions, or an unreaped child.
            while not communication.done():
                try:
                    await asyncio.shield(communication)
                except asyncio.CancelledError:
                    continue
            communication.result()
            raise

    @staticmethod
    def _protected_file_token(path: Path) -> tuple[object, ...] | None:
        try:
            info = path.stat(follow_symlinks=False)
        except OSError:
            return None
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_mode & 0o077
        ):
            return None
        return (
            path.as_posix(),
            info.st_dev,
            info.st_ino,
            info.st_nlink,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
        )

    def _authority_cache_token(self, authority) -> tuple[object, ...] | None:
        if getattr(authority, "origin", None) != NATIVE_AUTHORITY:
            return None
        mapping = self._protected_file_token(t2_user_authority.MAPPING_PATH)
        manifest = self._protected_file_token(
            t2_user_authority.USERS_ROOT / str(self.linux_uid) / "authority.json"
        )
        journal = self._protected_file_token(authority.enrollment_journal)
        if mapping is None or manifest is None or journal is None:
            return None
        return (
            os.environ.get("T2_TOUCHID_AUTHORITY_MODE", "linux-native"),
            mapping,
            manifest,
            journal,
        )

    def runtime_authority(self) -> t2_user_authority.RuntimeUserAuthority:
        cached = getattr(self, "_cached_runtime_authority", None)
        cached_token = getattr(self, "_cached_runtime_authority_token", None)
        if cached is not None and cached_token is not None:
            current = self._authority_cache_token(cached)
            if current is not None and current == cached_token:
                return cached
        try:
            authority = t2_user_authority.load_runtime(self.linux_uid)
        except t2_user_authority.UserAuthorityError as error:
            self._cached_runtime_authority = None
            self._cached_runtime_authority_token = None
            raise RuntimeError("runtime authority is unavailable") from error
        self._cached_runtime_authority = authority
        self._cached_runtime_authority_token = self._authority_cache_token(
            authority
        )
        return authority

    def _observation_seconds(self) -> float:
        seconds = getattr(self, "match_seconds", 0)
        if (
            type(seconds) is bool
            or type(seconds) not in (int, float)
            or seconds != seconds
            or seconds < 0
            or seconds == float("inf")
        ):
            raise RuntimeError("match observation deadline is invalid")
        if seconds == 0:
            return MAX_MATCH_SECONDS
        return min(float(seconds), MAX_MATCH_SECONDS)

    @staticmethod
    def _authority_token(authority) -> tuple[object, ...]:
        """Bind cached presentation to the protected authority generation."""

        selected = authority.selected
        return (
            authority.origin,
            authority.mapping_set.generation,
            selected.linux_account_generation,
            selected.keybag_sha256,
            selected.apple_uid,
            selected.account_uuid,
            selected.bag_uuid,
        )

    def invalidate_inventory(self, _reason: str = "explicit") -> None:
        """Invalidate presentation metadata without cancelling an owned read."""

        self.inventory_generation = getattr(self, "inventory_generation", 0) + 1
        self.inventory_projection = None
        self.inventory_authority_token = None
        self.inventory_state_token = None

    def _inventory_state_token(self, authority) -> tuple[object, ...] | None:
        """Notice out-of-process mutations without reading biometric payloads.

        Committed Catacombs are atomically replaced; mutation journals are
        appended even when a transaction fails before persistence. Neither
        change necessarily advances the account's authority generation.
        Unavailable or unsafe state disables reuse and leaves validation to
        the normal live collector. Compatibility state has no local token.
        """
        if authority.origin != NATIVE_AUTHORITY:
            return None
        tokens = []
        try:
            for root in (self.catacomb_root, self.catacomb_root.parent / "mutations"):
                info = root.stat(follow_symlinks=False)
                if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
                    return None
                tokens.append((info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns))
                entries = []
                for path in sorted(root.iterdir()):
                    info = path.stat(follow_symlinks=False)
                    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
                        return None
                    entries.append((
                        path.name, info.st_dev, info.st_ino, info.st_size,
                        info.st_mtime_ns, info.st_ctime_ns,
                    ))
                tokens.append(tuple(entries))
        except OSError:
            return None
        return tuple(tokens)

    async def runtime_projection(
        self, *, fresh: bool = False
    ) -> t2_fprint_runtime.RuntimeProjection:
        if getattr(self, "system_sleeping", False):
            raise RuntimeError("system sleep transition is active")
        authority = self.runtime_authority()
        authority_token = self._authority_token(authority)
        state_token = self._inventory_state_token(authority)
        now = time.monotonic()
        if (
            not fresh
            and self.inventory_projection is not None
            and self.inventory_authority_token == authority_token
            and state_token is not None
            and self.inventory_state_token == state_token
        ):
            t2_performance.emit("inventory", "presentation_cache", now)
            return self.inventory_projection
        generation = self.inventory_generation
        started = time.monotonic()
        try:
            projection = await self._collect_runtime_projection(authority)
        except BaseException:
            t2_performance.emit("inventory", "hardware_collection", started, "error")
            raise
        t2_performance.emit("inventory", "hardware_collection", started)
        if getattr(self, "system_sleeping", False):
            raise RuntimeError("system sleep transition is active")
        if (
            generation == self.inventory_generation
            and state_token is not None
            and state_token == self._inventory_state_token(authority)
        ):
            self.inventory_projection = projection
            self.inventory_authority_token = authority_token
            self.inventory_state_token = state_token
        return projection

    async def _collect_runtime_projection(
        self, authority
    ) -> t2_fprint_runtime.RuntimeProjection:
        if authority.origin == COMPATIBILITY_AUTHORITY:
            port = await self.discover()
            await self._run_probe(port, prepare_only=True)
        elif authority.origin != NATIVE_AUTHORITY:
            raise RuntimeError("configured T2 authority origin is unsupported")
        command = [
            sys.executable,
            str(self.project_dir / "src/t2-touchid-fprint-status.py"),
        ]
        environment = os.environ.copy()
        environment["SUDO_UID"] = str(self.linux_uid)
        process = await asyncio.create_subprocess_exec(
            *command,
            start_new_session=True,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=environment,
        )
        stdout, stderr = await self._collect_process(process)
        if process.returncode != 0 or not stdout:
            detail = stderr.decode(errors="replace").strip()
            raise RuntimeError(detail or "fprint projection collection failed")
        try:
            value = json.loads(stdout)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise RuntimeError("fprint projection returned malformed JSON") from error
        try:
            return t2_fprint_runtime.parse_projection(value)
        except t2_fprint_runtime.FprintRuntimeError as error:
            raise RuntimeError("fprint projection failed validation") from error

    async def enrollment_projection(
        self, *, fresh: bool = False
    ) -> t2_fprint_runtime.RuntimeProjection:
        """Project E4 state or the one valid pre-E4 native bootstrap state."""

        try:
            return await self.runtime_projection(fresh=fresh)
        except RuntimeError as projection_error:
            if os.environ.get("T2_TOUCHID_AUTHORITY_MODE") != "linux-native":
                raise
            try:
                native, _configuration, authority, existing_authority = (
                    t2_fprint_worker.native_enrollment_context(self.linux_uid)
                )
                if existing_authority is not None:
                    raise projection_error
                native._require_fresh_enrollment_state()
                if authority.selected.linux_uid != self.linux_uid:
                    raise RuntimeError("native bootstrap authority changed users")
            except RuntimeError:
                raise
            except Exception as error:
                raise RuntimeError(
                    "native enrollment bootstrap is unavailable"
                ) from error
            return t2_fprint_runtime.RuntimeProjection((), 0, True)

    async def list_fingers(self) -> tuple[str, ...]:
        # The lock UI and PAM can ask together. Share only a currently running
        # read, never a completed inventory or an authentication result.
        if getattr(self, "system_sleeping", False):
            raise RuntimeError("system sleep transition is active")
        if self.inventory_task is None or self.inventory_task.done():
            self.inventory_task = asyncio.create_task(self._collect_fingers())
            self.inventory_task.add_done_callback(
                lambda task: None if task.cancelled() else task.exception()
            )
        return await asyncio.shield(self.inventory_task)

    async def _collect_fingers(self) -> tuple[str, ...]:
        async with self.operation_lock:
            if getattr(self, "system_sleeping", False):
                raise RuntimeError("system sleep transition is active")
            return (await self.enrollment_projection()).listed_fingers

    async def discover(self) -> int:
        if self.port is not None:
            return self.port
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            str(self.project_dir / "src/discover-biometric-port.py"),
            start_new_session=True,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=os.environ.copy(),
        )
        stdout, stderr = await self._collect_process(process)
        if process.returncode != 0:
            raise RuntimeError(stderr.decode(errors="replace").strip())
        self.port = int(stdout.decode().strip())
        if not 49152 <= self.port <= 65535:
            self.port = None
            raise RuntimeError("discovery returned an invalid port")
        self.port_from_cache = False
        return self.port

    async def _run_probe(
        self,
        port: int,
        target_finger: str | None = None,
        resolve_any_finger: bool = False,
        live_feedback: Callable[[dict], None] | None = None,
        prepare_only: bool = False,
    ) -> dict:
        if type(prepare_only) is not bool or (
            prepare_only and (target_finger is not None or resolve_any_finger)
        ):
            raise RuntimeError("invalid compatibility projection preparation")
        authority = self.runtime_authority()
        if authority.origin != COMPATIBILITY_AUTHORITY:
            raise RuntimeError("compatibility Catacomb authority changed")
        command = [
            "/usr/bin/flock",
            "--exclusive",
            "--timeout",
            "10",
            "--no-fork",
            "/run/t2-touchid/operation.lock",
            sys.executable,
            str(self.project_dir / "src/bridge-xpc-probe.py"),
            "--port",
            str(port),
            "--initialize",
            "--biometric-protocol",
            "--sensor-readiness",
            "--reset-sensor",
            "--sensor-info",
            "--load-calibration",
            "--cancel-operation",
            "--bio-device-list",
            "--identity-list",
            "--service-template-sync",
            "--load-native-catacomb-root",
            str(self.catacomb_root),
            "--compatibility-authority-linux-uid",
            str(self.linux_uid),
            "--biolockout-state-dir",
            str(self.biolockout_state_dir),
            "--display-on",
            "--system-awake",
            "--macos-user-id",
            str(authority.selected.apple_uid),
        ]
        if not prepare_only:
            command.extend(
                [
                    "--match-seconds",
                    str(self._observation_seconds()),
                    "--stop-on-match-result",
                    "--retry-image-quality-no-match",
                    "--live-match-feedback",
                    "--live-match-feedback-format",
                    "json",
                ]
            )
            if target_finger is not None:
                command.extend(["--match-finger-name", target_finger])
            if resolve_any_finger:
                command.append("--resolve-any-finger-name")
        process = await asyncio.create_subprocess_exec(
            *command,
            start_new_session=True,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await self._collect_process(
            process, live_feedback, probe=True
        )
        if not stdout or process.returncode != 0:
            detail = stderr.decode(errors="replace").strip()
            raise RuntimeError(detail or "BridgeXPC probe failed")
        try:
            result = json.loads(stdout)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise RuntimeError("BridgeXPC probe returned malformed JSON") from error
        if not isinstance(result, dict):
            raise RuntimeError("BridgeXPC probe returned malformed JSON")
        return result

    async def _read_probe_stderr(
        self,
        stream: asyncio.StreamReader,
        live_feedback: Callable[[dict], None] | None,
    ) -> bytes:
        captured = bytearray()
        diagnostic_limit = 65536
        cue_sent = False
        prefix = b"T2_MATCH_EVENT "
        while True:
            line = await stream.readline()
            if not line:
                return bytes(captured[-diagnostic_limit:])
            captured.extend(line)
            # Retain a diagnostic tail, compacting in batches rather than
            # copying the entire window for every short feedback line.
            if len(captured) > 2 * diagnostic_limit:
                del captured[:-diagnostic_limit]
            if line.startswith(b"T2_PERF_EVENT "):
                t2_performance.relay(line.rstrip(b"\r\n"))
                continue
            if not line.startswith(prefix):
                continue
            try:
                event = json.loads(line[len(prefix) :])
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            if isinstance(event, dict):
                if live_feedback is not None:
                    try:
                        live_feedback(event)
                    except Exception:
                        pass  # UI delivery is never an authentication verdict.
                if event.get("event_kind") == "match_armed" and not cue_sent:
                    cue_sent = True
                    try:
                        self.schedule_feedback("ready")
                    except Exception:
                        pass  # Audio must not stop draining the worker pipe.

    async def _pump_native_worker_stderr(self, process) -> None:
        try:
            await self._pump_native_worker_stderr_stream(process)
        finally:
            boundary = getattr(self, "native_worker_boundary_event", None)
            if boundary is not None:
                boundary.set()

    async def _pump_native_worker_stderr_stream(self, process) -> None:
        stream = process.stderr
        if stream is None:
            return
        buffered = bytearray()
        while True:
            chunk = await stream.read(65536)
            if not chunk:
                if buffered:
                    self._handle_native_worker_stderr_line(bytes(buffered))
                return
            buffered.extend(chunk)
            while b"\n" in buffered:
                line, _separator, remainder = buffered.partition(b"\n")
                buffered = bytearray(remainder)
                self._handle_native_worker_stderr_line(line)
            if len(buffered) > 65536:
                # Protocol records are intentionally small. Continue draining
                # an untrusted oversized diagnostic without retaining it.
                buffered.clear()

    def _handle_native_worker_stderr_line(self, line: bytes) -> None:
        prefix = b"T2_MATCH_EVENT "
        if line.startswith(b"T2_WORKER_BOUNDARY "):
            try:
                request_id = int(line.removeprefix(b"T2_WORKER_BOUNDARY "))
            except ValueError:
                return
            if request_id == getattr(self, "native_worker_expected_boundary", None):
                boundary = getattr(self, "native_worker_boundary_event", None)
                if boundary is not None:
                    boundary.set()
            return
        if line.startswith(b"T2_PERF_EVENT "):
            t2_performance.relay(line)
            return
        if not line.startswith(prefix):
            return
        try:
            event = json.loads(line[len(prefix) :])
        except (UnicodeDecodeError, json.JSONDecodeError):
            return
        if not isinstance(event, dict):
            return
        feedback = self.native_worker_feedback
        if feedback is not None:
            try:
                feedback(event)
            except Exception:
                pass
        if (
            event.get("event_kind") == "match_armed"
            and not self.native_worker_cue_sent
        ):
            self.native_worker_cue_sent = True
            try:
                self.schedule_feedback("ready")
            except Exception:
                pass

    async def _ensure_native_worker(self):
        lock = getattr(self, "native_worker_start_lock", None)
        if lock is None:
            lock = asyncio.Lock()
            self.native_worker_start_lock = lock
        async with lock:
            return await self._ensure_native_worker_locked()

    async def _ensure_native_worker_locked(self):
        if getattr(self, "system_sleeping", False):
            raise RuntimeError("system sleep transition is active")
        process = self.native_worker
        stderr_task = self.native_worker_stderr_task
        if (
            process is not None
            and process.returncode is None
            and stderr_task is not None
            and not stderr_task.done()
        ):
            return process
        if process is not None:
            await self._discard_native_worker(process)
        command = [
            sys.executable,
            str(self.project_dir / "src/t2-native-match.py"),
            "--resident-worker",
        ]
        environment = os.environ.copy()
        environment["SUDO_UID"] = str(self.linux_uid)
        started = time.monotonic()
        process = await asyncio.create_subprocess_exec(
            *command,
            start_new_session=True,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=environment,
        )
        self.native_worker = process
        self.native_worker_stderr_task = asyncio.create_task(
            self._pump_native_worker_stderr(process)
        )
        if process.stdout is None:
            await self._discard_native_worker(process)
            raise RuntimeError("native T2 match worker output is unavailable")
        try:
            ready_line = await asyncio.wait_for(process.stdout.readline(), timeout=10)
            ready = json.loads(ready_line)
            if ready != {"schema_version": 1, "ready": True}:
                raise RuntimeError("native T2 match worker did not become ready")
        except BaseException:
            cleanup = asyncio.create_task(self._discard_native_worker(process))
            while not cleanup.done():
                try:
                    await asyncio.shield(cleanup)
                except asyncio.CancelledError:
                    continue
            cleanup.result()
            raise
        t2_performance.emit("native_match", "worker_start", started)
        return process

    def _schedule_native_worker_warm(self) -> None:
        if getattr(self, "system_sleeping", False):
            return
        task = getattr(self, "native_worker_warm_task", None)
        if task is not None and not task.done():
            return
        task = asyncio.create_task(self._ensure_native_worker())
        self.native_worker_warm_task = task

        def completed(done: asyncio.Task) -> None:
            if self.native_worker_warm_task is done:
                self.native_worker_warm_task = None
            try:
                done.result()
            except asyncio.CancelledError:
                pass
            except Exception as error:
                print(
                    "Touch ID native worker warmup failed: "
                    f"{public_verification_failure(error)}",
                    flush=True,
                )

        task.add_done_callback(completed)

    async def warm_runtime(self) -> None:
        """Move presentation and import cold starts before D-Bus exposure."""

        if getattr(self, "system_sleeping", False):
            return
        try:
            authority = self.runtime_authority()
        except Exception as error:
            print(
                "Touch ID runtime warmup skipped: "
                f"{public_verification_failure(error)}",
                flush=True,
            )
            return
        async def warm_projection():
            async with self.operation_lock:
                return await self.runtime_projection()

        operations = [warm_projection()]
        if authority.origin == NATIVE_AUTHORITY:
            operations.append(self._ensure_native_worker())
        results = await asyncio.gather(*operations, return_exceptions=True)
        for result in results:
            if isinstance(result, BaseException):
                print(
                    "Touch ID runtime warmup failed: "
                    f"{public_verification_failure(result)}",
                    flush=True,
                )

    def _schedule_runtime_warm(self) -> asyncio.Task | None:
        if getattr(self, "system_sleeping", False):
            return None
        task = getattr(self, "runtime_warm_task", None)
        sleep_task = getattr(self, "native_worker_sleep_task", None)
        sleep_pending = isinstance(sleep_task, asyncio.Task) and not sleep_task.done()
        if task is not None and not task.done() and not sleep_pending:
            return task
        task = asyncio.create_task(self._warm_runtime_after_sleep())
        self.runtime_warm_task = task

        def completed(done: asyncio.Task) -> None:
            if self.runtime_warm_task is done:
                self.runtime_warm_task = None
            try:
                done.result()
            except asyncio.CancelledError:
                pass
            except Exception as error:
                print(
                    "Touch ID runtime warmup failed: "
                    f"{public_verification_failure(error)}",
                    flush=True,
                )

        task.add_done_callback(completed)
        return task

    async def _warm_runtime_after_sleep(self) -> None:
        """Drain an in-flight sleep quiesce before importing state again."""

        sleep_task = getattr(self, "native_worker_sleep_task", None)
        current = asyncio.current_task()
        if (
            isinstance(sleep_task, asyncio.Task)
            and not sleep_task.done()
            and sleep_task is not current
        ):
            await asyncio.gather(sleep_task, return_exceptions=True)
        if getattr(self, "system_sleeping", False):
            return
        await self.warm_runtime()

    async def _quiesce_hardware_for_sleep(
        self, generation: int | None = None
    ) -> None:
        """Cancel and drain every owned hardware path before suspend."""

        current = asyncio.current_task()
        if generation is None:
            generation = getattr(self, "sleep_generation", 0)

        def still_this_sleep() -> bool:
            return (
                getattr(self, "system_sleeping", False)
                and getattr(self, "sleep_generation", 0) == generation
            )

        if not still_this_sleep():
            return

        active: list[asyncio.Task] = []
        for task in (
            getattr(self, "runtime_warm_task", None),
            getattr(self, "native_worker_warm_task", None),
            getattr(self, "inventory_task", None),
            getattr(self, "process_owner", None),
        ):
            if (
                isinstance(task, asyncio.Task)
                and task is not current
                and not task.done()
                and task not in active
            ):
                active.append(task)
        for task in active:
            task.cancel()
        if active:
            await asyncio.gather(*active, return_exceptions=True)

        lock = getattr(self, "native_worker_start_lock", None)
        if lock is None:
            lock = asyncio.Lock()
            self.native_worker_start_lock = lock
        if not still_this_sleep():
            return
        async with lock:
            if not still_this_sleep():
                return
            process = getattr(self, "native_worker", None)
            if process is not None:
                await self._discard_native_worker(process)
        if not still_this_sleep():
            return
        # A collector can own the operation lock before publishing itself as
        # process_owner. This barrier covers that interleaving and cannot admit
        # new work while system_sleeping remains true.
        operation_lock = getattr(self, "operation_lock", None)
        if operation_lock is not None:
            async with operation_lock:
                pass

    def system_sleep_changed(self, sleeping: bool) -> None:
        """Quiesce imported state for suspend and prepare it again on resume."""

        if type(sleeping) is not bool:
            raise RuntimeError("system sleep state is invalid")
        self.sleep_generation = getattr(self, "sleep_generation", 0) + 1
        generation = self.sleep_generation
        self.system_sleeping = sleeping
        self.invalidate_inventory("system_sleep")
        if sleeping:
            previous = getattr(self, "native_worker_sleep_task", None)

            async def run() -> None:
                if (
                    isinstance(previous, asyncio.Task)
                    and not previous.done()
                    and previous is not asyncio.current_task()
                ):
                    await asyncio.gather(previous, return_exceptions=True)
                if (
                    getattr(self, "system_sleeping", False)
                    and getattr(self, "sleep_generation", 0) == generation
                ):
                    await self._quiesce_hardware_for_sleep(generation)

            if previous is None or previous.done():
                task = asyncio.create_task(
                    self._quiesce_hardware_for_sleep(generation)
                )
            else:
                task = asyncio.create_task(run())
            self.native_worker_sleep_task = task

            def quiesced(done: asyncio.Task) -> None:
                if self.native_worker_sleep_task is done:
                    self.native_worker_sleep_task = None
                if not done.cancelled():
                    done.exception()

            task.add_done_callback(quiesced)
            return
        self._schedule_runtime_warm()

    async def _discard_native_worker(self, process) -> None:
        if self.native_worker is not process:
            return
        self.native_worker = None
        task = self.native_worker_stderr_task
        self.native_worker_stderr_task = None
        if process.stdin is not None:
            process.stdin.close()
        if process.returncode is None:
            try:
                pid = process.pid
                if type(pid) is not int or pid <= 1 or os.getpgid(pid) != pid:
                    raise ProcessLookupError
                os.killpg(pid, process_signal.SIGKILL)
            except (OSError, TypeError, ValueError):
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
            await process.wait()
        if task is not None:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    async def _finish_native_worker_discard(self, process) -> None:
        """Finish recovery after task cancellation, including repeated cancel."""

        cleanup = asyncio.create_task(self._discard_native_worker(process))
        while not cleanup.done():
            try:
                await asyncio.shield(cleanup)
            except asyncio.CancelledError:
                continue
        cleanup.result()

    async def _run_native_match(
        self,
        target_finger: str | None = None,
        resolve_any_finger: bool = False,
        live_feedback: Callable[[dict], None] | None = None,
    ) -> dict:
        if target_finger is not None and resolve_any_finger:
            raise RuntimeError("native match identity selectors conflict")
        process = await self._ensure_native_worker()
        if process.stdin is None or process.stdout is None:
            await self._discard_native_worker(process)
            raise RuntimeError("native T2 match worker pipes are unavailable")
        request = {
            "schema_version": 1,
            "request_id": (
                getattr(self, "native_worker_request_id", 0) % (2**63 - 1)
            )
            + 1,
            "observation_seconds": self._observation_seconds(),
            "match_finger_name": target_finger,
            "resolve_any_finger_name": resolve_any_finger,
        }
        owner = asyncio.current_task()
        self.native_worker_request_id = request["request_id"]
        self.native_worker_expected_boundary = request["request_id"]
        boundary_event = asyncio.Event()
        self.native_worker_boundary_event = boundary_event
        self.process = process
        self.process_owner = owner
        self.native_worker_feedback = live_feedback
        self.native_worker_cue_sent = False
        response_task = asyncio.create_task(process.stdout.readline())
        boundary_task = asyncio.create_task(boundary_event.wait())
        completion = asyncio.gather(response_task, boundary_task)
        async def exchange():
            process.stdin.write(
                json.dumps(request, separators=(",", ":")).encode("utf-8") + b"\n"
            )
            await process.stdin.drain()
            return await completion

        exchange_task = asyncio.create_task(exchange())
        cancelled = False
        try:
            try:
                response_line, _boundary = await asyncio.shield(exchange_task)
            except asyncio.CancelledError:
                cancelled = True
                try:
                    process.terminate()
                except ProcessLookupError:
                    pass
                deadline = (
                    asyncio.get_running_loop().time() + NATIVE_CANCEL_SECONDS
                )
                while not exchange_task.done() and asyncio.get_running_loop().time() < deadline:
                    try:
                        await asyncio.wait_for(
                            asyncio.shield(exchange_task),
                            timeout=max(
                                0.001,
                                deadline - asyncio.get_running_loop().time(),
                            ),
                        )
                    except asyncio.CancelledError:
                        continue
                    except asyncio.TimeoutError:
                        break
                if not exchange_task.done():
                    await self._finish_native_worker_discard(process)
                    raise asyncio.CancelledError
                try:
                    response_line, _boundary = exchange_task.result()
                except Exception:
                    await self._finish_native_worker_discard(process)
                    raise asyncio.CancelledError
            except Exception:
                await self._discard_native_worker(process)
                raise
            if not response_line:
                await self._discard_native_worker(process)
                if cancelled:
                    raise asyncio.CancelledError
                raise RuntimeError("native T2 match worker exited")
            try:
                response = json.loads(response_line)
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                await self._discard_native_worker(process)
                raise RuntimeError(
                    "native T2 match owner returned malformed JSON"
                ) from error
            if cancelled:
                raise asyncio.CancelledError
        finally:
            if not exchange_task.done():
                exchange_task.cancel()
                await asyncio.gather(exchange_task, return_exceptions=True)
            if not completion.done():
                completion.cancel()
                await asyncio.gather(completion, return_exceptions=True)
            self.native_worker_feedback = None
            self.native_worker_expected_boundary = None
            if self.native_worker_boundary_event is boundary_event:
                self.native_worker_boundary_event = None
            if self.process is process and self.process_owner is owner:
                self.process = None
                self.process_owner = None
            if self.native_worker is process:
                await self._discard_native_worker(process)
            self._schedule_native_worker_warm()
        if (
            type(response) is not dict
            or set(response) not in (
                {"schema_version", "request_id", "ok", "result"},
                {"schema_version", "request_id", "ok", "error"},
            )
            or response.get("schema_version") != 1
            or response.get("request_id") != request["request_id"]
            or type(response.get("ok")) is not bool
        ):
            await self._discard_native_worker(process)
            raise RuntimeError("native T2 match owner returned malformed JSON")
        if response["ok"] is not True:
            raise RuntimeError("native T2 match owner failed")
        result = response["result"]
        try:
            t2_fprint_result.validate_worker_terminal_result(
                result, target_finger, resolve_any_finger
            )
        except RuntimeError:
            await self._discard_native_worker(process)
            raise
        return result

    async def verify(
        self,
        target_finger: str | None = None,
        resolve_any_finger: bool = False,
        live_feedback: Callable[[dict], None] | None = None,
    ) -> tuple[str, dict]:
        if target_finger is not None and resolve_any_finger:
            raise RuntimeError("named and resolved-any matching conflict")
        authority = self.runtime_authority()
        if authority.origin == NATIVE_AUTHORITY:
            try:
                result = await self._run_native_match(
                    target_finger, resolve_any_finger, live_feedback
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                self.invalidate_inventory("native_match_failure")
                raise
        elif authority.origin == COMPATIBILITY_AUTHORITY:
            port = await self.discover()
            # Never replay authentication after an ambiguous transport failure.
            result = await self._run_probe(
                port, target_finger, resolve_any_finger, live_feedback
            )
        else:
            raise RuntimeError("configured T2 authority origin is unsupported")
        if resolve_any_finger:
            verdict = (
                "verify-match"
                if resolved_any_finger_from_result(result) is not None
                else "verify-no-match"
            )
        else:
            verdict = verdict_from_result(result, target_finger)
        self.schedule_feedback(verdict)
        return verdict, result

    async def verify_fprint(
        self,
        requested_finger: str,
        live_feedback: Callable[[dict], None] | None = None,
        *,
        projection: t2_fprint_runtime.RuntimeProjection | None = None,
    ) -> tuple[str, dict]:
        """Validate presentation once per request; the probe resolves authority.

        VerifyStart supplies the caller's request-local presentation. This is not an
        authentication cache: native matching still reconciles live identities
        and authorizes the current user under the hardware operation lock.
        Standalone callers collect their own fresh projection.
        """
        async with self.operation_lock:
            # Pin authority once for this verification; later loads reuse the
            # stat-token cache without skipping a fail-closed rebuild on change.
            self.runtime_authority()
            view = (
                projection if projection is not None
                else await self.runtime_projection()
            )
            try:
                request = t2_fprint_runtime.resolve_match(
                    view, requested_finger
                )
            except t2_fprint_runtime.FprintRuntimeError as error:
                raise RuntimeError("requested fprint identity is unavailable") from error
            return await self.verify(
                target_finger=None,
                resolve_any_finger=True,
                live_feedback=live_feedback,
            )

    async def _request_adaptive_sync(self) -> None:
        """Ask systemd to persist an adaptive update outside authentication."""

        process = await asyncio.create_subprocess_exec(
            "/usr/bin/systemctl",
            "start",
            "--no-block",
            "t2-touchid-adaptive-sync.service",
            start_new_session=True,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            _stdout, stderr = await self._bounded_communication(process)
        except asyncio.TimeoutError:
            raise RuntimeError("adaptive Catacomb sync request timed out")
        if process.returncode != 0:
            detail = stderr.decode(errors="replace").strip()
            raise RuntimeError(detail or "adaptive Catacomb sync request failed")

    @staticmethod
    def _consume_adaptive_sync_task(task: asyncio.Task) -> None:
        try:
            task.result()
        except BaseException as error:
            print(f"Adaptive Catacomb sync request failed: {error}", flush=True)

    def schedule_adaptive_sync(self) -> None:
        """Coalesce a best-effort post-verdict persistence request."""

        if not self.auto_sync_adaptive:
            return
        task = asyncio.create_task(self._request_adaptive_sync())
        self.adaptive_sync_tasks.add(task)
        task.add_done_callback(self.adaptive_sync_tasks.discard)
        task.add_done_callback(self._consume_adaptive_sync_task)

    def schedule_feedback(self, verdict: str) -> None:
        """Keep bounded desktop audio outside the authentication critical path."""
        if not hasattr(self, "feedback_tasks"):
            self.feedback_tasks = set()
        coroutine = (
            self.notify_finger_requested() if verdict == "ready"
            else self.notify_feedback(verdict)
        )
        task = asyncio.create_task(coroutine)
        self.feedback_tasks.add(task)
        def finished(completed):
            self.feedback_tasks.discard(completed)
            if not completed.cancelled():
                completed.exception()  # Best-effort feedback cannot fail auth.
        task.add_done_callback(finished)

    async def notify_feedback(self, verdict: str) -> None:
        unit = (
            "t2-touchid-success.service"
            if verdict == "verify-match"
            else "t2-touchid-failure.service"
        )
        await self.start_user_unit(unit)

    async def notify_finger_requested(self) -> None:
        """Play the user's requested audible cue without making it auth-critical."""
        if os.geteuid() == 0:
            await self.start_user_unit("t2-touchid-alert.service")
            return
        else:
            command = [
                "/usr/bin/canberra-gtk-play",
                "--id=message-new-instant",
                "--description=Touch ID finger requested",
            ]
        env = os.environ.copy()
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                start_new_session=True,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
            _stdout, stderr = await self._bounded_communication(process)
            if process.returncode != 0:
                print(
                    "Touch ID alert failed:",
                    stderr.decode(errors="replace").strip(),
                    flush=True,
                )
        except (FileNotFoundError, asyncio.TimeoutError):
            pass

    async def start_user_unit(self, unit: str) -> None:
        command = desktop_user_unit_command(unit)
        if command is None:
            return
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                start_new_session=True,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            _stdout, stderr = await self._bounded_communication(process)
            if process.returncode != 0:
                print(
                    f"Touch ID desktop unit {unit} failed:",
                    stderr.decode(errors="replace").strip(),
                    flush=True,
                )
        except (FileNotFoundError, asyncio.TimeoutError):
            pass

    async def cancel(self, *, owner=None) -> None:
        process = self.process
        if (
            process is None
            or process.returncode is not None
            or (owner is not None and getattr(self, "process_owner", None) is not owner)
        ):
            return
        try:
            process.terminate()
        except ProcessLookupError:
            pass
        if process is getattr(self, "native_worker", None):
            # SIGTERM is a per-request cooperative cancel. The owning task
            # drains the terminal response, consumes this worker, and starts a
            # fresh imported replacement.
            return
        try:
            await asyncio.wait_for(process.wait(), timeout=10)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()


class FprintDevice(ServiceInterface):
    def __init__(
        self,
        backend: T2Backend,
        identity_bus,
        caller_collector=t2_dbus_identity.collect,
        claim_evidence_collector=t2_fprint_claim.collect,
        enrollment_client=None,
        deletion_client=None,
    ) -> None:
        super().__init__("net.reactivated.Fprint.Device")
        self.backend = backend
        self.identity_bus = identity_bus
        self.caller_collector = caller_collector
        self.claim_evidence_collector = claim_evidence_collector
        self.enrollment_client = enrollment_client
        self.deletion_client = deletion_client
        self.claim_lock = asyncio.Lock()
        self.claimed_user: str | None = None
        self.claimed_sender: str | None = None
        self.claimed_caller: t2_dbus_identity.PinnedDBusCaller | None = None
        self.claimed_evidence: t2_fprint_claim.ClaimEvidence | None = None
        self.claim_generation = 0
        self.verify_task: asyncio.Task | None = None
        self.verify_selection_sent = False
        self.listed_presentation = None
        self.delete_task: asyncio.Task | None = None
        self.claim_expiry_task: asyncio.Task | None = None
        self.enrolled_fingers: tuple[str, ...] = ()
        self.finger_present = False
        self.finger_needed = False
        self.enrollment_progress: int | None = None
        self.sender_departed_tasks: set[asyncio.Task] = set()
        self._method_rate: dict[str, list[float]] = {}

    def _rate_limit_sender(self, sender: str) -> None:
        now = time.monotonic()
        window = METHOD_RATE_WINDOW_SECONDS
        rates = getattr(self, "_method_rate", None)
        if rates is None:
            rates = {}
            self._method_rate = rates
        stamps = [stamp for stamp in rates.get(sender, []) if now - stamp < window]
        if len(stamps) >= METHOD_RATE_LIMIT:
            raise DBusError(
                f"{FPRINT_ERROR}.AlreadyInUse",
                "device is busy",
            )
        stamps.append(now)
        rates[sender] = stamps
        if len(rates) > METHOD_RATE_MAX_SENDERS:
            expired = [
                name
                for name, seen in rates.items()
                if name != sender and not any(now - stamp < window for stamp in seen)
            ]
            for name in expired:
                rates.pop(name, None)

    def _emit_claimed(self, member: str, signature: str, body: list) -> None:
        hook = self.__dict__.get(member)
        if callable(hook):
            hook(*body)
            return
        dest = self.claimed_sender
        bus = self.identity_bus
        if dest is None or bus is None or not callable(getattr(bus, "send", None)):
            hook = getattr(type(self), member, None)
            if callable(hook):
                hook(self, *body)
            return
        self._consume_signal_send(
            bus.send(
                Message(
                    destination=dest,
                    path=DEVICE_PATH,
                    interface="net.reactivated.Fprint.Device",
                    member=member,
                    message_type=MessageType.SIGNAL,
                    signature=signature,
                    body=body,
                )
            )
        )

    @staticmethod
    def _consume_signal_send(result: object) -> None:
        if not isinstance(result, asyncio.Future):
            return

        def consume(future: asyncio.Future) -> None:
            try:
                future.exception()
            except BaseException:
                pass

        result.add_done_callback(consume)

    def _set_finger_state(
        self,
        present: object,
        needed: object,
        progress: object = UNSET_ENROLLMENT_PROGRESS,
    ) -> None:
        """Update and publish fprintd's historical dynamic properties."""

        if (
            type(present) is not bool
            or type(needed) is not bool
            or (present and needed)
            or (
                progress is not UNSET_ENROLLMENT_PROGRESS
                and progress is not None
                and (
                    type(progress) is not int
                    or not 0 <= progress <= 100
                )
            )
        ):
            raise RuntimeError("finger property state is invalid")
        changed: dict[str, Variant] = {}
        if present != self.finger_present:
            self.finger_present = present
            changed["finger-present"] = Variant("b", present)
        if needed != self.finger_needed:
            self.finger_needed = needed
            changed["finger-needed"] = Variant("b", needed)
        if (
            progress is not UNSET_ENROLLMENT_PROGRESS
            and progress != self.enrollment_progress
        ):
            self.enrollment_progress = progress
            changed["t2-enroll-progress"] = Variant(
                "i", -1 if progress is None else progress
            )
        if not changed:
            return
        send = getattr(self.identity_bus, "send", None)
        if not callable(send):
            return
        try:
            message = Message.new_signal(
                path=DEVICE_PATH,
                interface="org.freedesktop.DBus.Properties",
                member="PropertiesChanged",
                signature="sa{sv}as",
                body=[
                    "net.reactivated.Fprint.Device",
                    changed,
                    [],
                ],
            )
            destination = self.claimed_sender
            if type(destination) is str and destination.startswith(":"):
                message.destination = destination
            result = send(message)
        except Exception:
            # The D-Bus connection itself owns delivery failure. Never turn a
            # best-effort UI property notification into a biometric replay.
            return
        self._consume_signal_send(result)

    @dbus_property(access=PropertyAccess.READ, name="name")
    def device_name(self) -> "s":
        return "Apple T2 Touch ID"

    @method()
    async def Claim(self, username: "s"):
        requested = username or LINUX_USER
        if requested not in ALLOWED_PAM_USERS:
            raise DBusError(f"{FPRINT_ERROR}.PermissionDenied", "unknown user")
        try:
            sender = current_dbus_sender()
        except DBusSenderError as error:
            raise DBusError(
                f"{FPRINT_ERROR}.PermissionDenied", "caller identity unavailable"
            ) from error
        self._rate_limit_sender(sender)
        async with self.claim_lock:
            if self.claimed_user is not None:
                # NameOwnerChanged delivery can trail a short-lived PAM
                # client's replacement by a few milliseconds.  The pinned
                # process identity is stronger evidence than D-Bus signal
                # ordering: reap only a claim whose exact process is already
                # provably gone.  A live owner remains strictly exclusive.
                old_caller = self.claimed_caller
                old_caller_dead = False
                if old_caller is not None:
                    try:
                        old_caller.verify()
                    except t2_dbus_identity.DBusIdentityError:
                        old_caller_dead = True
                if old_caller_dead:
                    await self._stop_verification(require_running=False)
                    await self._stop_enrollment(require_running=False)
                    await self._wait_deletion(require_running=False)
                    self._clear_claim()
                else:
                    raise DBusError(
                        f"{FPRINT_ERROR}.AlreadyInUse", "device is claimed"
                    )
            caller = None
            claim_phase = "identity-collection"
            try:
                caller = await self.caller_collector(
                    self.identity_bus, sender
                )
                claim_phase = "sender-recheck"
                if current_dbus_sender() != sender or caller.sender != sender:
                    raise t2_dbus_identity.DBusIdentityError(
                        "D-Bus caller changed during claim"
                    )
                claim_phase = "identity-recheck"
                caller.verify()
                claim_phase = "claim-evidence"
                evidence = await asyncio.to_thread(
                    self.claim_evidence_collector, caller, requested
                )
                claim_phase = "evidence-type"
                if not isinstance(evidence, t2_fprint_claim.ClaimEvidence):
                    raise t2_fprint_claim.FprintClaimError(
                        "claim evidence collector returned an invalid result"
                    )
                claim_phase = "sender-final-recheck"
                if current_dbus_sender() != sender or caller.sender != sender:
                    raise t2_dbus_identity.DBusIdentityError(
                        "D-Bus caller changed during claim evidence collection"
                    )
                claim_phase = "identity-final-recheck"
                caller.verify()
            except (
                DBusSenderError,
                t2_dbus_identity.DBusIdentityError,
                t2_fprint_claim.FprintClaimError,
            ) as error:
                if caller is not None:
                    caller.close()
                print(
                    f"T2 fprint claim rejected during {claim_phase}: "
                    f"{public_verification_failure(error)}",
                    flush=True,
                )
                raise DBusError(
                    f"{FPRINT_ERROR}.PermissionDenied",
                    "caller process identity unavailable",
                ) from error
            self.claimed_user = requested
            self.claimed_sender = sender
            self.claimed_caller = caller
            self.claimed_evidence = evidence
            self.claim_generation += 1
            self.claim_expiry_task = asyncio.create_task(
                self._expire_unstarted_claim()
            )

    def _clear_claim(self) -> None:
        self.listed_presentation = None
        caller = self.claimed_caller
        self.claimed_user = None
        self.claimed_sender = None
        self.claimed_caller = None
        self.claimed_evidence = None
        self.claim_generation += 1
        if caller is not None:
            caller.close()

    async def _require_claim_owner(self) -> None:
        if (
            self.claimed_user is None
            or self.claimed_sender is None
            or self.claimed_caller is None
            or self.claimed_evidence is None
        ):
            raise DBusError(
                f"{FPRINT_ERROR}.ClaimDevice", "device is not claimed"
            )
        try:
            sender = current_dbus_sender()
        except DBusSenderError as error:
            raise DBusError(
                f"{FPRINT_ERROR}.PermissionDenied", "caller identity unavailable"
            ) from error
        owner_sender = self.claimed_sender
        owner_caller = self.claimed_caller
        owner_evidence = self.claimed_evidence
        owner_generation = self.claim_generation
        if sender != owner_sender:
            raise DBusError(
                f"{FPRINT_ERROR}.PermissionDenied",
                "device is claimed by another D-Bus connection",
            )
        try:
            if owner_caller.sender != sender:
                raise t2_dbus_identity.DBusIdentityError(
                    "pinned sender does not match the claim"
                )
            owner_caller.verify()
            await asyncio.to_thread(owner_evidence.revalidate, owner_caller)
        except (
            t2_dbus_identity.DBusIdentityError,
            t2_fprint_claim.FprintClaimError,
        ) as error:
            raise DBusError(
                f"{FPRINT_ERROR}.PermissionDenied",
                "caller process identity is no longer valid",
            ) from error
        if (
            self.claimed_sender is not owner_sender
            or self.claimed_caller is not owner_caller
            or self.claimed_evidence is not owner_evidence
            or self.claim_generation != owner_generation
        ):
            raise DBusError(
                f"{FPRINT_ERROR}.PermissionDenied",
                "device is claimed by another D-Bus connection",
            )
        try:
            if current_dbus_sender() != owner_sender:
                raise DBusError(
                    f"{FPRINT_ERROR}.PermissionDenied",
                    "device is claimed by another D-Bus connection",
                )
            owner_caller.verify()
        except DBusSenderError as error:
            raise DBusError(
                f"{FPRINT_ERROR}.PermissionDenied", "caller identity unavailable"
            ) from error
        except t2_dbus_identity.DBusIdentityError as error:
            raise DBusError(
                f"{FPRINT_ERROR}.PermissionDenied",
                "caller process identity is no longer valid",
            ) from error

    @method()
    async def Release(self):
        await self._require_claim_owner()
        await self._stop_verification(require_running=False)
        await self._stop_enrollment(require_running=False)
        await self._wait_deletion(require_running=False)
        self._clear_claim()

    @method()
    async def ListEnrolledFingers(self, username: "s") -> "as":
        self.listed_presentation = None
        try:
            self._rate_limit_sender(current_dbus_sender())
        except DBusSenderError as error:
            raise DBusError(
                f"{FPRINT_ERROR}.PermissionDenied", "caller identity unavailable"
            ) from error
        requested = username or LINUX_USER
        if requested not in ALLOWED_PAM_USERS:
            raise DBusError(f"{FPRINT_ERROR}.PermissionDenied", "unknown user")
        try:
            self.enrolled_fingers = await self.backend.list_fingers()
        except asyncio.CancelledError:
            raise cancelled_method_error(
                "Internal", "fingerprint inventory unavailable"
            ) from None
        except Exception as error:
            raise DBusError(
                f"{FPRINT_ERROR}.Internal", "fingerprint inventory unavailable"
            ) from error
        if not self.enrolled_fingers:
            raise DBusError(
                f"{FPRINT_ERROR}.NoEnrolledPrints",
                "no fingerprints are enrolled",
            )
        # Reuse this caller's presentation list once in its next VerifyStart.
        # This never replaces the native match's live authority/reconciliation.
        self.listed_presentation = (current_dbus_sender(), self.enrolled_fingers)
        return list(self.enrolled_fingers)

    @method()
    async def VerifyStart(self, finger_name: "s"):
        await self._require_claim_owner()
        if (
            self.verify_task is not None
            or (
                self.enrollment_client is not None
                and getattr(self.enrollment_client, "task", None) is not None
            )
            or self.delete_task is not None
        ):
            raise DBusError(f"{FPRINT_ERROR}.AlreadyInUse", "verification is active")
        if (
            finger_name != "any"
            and not t2_fprint_projection.is_finger_name(finger_name)
        ):
            raise DBusError(
                f"{FPRINT_ERROR}.InvalidFingername",
                "verification requires any or an enrolled numbered handle",
            )
        if self.claim_expiry_task is not None:
            self.claim_expiry_task.cancel()
            self.claim_expiry_task = None
        current_task = asyncio.current_task()
        if current_task is None:
            raise DBusError(
                f"{FPRINT_ERROR}.Internal",
                "verification task identity is unavailable",
            )
        self.verify_task = current_task
        started = False
        try:
            listed = self.listed_presentation
            self.listed_presentation = None
            if listed is not None and listed[0] == self.claimed_sender:
                names = tuple(listed[1])
                view = t2_fprint_runtime.RuntimeProjection(names, len(names), True)
            else:
                async with self.backend.operation_lock:
                    view = await self.backend.runtime_projection()
            await self._require_claim_owner()
            if self.verify_task is not current_task:
                raise RuntimeError("verification task binding changed")
            if (
                self.delete_task is not None
                or (
                    self.enrollment_client is not None
                    and getattr(self.enrollment_client, "task", None) is not None
                )
            ):
                raise DBusError(
                    f"{FPRINT_ERROR}.AlreadyInUse",
                    "a biometric operation is active",
                )
            if not isinstance(view, t2_fprint_runtime.RuntimeProjection):
                raise RuntimeError(
                    "fprint projection returned an invalid result"
                )
            self.enrolled_fingers = view.listed_fingers
            try:
                t2_fprint_runtime.resolve_match(view, finger_name)
            except t2_fprint_runtime.FprintRuntimeError as error:
                raise DBusError(
                    f"{FPRINT_ERROR}.NoEnrolledPrints",
                    "finger is not enrolled",
                ) from error
            operation = asyncio.create_task(
                self._run_verification(finger_name, view)
            )
            self.verify_task = operation
            self.verify_selection_sent = False
            # VerifyStart only schedules the backend. Native activation still
            # runs before Mesa accepts a touch, so publishing finger-needed
            # here hands the operator a false-ready prompt.
            # The match_armed event is the first authoritative boundary.
            self._set_finger_state(False, False)
            started = True
        except DBusError:
            raise
        except asyncio.CancelledError:
            raise cancelled_method_error(
                "NoActionInProgress", "verification was cancelled"
            ) from None
        except Exception as error:
            raise DBusError(
                f"{FPRINT_ERROR}.Internal",
                "verification could not be started",
            ) from error
        finally:
            if not started and self.verify_task is current_task:
                self.verify_task = None
            self._arm_unstarted_claim_expiry()

    @method()
    async def VerifyStop(self):
        await self._require_claim_owner()
        try:
            await self._stop_verification(require_running=True)
        finally:
            self._arm_unstarted_claim_expiry(replace=True)

    async def _run_verification(
        self, requested_finger: str, projection: t2_fprint_runtime.RuntimeProjection
    ) -> None:
        current_task = asyncio.current_task()
        try:
            # dbus-next sends an async method's reply from the completed
            # VerifyStart task. Yield once from this separately scheduled task
            # so that reply is queued before VerifyFingerSelected, matching
            # upstream fprintd's ordering contract. pam_fprintd 1.94.5 rejects
            # this signal while its VerifyStart reply is still outstanding.
            # "any" is intentional: every enrolled identity is valid for
            # authentication, regardless of which numbered handle a client
            # supplied, and the exact match is reported only after capture.
            await asyncio.sleep(0)
            verdict, result = await self.backend.verify_fprint(
                requested_finger, self._live_verify_event, projection=projection
            )
            # The touch wait can be unbounded. Account/session/process
            # evidence collected before it is not authority to publish now.
            await self._require_claim_owner()
            if verdict == "verify-match":
                selected = resolved_any_finger_from_result(result)
                if selected is None:
                    raise RuntimeError("matched any-finger result has no identity")
                self._emit_claimed("VerifyFingerMatched", "s", [selected])
            self._emit_claimed("VerifyStatus", "sb", [verdict, True])
            if verdict == "verify-match":
                # Authentication is already terminal. Persistence is a
                # separately journaled best-effort operation and can neither
                # delay nor replace the emitted verdict.
                try:
                    self.backend.schedule_adaptive_sync()
                except Exception as error:
                    print(
                        f"Adaptive Catacomb sync scheduling failed: {error}",
                        flush=True,
                    )
        except asyncio.CancelledError:
            raise
        except Exception as error:
            print(
                "T2 verification failed: "
                f"{public_verification_failure(error)}",
                flush=True,
            )
            self.backend.schedule_feedback("verify-unknown-error")
            self._emit_claimed("VerifyStatus", "sb", ["verify-unknown-error", True])
        finally:
            self._set_finger_state(False, False)
        # Keep the completed task as the active transaction until the client
        # calls VerifyStop (or Release).  pam_fprintd follows that lifecycle;
        # clearing it here would make its mandatory VerifyStop fail with
        # NoActionInProgress immediately after a terminal VerifyStatus.
        self.claim_expiry_task = asyncio.create_task(
            self._expire_stale_claim(current_task)
        )

    def _live_verify_event(self, event: dict) -> None:
        """Expose only nonterminal placement feedback from an untrusted stream."""
        if event.get("event_kind") == "match_armed":
            # PAM's placement prompt must follow actual sensor readiness,
            # not merely scheduling activation and transport setup.
            if not self.verify_selection_sent:
                self.verify_selection_sent = True
                self._emit_claimed("VerifyFingerSelected", "s", ["any"])
            self._set_finger_state(False, True)
            return
        semantics = event.get("status_semantics")
        if semantics == "finger-present":
            self._set_finger_state(True, False)
            return
        if semantics == "finger-removed":
            self._set_finger_state(False, True)
            return
        if (
            event.get("event_kind") == "match_result"
            and event.get("result_valid") is True
            and event.get("no_match") is True
            and event.get("no_match_image_quality") is True
        ):
            self._set_finger_state(False, True)
            self._emit_claimed("VerifyStatus", "sb", ["verify-retry-scan", False])

    async def _expire_stale_claim(self, completed_task: asyncio.Task) -> None:
        await asyncio.sleep(COMPLETED_CLAIM_SECONDS)
        if self.verify_task is completed_task:
            self.verify_task = None
            self._clear_claim()
        self.claim_expiry_task = None

    async def _expire_unstarted_claim(self) -> None:
        await asyncio.sleep(UNSTARTED_CLAIM_SECONDS)
        if (
            self.verify_task is None
            and (
                self.enrollment_client is None
                or getattr(self.enrollment_client, "task", None) is None
            )
            and self.delete_task is None
        ):
            self._clear_claim()
        self.claim_expiry_task = None

    async def sender_departed(self, sender: str) -> None:
        async with self.claim_lock:
            if sender != self.claimed_sender:
                return
            await self._stop_verification(require_running=False)
            await self._stop_enrollment(require_running=False)
            await self._wait_deletion(require_running=False)
            self._clear_claim()

    async def _stop_verification(self, require_running: bool) -> None:
        if require_running and self.verify_task is None:
            raise DBusError(
                f"{FPRINT_ERROR}.NoActionInProgress", "verification is not active"
            )
        expiry_task = self.claim_expiry_task
        if expiry_task is not None:
            expiry_task.cancel()
            self.claim_expiry_task = None
        task = self.verify_task
        if task is None:
            self._set_finger_state(False, False)
            return
        # Suppress result publication before any shutdown await. A queued
        # verification must not cancel another task's inventory subprocess.
        task.cancel()
        await self.backend.cancel(owner=task)
        await asyncio.gather(task, return_exceptions=True)
        if self.verify_task is task:
            self.verify_task = None
        self._set_finger_state(False, False)

    def _arm_unstarted_claim_expiry(self, *, replace: bool = False) -> None:
        """Restore bounded claim lifetime after a mutation call returns."""

        client = self.enrollment_client
        if (
            self.claimed_user is not None
            and (self.claim_expiry_task is None or replace)
            and self.verify_task is None
            and self.delete_task is None
            and (
                client is None
                or getattr(client, "task", None) is None
            )
        ):
            # A worker may emit its terminal update while Stop awaits cleanup.
            # Replace that completed-operation timer with an idle claim timer.
            if self.claim_expiry_task is not None:
                self.claim_expiry_task.cancel()
            self.claim_expiry_task = asyncio.create_task(
                self._expire_unstarted_claim()
            )

    @method()
    async def EnrollStart(self, finger_name: "s"):
        self.listed_presentation = None
        await self._require_claim_owner()
        self.backend.invalidate_inventory("enrollment_start")
        client = self.enrollment_client
        if client is None:
            raise DBusError(
                f"{FPRINT_ERROR}.Internal", "native enrollment is disabled"
            )
        if (
            self.verify_task is not None
            or getattr(client, "task", None) is not None
            or self.delete_task is not None
        ):
            raise DBusError(
                f"{FPRINT_ERROR}.AlreadyInUse", "a biometric operation is active"
            )
        if not t2_fprint_identity.is_enrollment_request(finger_name):
            raise DBusError(
                f"{FPRINT_ERROR}.InvalidFingername",
                "enrollment requires a neutral request or supported legacy client",
            )
        if self.claim_expiry_task is not None:
            self.claim_expiry_task.cancel()
            self.claim_expiry_task = None
        try:
            # A stock fprintd client may supply one of its historical anatomy
            # tokens.  It is only request syntax.  The authorized worker owns
            # the lowest vacant stable slot after it has reconciled the exact
            # current identity inventory. Retained slots are never renumbered.
            async with self.backend.operation_lock:
                view = await self.backend.enrollment_projection(fresh=True)
            await self._require_claim_owner()
            if (
                self.verify_task is not None
                or getattr(client, "task", None) is not None
                or self.delete_task is not None
            ):
                raise DBusError(
                    f"{FPRINT_ERROR}.AlreadyInUse",
                    "a biometric operation is active",
                )
            if not isinstance(view, t2_fprint_runtime.RuntimeProjection):
                raise RuntimeError("fprint projection returned an invalid result")
            if not view.complete:
                raise DBusError(
                    f"{FPRINT_ERROR}.Internal",
                    "existing fingerprint labels require migration",
                )
            self._set_finger_state(False, False, None)
            client.start(
                # Legacy anatomy tokens are syntax only. The worker protocol
                # accepts neutral handles and independently allocates a slot.
                (
                    finger_name
                    if t2_fprint_identity.is_handle(finger_name)
                    else "finger-1"
                ),
                self.claimed_caller,
                self.claimed_evidence,
                self._enrollment_update,
            )
        except DBusError:
            raise
        except asyncio.CancelledError:
            self._set_finger_state(False, False)
            raise cancelled_method_error(
                "NoActionInProgress", "enrollment was cancelled"
            ) from None
        except Exception as error:
            self._set_finger_state(False, False)
            raise DBusError(
                f"{FPRINT_ERROR}.Internal",
                "native enrollment could not be started",
            ) from error
        finally:
            # This also covers coroutine cancellation while collecting the
            # projection; a failed D-Bus call must not leave an immortal claim.
            self._arm_unstarted_claim_expiry()

    @method()
    async def EnrollStop(self):
        await self._require_claim_owner()
        try:
            await self._stop_enrollment(require_running=True)
        finally:
            self._arm_unstarted_claim_expiry(replace=True)

    def _enrollment_update(self, update: object) -> None:
        if not isinstance(
            update, t2_fprint_enrollment_runtime.EnrollmentUpdate
        ):
            raise RuntimeError("enrollment worker emitted malformed state")
        self._set_finger_state(
            update.finger_present,
            update.finger_needed,
            update.progress_percent,
        )
        if update.status is not None:
            self.EnrollStatus(update.status, update.done)
        if update.done:
            self.backend.invalidate_inventory("enrollment_complete")
            client = self.enrollment_client
            task = getattr(client, "task", None) if client is not None else None
            if task is None:
                raise RuntimeError("terminal enrollment has no retained task")
            self.claim_expiry_task = asyncio.create_task(
                self._expire_stale_enrollment_claim(task)
            )

    async def _expire_stale_enrollment_claim(self, completed_task) -> None:
        timer = asyncio.current_task()
        try:
            await asyncio.sleep(COMPLETED_CLAIM_SECONDS)
            client = self.enrollment_client
            if client is not None and getattr(client, "task", None) is completed_task:
                try:
                    await client.stop()
                except Exception:
                    pass
                # Cancellation must preserve a still-running worker's claim.
                # A replaced timer must never clear its successor's claim.
                if (
                    self.claim_expiry_task is timer
                    and getattr(client, "task", None) is None
                ):
                    self._set_finger_state(False, False, None)
                    self._clear_claim()
        finally:
            if self.claim_expiry_task is timer:
                self.claim_expiry_task = None

    async def _stop_enrollment(self, require_running: bool) -> None:
        client = self.enrollment_client
        if require_running and (client is None or getattr(client, "task", None) is None):
            raise DBusError(
                f"{FPRINT_ERROR}.NoActionInProgress", "enrollment is not active"
            )
        expiry_task = self.claim_expiry_task
        if expiry_task is not None:
            expiry_task.cancel()
            self.claim_expiry_task = None
        client = self.enrollment_client
        task = getattr(client, "task", None) if client is not None else None
        if task is None:
            self._set_finger_state(False, False, None)
            return
        try:
            await client.stop()
        except Exception as error:
            if require_running:
                raise DBusError(
                    f"{FPRINT_ERROR}.Internal",
                    "native enrollment did not stop cleanly",
                ) from error
        finally:
            self._set_finger_state(False, False, None)

    async def _wait_deletion(self, require_running: bool) -> None:
        task = self.delete_task
        if task is None:
            if require_running:
                raise DBusError(
                    f"{FPRINT_ERROR}.NoActionInProgress",
                    "deletion is not active",
                )
            return
        if task is asyncio.current_task():
            raise RuntimeError("deletion task cannot wait for itself")
        await asyncio.gather(asyncio.shield(task), return_exceptions=True)
        expiry_task = self.claim_expiry_task
        if expiry_task is not None:
            expiry_task.cancel()
            self.claim_expiry_task = None

    @method()
    def DeleteEnrolledFingers(self, username: "s"):
        raise DBusError(f"{FPRINT_ERROR}.PermissionDenied", "delete in macOS")

    @method()
    async def DeleteEnrolledFingers2(self):
        await self._require_claim_owner()
        raise DBusError(f"{FPRINT_ERROR}.PermissionDenied", "delete in macOS")

    @method()
    async def DeleteEnrolledFinger(self, finger_name: "s"):
        self.listed_presentation = None
        await self._require_claim_owner()
        self.backend.invalidate_inventory("deletion_start")
        client = self.deletion_client
        if client is None:
            raise DBusError(
                f"{FPRINT_ERROR}.PermissionDenied",
                "native single-finger deletion is disabled",
            )
        if not t2_fprint_projection.is_finger_name(finger_name):
            raise DBusError(
                f"{FPRINT_ERROR}.InvalidFingername",
                "deletion requires an enrolled numbered handle",
            )
        if (
            self.verify_task is not None
            or (
                self.enrollment_client is not None
                and getattr(self.enrollment_client, "task", None) is not None
            )
            or self.delete_task is not None
        ):
            raise DBusError(
                f"{FPRINT_ERROR}.AlreadyInUse",
                "a biometric operation is active",
            )
        if self.claim_expiry_task is not None:
            self.claim_expiry_task.cancel()
            self.claim_expiry_task = None
        current_task = asyncio.current_task()
        if current_task is None:
            raise DBusError(
                f"{FPRINT_ERROR}.PrintsNotDeleted",
                "deletion task identity is unavailable",
            )
        self.delete_task = current_task
        try:
            async with self.backend.operation_lock:
                view = await self.backend.runtime_projection(fresh=True)
            await self._require_claim_owner()
            if self.delete_task is not current_task:
                raise RuntimeError("deletion task binding changed")
            if self.verify_task is not None or (
                self.enrollment_client is not None
                and getattr(self.enrollment_client, "task", None) is not None
            ):
                raise DBusError(
                    f"{FPRINT_ERROR}.AlreadyInUse",
                    "a biometric operation is active",
                )
            if not isinstance(view, t2_fprint_runtime.RuntimeProjection):
                raise RuntimeError("fprint projection returned an invalid result")
            if not view.complete:
                raise DBusError(
                    f"{FPRINT_ERROR}.PrintsNotDeleted",
                    "existing fingerprint labels require migration",
                )
            if finger_name not in view.finger_names:
                raise DBusError(
                    f"{FPRINT_ERROR}.NoEnrolledPrints",
                    "finger is not enrolled",
                )
            operation = asyncio.create_task(
                client.delete(
                    finger_name,
                    self.claimed_caller,
                    self.claimed_evidence,
                )
            )
            try:
                result = await asyncio.shield(operation)
            except asyncio.CancelledError:
                # Once the injected client has accepted the request, caller
                # cancellation cannot kill or replay a possibly dispatched
                # delete. Wait for its journaled reconciliation boundary.
                while not operation.done():
                    try:
                        await asyncio.shield(operation)
                    except asyncio.CancelledError:
                        continue
                    except Exception:
                        break
                await asyncio.gather(operation, return_exceptions=True)
                raise
            if (
                type(result)
                is not t2_fprint_deletion_runtime.DeletionCompletion
                or result.finger_name != finger_name
            ):
                raise RuntimeError("deletion client returned an invalid result")
        except DBusError:
            raise
        except asyncio.CancelledError:
            raise cancelled_method_error(
                "PrintsNotDeleted", "deletion was cancelled"
            ) from None
        except Exception as error:
            raise DBusError(
                f"{FPRINT_ERROR}.PrintsNotDeleted",
                "single-finger deletion did not reconcile",
            ) from error
        finally:
            self.backend.invalidate_inventory("deletion_complete")
            if self.delete_task is current_task:
                self.delete_task = None
            self._arm_unstarted_claim_expiry()

    @signal()
    def VerifyFingerSelected(self, finger_name: "s") -> "s":
        return finger_name

    @signal()
    def VerifyFingerMatched(self, finger_name: "s") -> "s":
        return finger_name

    @signal()
    def VerifyStatus(self, result: "s", done: "b") -> "sb":
        return [result, done]

    @signal()
    def EnrollStatus(self, result: "s", done: "b") -> "sb":
        return [result, done]


class FprintManager(ServiceInterface):
    def __init__(self) -> None:
        super().__init__("net.reactivated.Fprint.Manager")

    @method()
    def GetDevices(self) -> "ao":
        return [DEVICE_PATH]

    @method()
    def GetDefaultDevice(self) -> "o":
        return DEVICE_PATH


def enrollment_client_for_arguments(args: argparse.Namespace):
    """Construct no mutation client unless the process flag is exactly set."""

    if not isinstance(args, argparse.Namespace):
        raise RuntimeError("fprintd arguments are invalid")
    enabled = getattr(args, "enable_native_enrollment", None)
    if type(enabled) is not bool:
        raise RuntimeError("native enrollment activation is invalid")
    return (
        t2_fprint_worker_client.EnrollmentWorkerClient()
        if enabled
        else None
    )


def deletion_client_for_arguments(args: argparse.Namespace):
    """Construct no deletion worker client unless its flag is exactly set."""

    if not isinstance(args, argparse.Namespace):
        raise RuntimeError("fprintd arguments are invalid")
    enabled = getattr(args, "enable_native_deletion", None)
    if type(enabled) is not bool:
        raise RuntimeError("native deletion activation is invalid")
    return (
        t2_fprint_delete_worker_client.DeletionWorkerClient()
        if enabled
        else None
    )


def legacy_property_reply(message: Message, device: FprintDevice):
    """Serve fprint's historical hyphenated property names."""
    if (
        not isinstance(message, Message)
        or not isinstance(device, FprintDevice)
        or message.message_type != MessageType.METHOD_CALL
        or message.path != DEVICE_PATH
        or message.interface != "org.freedesktop.DBus.Properties"
    ):
        return False
    values = {
        "name": Variant("s", "Apple T2 Touch ID"),
        "num-enroll-stages": Variant("i", -1),
        "scan-type": Variant("s", "press"),
        "finger-present": Variant("b", device.finger_present),
        "finger-needed": Variant("b", device.finger_needed),
        "t2-enroll-progress": Variant(
            "i",
            -1
            if device.enrollment_progress is None
            else device.enrollment_progress,
        ),
    }
    if (
        message.member == "Get"
        and message.body
        and message.body[0] == "net.reactivated.Fprint.Device"
        and len(message.body) == 2
        and message.body[1] in values
    ):
        return Message.new_method_return(
            message, signature="v", body=[values[message.body[1]]]
        )
    if (
        message.member == "GetAll"
        and message.body == ["net.reactivated.Fprint.Device"]
    ):
        return Message.new_method_return(
            message, signature="a{sv}", body=[values]
        )
    return False


def legacy_introspection_reply(message: Message, device: FprintDevice):
    """Advertise the same historical properties served by the raw handler."""

    if (
        not isinstance(message, Message)
        or not isinstance(device, FprintDevice)
        or message.message_type != MessageType.METHOD_CALL
        or message.path != DEVICE_PATH
        or message.interface != "org.freedesktop.DBus.Introspectable"
        or message.member != "Introspect"
        or message.body
        or str(message.signature)
    ):
        return False
    node = dbus_introspection.Node.default(DEVICE_PATH)
    node.interfaces.append(device.introspect())
    document = node.tostring()
    closing = document.rfind("</interface>")
    if closing < 0:
        raise RuntimeError("fprint introspection has no device interface")
    # dbus-next correctly rejects hyphens as D-Bus member names, while
    # fprintd's long-standing property ABI nevertheless uses them. The raw
    # Get/GetAll handler already serves these exact names; inject only their
    # XML declarations into the final exported interface.
    declarations = "".join(
        f'    <property name="{name}" type="{signature}" access="read" />\n'
        for name, signature in (
            ("num-enroll-stages", "i"),
            ("scan-type", "s"),
            ("finger-present", "b"),
            ("finger-needed", "b"),
            ("t2-enroll-progress", "i"),
        )
    )
    document = document[:closing] + declarations + document[closing:]
    return Message.new_method_return(
        message, signature="s", body=[document]
    )


async def main_async(args: argparse.Namespace) -> None:
    project_dir = Path(
        os.environ.get(
            "T2_TOUCHID_PROJECT_DIR", Path(__file__).resolve().parent.parent
        )
    )
    backend = T2Backend(project_dir, args.match_seconds)
    bus = await SenderAwareMessageBus(
        bus_type=BusType.SYSTEM, negotiate_unix_fd=True
    ).connect()
    device = FprintDevice(
        backend,
        bus,
        enrollment_client=enrollment_client_for_arguments(args),
        deletion_client=deletion_client_for_arguments(args),
    )
    login1_owner: str | None = None
    login1_owner_generation = 0
    login1_signal_generation = 0
    pending_sleep_signal: tuple[str, bool] | None = None
    login1_reconcile_lock = asyncio.Lock()
    login1_reconcile_tasks: set[asyncio.Task] = set()
    login1_awake = asyncio.Event()

    def apply_sleep_state(sleeping: bool) -> None:
        nonlocal login1_signal_generation
        login1_signal_generation += 1
        backend.system_sleep_changed(sleeping)
        if sleeping:
            login1_awake.clear()
        else:
            login1_awake.set()

    async def reconcile_login1() -> None:
        """Bind current sleep state to one stable, authenticated owner."""

        nonlocal login1_owner, pending_sleep_signal
        async with login1_reconcile_lock:
            while True:
                generation = login1_owner_generation
                owner_reply = await bus.call(
                    Message(
                        destination="org.freedesktop.DBus",
                        path="/org/freedesktop/DBus",
                        interface="org.freedesktop.DBus",
                        member="GetNameOwner",
                        signature="s",
                        body=["org.freedesktop.login1"],
                    )
                )
                if generation != login1_owner_generation:
                    continue
                if (
                    not isinstance(owner_reply, Message)
                    or owner_reply.message_type != MessageType.METHOD_RETURN
                    or owner_reply.signature != "s"
                    or len(owner_reply.body) != 1
                    or not isinstance(owner_reply.body[0], str)
                    or not owner_reply.body[0].startswith(":")
                ):
                    raise RuntimeError("system sleep authority is unavailable")
                login1_owner = owner_reply.body[0]
                had_pending_signal = False
                if (
                    pending_sleep_signal is not None
                    and pending_sleep_signal[0] == login1_owner
                ):
                    _sender, sleeping = pending_sleep_signal
                    pending_sleep_signal = None
                    apply_sleep_state(sleeping)
                    had_pending_signal = True
                signal_generation = login1_signal_generation
                owner = login1_owner
                property_reply = await bus.call(
                    Message(
                        destination=owner,
                        path="/org/freedesktop/login1",
                        interface="org.freedesktop.DBus.Properties",
                        member="Get",
                        signature="ss",
                        body=[
                            "org.freedesktop.login1.Manager",
                            "PreparingForSleep",
                        ],
                    )
                )
                if (
                    generation != login1_owner_generation
                    or login1_owner != owner
                ):
                    continue
                variant = (
                    property_reply.body[0]
                    if isinstance(property_reply, Message)
                    and property_reply.message_type == MessageType.METHOD_RETURN
                    and property_reply.signature == "v"
                    and len(property_reply.body) == 1
                    else None
                )
                if (
                    getattr(variant, "signature", None) != "b"
                    or type(getattr(variant, "value", None)) is not bool
                ):
                    raise RuntimeError("system sleep state is unavailable")
                # A signal observed during owner discovery is newer evidence
                # than the initialization query and must survive that race.
                if (
                    not had_pending_signal
                    and signal_generation == login1_signal_generation
                ):
                    apply_sleep_state(variant.value)
                return

    def schedule_login1_reconciliation() -> None:
        task = asyncio.create_task(reconcile_login1())
        login1_reconcile_tasks.add(task)

        def completed(done: asyncio.Task) -> None:
            login1_reconcile_tasks.discard(done)
            try:
                done.result()
            except asyncio.CancelledError:
                pass
            except Exception as error:
                print(
                    "Touch ID sleep-state reconciliation failed: "
                    f"{public_verification_failure(error)}",
                    flush=True,
                )

        task.add_done_callback(completed)

    # fprintd's historical ABI contains hyphenated property names, although
    # D-Bus member-name validators (including dbus-next's) reject hyphens.
    # Intercept the compatibility property before dbus-next's property layer.
    def legacy_property_handler(message: Message):
        return legacy_property_reply(message, device)

    def sender_departure_handler(message: Message):
        nonlocal login1_owner, login1_owner_generation, pending_sleep_signal
        if (
            message.message_type == MessageType.SIGNAL
            and message.sender == "org.freedesktop.DBus"
            and message.path == "/org/freedesktop/DBus"
            and message.interface == "org.freedesktop.DBus"
            and message.member == "NameOwnerChanged"
            and len(message.body) == 3
        ):
            name, old_owner, new_owner = message.body
            if name == "org.freedesktop.login1":
                login1_owner_generation += 1
                login1_owner = (
                    new_owner
                    if isinstance(new_owner, str) and new_owner.startswith(":")
                    else None
                )
                if (
                    pending_sleep_signal is not None
                    and pending_sleep_signal[0] != login1_owner
                ):
                    pending_sleep_signal = None
                apply_sleep_state(True)
                if login1_owner is not None:
                    schedule_login1_reconciliation()
            if name == old_owner and not new_owner:
                departed = asyncio.create_task(device.sender_departed(name))
                tracked = getattr(device, "sender_departed_tasks", None)
                if tracked is None:
                    tracked = set()
                    device.sender_departed_tasks = tracked
                tracked.add(departed)

                def completed(done: asyncio.Task) -> None:
                    tracked.discard(done)
                    try:
                        done.result()
                    except asyncio.CancelledError:
                        pass
                    except Exception as error:
                        print(
                            "Touch ID sender-departure handling failed: "
                            f"{public_verification_failure(error)}",
                            flush=True,
                        )

                departed.add_done_callback(completed)
        return False

    def system_sleep_handler(message: Message):
        nonlocal pending_sleep_signal
        if (
            message.message_type == MessageType.SIGNAL
            and isinstance(message.sender, str)
            and message.sender.startswith(":")
            and message.path == "/org/freedesktop/login1"
            and message.interface == "org.freedesktop.login1.Manager"
            and message.member == "PrepareForSleep"
            and message.signature == "b"
            and len(message.body) == 1
            and type(message.body[0]) is bool
        ):
            if login1_owner is None:
                pending_sleep_signal = (message.sender, message.body[0])
            elif message.sender == login1_owner:
                apply_sleep_state(message.body[0])
        return False

    def legacy_introspection_handler(message: Message):
        return legacy_introspection_reply(message, device)

    bus.add_message_handler(legacy_introspection_handler)
    bus.add_message_handler(legacy_property_handler)
    bus.add_message_handler(sender_departure_handler)
    bus.add_message_handler(system_sleep_handler)
    # A low-level dbus-next service does not install proxy-client match rules.
    # A local handler alone cannot receive other connections' departures.
    match_rules = (
        "type='signal',sender='org.freedesktop.DBus',"
        "path='/org/freedesktop/DBus',interface='org.freedesktop.DBus',"
        "member='NameOwnerChanged'",
        "type='signal',sender='org.freedesktop.login1',"
        "path='/org/freedesktop/login1',"
        "interface='org.freedesktop.login1.Manager',member='PrepareForSleep'",
    )
    for rule in match_rules:
        subscribed = await bus.call(
            Message(
                destination="org.freedesktop.DBus",
                path="/org/freedesktop/DBus",
                interface="org.freedesktop.DBus",
                member="AddMatch",
                signature="s",
                body=[rule],
            )
        )
        if (
            not isinstance(subscribed, Message)
            or subscribed.message_type != MessageType.METHOD_RETURN
            or subscribed.signature != ""
            or subscribed.body != []
        ):
            raise RuntimeError("D-Bus lifecycle monitoring is unavailable")
    await reconcile_login1()
    while True:
        while backend.system_sleeping:
            await login1_awake.wait()
        warm = backend._schedule_runtime_warm()
        if warm is not None:
            try:
                await warm
            except asyncio.CancelledError:
                if backend.system_sleeping:
                    continue
                raise
        if not backend.system_sleeping:
            break
    bus.export(MANAGER_PATH, FprintManager())
    bus.export(DEVICE_PATH, device)
    await bus.request_name(BUS_NAME)
    await asyncio.get_running_loop().create_future()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--match-seconds",
        type=float,
        default=0.0,
        help=(
            "biometric observation deadline in seconds; 0 waits for a "
            f"verdict up to {int(MAX_MATCH_SECONDS)} seconds"
        ),
    )
    parser.add_argument(
        "--enable-native-enrollment",
        action="store_true",
        help=(
            "activate the credential-scoped journaled enrollment worker; "
            "omit until every installed hardware gate passes"
        ),
    )
    parser.add_argument(
        "--enable-native-deletion",
        action="store_true",
        help=(
            "activate the credential-free journaled single-delete worker; "
            "omit until every installed hardware gate passes"
        ),
    )
    args = parser.parse_args()
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
