# SPDX-License-Identifier: GPL-2.0-only
"""Dependency-free boundary regressions; no D-Bus, SEP, or system mutations.

Execute the actual source definitions in private namespaces. External account,
D-Bus and hardware collaborators are test doubles: these tests do not replace
installed-service integration tests. Nothing is injected into sys.modules.
"""
from __future__ import annotations

import argparse
import ast
import asyncio
import inspect
import json
import os
from pathlib import Path
import re
import signal
import stat
import sys
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import t2_fprint_result

SOURCE = Path(__file__).resolve().parents[1] / "src"


def definitions(filename, names, namespace):
    tree = ast.parse((SOURCE / filename).read_text(encoding="utf-8"))
    selected = [node for node in tree.body if getattr(node, "name", None) in names]
    found = {node.name for node in selected}
    missing = set(names) - found
    if missing:
        raise AssertionError(f"missing source definitions: {missing}")
    selected.insert(0, ast.ImportFrom(module="__future__", names=[
        ast.alias(name="annotations")], level=0))
    code = ast.fix_missing_locations(ast.Module(body=selected, type_ignores=[]))
    exec(compile(code, str(SOURCE / filename), "exec"), namespace)
    return SimpleNamespace(**namespace)


def decorator(*_args, **_kwargs):
    return lambda function: function


class Message:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


TYPES = SimpleNamespace(METHOD_RETURN=1, ERROR=2, SIGNAL=3)
NS = dict(
    asyncio=asyncio, argparse=argparse, json=json, os=os, Path=Path, sys=sys,
    process_signal=signal, AUTO_SYNC_ADAPTIVE=False,
    NATIVE_AUTHORITY="linux-native-e4", COMPATIBILITY_AUTHORITY="macos-control-oracle-v1",
    UNSET_ENROLLMENT_PROGRESS=object(), COMPLETED_CLAIM_SECONDS=0,
    UNSTARTED_CLAIM_SECONDS=0, NATIVE_CANCEL_SECONDS=0.1,
    MAX_MATCH_SECONDS=120.0, METHOD_RATE_LIMIT=8,
    METHOD_RATE_WINDOW_SECONDS=10.0, METHOD_RATE_MAX_SENDERS=64,
    ServiceInterface=object, method=decorator,
    INVENTORY_CACHE_SECONDS=0.0,
    signal_decorator=decorator, dbus_property=decorator,
    PropertyAccess=SimpleNamespace(READ=1), Message=Message, MessageType=TYPES,
    BusType=SimpleNamespace(SYSTEM=1), BUS_NAME="net.reactivated.Fprint",
    DBusError=RuntimeError, FPRINT_ERROR="net.reactivated.Fprint.Error",
    public_verification_failure=lambda error: type(error).__name__,
    MANAGER_PATH="/net/reactivated/Fprint/Manager", DEVICE_PATH="/net/reactivated/Fprint/Device/0",
    t2_fprint_identity=SimpleNamespace(MAX_ENROLLED_IDENTITIES=5),
    t2_fprint_projection=SimpleNamespace(is_finger_name=lambda value:
        type(value) is str and re.fullmatch(r"finger-[1-5]", value) is not None),
    t2_dbus_identity=SimpleNamespace(collect=None),
    t2_fprint_claim=SimpleNamespace(collect=None),
    t2_performance=SimpleNamespace(emit=lambda *_args, **_kwargs: None),
    t2_fprint_result=t2_fprint_result,
    t2_user_authority=SimpleNamespace(
        MAPPING_PATH=Path("/var/lib/t2-touchid/users.json"),
        USERS_ROOT=Path("/var/lib/t2-touchid/users"),
        load_runtime=lambda *_args, **_kwargs: None,
        UserAuthorityError=RuntimeError,
    ),
    time=time,
    stat=stat,
    Variant=object,
    DBusSenderError=RuntimeError,
    current_dbus_sender=lambda: ":1.100",
    LINUX_USER="test",
    ALLOWED_PAM_USERS=("test", ""),
)
# The production name `signal` is the D-Bus decorator, not the stdlib module.
NS["signal"] = decorator
FPRINT = definitions("t2-fprintd.py", {
    "verdict_from_result", "resolved_any_finger_from_result", "T2Backend",
    "FprintDevice", "main_async", "cancelled_method_error",
}, NS)
WORKER_NS = dict(asyncio=asyncio, inspect=inspect, threading=threading,
                 t2_fprint_worker_launcher=SimpleNamespace(launch=lambda: None))
WORKER = definitions("t2_fprint_worker_client.py", {
    "FprintWorkerClientError", "EnrollmentWorkerClient",
}, WORKER_NS)


class Caller:
    subject = SimpleNamespace(uid=1000)


class Evidence:
    linux_uid = 1000
    account = SimpleNamespace(linux_uid=1000)


class Projection:
    complete = True
    finger_names = ("finger-1", "finger-2")


NS["t2_fprint_runtime"] = SimpleNamespace(RuntimeProjection=Projection)
DELETE = definitions("t2_fprint_delete_worker_client.py", {
    "FprintDeleteWorkerClientError", "DeletionWorkerClient",
}, dict(asyncio=asyncio, t2_fprint_delete_worker_launcher=SimpleNamespace(launch=lambda: None),
        t2_fprint_projection=NS["t2_fprint_projection"],
        t2_dbus_identity=SimpleNamespace(PinnedDBusCaller=Caller),
        t2_fprint_claim=SimpleNamespace(ClaimEvidence=Evidence)))


def match_result():
    return {
        "resolved_any_match_gate": dict(identity_count=2, complete_named_inventory=True,
            all_identities_selected=True, same_connection_inventory_stable=True,
            local_live_reconciled=True, identifiers_redacted=True),
        "resolved_any_match_post_attestation": dict(identity_state_unchanged=True,
            local_components_unchanged=True, per_user_inventory_unchanged=True,
            global_inventory_unchanged=True, identifiers_redacted=True),
        "match_cleanup_valid": True,
        "match_events": [dict(event_kind="match_result", result_valid=True,
            matched=True, no_match=False, matches_enrolled_identity=True,
            matched_finger_name_present=True, matched_finger_name="finger-2")],
    }


def negative(*, retry=False):
    return dict(event_kind="match_result", result_valid=True, matched=False,
                no_match=True, no_match_image_quality=retry)


class VerdictTests(unittest.TestCase):
    def test_valid_match(self):
        self.assertEqual(FPRINT.resolved_any_finger_from_result(match_result()), "finger-2")

    def test_cleanup_and_event_validity_are_mandatory(self):
        for field in ("match_cleanup_valid", "result_valid"):
            for value in (None, False, 1, "true"):
                with self.subTest(field=field, value=value):
                    result = match_result()
                    target = result if field == "match_cleanup_valid" else result["match_events"][0]
                    if value is None:
                        target.pop(field)
                    else:
                        target[field] = value
                    with self.assertRaises(RuntimeError):
                        FPRINT.resolved_any_finger_from_result(result)

    def test_retry_then_match_returns_actual_terminal_identity(self):
        result = match_result()
        result["match_events"][:0] = [negative(retry=True), negative(retry=True)]
        self.assertEqual(FPRINT.resolved_any_finger_from_result(result), "finger-2")

    def test_explicit_terminal_no_match(self):
        result = match_result()
        result["match_events"] = [negative(retry=True), negative()]
        self.assertIsNone(FPRINT.resolved_any_finger_from_result(result))

    def test_missing_or_unclassified_verdict_is_not_no_match(self):
        for events in ([], [negative(retry=True)], [{"event_kind": "match_result"}],
                       [{"event_kind": "match_result", "matched": False}]):
            with self.subTest(events=events):
                result = match_result()
                result["match_events"] = events
                with self.assertRaises(RuntimeError):
                    FPRINT.resolved_any_finger_from_result(result)

    def test_rejected_start_cannot_become_success(self):
        result = match_result()
        result["match_rejected"] = True
        with self.assertRaises(RuntimeError):
            FPRINT.resolved_any_finger_from_result(result)

    def test_multiple_terminal_results_are_ambiguous(self):
        for extra in (negative(), match_result()["match_events"][0]):
            result = match_result()
            result["match_events"].append(extra)
            with self.subTest(extra=extra), self.assertRaises(RuntimeError):
                FPRINT.resolved_any_finger_from_result(result)

    def test_conflicting_result_flags_fail_closed(self):
        result = match_result()
        result["match_events"][0]["no_match"] = True
        with self.assertRaises(RuntimeError):
            FPRINT.resolved_any_finger_from_result(result)


class LifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def test_cancelled_stop_retains_pending_worker(self):
        client = WORKER.EnrollmentWorkerClient()
        pending = asyncio.create_task(asyncio.Event().wait())
        client.task = pending
        client.cancel_event = threading.Event()
        stopped = asyncio.create_task(client.stop())
        await asyncio.sleep(0)
        stopped.cancel()
        try:
            with self.assertRaises(asyncio.CancelledError):
                await stopped
            self.assertIs(client.task, pending)
            self.assertTrue(client.cancel_event.is_set())
            with self.assertRaises(WORKER.FprintWorkerClientError):
                client.start("finger-1", None, None, lambda _: None)
        finally:
            pending.cancel()
            await asyncio.gather(pending, return_exceptions=True)

    async def test_terminal_worker_is_released(self):
        client = WORKER.EnrollmentWorkerClient()
        client.task = asyncio.create_task(asyncio.sleep(0, result="terminal"))
        client.cancel_event = threading.Event()
        self.assertEqual(await client.stop(), "terminal")
        self.assertIsNone(client.task)
        self.assertIsNone(client.cancel_event)

    async def test_old_stop_cannot_clear_replacement_worker(self):
        client = WORKER.EnrollmentWorkerClient()
        old = asyncio.create_task(asyncio.sleep(0))
        client.task = old
        client.cancel_event = threading.Event()
        stopped = asyncio.create_task(client.stop())
        await asyncio.sleep(0)
        # A different concurrent waiter has finished the old lifecycle.
        replacement = asyncio.create_task(asyncio.Event().wait())
        client.task = replacement
        replacement_cancel = threading.Event()
        client.cancel_event = replacement_cancel
        try:
            await stopped
            self.assertIs(client.task, replacement)
            self.assertIs(client.cancel_event, replacement_cancel)
        finally:
            replacement.cancel()
            await asyncio.gather(replacement, return_exceptions=True)

    def device(self):
        device = FPRINT.FprintDevice.__new__(FPRINT.FprintDevice)
        device._clear_claim = mock.Mock()
        device._set_finger_state = mock.Mock()
        return device

    async def test_cancelled_expiry_does_not_erase_new_timer(self):
        device = self.device()
        device.enrollment_client = None
        expiry = asyncio.create_task(device._expire_stale_enrollment_claim(object()))
        device.claim_expiry_task = expiry
        await asyncio.sleep(0)
        expiry.cancel()
        replacement = object()
        device.claim_expiry_task = replacement
        await asyncio.gather(expiry, return_exceptions=True)
        self.assertIs(device.claim_expiry_task, replacement)
        device._clear_claim.assert_not_called()

    async def test_cancelled_expiry_cleanup_keeps_claim(self):
        device = self.device()
        entered = asyncio.Event()
        async def stop():
            entered.set()
            await asyncio.Event().wait()
        owner = object()
        device.enrollment_client = SimpleNamespace(task=owner, stop=stop)
        expiry = asyncio.create_task(device._expire_stale_enrollment_claim(owner))
        device.claim_expiry_task = expiry
        await asyncio.wait_for(entered.wait(), 1)
        expiry.cancel()
        await asyncio.gather(expiry, return_exceptions=True)
        device._clear_claim.assert_not_called()


    async def test_failed_expiry_stop_keeps_active_claim(self):
        device = self.device()
        owner = object()
        device.enrollment_client = SimpleNamespace(task=owner,
            stop=mock.AsyncMock(side_effect=RuntimeError("cancel channel failed")))
        expiry = asyncio.create_task(device._expire_stale_enrollment_claim(owner))
        device.claim_expiry_task = expiry
        await expiry
        device._clear_claim.assert_not_called()

    async def test_repeated_enrollment_cancellation_keeps_reconciliation(self):
        client = WORKER.EnrollmentWorkerClient()
        entered, release, send_release = asyncio.Event(), asyncio.Event(), asyncio.Event()
        interrupted = []
        async def operation(*_args):
            entered.set()
            try:
                await release.wait()
            except asyncio.CancelledError:
                interrupted.append(True)
                raise
            return "terminal"
        client._run = operation
        client._send_cancel_if_ready = mock.AsyncMock(side_effect=send_release.wait)
        cancellation = threading.Event()
        task = asyncio.create_task(client._supervise("finger-1", None, None, None, cancellation))
        try:
            await entered.wait()
            for _ in range(4):
                task.cancel()
                await asyncio.sleep(0)
            self.assertFalse(task.done())
            self.assertEqual(interrupted, [])
            self.assertTrue(cancellation.is_set())
        finally:
            release.set()
            send_release.set()
            await asyncio.gather(task, return_exceptions=True)
        self.assertFalse(task.cancelled())
        self.assertEqual(task.result(), "terminal")
        client._send_cancel_if_ready.assert_awaited_once()

    async def test_repeated_deletion_cancellation_retains_lock(self):
        client = DELETE.DeletionWorkerClient()
        entered, release = asyncio.Event(), asyncio.Event()
        interrupted = []
        async def operation(*_args):
            entered.set()
            try:
                await release.wait()
            except asyncio.CancelledError:
                interrupted.append(True)
                raise
            return "terminal"
        client._run = operation
        task = asyncio.create_task(client.delete("finger-1", Caller(), Evidence()))
        try:
            await entered.wait()
            for _ in range(4):
                task.cancel()
                await asyncio.sleep(0)
            self.assertFalse(task.done())
            self.assertEqual(interrupted, [])
            self.assertTrue(client._lock.locked())
        finally:
            release.set()
            await asyncio.gather(task, return_exceptions=True)
        self.assertFalse(task.cancelled())
        self.assertEqual(task.result(), "terminal")
        self.assertFalse(client._lock.locked())

    async def test_repeated_facade_deletion_cancel_retains_operation(self):
        device = self.device()
        entered, release = asyncio.Event(), asyncio.Event()
        interrupted = []
        async def delete(*_args):
            entered.set()
            try:
                await release.wait()
            except asyncio.CancelledError:
                interrupted.append(True)
                raise
        device._require_claim_owner = mock.AsyncMock()
        device._arm_unstarted_claim_expiry = mock.Mock()
        device.backend = SimpleNamespace(operation_lock=asyncio.Lock(),
            runtime_projection=mock.AsyncMock(return_value=Projection()),
            invalidate_inventory=mock.Mock())
        device.deletion_client = SimpleNamespace(delete=delete)
        device.verify_task = device.enrollment_client = device.delete_task = None
        device.claim_expiry_task = device.claimed_caller = device.claimed_evidence = None
        task = asyncio.create_task(device.DeleteEnrolledFinger("finger-1"))
        try:
            await asyncio.wait_for(entered.wait(), 1)
            for _ in range(4):
                task.cancel()
                await asyncio.sleep(0)
            self.assertFalse(task.done())
            self.assertIs(device.delete_task, task)
            self.assertEqual(interrupted, [])
        finally:
            release.set()
            await asyncio.gather(task, return_exceptions=True)
        self.assertFalse(task.cancelled())
        with self.assertRaises(FPRINT.DBusError) as raised:
            task.result()
        self.assertEqual(
            raised.exception.args[0],
            f"{FPRINT.FPRINT_ERROR}.PrintsNotDeleted",
        )
        self.assertIsNone(device.delete_task)

    async def test_verification_revalidates_claim_before_publication(self):
        device = self.device()
        device._require_claim_owner = mock.AsyncMock(side_effect=RuntimeError("claim revoked"))
        device._live_verify_event = mock.Mock()
        device.backend = SimpleNamespace(
            verify_fprint=mock.AsyncMock(return_value=("verify-match", match_result())),
            schedule_feedback=mock.Mock(), schedule_adaptive_sync=mock.Mock())
        device.VerifyFingerMatched = mock.Mock()
        device.VerifyStatus = mock.Mock()
        device.verify_task = None
        await device._run_verification("any", Projection())
        device.claim_expiry_task.cancel()
        await asyncio.gather(device.claim_expiry_task, return_exceptions=True)
        device.VerifyFingerMatched.assert_not_called()
        device.VerifyStatus.assert_called_once_with("verify-unknown-error", True)
        device.backend.schedule_adaptive_sync.assert_not_called()

    async def test_live_claim_still_publishes_valid_match(self):
        device = self.device()
        device._require_claim_owner = mock.AsyncMock()
        device._live_verify_event = mock.Mock()
        device.backend = SimpleNamespace(
            verify_fprint=mock.AsyncMock(return_value=("verify-match", match_result())),
            schedule_feedback=mock.Mock(), schedule_adaptive_sync=mock.Mock())
        device.VerifyFingerMatched = mock.Mock()
        device.VerifyStatus = mock.Mock()
        device.verify_task = None
        await device._run_verification("any", Projection())
        device.claim_expiry_task.cancel()
        await asyncio.gather(device.claim_expiry_task, return_exceptions=True)
        device._require_claim_owner.assert_called_once()
        device.VerifyFingerMatched.assert_called_once_with("finger-2")
        device.VerifyStatus.assert_called_once_with("verify-match", True)
        device.backend.schedule_adaptive_sync.assert_called_once()

    async def test_stop_requests_task_cancellation_before_waiting_for_child(self):
        device = self.device()
        device.claim_expiry_task = None
        task = asyncio.create_task(asyncio.Event().wait())
        device.verify_task = task
        async def cancel(**_kwargs):
            self.assertGreater(task.cancelling(), 0)
            await asyncio.sleep(0)
        device.backend = SimpleNamespace(cancel=cancel)
        try:
            await device._stop_verification(require_running=True)
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        self.assertIsNone(device.verify_task)


class ProcessTests(unittest.IsolatedAsyncioTestCase):
    def backend(self):
        backend = FPRINT.T2Backend.__new__(FPRINT.T2Backend)
        backend.project_dir = Path("/unused")
        backend.linux_uid = 1000
        backend.match_seconds = 0
        backend.process = None
        backend.process_owner = None
        backend.native_worker = None
        backend.native_worker_stderr_task = None
        backend.native_worker_feedback = None
        backend.native_worker_cue_sent = False
        backend.schedule_feedback = mock.Mock()
        return backend

    async def test_feedback_exceptions_do_not_abort_reader(self):
        stream = asyncio.StreamReader()
        stream.feed_data(b'T2_MATCH_EVENT {"event_kind":"match_armed"}\n')
        stream.feed_eof()
        backend = self.backend()
        backend.schedule_feedback.side_effect = RuntimeError("audio failed")
        def feedback(_event):
            raise RuntimeError("D-Bus delivery failed")
        result = await backend._read_probe_stderr(stream, feedback)
        self.assertIn(b"match_armed", result)

    async def test_retained_stderr_is_bounded(self):
        stream = asyncio.StreamReader()
        for _ in range(1024):
            stream.feed_data(b"x" * 1023 + b"\n")
        stream.feed_data(b"last diagnostic\n")
        stream.feed_eof()
        result = await self.backend()._read_probe_stderr(stream, None)
        self.assertLessEqual(len(result), 65536)
        self.assertTrue(result.endswith(b"last diagnostic\n"))

    async def _native_with_child(self, program, *, cancel=False, repeated=False):
        spawn = asyncio.create_subprocess_exec
        children = []
        existing_tasks = set(asyncio.all_tasks())
        async def child(*_args, **kwargs):
            process = await spawn(sys.executable, "-c", program, **kwargs)
            children.append(process)
            return process
        backend = self.backend()
        try:
            with mock.patch.object(asyncio, "create_subprocess_exec", child):
                task = asyncio.create_task(backend._run_native_match())
                if cancel:
                    while not children:
                        await asyncio.sleep(0.005)
                    task.cancel()
                    if repeated:
                        for _ in range(4):
                            await asyncio.sleep(0)
                            task.cancel()
                    with self.assertRaises(asyncio.CancelledError):
                        await asyncio.wait_for(task, 2)
                else:
                    with self.assertRaises((RuntimeError, ValueError, TimeoutError)):
                        await asyncio.wait_for(task, 2)
            self.assertIsNotNone(children[0].returncode, "helper was not reaped")
            self.assertIsNone(backend.process)
        finally:
            for process in children:
                if process.returncode is None:
                    process.kill()
                pending = [task for task in asyncio.all_tasks()
                           if task not in existing_tasks and not task.done()]
                for reader in pending:
                    reader.cancel()
                await asyncio.gather(*pending, return_exceptions=True)
                await process.communicate()

    async def test_failed_line_reader_does_not_deadlock_child(self):
        await self._native_with_child(
            "import os,time; os.write(2,b'x'*1048576); time.sleep(30)"
        )

    async def test_native_task_cancellation_reaps_owned_child(self):
        await self._native_with_child("import time; time.sleep(30)", cancel=True)

    async def test_repeated_native_cancellation_still_reaps_child(self):
        await self._native_with_child("import time; time.sleep(30)", cancel=True, repeated=True)

    async def test_stuck_request_cancellation_kills_the_worker_session(self):
        spawn = asyncio.create_subprocess_exec
        children = []

        async def child(*_args, **kwargs):
            process = await spawn(
                sys.executable,
                "-c",
                "import signal,time; "
                "print('{\"schema_version\":1,\"ready\":true}', flush=True); "
                "signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(30)",
                **kwargs,
            )
            children.append(process)
            return process

        backend = self.backend()
        with (
            mock.patch.object(asyncio, "create_subprocess_exec", child),
            mock.patch.object(backend, "_schedule_native_worker_warm"),
        ):
            task = asyncio.create_task(backend._run_native_match())
            for _ in range(100):
                if backend.process is not None:
                    break
                await asyncio.sleep(0.01)
            self.assertIsNotNone(backend.process)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await asyncio.wait_for(task, 2)
        self.assertIsNotNone(children[0].returncode)
        self.assertIsNone(backend.process)

    async def test_stop_does_not_terminate_other_operation(self):
        backend = self.backend()
        backend.process = mock.Mock(returncode=None)
        backend.process_owner = object()
        backend.process.wait = mock.AsyncMock(return_value=0)
        device = FPRINT.FprintDevice.__new__(FPRINT.FprintDevice)
        device.backend = backend
        device.claim_expiry_task = None
        device._set_finger_state = mock.Mock()
        task = asyncio.create_task(asyncio.Event().wait())
        device.verify_task = task
        try:
            await device._stop_verification(require_running=True)
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        backend.process.terminate.assert_not_called()
        backend.process.kill.assert_not_called()

    async def test_exited_child_race_during_cancel_is_benign(self):
        backend = self.backend()
        backend.process = mock.Mock(returncode=None)
        backend.process.terminate.side_effect = ProcessLookupError()
        backend.process.wait = mock.AsyncMock(return_value=0)
        await backend.cancel()
        backend.process.wait.assert_awaited_once()

    async def test_healthy_native_child_result_is_preserved(self):
        backend = self.backend()
        expected = {
            "schema_version": 1,
            "selector": "all",
            "verdict": "verify-no-match",
            "finger_name": None,
        }
        spawn = asyncio.create_subprocess_exec
        children = []
        async def child(*_args, **kwargs):
            response = {
                "schema_version": 1,
                "request_id": 1,
                "ok": True,
                "result": expected,
            }
            program = "print('{\"schema_version\":1,\"ready\":true}', flush=True);"
            if not children:
                program += f"print({json.dumps(response)!r}, flush=True)"
            else:
                program += "import time; time.sleep(30)"
            process = await spawn(sys.executable, "-c", program, **kwargs)
            children.append(process)
            return process
        with mock.patch.object(asyncio, "create_subprocess_exec", child):
            self.assertEqual(await backend._run_native_match(), expected)
            for _ in range(100):
                if (
                    len(children) == 2
                    and backend.native_worker is children[1]
                    and getattr(backend, "native_worker_warm_task", None) is None
                ):
                    break
                await asyncio.sleep(0.01)
        self.assertEqual(len(children), 2)
        self.assertIsNot(backend.native_worker, children[0])
        self.assertIs(backend.native_worker, children[1])
        self.assertIsNone(backend.process)
        await backend._discard_native_worker(children[1])
        self.assertIsNotNone(children[0].returncode)
        self.assertIsNotNone(children[1].returncode)

    async def test_audio_timeout_reaps_helper(self):
        backend = self.backend()
        spawn = asyncio.create_subprocess_exec
        children = []
        async def child(*_args, **kwargs):
            process = await spawn(sys.executable, "-c", "import time; time.sleep(30)", **kwargs)
            children.append(process)
            return process
        try:
            with mock.patch.dict(NS, desktop_user_unit_command=lambda _unit: ("/fake",)):
                with mock.patch.object(asyncio, "create_subprocess_exec", child):
                    await asyncio.wait_for(backend.start_user_unit("t2-touchid-alert.service"), 5)
            self.assertIsNotNone(children[0].returncode, "timed-out helper was not reaped")
        finally:
            for process in children:
                if process.returncode is None:
                    process.kill()
                await process.communicate()


class KernelDiagnosticTests(unittest.TestCase):
    def test_acm_send_timeout_names_actual_transport_and_request(self):
        text = (SOURCE / "t2_sep_transport.c").read_text(encoding="utf-8")
        body = text.split("static int t2_acm_exchange_locked(", 1)[1]
        body = body.split("static long t2_acm_ioctl(", 1)[0]
        self.assertRegex(body, re.compile(
            r't2_sep_log_mailbox_timeout\(sep, "ACM",\s*'
            r'T2_SEP_ACM_ENDPOINT,\s*request_code, "send", 0\);'))


class SubscriptionTests(unittest.IsolatedAsyncioTestCase):
    async def run_main(
        self, reply, lifecycle_message=None, owner_lookup_message=None
    ):
        calls = []
        handlers = []
        ready = asyncio.Event()
        owner_message_sent = False
        current_owner = ":1.42"
        class Bus:
            async def connect(self):
                return self
            def add_message_handler(self, handler):
                handlers.append(handler)
            def export(self, *_args):
                pass
            async def call(self, message):
                nonlocal owner_message_sent
                calls.append(message)
                if message.member == "GetNameOwner":
                    if owner_lookup_message is not None and not owner_message_sent:
                        owner_message_sent = True
                        for handler in handlers:
                            if handler.__name__ == "system_sleep_handler":
                                handler(owner_lookup_message)
                    return Message(
                        message_type=TYPES.METHOD_RETURN,
                        signature="s",
                        body=[current_owner],
                    )
                if message.member == "Get":
                    return Message(
                        message_type=TYPES.METHOD_RETURN,
                        signature="v",
                        body=[SimpleNamespace(signature="b", value=False)],
                    )
                return reply
            async def request_name(self, _name):
                ready.set()
        bus = Bus()
        backend = SimpleNamespace(system_sleeping=True, runtime_warm_task=None)
        backend.warm_runtime = mock.AsyncMock()
        def schedule_warm():
            if backend.system_sleeping:
                return None
            task = backend.runtime_warm_task
            if task is not None and not task.done():
                return task
            task = asyncio.create_task(backend.warm_runtime())
            backend.runtime_warm_task = task
            return task
        backend._schedule_runtime_warm = mock.Mock(side_effect=schedule_warm)
        def sleep_changed(sleeping):
            backend.system_sleeping = sleeping
            if not sleeping:
                schedule_warm()
        backend.system_sleep_changed = mock.Mock(side_effect=sleep_changed)
        changes = dict(
            T2Backend=lambda *_args, **_kwargs: backend, SenderAwareMessageBus=lambda **_kwargs: bus,
            FprintDevice=lambda *_args, **_kwargs: object(), FprintManager=lambda: object(),
            enrollment_client_for_arguments=lambda _args: None,
            deletion_client_for_arguments=lambda _args: None,
            __file__=str(SOURCE / "t2-fprintd.py"),
        )
        with mock.patch.dict(NS, changes):
            task = asyncio.create_task(FPRINT.main_async(argparse.Namespace(match_seconds=0)))
            for _ in range(100):
                if task.done() or ready.is_set():
                    break
                await asyncio.sleep(0)
            if ready.is_set() and lifecycle_message is not None:
                if lifecycle_message.member == "NameOwnerChanged":
                    current_owner = lifecycle_message.body[2]
                for handler in handlers:
                    if (
                        handler.__name__ == "system_sleep_handler"
                        and lifecycle_message.member == "PrepareForSleep"
                    ) or (
                        handler.__name__ == "sender_departure_handler"
                        and lifecycle_message.member == "NameOwnerChanged"
                    ):
                        handler(lifecycle_message)
                for _ in range(10):
                    await asyncio.sleep(0)
            error = task.exception() if task.done() else None
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
        return calls, ready.is_set(), error, backend

    async def test_subscription_installed_before_exposure(self):
        calls, ready, error, _backend = await self.run_main(Message(
            message_type=TYPES.METHOD_RETURN, signature="", body=[]))
        self.assertIsNone(error)
        self.assertTrue(ready)
        self.assertEqual(len(calls), 4)
        self.assertEqual(calls[0].member, "AddMatch")
        self.assertIn("NameOwnerChanged", calls[0].body[0])
        self.assertIn("sender='org.freedesktop.DBus'", calls[0].body[0])
        self.assertIn("PrepareForSleep", calls[1].body[0])
        self.assertEqual(calls[2].member, "GetNameOwner")
        self.assertEqual(calls[2].body, ["org.freedesktop.login1"])
        self.assertEqual(calls[3].member, "Get")
        self.assertEqual(
            calls[3].body,
            ["org.freedesktop.login1.Manager", "PreparingForSleep"],
        )
        _backend.system_sleep_changed.assert_called_once_with(False)
        _backend.warm_runtime.assert_awaited_once_with()

    async def test_subscription_failure_prevents_exposure(self):
        for reply in (Message(message_type=TYPES.ERROR, signature="s", body=["denied"]),
                      Message(message_type=TYPES.METHOD_RETURN, signature="s", body=["bad"]),
                      None):
            with self.subTest(reply=reply):
                _calls, ready, error, _backend = await self.run_main(reply)
                self.assertFalse(ready)
                self.assertIsInstance(error, RuntimeError)

    async def test_resume_invalidates_then_rewarms_runtime(self):
        reply = Message(message_type=TYPES.METHOD_RETURN, signature="", body=[])
        lifecycle = Message(
            message_type=TYPES.SIGNAL,
            sender=":1.42",
            path="/org/freedesktop/login1",
            interface="org.freedesktop.login1.Manager",
            member="PrepareForSleep",
            signature="b",
            body=[False],
        )
        _calls, ready, error, backend = await self.run_main(reply, lifecycle)
        self.assertTrue(ready)
        self.assertIsNone(error)
        self.assertEqual(
            backend.system_sleep_changed.call_args_list,
            [mock.call(False), mock.call(False)],
        )

    async def test_suspend_invalidates_without_starting_a_warmup(self):
        reply = Message(message_type=TYPES.METHOD_RETURN, signature="", body=[])
        lifecycle = Message(
            message_type=TYPES.SIGNAL,
            sender=":1.42",
            path="/org/freedesktop/login1",
            interface="org.freedesktop.login1.Manager",
            member="PrepareForSleep",
            signature="b",
            body=[True],
        )
        _calls, ready, error, backend = await self.run_main(reply, lifecycle)
        self.assertTrue(ready)
        self.assertIsNone(error)
        self.assertEqual(
            backend.system_sleep_changed.call_args_list,
            [mock.call(False), mock.call(True)],
        )

    async def test_spoofed_sleep_sender_is_ignored(self):
        reply = Message(message_type=TYPES.METHOD_RETURN, signature="", body=[])
        lifecycle = Message(
            message_type=TYPES.SIGNAL,
            sender="org.freedesktop.login1",
            path="/org/freedesktop/login1",
            interface="org.freedesktop.login1.Manager",
            member="PrepareForSleep",
            signature="b",
            body=[True],
        )
        _calls, ready, error, backend = await self.run_main(reply, lifecycle)
        self.assertTrue(ready)
        self.assertIsNone(error)
        backend.system_sleep_changed.assert_called_once_with(False)

    async def test_sleep_signal_during_owner_lookup_is_preserved(self):
        reply = Message(message_type=TYPES.METHOD_RETURN, signature="", body=[])
        lifecycle = Message(
            message_type=TYPES.SIGNAL,
            sender=":1.42",
            path="/org/freedesktop/login1",
            interface="org.freedesktop.login1.Manager",
            member="PrepareForSleep",
            signature="b",
            body=[True],
        )
        _calls, ready, error, backend = await self.run_main(
            reply, owner_lookup_message=lifecycle
        )
        self.assertFalse(ready)
        self.assertIsNone(error)
        backend.system_sleep_changed.assert_called_once_with(True)
        backend.warm_runtime.assert_not_awaited()

    async def test_login1_owner_change_fails_closed_until_reconciled(self):
        reply = Message(message_type=TYPES.METHOD_RETURN, signature="", body=[])
        owner_change = Message(
            message_type=TYPES.SIGNAL,
            sender="org.freedesktop.DBus",
            path="/org/freedesktop/DBus",
            interface="org.freedesktop.DBus",
            member="NameOwnerChanged",
            signature="sss",
            body=["org.freedesktop.login1", ":1.42", ":1.43"],
        )
        _calls, ready, error, backend = await self.run_main(
            reply, lifecycle_message=owner_change
        )
        self.assertTrue(ready)
        self.assertIsNone(error)
        self.assertEqual(
            backend.system_sleep_changed.call_args_list,
            [mock.call(False), mock.call(True), mock.call(False)],
        )
        self.assertEqual(backend.warm_runtime.await_count, 2)


if __name__ == "__main__":
    unittest.main()
