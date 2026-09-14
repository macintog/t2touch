#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Hardware-free lifecycle tests for the T2 fprintd facade."""

import asyncio
import argparse
import importlib.util
import os
from pathlib import Path
import stat
import tempfile
import unittest
import xml.etree.ElementTree as ElementTree
from unittest import mock
from unittest.mock import AsyncMock


MODULE_PATH = Path(__file__).resolve().parents[1] / "src/t2-fprintd.py"
SPEC = importlib.util.spec_from_file_location("t2_fprintd", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)
MODULE.current_dbus_sender = lambda: ":1.100"


def resolved_match_result(finger_name="finger-1"):
    return {
        "resolved_any_match_gate": {
            "identity_count": 2,
            "complete_named_inventory": True,
            "all_identities_selected": True,
            "same_connection_inventory_stable": True,
            "local_live_reconciled": True,
            "identifiers_redacted": True,
        },
        "resolved_any_match_post_attestation": {
            "identity_state_unchanged": True,
            "local_components_unchanged": True,
            "per_user_inventory_unchanged": True,
            "global_inventory_unchanged": True,
            "identifiers_redacted": True,
        },
        "match_events": [
            {
                "event_kind": "match_result",
                "matched": True,
                "matches_enrolled_identity": True,
                "matched_finger_name_present": True,
                "matched_finger_name": finger_name,
            }
        ],
    }


class FakeBackend:
    def __init__(self, verdict="verify-match"):
        self.verdict = verdict
        self.cancel_count = 0
        self.adaptive_sync_requests = 0
        self.operation_lock = asyncio.Lock()
        self.projection = MODULE.t2_fprint_runtime.RuntimeProjection(
            ("finger-1",),
            1,
            True,
        )

    async def verify(self):
        await asyncio.sleep(0)
        return self.verdict, (
            resolved_match_result() if self.verdict == "verify-match" else {}
        )

    async def verify_fprint(self, _requested_finger, _live_feedback=None):
        return await self.verify()

    async def list_fingers(self):
        return ("finger-1",)

    async def runtime_projection(self):
        return self.projection

    async def enrollment_projection(self):
        return self.projection

    async def cancel(self):
        self.cancel_count += 1

    def schedule_adaptive_sync(self):
        self.adaptive_sync_requests += 1


class FakePinnedCaller:
    def __init__(self, sender):
        self.sender = sender
        self.closed = False
        self.verify_count = 0

    def verify(self):
        if self.closed:
            raise MODULE.t2_dbus_identity.DBusIdentityError("closed")
        self.verify_count += 1

    def close(self):
        self.closed = True


class FakeClaimEvidence(MODULE.t2_fprint_claim.ClaimEvidence):
    def __init__(self):
        super().__init__("test", 1000, None, None, None, None, None)
        self.revalidate_count = 0
        self.invalid = False

    def revalidate(self, caller):
        caller.verify()
        if self.invalid:
            raise MODULE.t2_fprint_claim.FprintClaimError("changed")
        self.revalidate_count += 1


class FakeEnrollmentClient:
    def __init__(self):
        self.task = None
        self.on_update = None
        self.start_arguments = None
        self.stop_count = 0
        self.release = asyncio.Event()

    def start(self, finger_name, caller, evidence, on_update):
        self.start_arguments = (finger_name, caller, evidence)
        self.on_update = on_update
        self.task = asyncio.create_task(self.release.wait())
        return self.task

    def emit(self, update):
        self.on_update(update)

    async def stop(self):
        self.stop_count += 1
        task = self.task
        self.release.set()
        if task is not None:
            await task
        self.task = None
        return MODULE.t2_fprint_enrollment_runtime.EnrollmentUpdate(
            "enroll-failed", True, False, False
        )


class FakeDeletionClient:
    def __init__(self):
        self.arguments = None
        self.entered = asyncio.Event()
        self.release = asyncio.Event()
        self.block = False
        self.result = MODULE.t2_fprint_deletion_runtime.DeletionCompletion(
            "finger-1", True, True, False, True
        )

    async def delete(self, finger_name, caller, evidence):
        self.arguments = (finger_name, caller, evidence)
        self.entered.set()
        if self.block:
            await self.release.wait()
        return self.result


class FakeBus:
    def __init__(self):
        self.sent = []

    def send(self, message):
        self.sent.append(message)


async def fake_caller_collector(_bus, sender):
    return FakePinnedCaller(sender)


def fake_claim_evidence_collector(_caller, _username):
    return FakeClaimEvidence()


def make_device(
    backend=None, enrollment_client=None, deletion_client=None, identity_bus=None
):
    return MODULE.FprintDevice(
        backend or FakeBackend(),
        identity_bus or object(),
        fake_caller_collector,
        fake_claim_evidence_collector,
        enrollment_client,
        deletion_client,
    )


async def claim(device, username=None):
    await MODULE.FprintDevice.Claim.__wrapped__(
        device, username or MODULE.LINUX_USER
    )


async def enroll_start(device, finger_name):
    await MODULE.FprintDevice.EnrollStart.__wrapped__(device, finger_name)


async def verify_start(device, finger_name):
    await MODULE.FprintDevice.VerifyStart.__wrapped__(device, finger_name)


async def delete_finger(device, finger_name):
    await MODULE.FprintDevice.DeleteEnrolledFinger.__wrapped__(
        device, finger_name
    )


class DeviceLifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def test_desktop_feedback_uses_exact_target_user_bus(self):
        account = mock.Mock(pw_uid=1000)
        runtime = mock.Mock(st_mode=stat.S_IFDIR | 0o700, st_uid=1000, st_nlink=2)
        bus = mock.Mock(st_mode=stat.S_IFSOCK | 0o666, st_uid=1000, st_nlink=1)

        def path_stat(path, *, follow_symlinks=True):
            self.assertFalse(follow_symlinks)
            return bus if path.name == "bus" else runtime

        with (
            mock.patch.object(MODULE, "LINUX_USER", "mapped"),
            mock.patch.object(MODULE.pwd, "getpwnam", return_value=account),
            mock.patch.object(MODULE.Path, "stat", path_stat),
        ):
            command = MODULE.desktop_user_unit_command(
                "t2-touchid-success.service"
            )
        self.assertEqual(
            command,
            (
                "/usr/bin/runuser",
                "-u",
                "mapped",
                "--",
                "/usr/bin/env",
                "XDG_RUNTIME_DIR=/run/user/1000",
                "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus",
                "/usr/bin/systemctl",
                "--user",
                "start",
                "--no-block",
                "t2-touchid-success.service",
            ),
        )

    async def test_desktop_feedback_rejects_untrusted_bus_or_unit(self):
        account = mock.Mock(pw_uid=1000)
        runtime = mock.Mock(st_mode=stat.S_IFDIR | 0o700, st_uid=1000, st_nlink=2)
        wrong_bus = mock.Mock(
            st_mode=stat.S_IFSOCK | 0o666, st_uid=1001, st_nlink=1
        )

        def path_stat(path, *, follow_symlinks=True):
            self.assertFalse(follow_symlinks)
            return wrong_bus if path.name == "bus" else runtime

        with (
            mock.patch.object(MODULE, "LINUX_USER", "mapped"),
            mock.patch.object(MODULE.pwd, "getpwnam", return_value=account),
            mock.patch.object(MODULE.Path, "stat", path_stat),
        ):
            self.assertIsNone(
                MODULE.desktop_user_unit_command(
                    "t2-touchid-success.service"
                )
            )
            self.assertIsNone(
                MODULE.desktop_user_unit_command("not-a-feedback.service")
            )

    async def test_complete_historical_property_set_is_available(self):
        device = make_device()
        device.finger_present = True
        request = MODULE.Message(
            destination=MODULE.BUS_NAME,
            path=MODULE.DEVICE_PATH,
            interface="org.freedesktop.DBus.Properties",
            member="GetAll",
            signature="s",
            body=["net.reactivated.Fprint.Device"],
            serial=1,
        )
        reply = MODULE.legacy_property_reply(request, device)
        values = reply.body[0]
        self.assertEqual(
            set(values),
            {
                "name",
                "num-enroll-stages",
                "scan-type",
                "finger-present",
                "finger-needed",
                "t2-enroll-progress",
            },
        )
        self.assertEqual(values["num-enroll-stages"].value, -1)
        self.assertTrue(values["finger-present"].value)
        self.assertFalse(values["finger-needed"].value)
        self.assertEqual(values["t2-enroll-progress"].value, -1)

    async def test_introspection_advertises_complete_historical_properties(self):
        device = make_device()
        request = MODULE.Message(
            destination=MODULE.BUS_NAME,
            path=MODULE.DEVICE_PATH,
            interface="org.freedesktop.DBus.Introspectable",
            member="Introspect",
            serial=1,
        )
        reply = MODULE.legacy_introspection_reply(request, device)
        root = ElementTree.fromstring(reply.body[0])
        interface = next(
            item
            for item in root.findall("interface")
            if item.attrib.get("name") == "net.reactivated.Fprint.Device"
        )
        self.assertEqual(
            {
                item.attrib["name"]: (
                    item.attrib["type"], item.attrib["access"]
                )
                for item in interface.findall("property")
            },
            {
                "name": ("s", "read"),
                "num-enroll-stages": ("i", "read"),
                "scan-type": ("s", "read"),
                "finger-present": ("b", "read"),
                "finger-needed": ("b", "read"),
                "t2-enroll-progress": ("i", "read"),
            },
        )
        self.assertEqual(
            {
                item.attrib["name"] for item in interface.findall("method")
            },
            {
                "Claim",
                "Release",
                "ListEnrolledFingers",
                "VerifyStart",
                "VerifyStop",
                "EnrollStart",
                "EnrollStop",
                "DeleteEnrolledFingers",
                "DeleteEnrolledFingers2",
                "DeleteEnrolledFinger",
            },
        )

        wrong_path = MODULE.Message(
            destination=MODULE.BUS_NAME,
            path=MODULE.MANAGER_PATH,
            interface="org.freedesktop.DBus.Introspectable",
            member="Introspect",
            serial=2,
        )
        self.assertFalse(
            MODULE.legacy_introspection_reply(wrong_path, device)
        )

    async def test_dynamic_finger_properties_emit_exact_changes(self):
        bus = FakeBus()
        device = make_device(identity_bus=bus)

        device._set_finger_state(False, True)
        device._set_finger_state(True, False, 23)
        device._set_finger_state(True, False, 23)
        device._set_finger_state(False, False, 23)

        self.assertEqual(len(bus.sent), 3)
        self.assertEqual(
            [set(message.body[1]) for message in bus.sent],
            [
                {"finger-needed"},
                {
                    "finger-present",
                    "finger-needed",
                    "t2-enroll-progress",
                },
                {"finger-present"},
            ],
        )
        for message in bus.sent:
            self.assertEqual(message.path, MODULE.DEVICE_PATH)
            self.assertEqual(
                message.interface, "org.freedesktop.DBus.Properties"
            )
            self.assertEqual(message.member, "PropertiesChanged")
            self.assertEqual(message.signature, "sa{sv}as")
            self.assertEqual(
                message.body[0], "net.reactivated.Fprint.Device"
            )
            self.assertEqual(message.body[2], [])

    async def test_invalid_or_undeliverable_property_update_is_bounded(self):
        class BrokenBus:
            def send(self, _message):
                raise RuntimeError("disconnected")

        device = make_device(identity_bus=BrokenBus())
        device._set_finger_state(False, True)
        self.assertTrue(device.finger_needed)
        with self.assertRaises(RuntimeError):
            device._set_finger_state(True, True)

    async def test_listing_refreshes_backend_projection(self):
        backend = FakeBackend()
        backend.list_fingers = AsyncMock(
            return_value=("finger-1", "finger-2")
        )
        device = make_device(backend)
        listed = await MODULE.FprintDevice.ListEnrolledFingers.__wrapped__(
            device, MODULE.LINUX_USER
        )
        self.assertEqual(listed, ["finger-1", "finger-2"])
        self.assertEqual(
            device.enrolled_fingers,
            ("finger-1", "finger-2"),
        )

    async def test_verify_start_refreshes_projection_before_named_match(self):
        backend = FakeBackend("verify-no-match")
        backend.projection = MODULE.t2_fprint_runtime.RuntimeProjection(
            ("finger-1", "finger-2"),
            2,
            True,
        )
        backend.runtime_projection = AsyncMock(
            return_value=backend.projection
        )
        backend.verify_fprint = AsyncMock(
            return_value=("verify-no-match", {})
        )
        device = make_device(backend)
        selected = []
        device.VerifyFingerSelected = selected.append
        device.VerifyStatus = lambda _result, _done: None
        await claim(device)

        await verify_start(device, "finger-1")
        await device.verify_task

        self.assertEqual(
            device.enrolled_fingers,
            ("finger-1", "finger-2"),
        )
        self.assertEqual(selected, ["any"])
        backend.runtime_projection.assert_awaited_once_with()
        backend.verify_fprint.assert_awaited_once_with("finger-1", mock.ANY)

    async def test_verification_publishes_waiting_and_terminal_properties(self):
        entered = asyncio.Event()
        finish = asyncio.Event()

        class LiveBackend(FakeBackend):
            async def verify_fprint(self, _requested_finger, live_feedback=None):
                self.live_feedback = live_feedback
                entered.set()
                await finish.wait()
                return "verify-no-match", {}

        bus = FakeBus()
        backend = LiveBackend("verify-no-match")
        device = make_device(backend, identity_bus=bus)
        device.VerifyStatus = lambda _status, _done: None
        await claim(device)

        await verify_start(device, "any")
        await entered.wait()
        self.assertFalse(device.finger_needed)
        backend.live_feedback({"event_kind": "match_armed"})
        self.assertTrue(device.finger_needed)
        backend.live_feedback(
            {"event_kind": "status", "status_semantics": "finger-present"}
        )
        self.assertTrue(device.finger_present)
        self.assertFalse(device.finger_needed)
        backend.live_feedback(
            {"event_kind": "status", "status_semantics": "finger-removed"}
        )
        self.assertFalse(device.finger_present)
        self.assertTrue(device.finger_needed)
        finish.set()
        await device.verify_task

        self.assertFalse(device.finger_present)
        self.assertFalse(device.finger_needed)
        self.assertEqual(
            [set(message.body[1]) for message in bus.sent],
            [
                {"finger-needed"},
                {"finger-present", "finger-needed"},
                {"finger-present", "finger-needed"},
                {"finger-needed"},
            ],
        )
        self.assertTrue(bus.sent[0].body[1]["finger-needed"].value)
        self.assertFalse(bus.sent[-1].body[1]["finger-needed"].value)
        await MODULE.FprintDevice.VerifyStop.__wrapped__(device)

    async def test_verify_start_rejects_absent_or_invalid_name_before_match(self):
        backend = FakeBackend()
        backend.projection = MODULE.t2_fprint_runtime.RuntimeProjection(
            ("finger-2",),
            1,
            True,
        )
        backend.verify_fprint = AsyncMock()
        device = make_device(backend)
        await claim(device)
        with self.assertRaises(MODULE.DBusError) as absent:
            await verify_start(device, "finger-1")
        self.assertTrue(absent.exception.type.endswith(".NoEnrolledPrints"))
        with self.assertRaises(MODULE.DBusError) as invalid:
            await verify_start(device, "not-a-finger")
        self.assertTrue(invalid.exception.type.endswith(".InvalidFingername"))
        backend.verify_fprint.assert_not_awaited()
        await MODULE.FprintDevice.Release.__wrapped__(device)

    async def test_cancelled_verify_projection_restores_bounded_claim(self):
        entered = asyncio.Event()

        class BlockingBackend(FakeBackend):
            async def runtime_projection(self):
                entered.set()
                await asyncio.Event().wait()

        device = make_device(BlockingBackend())
        await claim(device)
        task = asyncio.create_task(verify_start(device, "any"))
        await entered.wait()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertIsNone(device.verify_task)
        self.assertIsNotNone(device.claim_expiry_task)
        await MODULE.FprintDevice.Release.__wrapped__(device)

    async def test_any_match_prompts_before_capture_and_reports_exact_match(self):
        backend = FakeBackend()
        backend.verify_fprint = AsyncMock(
            return_value=(
                "verify-match",
                {
                    "resolved_any_match_gate": {
                        "identity_count": 2,
                        "complete_named_inventory": True,
                        "all_identities_selected": True,
                        "same_connection_inventory_stable": True,
                        "local_live_reconciled": True,
                        "identifiers_redacted": True,
                    },
                    "resolved_any_match_post_attestation": {
                        "identity_state_unchanged": True,
                        "local_components_unchanged": True,
                        "per_user_inventory_unchanged": True,
                        "global_inventory_unchanged": True,
                        "identifiers_redacted": True,
                    },
                    "match_events": [
                        {
                            "event_kind": "match_result",
                            "matched": True,
                            "matches_enrolled_identity": True,
                            "matched_finger_name_present": True,
                            "matched_finger_name": "finger-1",
                        }
                    ],
                },
            )
        )
        device = make_device(backend)
        emitted = []
        device.VerifyFingerSelected = lambda name: emitted.append(("finger", name))
        device.VerifyFingerMatched = lambda name: emitted.append(("matched", name))
        device.VerifyStatus = lambda result, done: emitted.append(
            ("status", result, done)
        )
        await claim(device)
        await verify_start(device, "any")
        await device.verify_task
        self.assertEqual(
            emitted,
            [
                ("finger", "any"),
                ("matched", "finger-1"),
                ("status", "verify-match", True),
            ],
        )
        self.assertEqual(backend.adaptive_sync_requests, 1)

    async def test_negative_match_never_requests_adaptive_sync(self):
        backend = FakeBackend("verify-no-match")
        device = make_device(backend)
        statuses = []
        device.VerifyStatus = lambda result, done: statuses.append((result, done))
        await claim(device)
        await verify_start(device, "any")
        await device.verify_task
        self.assertEqual(statuses, [("verify-no-match", True)])
        self.assertEqual(backend.adaptive_sync_requests, 0)

    async def test_empty_listing_uses_upstream_no_prints_error(self):
        backend = FakeBackend()
        backend.list_fingers = AsyncMock(return_value=())
        device = make_device(backend)
        with self.assertRaises(MODULE.DBusError) as raised:
            await MODULE.FprintDevice.ListEnrolledFingers.__wrapped__(
                device, MODULE.LINUX_USER
            )
        self.assertTrue(raised.exception.type.endswith(".NoEnrolledPrints"))

    async def test_terminal_verdict_remains_stoppable(self):
        backend = FakeBackend()
        device = make_device(backend)
        statuses = []
        device.VerifyStatus = lambda result, done: statuses.append((result, done))

        await claim(device)
        await verify_start(device, "any")
        task = device.verify_task
        self.assertIsNotNone(task)
        await task

        self.assertEqual(statuses, [("verify-match", True)])
        self.assertIs(device.verify_task, task)
        await MODULE.FprintDevice.VerifyStop.__wrapped__(device)
        self.assertIsNone(device.verify_task)

    async def test_second_claim_is_rejected(self):
        device = make_device()
        await claim(device)
        with self.assertRaises(MODULE.DBusError) as raised:
            await claim(device)
        self.assertTrue(raised.exception.type.endswith(".AlreadyInUse"))
        await MODULE.FprintDevice.Release.__wrapped__(device)

    async def test_dead_completed_claim_is_reaped_before_replacement(self):
        backend = FakeBackend()
        device = make_device(backend)
        old_sender = MODULE.current_dbus_sender
        try:
            await claim(device)
            first_caller = device.claimed_caller
            await verify_start(device, "any")
            first_task = device.verify_task
            self.assertIsNotNone(first_task)
            await first_task
            self.assertIsNotNone(device.claim_expiry_task)

            first_caller.closed = True
            MODULE.current_dbus_sender = lambda: ":1.101"
            await claim(device)

            self.assertEqual(device.claimed_sender, ":1.101")
            self.assertIsNot(device.claimed_caller, first_caller)
            self.assertTrue(first_caller.closed)
            self.assertIsNone(device.verify_task)
            self.assertEqual(backend.cancel_count, 1)
            await MODULE.FprintDevice.Release.__wrapped__(device)
        finally:
            MODULE.current_dbus_sender = old_sender

    async def test_claim_is_bound_to_exact_dbus_sender(self):
        device = make_device()
        await claim(device)
        pinned = device.claimed_caller
        old = MODULE.current_dbus_sender
        MODULE.current_dbus_sender = lambda: ":1.101"
        try:
            with self.assertRaises(MODULE.DBusError) as raised:
                await verify_start(device, "any")
            self.assertTrue(raised.exception.type.endswith(".PermissionDenied"))
            await device.sender_departed(":1.100")
            self.assertIsNone(device.claimed_user)
            self.assertIsNone(device.claimed_sender)
            self.assertIsNone(device.claimed_caller)
            self.assertIsNone(device.claimed_evidence)
            self.assertTrue(pinned.closed)
        finally:
            MODULE.current_dbus_sender = old

    async def test_claim_revalidates_pinned_process_on_every_scoped_call(self):
        device = make_device()
        await claim(device)
        pinned = device.claimed_caller
        self.assertIsNotNone(pinned)
        pinned.closed = True
        with self.assertRaises(MODULE.DBusError) as raised:
            await verify_start(device, "any")
        self.assertTrue(raised.exception.type.endswith(".PermissionDenied"))

    async def test_claim_revalidates_session_and_account_on_scoped_calls(self):
        device = make_device()
        await claim(device)
        evidence = device.claimed_evidence
        self.assertIsNotNone(evidence)
        evidence.invalid = True
        with self.assertRaises(MODULE.DBusError) as raised:
            await verify_start(device, "any")
        self.assertTrue(raised.exception.type.endswith(".PermissionDenied"))

    async def test_departure_waiting_during_claim_clears_the_new_claim(self):
        collecting = asyncio.Event()
        proceed = asyncio.Event()
        pinned = FakePinnedCaller(":1.100")

        async def delayed_collector(_bus, _sender):
            collecting.set()
            await proceed.wait()
            return pinned

        device = MODULE.FprintDevice(
            FakeBackend(),
            object(),
            delayed_collector,
            fake_claim_evidence_collector,
        )
        claim_task = asyncio.create_task(claim(device))
        await collecting.wait()
        departure_task = asyncio.create_task(device.sender_departed(":1.100"))
        proceed.set()
        await claim_task
        await departure_task
        self.assertIsNone(device.claimed_user)
        self.assertTrue(pinned.closed)

    async def test_concurrent_claims_are_serialized(self):
        collecting = asyncio.Event()
        proceed = asyncio.Event()

        async def delayed_collector(_bus, sender):
            collecting.set()
            await proceed.wait()
            return FakePinnedCaller(sender)

        device = MODULE.FprintDevice(
            FakeBackend(),
            object(),
            delayed_collector,
            fake_claim_evidence_collector,
        )
        first = asyncio.create_task(claim(device))
        await collecting.wait()
        second = asyncio.create_task(claim(device))
        proceed.set()
        await first
        with self.assertRaises(MODULE.DBusError) as raised:
            await second
        self.assertTrue(raised.exception.type.endswith(".AlreadyInUse"))
        await MODULE.FprintDevice.Release.__wrapped__(device)

    async def test_failed_claim_evidence_closes_process_pin(self):
        pinned = FakePinnedCaller(":1.100")

        async def caller_collector(_bus, _sender):
            return pinned

        def evidence_collector(_caller, _username):
            raise MODULE.t2_fprint_claim.FprintClaimError("denied")

        device = MODULE.FprintDevice(
            FakeBackend(), object(), caller_collector, evidence_collector
        )
        with self.assertRaises(MODULE.DBusError) as raised:
            await claim(device)
        self.assertTrue(raised.exception.type.endswith(".PermissionDenied"))
        self.assertTrue(pinned.closed)
        self.assertIsNone(device.claimed_user)

    async def test_unstarted_claim_expires(self):
        old_timeout = MODULE.UNSTARTED_CLAIM_SECONDS
        MODULE.UNSTARTED_CLAIM_SECONDS = 0.001
        try:
            device = make_device()
            await claim(device)
            await asyncio.sleep(0.01)
            self.assertIsNone(device.claimed_user)
        finally:
            MODULE.UNSTARTED_CLAIM_SECONDS = old_timeout

    async def test_verify_stop_cancels_inflight_backend(self):
        started = asyncio.Event()

        class SlowBackend(FakeBackend):
            async def verify_fprint(self, _requested_finger, _live_feedback=None):
                started.set()
                await asyncio.Event().wait()

        backend = SlowBackend()
        device = make_device(backend)
        device.VerifyStatus = lambda _result, _done: None
        await claim(device)
        await verify_start(device, "any")
        self.assertFalse(device.finger_needed)
        await started.wait()
        await MODULE.FprintDevice.VerifyStop.__wrapped__(device)
        self.assertEqual(backend.cancel_count, 1)
        self.assertIsNone(device.verify_task)
        self.assertEqual(backend.cancel_count, 1)
        self.assertFalse(device.finger_present)
        self.assertFalse(device.finger_needed)

    async def test_release_cleans_up_completed_verification(self):
        backend = FakeBackend("verify-no-match")
        device = make_device(backend)
        device.VerifyStatus = lambda _result, _done: None

        await claim(device)
        await verify_start(device, "any")
        await device.verify_task
        await MODULE.FprintDevice.Release.__wrapped__(device)

        self.assertIsNone(device.claimed_user)
        self.assertIsNone(device.verify_task)

    async def test_unattached_enrollment_remains_disabled(self):
        device = make_device()
        await claim(device)
        with self.assertRaises(MODULE.DBusError) as raised:
            await enroll_start(device, "finger-1")
        self.assertTrue(raised.exception.type.endswith(".Internal"))
        self.assertFalse(device.finger_present)
        self.assertFalse(device.finger_needed)
        await MODULE.FprintDevice.Release.__wrapped__(device)

    async def test_attached_enrollment_streams_state_and_is_stoppable(self):
        client = FakeEnrollmentClient()
        device = make_device(enrollment_client=client)
        emitted = []
        device.EnrollStatus = lambda status, done: emitted.append(
            (status, done)
        )
        await claim(device)
        caller = device.claimed_caller
        evidence = device.claimed_evidence
        await enroll_start(device, "finger-1")
        self.assertEqual(
            client.start_arguments, ("finger-1", caller, evidence)
        )
        client.emit(
            MODULE.t2_fprint_enrollment_runtime.EnrollmentUpdate(
                None, False, False, True
            )
        )
        self.assertTrue(device.finger_needed)
        client.emit(
            MODULE.t2_fprint_enrollment_runtime.EnrollmentUpdate(
                "enroll-stage-passed", False, True, False, 23
            )
        )
        client.emit(
            MODULE.t2_fprint_enrollment_runtime.EnrollmentUpdate(
                "enroll-completed", True, False, False, 100
            )
        )
        self.assertEqual(
            emitted,
            [
                ("enroll-stage-passed", False),
                ("enroll-completed", True),
            ],
        )
        self.assertEqual(device.enrollment_progress, 100)
        await MODULE.FprintDevice.EnrollStop.__wrapped__(device)
        self.assertEqual(client.stop_count, 1)
        self.assertIsNone(client.task)
        self.assertFalse(device.finger_present)
        self.assertFalse(device.finger_needed)
        self.assertIsNone(device.enrollment_progress)
        await MODULE.FprintDevice.Release.__wrapped__(device)

    async def test_enrollment_refuses_incomplete_legacy_projection(self):
        backend = FakeBackend()
        backend.projection = MODULE.t2_fprint_runtime.RuntimeProjection(
            (), 2, False
        )
        client = FakeEnrollmentClient()
        device = make_device(backend, client)

        await claim(device)
        with self.assertRaises(MODULE.DBusError) as raised:
            await enroll_start(device, "finger-1")

        self.assertTrue(raised.exception.type.endswith(".Internal"))
        self.assertIn("require migration", raised.exception.text)
        self.assertIsNone(client.start_arguments)
        self.assertIsNotNone(device.claim_expiry_task)
        await MODULE.FprintDevice.Release.__wrapped__(device)

    async def test_legacy_enrollment_request_is_only_forwarded_syntax(self):
        client = FakeEnrollmentClient()
        device = make_device(enrollment_client=client)

        await claim(device)
        caller = device.claimed_caller
        evidence = device.claimed_evidence
        await enroll_start(device, "right-index-finger")

        self.assertEqual(
            client.start_arguments, ("finger-1", caller, evidence)
        )
        await MODULE.FprintDevice.EnrollStop.__wrapped__(device)
        await MODULE.FprintDevice.Release.__wrapped__(device)

    async def test_legacy_enrollment_reaches_real_worker_client(self):
        client = MODULE.t2_fprint_worker_client.EnrollmentWorkerClient()
        device = make_device(enrollment_client=client)
        await claim(device)
        # Kernel identity collection is tested separately on Linux. Keep the
        # actual facade -> worker validation boundary in this portable test.
        caller = mock.Mock(spec=MODULE.t2_dbus_identity.PinnedDBusCaller)
        caller.sender = ":1.100"
        caller.subject = mock.Mock(uid=1000)
        device.claimed_caller = caller
        object.__setattr__(device.claimed_evidence, "account", mock.Mock(linux_uid=1000))
        with mock.patch.object(client, "_supervise", new_callable=AsyncMock) as run:
            await enroll_start(device, "right-index-finger")
            await client.task
            self.assertEqual(run.call_args.args[0], "finger-1")
            await MODULE.FprintDevice.Release.__wrapped__(device)

    async def test_stop_calls_rearm_idle_claim_expiry(self):
        for operation in ("verify", "enroll", "idle-verify", "idle-enroll"):
            with self.subTest(operation=operation), mock.patch.object(
                MODULE, "UNSTARTED_CLAIM_SECONDS", 0.01
            ):
                client = FakeEnrollmentClient()
                device = make_device(enrollment_client=client)
                await claim(device)
                if operation == "verify":
                    device.VerifyFingerSelected = lambda _: None
                    device.VerifyFingerMatched = lambda _: None
                    device.VerifyStatus = lambda *_: None
                    await verify_start(device, "any")
                    await device.verify_task
                elif operation == "enroll":
                    await enroll_start(device, "finger-1")
                stop = (
                    MODULE.FprintDevice.VerifyStop.__wrapped__
                    if operation.endswith("verify")
                    else MODULE.FprintDevice.EnrollStop.__wrapped__
                )
                if operation.startswith("idle-"):
                    with self.assertRaises(MODULE.DBusError):
                        await stop(device)
                else:
                    await stop(device)
                self.assertIsNotNone(device.claim_expiry_task)
                await asyncio.sleep(0.03)
                self.assertIsNone(device.claimed_user)
                # Another client can now acquire the device.
                await claim(device)
                await MODULE.FprintDevice.Release.__wrapped__(device)

    async def test_terminal_update_during_stop_does_not_lose_idle_expiry(self):
        client = FakeEnrollmentClient()
        original_stop = client.stop
        async def stop_with_terminal():
            client.emit(MODULE.t2_fprint_enrollment_runtime.EnrollmentUpdate(
                "enroll-failed", True, False, False
            ))
            return await original_stop()
        client.stop = stop_with_terminal
        device = make_device(enrollment_client=client)
        device.EnrollStatus = lambda *_: None
        with mock.patch.object(MODULE, "UNSTARTED_CLAIM_SECONDS", 0.01):
            await claim(device)
            await enroll_start(device, "finger-1")
            await MODULE.FprintDevice.EnrollStop.__wrapped__(device)
            await asyncio.sleep(0.03)
            self.assertIsNone(device.claimed_user)

    async def test_wrong_stop_preserves_completed_other_operation_expiry(self):
        client = FakeEnrollmentClient()
        device = make_device(enrollment_client=client)
        device.EnrollStatus = lambda *_: None
        with mock.patch.object(MODULE, "COMPLETED_CLAIM_SECONDS", 0.01):
            await claim(device)
            await enroll_start(device, "finger-1")
            client.emit(MODULE.t2_fprint_enrollment_runtime.EnrollmentUpdate(
                "enroll-completed", True, False, False, 100
            ))
            timer = device.claim_expiry_task
            with self.assertRaises(MODULE.DBusError):
                await MODULE.FprintDevice.VerifyStop.__wrapped__(device)
            self.assertIs(device.claim_expiry_task, timer)
            await asyncio.sleep(0.03)
            self.assertIsNone(device.claimed_user)

    async def test_enrollment_refuses_malformed_projection(self):
        backend = FakeBackend()
        backend.enrollment_projection = AsyncMock(return_value={})
        client = FakeEnrollmentClient()
        device = make_device(backend, client)

        await claim(device)
        with self.assertRaises(MODULE.DBusError) as raised:
            await enroll_start(device, "finger-1")

        self.assertTrue(raised.exception.type.endswith(".Internal"))
        self.assertIsNone(client.start_arguments)
        await MODULE.FprintDevice.Release.__wrapped__(device)

    async def test_enrollment_refuses_projection_collection_failure(self):
        backend = FakeBackend()
        backend.enrollment_projection = AsyncMock(
            side_effect=RuntimeError("unavailable")
        )
        client = FakeEnrollmentClient()
        device = make_device(backend, client)

        await claim(device)
        with self.assertRaises(MODULE.DBusError) as raised:
            await enroll_start(device, "finger-1")

        self.assertTrue(raised.exception.type.endswith(".Internal"))
        self.assertIsNone(client.start_arguments)
        await MODULE.FprintDevice.Release.__wrapped__(device)

    async def test_first_native_enrollment_accepts_valid_pre_e4_projection(self):
        backend = MODULE.T2Backend.__new__(MODULE.T2Backend)
        backend.linux_uid = 1000
        backend.operation_lock = asyncio.Lock()
        backend.runtime_projection = AsyncMock(
            side_effect=RuntimeError("E4 authority is not published")
        )
        native = mock.Mock()
        authority = mock.Mock()
        authority.selected.linux_uid = 1000
        client = FakeEnrollmentClient()
        device = make_device(backend, client)

        await claim(device)
        with mock.patch.dict(
            os.environ, {"T2_TOUCHID_AUTHORITY_MODE": "linux-native"}
        ), mock.patch.object(
            MODULE.t2_fprint_worker,
            "native_enrollment_context",
            return_value=(native, {}, authority, None),
        ) as context:
            await enroll_start(device, "finger-1")

        self.assertIsNotNone(client.start_arguments)
        context.assert_called_once_with(1000)
        native._require_fresh_enrollment_state.assert_called_once_with()
        await MODULE.FprintDevice.Release.__wrapped__(device)

    async def test_cancelled_projection_restores_claim_expiry(self):
        entered = asyncio.Event()

        class BlockingBackend(FakeBackend):
            async def enrollment_projection(self):
                entered.set()
                await asyncio.Event().wait()

        client = FakeEnrollmentClient()
        device = make_device(BlockingBackend(), client)
        await claim(device)
        task = asyncio.create_task(enroll_start(device, "finger-1"))
        await entered.wait()

        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task

        self.assertIsNone(client.start_arguments)
        self.assertIsNotNone(device.claim_expiry_task)
        await MODULE.FprintDevice.Release.__wrapped__(device)

    async def test_enrollment_rechecks_operation_after_projection_await(self):
        entered = asyncio.Event()
        release = asyncio.Event()

        class BlockingBackend(FakeBackend):
            async def enrollment_projection(self):
                entered.set()
                await release.wait()
                return self.projection

        backend = BlockingBackend()
        client = FakeEnrollmentClient()
        device = make_device(backend, client)
        device.VerifyStatus = lambda _result, _done: None
        await claim(device)
        task = asyncio.create_task(enroll_start(device, "finger-1"))
        await entered.wait()

        verification = asyncio.create_task(verify_start(device, "any"))
        await asyncio.sleep(0)
        release.set()
        with self.assertRaises(MODULE.DBusError) as raised:
            await task
        await verification

        self.assertTrue(raised.exception.type.endswith(".AlreadyInUse"))
        self.assertIsNone(client.start_arguments)
        await MODULE.FprintDevice.Release.__wrapped__(device)

    async def test_enrollment_is_caller_bound_and_mutually_exclusive(self):
        client = FakeEnrollmentClient()
        device = make_device(
            enrollment_client=client,
            deletion_client=FakeDeletionClient(),
        )
        await claim(device)
        with self.assertRaises(MODULE.DBusError) as raised:
            await enroll_start(device, "any")
        self.assertTrue(raised.exception.type.endswith(".InvalidFingername"))
        await enroll_start(device, "finger-3")
        with self.assertRaises(MODULE.DBusError) as raised:
            await verify_start(device, "any")
        self.assertTrue(raised.exception.type.endswith(".AlreadyInUse"))
        with self.assertRaises(MODULE.DBusError) as raised:
            await delete_finger(device, "finger-3")
        self.assertTrue(raised.exception.type.endswith(".AlreadyInUse"))
        await device.sender_departed(":1.100")
        self.assertEqual(client.stop_count, 1)
        self.assertIsNone(device.claimed_user)

    async def test_terminal_enrollment_claim_expires_after_client_grace(self):
        old_timeout = MODULE.COMPLETED_CLAIM_SECONDS
        MODULE.COMPLETED_CLAIM_SECONDS = 0.001
        try:
            client = FakeEnrollmentClient()
            device = make_device(enrollment_client=client)
            device.EnrollStatus = lambda _status, _done: None
            await claim(device)
            await enroll_start(device, "finger-1")
            client.emit(
                MODULE.t2_fprint_enrollment_runtime.EnrollmentUpdate(
                    "enroll-completed", True, False, False, 100
                )
            )
            await asyncio.sleep(0.01)
            self.assertEqual(client.stop_count, 1)
            self.assertIsNone(device.claimed_user)
            self.assertIsNone(client.task)
        finally:
            MODULE.COMPLETED_CLAIM_SECONDS = old_timeout

    async def test_single_deletion_remains_unattached_by_default(self):
        device = make_device()
        await claim(device)
        with self.assertRaises(MODULE.DBusError) as raised:
            await delete_finger(device, "finger-1")
        self.assertTrue(raised.exception.type.endswith(".PermissionDenied"))
        await MODULE.FprintDevice.Release.__wrapped__(device)

    async def test_attached_single_deletion_requires_fresh_exact_name(self):
        backend = FakeBackend()
        backend.projection = MODULE.t2_fprint_runtime.RuntimeProjection(
            ("finger-1", "finger-2"),
            2,
            True,
        )
        client = FakeDeletionClient()
        device = make_device(backend, deletion_client=client)
        await claim(device)
        caller = device.claimed_caller
        evidence = device.claimed_evidence

        await delete_finger(device, "finger-1")

        self.assertEqual(client.arguments, ("finger-1", caller, evidence))
        self.assertIsNone(device.delete_task)
        self.assertIsNotNone(device.claim_expiry_task)
        await MODULE.FprintDevice.Release.__wrapped__(device)

    async def test_single_deletion_rejects_invalid_absent_and_incomplete_name(self):
        cases = (
            (
                MODULE.t2_fprint_runtime.RuntimeProjection(
                    ("finger-1", "finger-2"),
                    2,
                    True,
                ),
                "any",
                ".InvalidFingername",
            ),
            (
                MODULE.t2_fprint_runtime.RuntimeProjection(
                    ("finger-1", "finger-2"),
                    2,
                    True,
                ),
                "finger-3",
                ".NoEnrolledPrints",
            ),
            (
                MODULE.t2_fprint_runtime.RuntimeProjection(
                    (), 2, False
                ),
                "finger-1",
                ".PrintsNotDeleted",
            ),
        )
        for view, finger_name, error_name in cases:
            backend = FakeBackend()
            backend.projection = view
            client = FakeDeletionClient()
            device = make_device(backend, deletion_client=client)
            await claim(device)
            with self.subTest(finger_name=finger_name), self.assertRaises(
                MODULE.DBusError
            ) as raised:
                await delete_finger(device, finger_name)
            self.assertTrue(raised.exception.type.endswith(error_name))
            self.assertIsNone(client.arguments)
            await MODULE.FprintDevice.Release.__wrapped__(device)

    async def test_single_deletion_accepts_the_final_named_identity(self):
        backend = FakeBackend()
        backend.projection = MODULE.t2_fprint_runtime.RuntimeProjection(
            ("finger-1",), 1, True
        )
        client = FakeDeletionClient()
        device = make_device(backend, deletion_client=client)
        await claim(device)
        caller = device.claimed_caller
        evidence = device.claimed_evidence

        await delete_finger(device, "finger-1")

        self.assertEqual(client.arguments, ("finger-1", caller, evidence))
        await MODULE.FprintDevice.Release.__wrapped__(device)

    async def test_single_deletion_rejects_malformed_client_completion(self):
        backend = FakeBackend()
        backend.projection = MODULE.t2_fprint_runtime.RuntimeProjection(
            ("finger-1", "finger-2"),
            2,
            True,
        )
        client = FakeDeletionClient()
        client.result = object()
        device = make_device(backend, deletion_client=client)
        await claim(device)

        with self.assertRaises(MODULE.DBusError) as raised:
            await delete_finger(device, "finger-1")

        self.assertTrue(raised.exception.type.endswith(".PrintsNotDeleted"))
        await MODULE.FprintDevice.Release.__wrapped__(device)

    async def test_deletion_is_mutually_exclusive_and_disconnect_waits(self):
        backend = FakeBackend()
        backend.projection = MODULE.t2_fprint_runtime.RuntimeProjection(
            ("finger-1", "finger-2"),
            2,
            True,
        )
        client = FakeDeletionClient()
        client.block = True
        device = make_device(backend, deletion_client=client)
        await claim(device)
        task = asyncio.create_task(delete_finger(device, "finger-1"))
        await client.entered.wait()

        with self.assertRaises(MODULE.DBusError) as raised:
            await verify_start(device, "any")
        self.assertTrue(raised.exception.type.endswith(".AlreadyInUse"))
        departure = asyncio.create_task(device.sender_departed(":1.100"))
        await asyncio.sleep(0)
        self.assertFalse(departure.done())
        self.assertIsNotNone(device.claimed_user)

        client.release.set()
        await task
        await departure
        self.assertIsNone(device.claimed_user)
        self.assertIsNone(device.delete_task)

    async def test_cancelled_deletion_projection_restores_bounded_claim(self):
        entered = asyncio.Event()

        class BlockingBackend(FakeBackend):
            async def runtime_projection(self):
                entered.set()
                await asyncio.Event().wait()

        client = FakeDeletionClient()
        device = make_device(
            BlockingBackend(),
            enrollment_client=FakeEnrollmentClient(),
            deletion_client=client,
        )
        await claim(device)
        task = asyncio.create_task(delete_finger(device, "finger-1"))
        await entered.wait()

        with self.assertRaises(MODULE.DBusError) as raised:
            await verify_start(device, "any")
        self.assertTrue(raised.exception.type.endswith(".AlreadyInUse"))
        with self.assertRaises(MODULE.DBusError) as raised:
            await enroll_start(device, "finger-3")
        self.assertTrue(raised.exception.type.endswith(".AlreadyInUse"))

        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task

        self.assertIsNone(device.delete_task)
        self.assertIsNone(client.arguments)
        self.assertIsNotNone(device.claim_expiry_task)
        await MODULE.FprintDevice.Release.__wrapped__(device)

    async def test_cancellation_after_delete_handoff_waits_for_reconciliation(self):
        backend = FakeBackend()
        backend.projection = MODULE.t2_fprint_runtime.RuntimeProjection(
            ("finger-1", "finger-2"),
            2,
            True,
        )
        client = FakeDeletionClient()
        client.block = True
        device = make_device(backend, deletion_client=client)
        await claim(device)
        task = asyncio.create_task(delete_finger(device, "finger-1"))
        await client.entered.wait()

        task.cancel()
        await asyncio.sleep(0)
        self.assertFalse(task.done())
        self.assertIs(device.delete_task, task)

        client.release.set()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertIsNone(device.delete_task)
        self.assertIsNotNone(device.claim_expiry_task)
        await MODULE.FprintDevice.Release.__wrapped__(device)

    async def test_bulk_deletion_stays_fail_closed_with_single_client(self):
        device = make_device(deletion_client=FakeDeletionClient())
        with self.assertRaises(MODULE.DBusError) as raised:
            device.DeleteEnrolledFingers(MODULE.LINUX_USER)
        self.assertTrue(raised.exception.type.endswith(".PermissionDenied"))
        await claim(device)
        with self.assertRaises(MODULE.DBusError) as raised:
            device.DeleteEnrolledFingers2()
        self.assertTrue(raised.exception.type.endswith(".PermissionDenied"))
        await MODULE.FprintDevice.Release.__wrapped__(device)


class VerdictTests(unittest.TestCase):
    def test_accepts_only_explicit_enrolled_identity_match(self):
        result = {
            "match_cleanup_valid": True,
            "match_events": [
                {
                    "event_kind": "match_result",
                    "result_valid": True,
                    "matched": True,
                    "matches_enrolled_identity": True,
                }
            ]
        }
        self.assertEqual(MODULE.verdict_from_result(result), "verify-match")

    def test_unenrolled_identity_fails_closed(self):
        result = {
            "match_cleanup_valid": True,
            "match_events": [
                {
                    "event_kind": "match_result",
                    "result_valid": True,
                    "matched": False,
                    "no_match": True,
                    "matches_enrolled_identity": False,
                }
            ]
        }
        self.assertEqual(MODULE.verdict_from_result(result), "verify-no-match")

    def test_named_match_requires_selected_identity_and_both_attestations(self):
        result = {
            "match_cleanup_valid": True,
            "targeted_match_gate": {
                "finger_name": "finger-1",
                "single_identity_selected": True,
                "same_connection_inventory_stable": True,
                "local_live_reconciled": True,
                "identifiers_redacted": True,
            },
            "targeted_match_post_attestation": {
                "identity_state_unchanged": True,
                "local_components_unchanged": True,
                "per_user_inventory_unchanged": True,
                "global_inventory_unchanged": True,
                "identifiers_redacted": True,
            },
            "match_events": [
                {
                    "event_kind": "match_result",
                    "result_valid": True,
                    "matched": True,
                    "matches_enrolled_identity": True,
                    "matches_selected_identity": True,
                }
            ],
        }
        self.assertEqual(
            MODULE.verdict_from_result(result, "finger-1"),
            "verify-match",
        )
        wrong_identity = {
            **result,
            "match_events": [
                {
                    "event_kind": "match_result",
                    "result_valid": True,
                    "matched": True,
                    "matches_enrolled_identity": True,
                    "matches_selected_identity": False,
                }
            ],
        }
        with self.assertRaises(RuntimeError):
            MODULE.verdict_from_result(wrong_identity, "finger-1")

    def test_named_match_missing_or_rebound_attestation_is_error(self):
        base = {
            "targeted_match_gate": {
                "finger_name": "finger-3",
                "single_identity_selected": True,
                "same_connection_inventory_stable": True,
                "local_live_reconciled": True,
                "identifiers_redacted": True,
            },
            "targeted_match_post_attestation": {
                "identity_state_unchanged": True,
                "local_components_unchanged": True,
                "per_user_inventory_unchanged": True,
                "global_inventory_unchanged": True,
                "identifiers_redacted": True,
            },
            "match_events": [],
        }
        for changed in (
            {**base, "targeted_match_gate": None},
            {**base, "targeted_match_post_attestation": None},
            base,
        ):
            with self.subTest(), self.assertRaises(RuntimeError):
                MODULE.verdict_from_result(changed, "finger-1")

    def test_resolved_any_returns_only_attested_canonical_name(self):
        result = {
            "resolved_any_match_gate": {
                "identity_count": 2,
                "complete_named_inventory": True,
                "all_identities_selected": True,
                "same_connection_inventory_stable": True,
                "local_live_reconciled": True,
                "identifiers_redacted": True,
            },
            "resolved_any_match_post_attestation": {
                "identity_state_unchanged": True,
                "local_components_unchanged": True,
                "per_user_inventory_unchanged": True,
                "global_inventory_unchanged": True,
                "identifiers_redacted": True,
            },
            "match_events": [
                {
                    "event_kind": "match_result",
                    "matched": True,
                    "matches_enrolled_identity": True,
                    "matched_finger_name_present": True,
                    "matched_finger_name": "finger-1",
                }
            ],
        }
        self.assertEqual(
            MODULE.resolved_any_finger_from_result(result), "finger-1"
        )
        negative = {
            **result,
            "match_events": [
                {"event_kind": "match_result", "matched": False}
            ],
        }
        self.assertIsNone(MODULE.resolved_any_finger_from_result(negative))

    def test_resolved_any_malformed_name_or_attestation_is_error(self):
        gate = {
            "identity_count": 2,
            "complete_named_inventory": True,
            "all_identities_selected": True,
            "same_connection_inventory_stable": True,
            "local_live_reconciled": True,
            "identifiers_redacted": True,
        }
        post = {
            "identity_state_unchanged": True,
            "local_components_unchanged": True,
            "per_user_inventory_unchanged": True,
            "global_inventory_unchanged": True,
            "identifiers_redacted": True,
        }
        for candidate in (
            {"resolved_any_match_gate": None, "match_events": []},
            {
                "resolved_any_match_gate": gate,
                "resolved_any_match_post_attestation": post,
                "match_events": [
                    {
                        "event_kind": "match_result",
                        "matched": True,
                        "matches_enrolled_identity": True,
                        "matched_finger_name_present": True,
                        "matched_finger_name": "any",
                    }
                ],
            },
        ):
            with self.subTest(), self.assertRaises(RuntimeError):
                MODULE.resolved_any_finger_from_result(candidate)

    def test_missing_or_explicit_no_match_fails_closed(self):
        with self.assertRaises(RuntimeError):
            MODULE.verdict_from_result(
                {"match_cleanup_valid": True, "match_events": []}
            )
        self.assertEqual(
            MODULE.verdict_from_result(
                {
                    "match_cleanup_valid": True,
                    "match_events": [
                        {
                            "event_kind": "match_result",
                            "result_valid": True,
                            "matched": False,
                            "no_match": True,
                        }
                    ],
                }
            ),
            "verify-no-match",
        )

    def test_rejected_or_malformed_result_is_an_error(self):
        with self.assertRaises(RuntimeError):
            MODULE.verdict_from_result({"match_rejected": True})
        with self.assertRaises(RuntimeError):
            MODULE.verdict_from_result([])
        with self.assertRaises(RuntimeError):
            MODULE.verdict_from_result({"match_events": {}})


class BackendRecoveryTests(unittest.IsolatedAsyncioTestCase):
    async def test_backend_cancel_terminates_unbounded_native_owner(self):
        backend = MODULE.T2Backend.__new__(MODULE.T2Backend)
        process = mock.Mock(returncode=None)
        process.wait = AsyncMock(return_value=0)
        backend.process = process

        await backend.cancel()

        process.terminate.assert_called_once_with()
        process.wait.assert_awaited_once_with()
        process.kill.assert_not_called()

    async def test_native_standard_verification_requests_first_verdict(self):
        backend = MODULE.T2Backend.__new__(MODULE.T2Backend)
        backend.linux_uid = 1000
        backend.project_dir = Path("/opt/t2-touchid")
        backend.match_seconds = 15
        backend.process = None
        stdout = asyncio.StreamReader()
        stdout.feed_data(
            b'{"configured_identity_records_reconciled":true,'
            b'"bridge_os_transaction_released_after_match":true,'
            b'"termination_requested":false}'
        )
        stdout.feed_eof()
        stderr = asyncio.StreamReader()
        stderr.feed_eof()
        process = mock.Mock(returncode=0, stdout=stdout, stderr=stderr)
        process.wait = AsyncMock(return_value=0)
        with mock.patch.object(
            MODULE.asyncio,
            "create_subprocess_exec",
            AsyncMock(return_value=process),
        ) as spawn:
            await backend._run_native_match("finger-2")
        arguments = spawn.await_args.args
        self.assertIn("--stop-on-first-verdict", arguments)
        self.assertIn("--match-finger-name", arguments)

    async def test_compatibility_projection_prepares_live_catacomb_first(self):
        backend = MODULE.T2Backend.__new__(MODULE.T2Backend)
        backend.linux_uid = 1000
        backend.project_dir = Path("/opt/t2-touchid")
        backend.process = None
        backend.runtime_authority = mock.Mock(
            return_value=mock.Mock(origin=MODULE.COMPATIBILITY_AUTHORITY)
        )
        backend.discover = AsyncMock(return_value=50001)
        backend._run_probe = AsyncMock(return_value={})
        process = mock.Mock(returncode=1)
        process.communicate = AsyncMock(return_value=(b"", b"projection failed"))
        with mock.patch.object(
            MODULE.asyncio,
            "create_subprocess_exec",
            AsyncMock(return_value=process),
        ):
            with self.assertRaisesRegex(RuntimeError, "projection failed"):
                await backend.runtime_projection()
        backend._run_probe.assert_awaited_once_with(50001, prepare_only=True)

    async def test_compatibility_probe_restores_canonical_managed_catacomb(self):
        backend = MODULE.T2Backend.__new__(MODULE.T2Backend)
        backend.linux_uid = 1000
        backend.project_dir = Path("/opt/t2-touchid")
        backend.catacomb_root = Path("/var/lib/t2-touchid/catacomb")
        backend.biolockout_state_dir = Path("/var/lib/t2-touchid/biolockout")
        backend.match_seconds = 15
        backend.process = None
        backend.runtime_authority = mock.Mock(
            return_value=mock.Mock(origin=MODULE.COMPATIBILITY_AUTHORITY)
        )
        stdout = asyncio.StreamReader()
        stdout.feed_data(b"{}")
        stdout.feed_eof()
        stderr = asyncio.StreamReader()
        stderr.feed_eof()
        process = mock.Mock(returncode=0, stdout=stdout, stderr=stderr)
        process.wait = AsyncMock(return_value=0)
        with mock.patch.object(
            MODULE.asyncio,
            "create_subprocess_exec",
            AsyncMock(return_value=process),
        ) as spawn:
            self.assertEqual(
                await backend._run_probe(50001, prepare_only=True), {}
            )
        arguments = spawn.await_args.args
        self.assertIn("--identity-list", arguments)
        root = arguments.index("--load-native-catacomb-root")
        self.assertEqual(arguments[root + 1], "/var/lib/t2-touchid/catacomb")
        authority = arguments.index("--compatibility-authority-linux-uid")
        self.assertEqual(arguments[authority + 1], "1000")
        self.assertNotIn("--load-catacomb-archive", arguments)

    def test_adaptive_sync_service_is_static_and_default_off(self):
        root = MODULE_PATH.parents[1]
        unit = (
            root / "systemd/system/t2-touchid-adaptive-sync.service"
        ).read_text(encoding="utf-8")
        self.assertIn("Type=oneshot", unit)
        self.assertIn("ExecStartPre=/usr/bin/sleep 2", unit)
        self.assertIn(
            "ExecStart=/usr/local/sbin/t2-touchid-manage "
            "sync-user-catacomb "
            "--acknowledge-adaptive-template-persistence "
            "--acknowledge-local-catacomb-persistence",
            unit,
        )
        self.assertNotIn("[Install]", unit)
        config = (root / "t2-touchid.conf.example").read_text(encoding="utf-8")
        self.assertIn("T2_TOUCHID_AUTO_SYNC_ADAPTIVE=0", config)
        installer = (root / "install.sh").read_text(encoding="utf-8")
        self.assertIn(
            "ensure_config_default T2_TOUCHID_AUTO_SYNC_ADAPTIVE 0",
            installer,
        )

    def test_fprintd_sandbox_exposes_only_the_configured_home_binding(self):
        root = MODULE_PATH.parents[1]
        unit = (root / "systemd/system/fprintd.service").read_text(
            encoding="utf-8"
        )
        installer = (root / "install.sh").read_text(encoding="utf-8")
        uninstaller = (root / "uninstall.sh").read_text(encoding="utf-8")
        self.assertIn("ProtectHome=tmpfs", unit)
        self.assertNotIn("ProtectHome=true", unit)
        self.assertIn("BindReadOnlyPaths=%s", installer)
        self.assertIn("05-account-home.conf", installer)
        self.assertIn("05-account-home.conf", uninstaller)
        adaptive = (
            root / "systemd/system/t2-touchid-adaptive-sync.service"
        ).read_text(encoding="utf-8")
        self.assertIn("ProtectHome=tmpfs", adaptive)
        self.assertNotIn("ProtectHome=yes", adaptive)
        self.assertIn("for service in fprintd t2-touchid-adaptive-sync", installer)
        self.assertIn(
            "t2-touchid-adaptive-sync.service.d/05-account-home.conf",
            uninstaller,
        )
        self.assertIn("Environment=SUDO_UID=%s", installer)

    async def test_adaptive_sync_dispatch_is_explicit_and_exact(self):
        backend = MODULE.T2Backend.__new__(MODULE.T2Backend)
        backend.auto_sync_adaptive = False
        backend.adaptive_sync_tasks = set()
        backend._request_adaptive_sync = AsyncMock()
        backend.schedule_adaptive_sync()
        backend._request_adaptive_sync.assert_not_called()

        backend.auto_sync_adaptive = True
        backend.schedule_adaptive_sync()
        await asyncio.gather(*tuple(backend.adaptive_sync_tasks))
        backend._request_adaptive_sync.assert_awaited_once_with()

    async def test_adaptive_sync_requests_only_the_static_systemd_unit(self):
        backend = MODULE.T2Backend.__new__(MODULE.T2Backend)
        process = mock.Mock()
        process.communicate = AsyncMock(return_value=(b"", b""))
        process.returncode = 0
        with mock.patch.object(
            MODULE.asyncio,
            "create_subprocess_exec",
            AsyncMock(return_value=process),
        ) as spawn:
            await backend._request_adaptive_sync()
        spawn.assert_awaited_once_with(
            "/usr/bin/systemctl",
            "start",
            "--no-block",
            "t2-touchid-adaptive-sync.service",
            stdout=MODULE.asyncio.subprocess.DEVNULL,
            stderr=MODULE.asyncio.subprocess.PIPE,
        )

    async def test_runtime_policy_authenticates_every_request_against_all(self):
        backend = MODULE.T2Backend.__new__(MODULE.T2Backend)
        backend.operation_lock = asyncio.Lock()
        backend.runtime_projection = AsyncMock()
        backend.verify = AsyncMock(return_value=("verify-match", {}))

        backend.runtime_projection.return_value = MODULE.t2_fprint_runtime.RuntimeProjection(
            ("finger-1", "finger-2"),
            2,
            True,
        )
        await backend.verify_fprint("finger-1")
        backend.verify.assert_awaited_once_with(
            target_finger=None, resolve_any_finger=True, live_feedback=None
        )

        backend.verify.reset_mock()
        backend.runtime_projection.return_value = MODULE.t2_fprint_runtime.RuntimeProjection(
            (), 2, False
        )
        with self.assertRaises(RuntimeError):
            await backend.verify_fprint("finger-1")
        backend.verify.assert_not_awaited()

        backend.verify.reset_mock()
        backend.runtime_projection.return_value = MODULE.t2_fprint_runtime.RuntimeProjection(
            ("finger-1", "finger-2"),
            2,
            True,
        )
        await backend.verify_fprint("any")
        backend.verify.assert_awaited_once_with(
            target_finger=None, resolve_any_finger=True, live_feedback=None
        )

    async def test_compatibility_transport_failure_is_never_replayed(self):
        with tempfile.TemporaryDirectory() as directory:
            port_file = Path(directory) / "port"
            port_file.write_text("50001\n")
            old_port_file = os.environ.get("T2_TOUCHID_PORT_FILE")
            old_linux_user = MODULE.LINUX_USER
            os.environ["T2_TOUCHID_PORT_FILE"] = str(port_file)
            MODULE.LINUX_USER = "test-user"
            try:
                with mock.patch.object(
                    MODULE.pwd,
                    "getpwnam",
                    return_value=mock.Mock(pw_uid=1000),
                ):
                    backend = MODULE.T2Backend(Path(directory), 1)
            finally:
                MODULE.LINUX_USER = old_linux_user
                if old_port_file is None:
                    os.environ.pop("T2_TOUCHID_PORT_FILE", None)
                else:
                    os.environ["T2_TOUCHID_PORT_FILE"] = old_port_file

        backend.notify_finger_requested = AsyncMock()
        backend.notify_feedback = AsyncMock()
        backend.runtime_authority = mock.Mock(
            return_value=mock.Mock(origin=MODULE.COMPATIBILITY_AUTHORITY)
        )
        backend._run_probe = AsyncMock(
            side_effect=RuntimeError("ambiguous transport failure")
        )

        async def discover_fresh():
            backend.port = 50002
            backend.port_from_cache = False
            return backend.port

        original_discover = backend.discover
        calls = 0

        async def discover():
            nonlocal calls
            calls += 1
            if calls == 1:
                return await original_discover()
            return await discover_fresh()

        backend.discover = discover
        with self.assertRaisesRegex(RuntimeError, "ambiguous"):
            await backend.verify()
        self.assertEqual(backend._run_probe.await_count, 1)
        self.assertEqual(calls, 1)

    async def test_valid_negative_match_does_not_rediscover(self):
        backend = MODULE.T2Backend.__new__(MODULE.T2Backend)
        backend.port = 50001
        backend.port_from_cache = True
        backend.notify_finger_requested = AsyncMock()
        backend.notify_feedback = AsyncMock()
        backend.runtime_authority = mock.Mock(
            return_value=mock.Mock(origin=MODULE.COMPATIBILITY_AUTHORITY)
        )
        backend.discover = AsyncMock(return_value=50001)
        backend._run_probe = AsyncMock(
            return_value={
                "match_cleanup_valid": True,
                "match_events": [
                    {
                        "event_kind": "match_result",
                        "result_valid": True,
                        "matched": False,
                        "no_match": True,
                    }
                ]
            }
        )
        verdict, _result = await backend.verify()
        self.assertEqual(verdict, "verify-no-match")
        backend.discover.assert_awaited_once()

    async def test_native_authority_uses_native_owner_without_compatibility_probe(self):
        backend = MODULE.T2Backend.__new__(MODULE.T2Backend)
        backend.notify_finger_requested = AsyncMock()
        backend.notify_feedback = AsyncMock()
        backend.runtime_authority = mock.Mock(
            return_value=mock.Mock(origin=MODULE.NATIVE_AUTHORITY)
        )
        backend._run_native_match = AsyncMock(
            return_value={
                "match_events": [
                    {
                        "event_kind": "match_result",
                        "result_valid": True,
                        "matched": False,
                        "no_match": True,
                    }
                ],
                "match_cleanup_valid": True,
            }
        )
        backend._run_probe = AsyncMock()
        backend.discover = AsyncMock()
        verdict, _result = await backend.verify(target_finger=None)
        self.assertEqual(verdict, "verify-no-match")
        backend._run_native_match.assert_awaited_once_with(None, False, None)
        backend._run_probe.assert_not_awaited()
        backend.discover.assert_not_awaited()


class NativeEnrollmentActivationTests(unittest.TestCase):
    def test_default_arguments_construct_no_worker_client(self):
        self.assertIsNone(
            MODULE.enrollment_client_for_arguments(
                argparse.Namespace(enable_native_enrollment=False)
            )
        )

    def test_explicit_process_flag_constructs_exact_worker_client(self):
        sentinel = object()
        with mock.patch.object(
            MODULE.t2_fprint_worker_client,
            "EnrollmentWorkerClient",
            return_value=sentinel,
        ) as factory:
            result = MODULE.enrollment_client_for_arguments(
                argparse.Namespace(enable_native_enrollment=True)
            )
        self.assertIs(result, sentinel)
        factory.assert_called_once_with()

    def test_malformed_activation_and_installed_service_fail_closed(self):
        for args in (object(), argparse.Namespace(), argparse.Namespace(
            enable_native_enrollment=1
        )):
            with self.subTest(args=args), self.assertRaises(RuntimeError):
                MODULE.enrollment_client_for_arguments(args)
        unit = (
            MODULE_PATH.parents[1]
            / "systemd/system/fprintd.service"
        ).read_text(encoding="utf-8")
        self.assertIn("--enable-native-enrollment", unit)

    def test_research_dropin_enables_only_the_explicit_process_flag(self):
        root = MODULE_PATH.parents[1]
        candidate = (
            root
            / "systemd/research/fprintd.service.d/10-native-enrollment.conf"
        ).read_text(encoding="utf-8")
        directives = [
            line
            for line in candidate.splitlines()
            if line and not line.startswith("#")
        ]
        self.assertEqual(
            directives,
            [
                "[Service]",
                "ExecStart=",
                "ExecStart=/opt/t2-touchid/.venv/bin/python "
                "/opt/t2-touchid/src/t2-fprintd.py "
                "--enable-native-enrollment",
            ],
        )


class NativeDeletionActivationTests(unittest.TestCase):
    def test_default_arguments_construct_no_deletion_client(self):
        self.assertIsNone(
            MODULE.deletion_client_for_arguments(
                argparse.Namespace(enable_native_deletion=False)
            )
        )

    def test_explicit_process_flag_constructs_exact_deletion_client(self):
        sentinel = object()
        with mock.patch.object(
            MODULE.t2_fprint_delete_worker_client,
            "DeletionWorkerClient",
            return_value=sentinel,
        ) as factory:
            result = MODULE.deletion_client_for_arguments(
                argparse.Namespace(enable_native_deletion=True)
            )
        self.assertIs(result, sentinel)
        factory.assert_called_once_with()

    def test_malformed_activation_and_installed_service_fail_closed(self):
        for args in (
            object(),
            argparse.Namespace(),
            argparse.Namespace(enable_native_deletion=1),
        ):
            with self.subTest(args=args), self.assertRaises(RuntimeError):
                MODULE.deletion_client_for_arguments(args)
        unit = (
            MODULE_PATH.parents[1] / "systemd/system/fprintd.service"
        ).read_text(encoding="utf-8")
        self.assertIn("--enable-native-deletion", unit)

    def test_combined_research_dropin_requires_both_explicit_flags(self):
        root = MODULE_PATH.parents[1]
        candidate = (
            root
            / "systemd/research/fprintd.service.d/20-native-identity-management.conf"
        ).read_text(encoding="utf-8")
        directives = [
            line
            for line in candidate.splitlines()
            if line and not line.startswith("#")
        ]
        self.assertEqual(
            directives,
            [
                "[Service]",
                "ExecStart=",
                "ExecStart=/opt/t2-touchid/.venv/bin/python "
                "/opt/t2-touchid/src/t2-fprintd.py "
                "--enable-native-enrollment --enable-native-deletion",
            ],
        )
        installer = (root / "install.sh").read_text(encoding="utf-8")
        self.assertNotIn("10-native-enrollment.conf", installer)
        self.assertNotIn("20-native-identity-management.conf", installer)


if __name__ == "__main__":
    unittest.main()
