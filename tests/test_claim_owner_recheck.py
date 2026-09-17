#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Behavioral claim-owner recheck after the off-thread revalidation await."""

import asyncio
import importlib.util
import threading
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "src/t2-fprintd.py"
SPEC = importlib.util.spec_from_file_location("t2_fprintd_claim_recheck", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)
MODULE.current_dbus_sender = lambda: ":1.1"


class FakePinnedCaller:
    def __init__(self, sender):
        self.sender = sender
        self.closed = False

    def verify(self):
        if self.closed:
            raise MODULE.t2_dbus_identity.DBusIdentityError("closed")

    def close(self):
        self.closed = True


class BlockingClaimEvidence(MODULE.t2_fprint_claim.ClaimEvidence):
    def __init__(self, started, release):
        super().__init__("test", 1000, None, None, None, None, None)
        self.started = started
        self.release = release

    def revalidate(self, caller):
        caller.verify()
        self.started.set()
        if not self.release.wait(5):
            raise TimeoutError("revalidation was not released")


class FakeClaimEvidence(MODULE.t2_fprint_claim.ClaimEvidence):
    def __init__(self):
        super().__init__("test", 1000, None, None, None, None, None)

    def revalidate(self, caller):
        caller.verify()


class FakeBus:
    def __init__(self):
        self.sent = []

    def send(self, message):
        self.sent.append(message)


def make_device(identity_bus=None):
    return MODULE.FprintDevice(
        object(),
        identity_bus or object(),
        lambda _bus, sender: FakePinnedCaller(sender),
        lambda _caller, _username: FakeClaimEvidence(),
    )


class ClaimOwnerRecheckTests(unittest.IsolatedAsyncioTestCase):
    async def test_stale_sender_is_rejected_after_blocked_revalidate(self):
        started = threading.Event()
        release = threading.Event()
        device = make_device()
        device.claimed_user = MODULE.LINUX_USER
        device.claimed_sender = ":1.1"
        device.claimed_caller = FakePinnedCaller(":1.1")
        device.claimed_evidence = BlockingClaimEvidence(started, release)
        device.claim_generation = 1

        task = asyncio.create_task(device._require_claim_owner())
        for _ in range(50):
            if started.is_set():
                break
            await asyncio.sleep(0.05)
        self.assertTrue(started.is_set())
        device.claimed_sender = ":1.2"
        device.claimed_caller = FakePinnedCaller(":1.2")
        device.claimed_evidence = FakeClaimEvidence()
        device.claim_generation = 2
        release.set()
        with self.assertRaises(MODULE.DBusError) as raised:
            await task
        self.assertIn("PermissionDenied", raised.exception.type)
        self.assertEqual(device.claimed_sender, ":1.2")

    async def test_matching_owner_still_succeeds_after_revalidate(self):
        started = threading.Event()
        release = threading.Event()
        device = make_device()
        owner = FakePinnedCaller(":1.1")
        device.claimed_user = MODULE.LINUX_USER
        device.claimed_sender = ":1.1"
        device.claimed_caller = owner
        device.claimed_evidence = BlockingClaimEvidence(started, release)
        device.claim_generation = 1

        task = asyncio.create_task(device._require_claim_owner())
        for _ in range(50):
            if started.is_set():
                break
            await asyncio.sleep(0.05)
        self.assertTrue(started.is_set())
        release.set()
        await task
        self.assertIs(device.claimed_caller, owner)

    def test_property_change_is_unicast_to_claimed_sender(self):
        bus = FakeBus()
        device = make_device(identity_bus=bus)
        device.claimed_sender = ":1.1"
        device.finger_present = False
        device.finger_needed = False
        device._set_finger_state(True, False)
        self.assertEqual(len(bus.sent), 1)
        self.assertEqual(bus.sent[0].destination, ":1.1")
        self.assertEqual(bus.sent[0].member, "PropertiesChanged")


if __name__ == "__main__":
    unittest.main()
