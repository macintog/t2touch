# SPDX-License-Identifier: GPL-2.0-only
"""Exercise real Unix-socket handoff without opening any hardware device."""

from pathlib import Path
import socket
import struct
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import t2_preparation_lease as lease


class PreparationLeaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        # Non-root test runners own this fixture directory and both peers.
        for name in ("_private_root", "_root_peer"):
            p = patch.object(lease, name)
            p.start()
            self.addCleanup(p.stop)
        p = patch.object(lease, "_socket_info", side_effect=lambda p: p.stat())
        p.start()
        self.addCleanup(p.stop)
        self.released = Mock()
        self.owner = lease.IdleOwner(self.released, self.root)
        self.addCleanup(self.owner.close)

    def test_release_ack_follows_cleanup(self):
        server = threading.Thread(target=self.owner.service)
        server.start()
        try:
            self.assertTrue(lease.release_idle_owner(self.root))
            self.released.assert_called_once()
        finally:
            server.join(2)
        self.assertFalse(server.is_alive())

    def test_stale_sockets_do_not_hide_live_owner_after_thirty_two_entries(self):
        for index in range(40):
            stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            stale.bind(str(self.root / f"000-stale-{index}.sock"))
            stale.close()
        server = threading.Thread(target=self.owner.service)
        server.start()
        try:
            self.assertTrue(lease.release_idle_owner(self.root))
        finally:
            server.join(2)
        self.assertFalse(server.is_alive())
        self.released.assert_called_once()
        self.assertEqual(list(self.root.glob("000-stale-*")), [])

    def test_departed_requester_does_not_release_idle_state(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.connect(str(self.owner.path))
            client.sendall(b"R")
        self.owner.service()
        self.released.assert_not_called()

    def test_invalid_request_never_releases(self):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.connect(str(self.owner.path))
            client.sendall(b"X")
            self.owner.service()
        self.released.assert_not_called()

    def test_active_owner_is_not_interrupted(self):
        with patch.object(lease, "TIMEOUT", .01):
            self.assertFalse(lease.release_idle_owner(self.root))
        self.owner.service()
        self.released.assert_not_called()

    def test_non_root_peer_is_rejected(self):
        peer = Mock()
        peer.getsockopt.return_value = struct.pack("3i", 123, 1000, 1000)
        # Test the real credential validator, independently of fixture peers.
        with self.assertRaises(PermissionError):
            self.real_root_peer(peer)

    real_root_peer = staticmethod(lease._root_peer)
