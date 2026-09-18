#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Hardware-free regressions for the Bridge/RSD responsiveness fixes.

Real loopback TCP tests check socket options and exact wire traffic, not timing
thresholds. Deterministic fragmented-read tests cover timeout/error boundaries.
"""

import asyncio
from collections import deque
import json
from pathlib import Path
import plistlib
import socket
import sys
import tempfile
from types import ModuleType
import unittest
from unittest.mock import AsyncMock, Mock, patch


SOURCE = Path(__file__).resolve().parents[1] / "src"
if str(SOURCE) not in sys.path:
    sys.path.insert(0, str(SOURCE))

import t2_bridge_wire as wire
import t2_rsd as rsd


class ScriptedSocket:
    """Return precisely controlled stream fragments, EOF, or I/O errors."""

    def __init__(self, reads=(), *, family=socket.AF_UNIX):
        self.reads = deque(reads)
        self.family = family
        self.sent = []
        self.options = []

    def recv(self, length):
        if not self.reads:
            raise AssertionError("unexpected extra read")
        value = self.reads.popleft()
        if isinstance(value, BaseException):
            raise value
        if len(value) > length:
            self.reads.appendleft(value[length:])
            value = value[:length]
        return value

    def setsockopt(self, *option):
        self.options.append(option)

    def sendall(self, data):
        self.sent.append(data)


def message_frame(envelope):
    body = plistlib.dumps(envelope, fmt=plistlib.FMT_BINARY, sort_keys=False)
    return wire.HEADER.pack(
        wire.MAGIC, wire.PROTOCOL_VERSION, wire.TYPE_MESSAGE, len(body)
    ) + body


class BridgeResponsivenessTests(unittest.TestCase):
    def test_nodelay_is_set_before_helo_on_both_tcp_families(self):
        for family in (socket.AF_INET, socket.AF_INET6):
            with self.subTest(family=family):
                sock = ScriptedSocket(family=family)
                sock.sendall = Mock(side_effect=lambda _: self.assertEqual(
                    sock.options, [(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)]
                ))
                wire.send_helo(sock, 2)
                sock.sendall.assert_called_once()

    def test_helo_over_real_socketpair(self):
        left, right = socket.socketpair()
        with left, right:
            left.settimeout(1)
            right.settimeout(1)
            wire.send_helo(left, 2)
            kind, body = wire.receive_frame(right)
        self.assertEqual(kind, wire.TYPE_HELO)
        self.assertEqual(json.loads(body), {
            "MaxSupportedProtocolVersion": 1,
            "OSBuild": "Linux",
            "BridgeXPCVersion": 2,
            "ProcessName": "t2-touchid-probe",
        })

    def test_real_loopback_tcp_option_and_followup_bytes(self):
        for family, address in ((socket.AF_INET, ("127.0.0.1", 0)),
                                (socket.AF_INET6, ("::1", 0))):
            with self.subTest(family=family):
                with socket.socket(family, socket.SOCK_STREAM) as listener:
                    try:
                        listener.bind(address)
                    except OSError as error:
                        if family == socket.AF_INET6:
                            self.skipTest(f"IPv6 loopback unavailable: {error}")
                        raise
                    listener.listen(1)
                    listener.settimeout(1)
                    with socket.socket(family, socket.SOCK_STREAM) as client:
                        client.settimeout(1)
                        client.connect(listener.getsockname())
                        peer, _address = listener.accept()
                        with peer:
                            peer.settimeout(1)
                            wire.send_helo(client, 2)
                            self.assertNotEqual(client.getsockopt(
                                socket.IPPROTO_TCP, socket.TCP_NODELAY
                            ), 0)
                            wire.notify(client, [12, True])
                            wire.send_message(client, [1, False, "next", [0]])
                            kind, _body = wire.receive_frame(peer)
                            self.assertEqual(kind, wire.TYPE_HELO)
                            self.assertEqual(wire.receive_envelope(peer), [
                                1, False, wire.BRIDGE_NO_REPLY_ID, [12, True]
                            ])
                            self.assertEqual(wire.receive_envelope(peer), [
                                1, False, "next", [0]
                            ])

    def test_idle_header_timeout_is_still_retryable(self):
        expected = [1, False, "callback", [9]]
        sock = ScriptedSocket((TimeoutError(), message_frame(expected)))
        with self.assertRaises(TimeoutError):
            wire.receive_envelope(sock)
        self.assertEqual(wire.receive_envelope(sock), expected)

    def test_partial_header_timeout_is_not_idle(self):
        sock = ScriptedSocket((b"\x92", TimeoutError()))
        with self.assertRaises(ConnectionError) as raised:
            wire.receive_frame(sock)
        self.assertNotIsInstance(raised.exception, TimeoutError)

    def test_body_timeout_after_header_is_not_idle(self):
        frame = message_frame([1, False, "callback", [9]])
        for partial_body in (b"", frame[wire.HEADER.size:wire.HEADER.size + 5]):
            with self.subTest(body_length=len(partial_body)):
                reads = [frame[:wire.HEADER.size]]
                if partial_body:
                    reads.append(partial_body)
                reads.append(TimeoutError())
                with self.assertRaises(ConnectionError) as raised:
                    wire.receive_envelope(ScriptedSocket(reads))
                self.assertNotIsInstance(raised.exception, TimeoutError)

    def test_every_fragmentation_boundary_preserves_the_frame(self):
        expected = [1, False, "callback", [9, b"synthetic"]]
        frame = message_frame(expected)
        for split in range(1, len(frame)):
            with self.subTest(split=split):
                sock = ScriptedSocket((frame[:split], frame[split:]))
                self.assertEqual(wire.receive_envelope(sock), expected)

    def test_partial_eof_is_always_fatal(self):
        frame = message_frame([1, False, "callback", [9]])
        for prefix in (b"", frame[:3], frame[:wire.HEADER.size], frame[:-1]):
            with self.subTest(size=len(prefix)):
                reads = ([prefix] if prefix else []) + [b""]
                with self.assertRaises(EOFError):
                    wire.receive_envelope(ScriptedSocket(reads))

    def test_frame_magic_version_and_size_guards_remain(self):
        headers = (
            (wire.MAGIC ^ 1, wire.PROTOCOL_VERSION, wire.TYPE_MESSAGE, 0),
            (wire.MAGIC, 99, wire.TYPE_MESSAGE, 0),
            (wire.MAGIC, wire.PROTOCOL_VERSION, wire.TYPE_MESSAGE,
             wire.MAX_FRAME_BODY + 1),
        )
        for values in headers:
            with self.subTest(values=values), self.assertRaises(ValueError):
                wire.receive_frame(ScriptedSocket((wire.HEADER.pack(*values),)))

    def test_malformed_envelope_is_rejected_before_any_ack(self):
        invalid = (
            [True, False, "callback", [9]],
            [1.0, False, "callback", [9]],
            [2, False, "callback", [9]],
            [1, 0, "callback", [9]],
            [1, 1, "reply", [0]],
            [1, False, "", [9]],
            [1, False, b"callback", [9]],
            [1, False, "callback"],
        )
        for envelope in invalid:
            with self.subTest(envelope=envelope):
                sock = ScriptedSocket((message_frame(envelope),))
                with self.assertRaises(ValueError):
                    wire.receive_envelope(sock)
                self.assertEqual(sock.sent, [])
                sock = ScriptedSocket((message_frame(envelope),))
                with self.assertRaises(ValueError):
                    wire.request_with_events(sock, [0])
                self.assertEqual(len(sock.sent), 1)  # Request, never callback ACK.

    def test_callbacks_acknowledged_before_correlated_reply(self):
        sock = ScriptedSocket((
            message_frame([1, False, "callback", [9, b"synthetic"]]),
            message_frame([1, True, "REPLY", [0]]),
        ))
        with patch.object(wire.uuid, "uuid4", return_value="REPLY"):
            reply, events = wire.request_with_events(sock, [0])
        self.assertEqual(reply, [0])
        self.assertEqual(events, [[9, b"synthetic"]])
        self.assertEqual(len(sock.sent), 2)
        self.assertEqual(wire.receive_envelope(ScriptedSocket((sock.sent[1],))),
                         [1, True, "callback", [0]])

    def test_mismatched_reply_and_callback_flood_still_fail(self):
        with self.assertRaisesRegex(ValueError, "does not match"):
            wire.request_with_events(ScriptedSocket((
                message_frame([1, True, "wrong", [0]]),
            )), [0])
        callback = message_frame([1, False, "callback", [9]])
        with patch.object(wire, "MAX_SERVICE_CALLBACKS", 1):
            with self.assertRaisesRegex(ValueError, "flood"):
                wire.request_with_events(ScriptedSocket((callback, callback)), [0])
        with patch.object(wire, "MAX_SERVICE_CALLBACK_BYTES", 1):
            with self.assertRaisesRegex(ValueError, "flood"):
                wire.request_with_events(ScriptedSocket((callback,)), [0])


class RsdResponsivenessTests(unittest.IsolatedAsyncioTestCase):
    HEADER = b"\0\0\x0c\x04\0\0\0\0\0"

    async def probe(self, pieces, *, timeout=0.2):
        loop = asyncio.get_running_loop()
        sock = Mock()
        with (
            patch.object(rsd.socket, "socket", return_value=sock),
            patch.object(loop, "sock_connect", new_callable=AsyncMock),
            patch.object(loop, "sock_recv", new_callable=AsyncMock,
                         side_effect=pieces) as receive,
        ):
            result = await rsd._probe_port("::1", 50000, 0,
                                           asyncio.Semaphore(1), timeout)
        sock.close.assert_called_once()
        return result, receive

    async def test_fragmented_header_is_a_candidate_at_every_split(self):
        for split in range(1, 9):
            with self.subTest(split=split):
                result, receive = await self.probe((
                    self.HEADER[:split], self.HEADER[split:]
                ))
                self.assertEqual(result, 50000)
                self.assertEqual(receive.await_count, 2)

    async def test_bytewise_header_and_whole_header(self):
        for pieces in ((self.HEADER,), tuple(bytes([b]) for b in self.HEADER)):
            with self.subTest(fragments=len(pieces)):
                result, _receive = await self.probe(pieces)
                self.assertEqual(result, 50000)

    async def test_incomplete_header_eof_or_error_is_not_a_candidate(self):
        for ending in (b"", TimeoutError(), OSError("test failure")):
            with self.subTest(ending=type(ending).__name__):
                result, _receive = await self.probe((self.HEADER[:4], ending))
                self.assertIsNone(result)

    async def test_other_frame_or_nonzero_stream_is_not_a_candidate(self):
        for header in (b"\0\0\0\x01\0\0\0\0\0",
                       b"\0\0\0\x04\0\0\0\0\x01"):
            result, _receive = await self.probe((header,))
            self.assertIsNone(result)

    async def test_header_has_one_timeout_budget_not_one_per_fragment(self):
        loop = asyncio.get_running_loop()
        sock = Mock()
        real_wait_for = asyncio.wait_for
        waits = []

        async def checked_wait_for(awaitable, timeout):
            waits.append(timeout)
            return await real_wait_for(awaitable, timeout)

        with (
            patch.object(rsd.socket, "socket", return_value=sock),
            patch.object(loop, "sock_connect", new_callable=AsyncMock),
            patch.object(loop, "sock_recv", new_callable=AsyncMock,
                         side_effect=tuple(bytes([b]) for b in self.HEADER)),
            patch.object(rsd.asyncio, "wait_for", side_effect=checked_wait_for),
        ):
            self.assertEqual(await rsd._probe_port(
                "::1", 50000, 0, asyncio.Semaphore(1), 0.2
            ), 50000)
        self.assertEqual(waits, [0.2, 0.2])  # Connect, then complete header.
        sock.close.assert_called_once()

    async def test_cancel_closes_socket_and_releases_concurrency_slot(self):
        loop = asyncio.get_running_loop()
        entered = asyncio.Event()
        semaphore = asyncio.Semaphore(1)
        sock = Mock()

        async def blocked_receive(*_args):
            entered.set()
            await asyncio.Future()

        with (
            patch.object(rsd.socket, "socket", return_value=sock),
            patch.object(loop, "sock_connect", new_callable=AsyncMock),
            patch.object(loop, "sock_recv", side_effect=blocked_receive),
        ):
            task = asyncio.create_task(rsd._probe_port(
                "::1", 50000, 0, semaphore, 5
            ))
            await asyncio.wait_for(entered.wait(), 1)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        sock.close.assert_called_once()
        self.assertFalse(semaphore.locked())


class RsdPeerFreshnessTests(unittest.IsolatedAsyncioTestCase):
    async def test_hint_is_revalidated_on_every_request(self):
        peers = [
            {"Services": {"test": {"Port": 50001}}},
            {"Services": {"test": {"Port": 50002}}},
        ]
        instances = []

        class PeerConnection:
            def __init__(self, endpoint):
                self.endpoint = endpoint
                self.connect = AsyncMock()
                self.send_device_handshake = AsyncMock()
                self.receive_response = AsyncMock(return_value=peers[len(instances)])
                self.close = AsyncMock()
                instances.append(self)

        remote = ModuleType("pymobiledevice3.remote.remotexpc")
        remote.RemoteXPCConnection = PeerConnection
        with (
            patch.dict(sys.modules, {"pymobiledevice3.remote.remotexpc": remote}),
            patch.object(rsd, "_load_hint", return_value=50000),
            patch.object(rsd, "_probe_port", new_callable=AsyncMock) as probe,
        ):
            first = await rsd.discover_peer("::1", "lo", 0.2, 4)
            second = await rsd.discover_peer("::1", "lo", 0.2, 4)
        self.assertEqual(first, ("::1%lo", peers[0]))
        self.assertEqual(second, ("::1%lo", peers[1]))
        probe.assert_not_called()
        self.assertEqual(len(instances), 2)
        for connection in instances:
            self.assertEqual(connection.endpoint, ("::1%lo", 50000))
            connection.connect.assert_awaited_once()
            connection.send_device_handshake.assert_awaited_once()
            connection.receive_response.assert_awaited_once()
            connection.close.assert_awaited_once()

    async def test_stale_hint_falls_back_and_returns_only_a_validated_peer(self):
        instances = []
        peer = {"Services": {"test": {"Port": 50002}}}

        class PeerConnection:
            def __init__(self, endpoint):
                self.endpoint = endpoint
                self.connect = AsyncMock()
                self.send_device_handshake = AsyncMock()
                self.receive_response = AsyncMock(return_value=(
                    {"Services": {}} if endpoint[1] == 50000 else peer
                ))
                self.close = AsyncMock()
                instances.append(self)

        remote = ModuleType("pymobiledevice3.remote.remotexpc")
        remote.RemoteXPCConnection = PeerConnection

        async def candidate(_host, port, *_args):
            return port

        with (
            patch.dict(sys.modules, {"pymobiledevice3.remote.remotexpc": remote}),
            patch.object(rsd, "_load_hint", return_value=50000),
            patch.object(rsd, "FIRST_DYNAMIC_PORT", 50000),
            patch.object(rsd, "LAST_DYNAMIC_PORT", 50001),
            patch.object(rsd.socket, "if_nametoindex", return_value=1),
            patch.object(rsd, "_probe_port", side_effect=candidate),
            patch.object(rsd, "_save_hint") as save,
        ):
            result = await rsd.discover_peer("::1", "lo", 0.2, 1)
        self.assertEqual(result, ("::1%lo", peer))
        self.assertEqual([connection.endpoint[1] for connection in instances],
                         [50000, 50001])
        for connection in instances:
            connection.close.assert_awaited_once()
        save.assert_called_once_with("::1", "lo", 50001)


class RsdBoundaryTests(unittest.TestCase):
    def test_exact_integer_and_decimal_string_ports_remain_supported(self):
        for port in (49152, 65535, "49152", "65535"):
            self.assertEqual(rsd.service_port(
                {"Services": {"test": {"Port": port}}}, "test"
            ), int(port))

    def test_xpc_integer_wrappers_normalize_to_a_plain_int(self):
        # The pinned pymobiledevice3 decoder returns these int subclasses.
        class XpcInt64Type(int):
            pass

        class XpcUInt64Type(int):
            pass

        for kind in (XpcInt64Type, XpcUInt64Type):
            result = rsd.service_port({"Services": {"test": {
                "Port": kind(50000)
            }}}, "test")
            self.assertEqual(result, 50000)
            self.assertIs(type(result), int)

    def test_lossy_or_ambiguous_ports_are_rejected(self):
        for port in (50000.9, 50000.0, True, False, b"50000", " 50000",
                     "+50000", "５００００", "50000.0", None, [], {},
                     "9" * 5000, 49151, 65536):
            with self.subTest(port_type=type(port).__name__), self.assertRaises(RuntimeError):
                rsd.service_port({"Services": {"test": {"Port": port}}}, "test")

    def test_malformed_peer_shape_produces_typed_discovery_error(self):
        for peer in (None, [], {}, {"Services": None}, {"Services": []},
                     {"Services": {"test": []}}):
            with self.subTest(peer=peer), self.assertRaises(RuntimeError):
                rsd.service_port(peer, "test")

    def test_failed_hint_cleanup_cannot_mask_successful_discovery(self):
        with tempfile.TemporaryDirectory() as temporary:
            hint = Path(temporary) / "rsd-endpoint.json"
            with (
                patch.object(rsd, "RSD_HINT", hint),
                patch.object(rsd.os, "replace", side_effect=OSError("test replace")),
                patch.object(rsd.os, "unlink", side_effect=OSError("test unlink")),
            ):
                rsd._save_hint("::1", "lo", 50000)

    def test_hint_roundtrip_is_scoped_and_still_only_a_port(self):
        with tempfile.TemporaryDirectory() as temporary:
            hint = Path(temporary) / "rsd-endpoint.json"
            with patch.object(rsd, "RSD_HINT", hint):
                rsd._save_hint("::1", "lo", 50000)
                self.assertEqual(rsd._load_hint("::1", "lo"), 50000)
                self.assertIsNone(rsd._load_hint("::2", "lo"))
                self.assertIsNone(rsd._load_hint("::1", "other"))
                self.assertEqual(set(json.loads(hint.read_text())),
                                 {"host", "interface", "port"})


if __name__ == "__main__":
    unittest.main()
