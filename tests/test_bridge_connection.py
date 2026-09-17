import json
import plistlib
import socket
import struct
import sys
import threading
import unittest
import uuid
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import t2_bridge_connection as connection
import t2_bridge_wire as wire


GENERATION = str(uuid.UUID(int=31))


def send_frame(sock: socket.socket, frame_type: int, value: object) -> None:
    if frame_type == wire.TYPE_HELO:
        body = json.dumps(value).encode()
    else:
        body = plistlib.dumps(value, fmt=plistlib.FMT_BINARY, sort_keys=False)
    sock.sendall(wire.HEADER.pack(wire.MAGIC, 1, frame_type, len(body)) + body)


def receive_message(sock: socket.socket) -> list[object]:
    frame_type, body = wire.receive_frame(sock)
    if frame_type != wire.TYPE_MESSAGE:
        raise AssertionError("expected message")
    value = plistlib.loads(body)
    if type(value) is not list:
        raise AssertionError("expected list")
    return value


def reply_to(sock: socket.socket, request: list[object], value: object) -> None:
    send_frame(sock, wire.TYPE_MESSAGE, [1, True, request[2], value])


class ScriptedPeer:
    def __init__(self, script) -> None:
        self.client, self.peer = socket.socketpair()
        self.error: BaseException | None = None

        def run() -> None:
            try:
                send_frame(
                    self.peer,
                    wire.TYPE_HELO,
                    {
                        "BridgeXPCVersion": 39,
                        "BootSessionUUID": str(uuid.UUID(int=32)),
                    },
                )
                frame_type, _body = wire.receive_frame(self.peer)
                if frame_type != wire.TYPE_HELO:
                    raise AssertionError("client did not send HELO")
                version = receive_message(self.peer)
                reply_to(self.peer, version, [0, 3])
                set_version = receive_message(self.peer)
                if set_version[3] != [10, 2]:
                    raise AssertionError("client selected the wrong API version")
                reply_to(self.peer, set_version, [0])
                script(self.peer)
            except BaseException as error:
                self.error = error
            finally:
                self.peer.close()

        self.thread = threading.Thread(target=run)
        self.thread.start()

    def finish(self) -> None:
        self.thread.join(timeout=2)
        if self.thread.is_alive():
            raise AssertionError("scripted peer did not finish")
        if self.error is not None:
            raise self.error


class BridgeConnectionTests(unittest.TestCase):
    def test_deferred_client_selection_follows_only_protocol_preflight(self):
        client, peer_socket = socket.socketpair()
        peer_error: list[BaseException] = []

        def run_peer() -> None:
            try:
                send_frame(
                    peer_socket,
                    wire.TYPE_HELO,
                    {
                        "BridgeXPCVersion": 39,
                        "BootSessionUUID": str(uuid.UUID(int=32)),
                    },
                )
                frame_type, _body = wire.receive_frame(peer_socket)
                self.assertEqual(frame_type, wire.TYPE_HELO)
                version = receive_message(peer_socket)
                reply_to(peer_socket, version, [0, 3])
                protocol = receive_message(peer_socket)
                self.assertEqual(protocol[3][0:2], [3, 0])
                self.assertEqual(
                    wire.BIOMETRIC_COMMAND_HEADER.unpack_from(protocol[3][2]),
                    (wire.BIOMETRIC_COMMAND_MAGIC, 0x01, 1, 0),
                )
                reply_to(peer_socket, protocol, [0, b"\x02\x00\x00\x00"])
                component = receive_message(peer_socket)
                self.assertEqual(component[3][0:2], [3, 0])
                header = wire.BIOMETRIC_COMMAND_HEADER.unpack_from(component[3][2])
                self.assertEqual(
                    header, (wire.BIOMETRIC_COMMAND_MAGIC, 0x31, 1, 0)
                )
                self.assertEqual(
                    component[3][2][8:], struct.pack("<I", 0xFFFFFFFF)
                )
                reply_to(peer_socket, component, [0])
                set_version = receive_message(peer_socket)
                self.assertEqual(set_version[3], [10, 2])
                reply_to(peer_socket, set_version, [0])
            except BaseException as error:
                peer_error.append(error)
            finally:
                peer_socket.close()

        thread = threading.Thread(target=run_peer)
        thread.start()
        lease = connection.BridgeConnectionLease(
            client,
            connection_generation=GENERATION,
            defer_client_version=True,
        )
        self.assertEqual(lease.client_version, 0)
        with self.assertRaisesRegex(
            connection.BridgeConnectionError, "service preflight commands"
        ):
            lease.biometric_command(
                0x38,
                version=1,
                value=0,
                data=b"\x00" * 4,
                output_capacity=16,
            )
        self.assertEqual(lease.state, connection.BridgeConnectionState.ACTIVE)
        self.assertEqual(
            lease.biometric_command(
                0x01,
                version=1,
                value=0,
                data=b"",
                output_capacity=4,
            ),
            ([0, b"\x02\x00\x00\x00"], []),
        )
        self.assertEqual(
            lease.biometric_command(
                0x31,
                version=1,
                value=0,
                data=struct.pack("<I", 0xFFFFFFFF),
                output_capacity=0,
            ),
            ([0], []),
        )
        self.assertEqual(lease.select_client_version(), 2)
        lease.close()
        thread.join(timeout=2)
        self.assertFalse(thread.is_alive())
        if peer_error:
            raise peer_error[0]

    def test_initialization_command_and_async_event_share_one_socket(self):
        raw_event = b"event-data"

        def script(peer: socket.socket) -> None:
            command = receive_message(peer)
            inner = command[3][2]
            self.assertEqual(command[3][0:2], [3, 0])
            self.assertEqual(
                wire.BIOMETRIC_COMMAND_HEADER.unpack_from(inner),
                (wire.BIOMETRIC_COMMAND_MAGIC, 0x51, 2, 0),
            )
            self.assertEqual(inner[8:], b"input")
            reply_to(peer, command, [0, b"output"])
            send_frame(peer, wire.TYPE_MESSAGE, [1, False, "EVENT-1", raw_event])
            acknowledgement = receive_message(peer)
            self.assertEqual(acknowledgement, [1, True, "EVENT-1", [0]])

        peer = ScriptedPeer(script)
        lease = connection.BridgeConnectionLease(
            peer.client, connection_generation=GENERATION
        )
        self.assertEqual(lease.client_version, 2)
        self.assertEqual(lease.peer_boot_uuid, str(uuid.UUID(int=32)))
        self.assertEqual(
            lease.biometric_command(
                0x51,
                version=2,
                value=0,
                data=b"input",
                output_capacity=40,
            ),
            ([0, b"output"], []),
        )
        self.assertEqual(lease.next_service_event(), raw_event)
        lease.close()
        peer.finish()

    def test_interleaved_command_event_is_acknowledged_and_returned(self):
        event = [9, 0, b"service-event", None, None]

        def script(peer: socket.socket) -> None:
            command = receive_message(peer)
            send_frame(peer, wire.TYPE_MESSAGE, [1, False, "CALLBACK", event])
            self.assertEqual(
                receive_message(peer), [1, True, "CALLBACK", [0]]
            )
            reply_to(peer, command, [0, None])

        peer = ScriptedPeer(script)
        lease = connection.BridgeConnectionLease(
            peer.client, connection_generation=GENERATION
        )
        reply, events = lease.biometric_command(
            3, version=2, value=0, data=memoryview(bytes(68)), output_capacity=0
        )
        self.assertEqual(reply, [0, None])
        self.assertEqual(events, [event])
        lease.close()
        peer.finish()

    def test_idle_event_poll_consumes_nothing_and_keeps_generation_active(self):
        release_peer = threading.Event()

        def script(_peer: socket.socket) -> None:
            if not release_peer.wait(timeout=2):
                raise AssertionError("test did not release peer")

        peer = ScriptedPeer(script)
        lease = connection.BridgeConnectionLease(
            peer.client, connection_generation=GENERATION
        )
        self.assertIsNone(lease.wait_service_event(0.01))
        self.assertEqual(lease.state, connection.BridgeConnectionState.ACTIVE)
        self.assertEqual(lease.connection_generation, GENERATION)
        lease.close()
        release_peer.set()
        peer.finish()

    def test_disconnect_poisons_and_generation_becomes_unavailable(self):
        def script(peer: socket.socket) -> None:
            receive_message(peer)

        peer = ScriptedPeer(script)
        lease = connection.BridgeConnectionLease(
            peer.client, connection_generation=GENERATION
        )
        with self.assertRaisesRegex(connection.BridgeConnectionError, "poisoned"):
            lease.biometric_command(
                1, version=2, value=0, data=b"", output_capacity=4
            )
        self.assertEqual(lease.state, connection.BridgeConnectionState.POISONED)
        with self.assertRaises(connection.BridgeConnectionError):
            _generation = lease.connection_generation
        peer.finish()

    def test_invalid_command_is_rejected_before_socket_use(self):
        def script(_peer: socket.socket) -> None:
            return

        peer = ScriptedPeer(script)
        lease = connection.BridgeConnectionLease(
            peer.client, connection_generation=GENERATION
        )
        with self.assertRaises(connection.BridgeConnectionError):
            lease.biometric_command(
                -1, version=2, value=0, data=b"", output_capacity=0
            )
        self.assertEqual(lease.state, connection.BridgeConnectionState.ACTIVE)
        lease.close()
        peer.finish()

    def test_constructor_rejects_noncanonical_generation(self):
        left, right = socket.socketpair()
        try:
            with self.assertRaises(connection.BridgeConnectionError):
                connection.BridgeConnectionLease(
                    left, connection_generation=GENERATION.upper()
                )
        finally:
            left.close()
            right.close()


class BridgeWireBoundTests(unittest.TestCase):
    def test_request_with_events_caps_callback_flood(self):
        client, peer = socket.socketpair()
        client.settimeout(2)
        peer.settimeout(2)
        errors: list[BaseException] = []

        def run_peer() -> None:
            try:
                request = receive_message(peer)
                self.assertEqual(request[0], 1)
                self.assertIs(request[1], False)
                for index in range(wire.MAX_SERVICE_CALLBACKS + 1):
                    send_frame(
                        peer,
                        wire.TYPE_MESSAGE,
                        [1, False, f"cb-{index}", ["event", index]],
                    )
                    try:
                        receive_message(peer)
                    except (TimeoutError, OSError, EOFError):
                        return
            except BaseException as error:
                errors.append(error)
            finally:
                peer.close()

        thread = threading.Thread(target=run_peer)
        thread.start()
        try:
            with self.assertRaisesRegex(ValueError, "flood"):
                wire.request_with_events(client, ["payload"])
        finally:
            client.close()
            thread.join(timeout=2)
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
