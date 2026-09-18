# SPDX-License-Identifier: GPL-2.0-only
"""Diagnostic file transfers must not discard gzip bytes or await phantom bytes."""

import asyncio
from contextlib import suppress
import gzip
import hashlib
import importlib.util
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
spec = importlib.util.spec_from_file_location(
    "bridgeos_oslog", Path(__file__).resolve().parents[1] / "src/t2-bridgeos-oslog.py"
)
oslog = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oslog)


class Transfer:
    def __init__(self, chunks, *, fail_if_overread=True):
        self.chunks = chunks
        self.closed = False
        self.fail_if_overread = fail_if_overread

    async def iter_file_chunks(self, total_size):
        try:
            for chunk in self.chunks:
                yield chunk
            if self.fail_if_overread:
                raise AssertionError("waited beyond the announced archive")
        finally:
            self.closed = True


class SysdiagnoseTransferTests(unittest.IsolatedAsyncioTestCase):
    async def test_final_data_frame_is_consumed_before_end_of_stream(self):
        from pymobiledevice3.remote.remotexpc import RemoteXPCConnection

        payload = gzip.compress(b"synthetic final-frame archive")

        class FramedTransfer:
            def __init__(self):
                self._file_chunk_queues = {}
                self.frames = iter([
                    SimpleNamespace(stream_id=3, flags=set(), data=b"control reply"),
                    SimpleNamespace(stream_id=2, flags={"END_STREAM"}, data=payload),
                ])

            async def _receive_next_data_frame(self):
                frame = next(self.frames, None)
                if frame is None:
                    await asyncio.Future()
                return frame

            async def iter_file_chunks(self, total_size):
                queue = self._file_chunk_queues[2] = asyncio.Queue()
                router = asyncio.create_task(RemoteXPCConnection._route_file_chunks(self))
                try:
                    while True:
                        item = await queue.get()
                        if isinstance(item, BaseException):
                            raise item
                        yield item
                finally:
                    self._file_chunk_queues.clear()
                    router.cancel()
                    with suppress(asyncio.CancelledError):
                        await router

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "logs.gz"
            await asyncio.wait_for(
                oslog._receive_archive(FramedTransfer(), len(payload), output), 2
            )
            self.assertEqual(output.read_bytes(), payload)

    async def test_bare_and_wrapped_gzip_finish_at_announced_payload_length(self):
        from pymobiledevice3.remote.xpc_message import XpcFlags, XpcWrapper, XpcUInt64Type

        payload = gzip.compress(b"synthetic log archive" * 100)
        wrapper = XpcWrapper.build({
            "size": 0,
            "flags": XpcFlags.FILE_TX_STREAM_REQUEST | XpcFlags.ALWAYS_SET,
            "payload": None,
        })
        for prefix in (b"", wrapper):
            for split in (False, True):
                with self.subTest(wrapped=bool(prefix), split=split):
                    data = prefix + payload
                    chunks = [data[i:i + 1] for i in range(len(data))] if split else [data]
                    connection = Transfer(chunks)
                    with tempfile.TemporaryDirectory() as directory:
                        output = Path(directory) / "logs.gz"
                        size, digest = await oslog._receive_archive(
                            connection, XpcUInt64Type(len(payload)), output
                        )
                        self.assertEqual(output.read_bytes(), payload)
                        self.assertEqual(size, len(payload))
                        self.assertEqual(digest, hashlib.sha256(payload).hexdigest())
                        self.assertFalse(output.with_name("logs.gz.part").exists())
                    self.assertTrue(connection.closed)

    async def test_invalid_truncated_and_oversized_transfers_do_not_publish(self):
        from pymobiledevice3.remote.remotexpc import RemoteXPCConnection

        payload = gzip.compress(b"synthetic log archive" * 100)
        corrupted = payload[:-1] + bytes([payload[-1] ^ 1])
        for data in (bytes(len(payload)), payload[:-4], payload + b"extra", corrupted):
            with self.subTest(size=len(data)):
                connection = Transfer([data], fail_if_overread=False)
                router = RemoteXPCConnection._route_file_chunks
                with tempfile.TemporaryDirectory() as directory:
                    output = Path(directory) / "logs.gz"
                    with self.assertRaises((RuntimeError, EOFError, gzip.BadGzipFile)):
                        await oslog._receive_archive(connection, len(payload), output)
                    self.assertFalse(output.exists())
                    self.assertFalse(output.with_name("logs.gz.part").exists())
                self.assertIs(RemoteXPCConnection._route_file_chunks, router)
                self.assertTrue(connection.closed)
