#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Collect only the bridgeOS unified-log archive through sysdiagnose."""

import argparse
import asyncio
import gzip
import hashlib
import os
from pathlib import Path
import sys
from typing import Any, Iterator

from t2_rsd import discover_peer, service_port


UPDATE_SERVICE = "com.apple.bridgeOSUpdated"
SYSDIAGNOSE_SERVICE = "com.apple.sysdiagnose.remote.trusted"
REMOTE_XPC_WRAPPER_SIZE = 24
REQUEST_SYSDIAGNOSE = 1
REQUEST_GET_IN_PROGRESS_ARCHIVE = 11


def _file_transfers(value: Any) -> Iterator[Any]:
    from pymobiledevice3.remote.xpc_message import FileTransferType

    if isinstance(value, FileTransferType):
        yield value
    elif isinstance(value, dict):
        for child in value.values():
            yield from _file_transfers(child)
    elif isinstance(value, list):
        for child in value:
            yield from _file_transfers(child)


async def _current_build(scoped_host: str, peer: dict[str, Any], timeout: float) -> str:
    from pymobiledevice3.remote.remotexpc import RemoteXPCConnection

    connection = RemoteXPCConnection(
        (scoped_host, service_port(peer, UPDATE_SERVICE))
    )
    try:
        await asyncio.wait_for(connection.connect(), timeout)
        response = await asyncio.wait_for(
            connection.send_receive_request({"Command": "QueryUpdateState"}),
            timeout,
        )
    finally:
        await connection.close()
    results = response.get("Results") if isinstance(response, dict) else None
    build = results.get("CurrentOSBuildVersion") if isinstance(results, dict) else None
    if response.get("Response") != "QueryUpdateState" or not isinstance(build, str):
        raise RuntimeError("bridgeOS returned an invalid update-state response")
    return build


async def _receive_archive(connection: Any, transfer_size: int, output: Path) -> tuple[int, str]:
    """Receive the one announced archive, removing its stream wrapper."""

    from pymobiledevice3.exceptions import ProtocolError
    from pymobiledevice3.remote.remotexpc import RemoteXPCConnection

    async def route_file_chunks(self: Any) -> None:
        try:
            while self._file_chunk_queues:
                frame = await self._receive_next_data_frame()
                if "END_STREAM" in frame.flags:
                    continue
                queue = self._file_chunk_queues.get(frame.stream_id)
                if queue is not None:
                    queue.put_nowait(frame.data)
                    continue
                # This service duplicates its requested reply on stream 3.
                # The file payload is exclusively on stream 2.
                if frame.stream_id == 3:
                    continue
                raise ProtocolError(
                    f"unexpected sysdiagnose file-transfer stream {frame.stream_id}"
                )
        except asyncio.CancelledError:
            raise
        except BaseException as error:
            for queue in self._file_chunk_queues.values():
                queue.put_nowait(error)

    original_router = RemoteXPCConnection._route_file_chunks
    RemoteXPCConnection._route_file_chunks = route_file_chunks
    temporary = output.with_name(output.name + ".part")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    digest = hashlib.sha256()
    payload_size = 0
    prefix = bytearray()
    try:
        with os.fdopen(descriptor, "wb") as stream:
            # The service's FILE_TX count excludes the leading wrapper, while
            # pymobiledevice3 counts every byte read from stream 2.
            async for chunk in connection.iter_file_chunks(
                transfer_size + REMOTE_XPC_WRAPPER_SIZE
            ):
                if len(prefix) < REMOTE_XPC_WRAPPER_SIZE:
                    needed = REMOTE_XPC_WRAPPER_SIZE - len(prefix)
                    prefix.extend(chunk[:needed])
                    chunk = chunk[needed:]
                if chunk:
                    stream.write(chunk)
                    digest.update(chunk)
                    payload_size += len(chunk)
            stream.flush()
            os.fsync(stream.fileno())
        if len(prefix) != REMOTE_XPC_WRAPPER_SIZE:
            raise RuntimeError("sysdiagnose transfer omitted its RemoteXPC wrapper")
        if payload_size != transfer_size:
            raise RuntimeError(
                f"sysdiagnose payload length mismatch: {payload_size} != {transfer_size}"
            )
        with gzip.open(temporary, "rb") as archive:
            while archive.read(1024 * 1024):
                pass
        os.replace(temporary, output)
        return payload_size, digest.hexdigest()
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    finally:
        RemoteXPCConnection._route_file_chunks = original_router


async def collect(args: argparse.Namespace) -> tuple[int, str, str]:
    try:
        from pymobiledevice3.remote.remotexpc import RemoteXPCConnection
        from pymobiledevice3.remote.xpc_message import XpcUInt64Type
    except ImportError as error:
        raise RuntimeError(
            "run with the repository virtual environment (.venv/bin/python)"
        ) from error

    scoped_host, peer = await discover_peer(
        args.host, args.interface, args.probe_timeout, args.concurrency
    )
    build = await _current_build(scoped_host, peer, args.request_timeout)
    if build != args.expected_build:
        raise RuntimeError(
            f"refusing sysdiagnose: expected build {args.expected_build}, got {build}"
        )
    port = service_port(peer, SYSDIAGNOSE_SERVICE)
    request = {
        "MSG_TYPE": XpcUInt64Type(1),
        "REQUEST_TYPE": XpcUInt64Type(
            REQUEST_GET_IN_PROGRESS_ARCHIVE
            if args.recover_in_progress
            else REQUEST_SYSDIAGNOSE
        ),
    }
    if not args.recover_in_progress:
        request.update({
        "initiatedByRemoteHost": True,
        "shouldCreateTarBall": True,
        "shouldDisplayBannerUI": False,
        "shouldDisplayTarBall": False,
        "shouldRunLogCopyTasks": False,
        "shouldRunLogGenerationTasks": False,
        "shouldRunTimeSensitiveTasks": False,
        "shouldRunOSLogArchive": True,
        "shouldRemoveTemporaryDirectory": True,
        "disableUIFeedback": True,
        })
    connection = RemoteXPCConnection((scoped_host, port))
    try:
        await asyncio.wait_for(connection.connect(), args.request_timeout)
        await connection.send_request(request, wanting_reply=True)
        response = await asyncio.wait_for(
            connection.receive_response(), args.collection_timeout
        )
        if not isinstance(response, dict) or int(response.get("RESPONSE_TYPE", 0)) != 1:
            raise RuntimeError("bridgeOS sysdiagnose request failed")
        transfers = list(_file_transfers(response))
        if len(transfers) != 1:
            raise RuntimeError("bridgeOS did not announce exactly one log archive")
        size, digest = await asyncio.wait_for(
            _receive_archive(connection, transfers[0].transfer_size, args.output),
            args.collection_timeout,
        )
    finally:
        await connection.close()
    return size, digest, build


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=os.environ.get("T2_TOUCHID_HOST"))
    parser.add_argument("--interface", default=os.environ.get("T2_TOUCHID_INTERFACE"))
    parser.add_argument("--expected-build", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--recover-in-progress",
        action="store_true",
        help="retrieve the existing server-side archive without starting sysdiagnose",
    )
    parser.add_argument("--probe-timeout", type=float, default=0.15)
    parser.add_argument("--request-timeout", type=float, default=5.0)
    parser.add_argument("--collection-timeout", type=float, default=900.0)
    parser.add_argument("--concurrency", type=int, default=512)
    args = parser.parse_args()

    if os.geteuid() != 0:
        parser.error("run as root so the private archive cannot be exposed")
    if not args.host or not args.interface:
        parser.error("set --host/--interface or the matching environment variables")
    if not args.output.is_absolute() or args.output.exists():
        parser.error("--output must be an unused absolute path")
    parent = args.output.parent
    parent_stat = parent.stat()
    if parent_stat.st_uid != 0 or parent_stat.st_gid != 0 or parent_stat.st_mode & 0o077:
        parser.error("--output parent must be root:root with no group/other access")
    if not 1 <= args.concurrency <= 2048:
        parser.error("--concurrency must be between 1 and 2048")
    if min(args.probe_timeout, args.request_timeout, args.collection_timeout) <= 0:
        parser.error("timeouts must be positive")

    try:
        size, digest, build = asyncio.run(collect(args))
    except (OSError, RuntimeError, asyncio.TimeoutError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
    print(f"bridgeos_build={build}")
    print(f"archive_bytes={size}")
    print(f"archive_sha256={digest}")


if __name__ == "__main__":
    main()
