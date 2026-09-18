#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Minimal, identifier-safe Remote Service Discovery helpers for the T2 link."""

import asyncio
import json
import os
from pathlib import Path
import socket
import stat
import tempfile
from typing import Any


FIRST_DYNAMIC_PORT = 49152
LAST_DYNAMIC_PORT = 65535
HTTP2_SETTINGS = 4
RSD_HINT = Path("/run/t2-touchid/rsd-endpoint.json")


def _private_hint_directory() -> bool:
    try:
        info = RSD_HINT.parent.stat(follow_symlinks=False)
        return (
            stat.S_ISDIR(info.st_mode)
            and info.st_uid == os.geteuid()
            and not info.st_mode & 0o077
        )
    except OSError:
        return False


def _load_hint(host: str, interface: str) -> int | None:
    """Read a private routing hint, never cached service or identity authority."""
    if not _private_hint_directory():
        return None
    try:
        descriptor = os.open(RSD_HINT, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_mode & 0o077
                or info.st_nlink != 1
                or info.st_size > 1024
            ):
                return None
            value = json.loads(stream.read(1025))
        if (
            isinstance(value, dict)
            and value.get("host") == host
            and value.get("interface") == interface
            and type(value.get("port")) is int
            and FIRST_DYNAMIC_PORT <= value["port"] <= LAST_DYNAMIC_PORT
        ):
            return value["port"]
    except (OSError, ValueError):
        pass
    return None


def _save_hint(host: str, interface: str, port: int) -> None:
    """Best-effort per-boot hint; discovery works when caching is unavailable."""
    if not _private_hint_directory():
        return
    temporary = None
    try:
        descriptor, temporary = tempfile.mkstemp(prefix=".rsd-", dir=RSD_HINT.parent)
        with os.fdopen(descriptor, "w") as stream:
            json.dump({"host": host, "interface": interface, "port": port}, stream)
        os.replace(temporary, RSD_HINT)
    except OSError:
        pass
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary)
            except OSError:
                pass  # A best-effort hint must not invalidate live discovery.


async def _probe_port(
    host: str,
    port: int,
    scope_id: int,
    semaphore: asyncio.Semaphore,
    timeout: float,
) -> int | None:
    async with semaphore:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock.setblocking(False)
        try:
            loop = asyncio.get_running_loop()
            await asyncio.wait_for(
                loop.sock_connect(sock, (host, port, 0, scope_id)), timeout
            )
            async def read_header() -> bytes:
                # TCP can split even this nine-byte HTTP/2 header. Bound the
                # entire read, not each fragment, and treat EOF as no candidate.
                header = bytearray()
                while len(header) < 9:
                    chunk = await loop.sock_recv(sock, 9 - len(header))
                    if not chunk:
                        break
                    header.extend(chunk)
                return bytes(header)

            greeting = await asyncio.wait_for(read_header(), timeout)
            if (
                len(greeting) >= 9
                and greeting[3] == HTTP2_SETTINGS
                and greeting[5:9] == b"\0\0\0\0"
            ):
                return port
        except (OSError, asyncio.TimeoutError):
            return None
        finally:
            sock.close()
    return None


async def discover_rsd_ports(
    host: str, interface: str, timeout: float, concurrency: int
) -> list[int]:
    """Return HTTP/2 candidates without exposing the peer record."""

    scope_id = socket.if_nametoindex(interface)
    semaphore = asyncio.Semaphore(concurrency)
    tasks = [
        asyncio.create_task(
            _probe_port(host, port, scope_id, semaphore, timeout)
        )
        for port in range(FIRST_DYNAMIC_PORT, LAST_DYNAMIC_PORT + 1)
    ]
    ports = [port for port in await asyncio.gather(*tasks) if port is not None]
    if not ports:
        raise RuntimeError("T2 Remote Service Discovery endpoint was not found")
    return ports


async def discover_peer(
    host: str, interface: str, timeout: float, concurrency: int
) -> tuple[str, dict[str, Any]]:
    """Find the RSD control endpoint and return its in-memory peer record.

    Callers must select only the fields they intend to publish. The record can
    contain device identifiers and must never be dumped wholesale.
    """

    try:
        from pymobiledevice3.remote.remotexpc import RemoteXPCConnection
    except ImportError as error:
        raise RuntimeError(
            "run with the repository virtual environment (.venv/bin/python)"
        ) from error

    scoped_host = f"{host}%{interface}"

    async def read_peer(port: int) -> dict[str, Any] | None:
        connection = RemoteXPCConnection((scoped_host, port))
        try:
            async def receive_peer_record() -> dict[str, Any]:
                await connection.connect()
                await connection.send_device_handshake()
                return await connection.receive_response()

            peer = await asyncio.wait_for(receive_peer_record(), 2.0)
            # Several T2 HTTP/2 listeners accept the same handshake. Some
            # return a syntactically valid but empty service dictionary; keep
            # searching for the actual RSD control endpoint.
            if (
                isinstance(peer, dict)
                and isinstance(peer.get("Services"), dict)
                and peer["Services"]
            ):
                return peer
        except Exception:
            # Other T2 services use HTTP/2 but reject the RSD handshake.
            return None
        finally:
            try:
                await asyncio.wait_for(connection.close(), 2.0)
            except Exception:
                pass
        return None

    # Every invocation obtains a fresh peer record. Remember only where to ask;
    # a changed/restarted endpoint falls back to discovery before any command.
    hint = _load_hint(host, interface)
    if hint is not None:
        peer = await read_peer(hint)
        if peer is not None:
            return scoped_host, peer

    scope_id = socket.if_nametoindex(interface)
    semaphore = asyncio.Semaphore(concurrency)
    handshakes = asyncio.Semaphore(4)
    ports = iter(range(FIRST_DYNAMIC_PORT, LAST_DYNAMIC_PORT + 1))

    async def scan_worker() -> tuple[int, dict[str, Any]] | None:
        for port in ports:
            if port == hint:
                continue
            if await _probe_port(host, port, scope_id, semaphore, timeout) is None:
                continue
            async with handshakes:
                peer = await read_peer(port)
            if peer is not None:
                return port, peer
        return None

    # Begin validating candidates as soon as they answer. A bounded worker
    # pool avoids allocating 16,384 tasks or waiting for unrelated timeouts.
    tasks = [
        asyncio.create_task(scan_worker())
        for _ in range(min(concurrency, LAST_DYNAMIC_PORT - FIRST_DYNAMIC_PORT + 1))
    ]
    try:
        for completed in asyncio.as_completed(tasks):
            found = await completed
            if found is not None:
                port, peer = found
                _save_hint(host, interface, port)
                return scoped_host, peer
    finally:
        for task in tasks:
            if not task.done():
                task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    raise RuntimeError("T2 Remote Service Discovery peer record was not found")


def service_port(peer: dict[str, Any], service_name: str) -> int:
    """Return one validated dynamic service port from an RSD peer record."""

    services = peer.get("Services") if isinstance(peer, dict) else None
    service = services.get(service_name) if isinstance(services, dict) else None
    if not isinstance(service, dict) or "Port" not in service:
        raise RuntimeError(f"T2 did not advertise {service_name}")
    port = service["Port"]
    # Preserve pymobiledevice3's XpcInt64Type/XpcUInt64Type integer wrappers,
    # but reject booleans and lossy float/string coercions before normalization.
    if isinstance(port, int) and not isinstance(port, bool):
        port = int(port)
    elif (
        type(port) is str
        and 1 <= len(port) <= 5
        and port.isascii()
        and port.isdecimal()
    ):
        port = int(port)
    if type(port) is not int:
        raise RuntimeError(f"T2 advertised an invalid port for {service_name}")
    if not FIRST_DYNAMIC_PORT <= port <= LAST_DYNAMIC_PORT:
        raise RuntimeError(f"T2 advertised an invalid port for {service_name}")
    return port
