# SPDX-License-Identifier: GPL-2.0-only
"""Root-only cooperative release of an idle verifier's AKS descriptor.

An active verification does not service this socket. Other hardware owners
request a release only after the kernel reports EBUSY; a failed handshake is
still busy, never permission to bypass the exclusive kernel owner.
"""

import os
import errno
from pathlib import Path
import socket
import stat
import struct

ROOT = Path("/run/t2-touchid/prepared")
TIMEOUT = 0.5


def _private_root(root):
    info = root.stat(follow_symlinks=False)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise PermissionError("prepared owner directory is unsafe")


def _root_peer(connection):
    _pid, uid, _gid = struct.unpack(
        "3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
    )
    if uid != 0:
        raise PermissionError("prepared owner peer is not root")


def _socket_info(path):
    info = path.stat(follow_symlinks=False)
    if not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0:
        raise PermissionError("prepared owner socket is unsafe")
    return info


def release_idle_owner(root=ROOT):
    """Return true only after a root owner acknowledges complete cleanup."""
    try:
        _private_root(root)
        # Reap refused sockets after SIGKILL without spending the live-peer
        # timeout budget on them. Only a live owner can acknowledge release.
        attempted_live_peers = 0
        for path in sorted(root.glob("*.sock")):
            if attempted_live_peers >= 32:
                break
            info = _socket_info(path)
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(TIMEOUT)
                try:
                    connection.connect(str(path))
                    attempted_live_peers += 1
                    _root_peer(connection)
                    connection.sendall(b"R")
                    if connection.recv(1) != b"?":
                        continue
                    # Confirm only while this requester is still waiting.
                    connection.sendall(b"Y")
                    connection.settimeout(10)
                    return connection.recv(1) == b"K"
                except ConnectionRefusedError:
                    # Only a dead socket with unchanged inode is disposable.
                    try:
                        if path.stat(follow_symlinks=False).st_ino == info.st_ino:
                            path.unlink()
                    except OSError:
                        pass
                    continue
                except (OSError, ValueError):
                    continue
    except OSError:
        return False
    return False


class IdleOwner:
    def __init__(self, release, root=ROOT):
        root.mkdir(mode=0o700, exist_ok=True)
        _private_root(root)
        self.path = root / f"{os.getpid()}.sock"
        self.release = release
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            if self.path.exists():
                # PID reuse can encounter one stale socket. Probe rather than
                # replacing a live owner merely because its name matches.
                prior = self.path.stat(follow_symlinks=False)
                if not stat.S_ISSOCK(prior.st_mode) or prior.st_uid != 0:
                    raise PermissionError("prepared owner path is unsafe")
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
                    probe.settimeout(TIMEOUT)
                    if probe.connect_ex(str(self.path)) != errno.ECONNREFUSED:
                        raise RuntimeError("prepared owner path is already live")
                if self.path.stat(follow_symlinks=False).st_ino != prior.st_ino:
                    raise RuntimeError("prepared owner path changed")
                self.path.unlink()
            self.socket.bind(str(self.path))
            os.chmod(self.path, 0o600)
            self.inode = self.path.stat(follow_symlinks=False).st_ino
            self.socket.listen(4)
        except BaseException:
            self.socket.close()
            raise

    def fileno(self):
        return self.socket.fileno()

    def service(self):
        connection, _ = self.socket.accept()
        with connection:
            connection.settimeout(TIMEOUT)
            try:
                _root_peer(connection)
                if connection.recv(1) != b"R":
                    return
                connection.sendall(b"?")
                if connection.recv(1) != b"Y":
                    return
            except (OSError, ValueError):
                return
            # Cleanup failure is fatal to this worker. Never acknowledge it.
            self.release()
            try:
                connection.sendall(b"K")
            except OSError:
                pass  # The caller departed; cleanup still completed.

    def close(self):
        self.socket.close()
        try:
            if self.path.stat(follow_symlinks=False).st_ino == self.inode:
                self.path.unlink()
        except FileNotFoundError:
            pass


if __name__ == "__main__":
    # The C AKS helper invokes this fixed installed path with Python -I.
    # Exit success only after the same root-peer cleanup acknowledgement.
    raise SystemExit(0 if release_idle_owner() else 1)
