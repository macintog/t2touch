# SPDX-License-Identifier: GPL-2.0-only
"""Append-only persistence for SEP's opaque biometric lockout record."""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
import re
import secrets
import stat


class BioLockoutStoreError(RuntimeError):
    """Raised when durable BioLockout state cannot be trusted."""


SCHEMA_VERSION = 1
MIN_RECORD_LENGTH = 16
MAX_RECORD_LENGTH = 4096
RECORD_MAGIC = b"HRLB"
GENERATION_RE = re.compile(r"^generation-([0-9]{20})\.(hrlb|json)$")


@dataclass(frozen=True)
class BioLockoutGeneration:
    sequence: int
    payload: bytes
    length: int
    sha256: str


class BioLockoutStore:
    """Read and append complete root-only generations without rollback."""

    def __init__(self, root: str) -> None:
        if not os.path.isabs(root):
            raise BioLockoutStoreError("bio-lockout state directory must be absolute")
        self.root = root

    def _open_root(self) -> int:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(self.root, flags)
        except OSError as error:
            raise BioLockoutStoreError(
                "bio-lockout state directory is unavailable"
            ) from error
        info = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            os.close(descriptor)
            raise BioLockoutStoreError(
                "bio-lockout state directory must be root-owned mode 0700"
            )
        return descriptor

    @staticmethod
    def _read_private_file(
        directory: int, name: str, maximum: int
    ) -> bytes:
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(name, flags, dir_fd=directory)
        except OSError as error:
            raise BioLockoutStoreError(
                "bio-lockout generation file is unavailable"
            ) from error
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != 0
                or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600
                or not 1 <= info.st_size <= maximum
            ):
                raise BioLockoutStoreError(
                    "bio-lockout generation file failed ownership or size checks"
                )
            chunks = bytearray()
            while len(chunks) < info.st_size:
                chunk = os.read(descriptor, info.st_size - len(chunks))
                if not chunk:
                    break
                chunks.extend(chunk)
            if len(chunks) != info.st_size:
                raise BioLockoutStoreError("bio-lockout generation read was short")
            return bytes(chunks)
        finally:
            os.close(descriptor)

    @staticmethod
    def _write_private_file(directory: int, name: str, payload: bytes) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(name, flags, 0o600, dir_fd=directory)
        try:
            offset = 0
            while offset < len(payload):
                written = os.write(descriptor, payload[offset:])
                if written <= 0:
                    raise BioLockoutStoreError(
                        "bio-lockout generation write made no progress"
                    )
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @staticmethod
    def _validate_payload(payload: object) -> bytes:
        if type(payload) is not bytes:
            raise BioLockoutStoreError("bio-lockout generation is not byte data")
        if not MIN_RECORD_LENGTH <= len(payload) <= MAX_RECORD_LENGTH:
            raise BioLockoutStoreError("bio-lockout generation length is invalid")
        if not payload.startswith(RECORD_MAGIC):
            raise BioLockoutStoreError("bio-lockout generation envelope is invalid")
        return payload

    def current(self) -> BioLockoutGeneration | None:
        """Return the highest fully committed generation, or no state yet."""
        directory = self._open_root()
        try:
            manifests = []
            for name in os.listdir(directory):
                match = GENERATION_RE.fullmatch(name)
                if match is not None and match.group(2) == "json":
                    manifests.append((int(match.group(1)), name))
            if not manifests:
                return None
            sequence, manifest_name = max(manifests)
            raw_manifest = self._read_private_file(directory, manifest_name, 4096)
            try:
                manifest = json.loads(raw_manifest)
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise BioLockoutStoreError(
                    "latest bio-lockout manifest is malformed"
                ) from error
            blob_name = f"generation-{sequence:020d}.hrlb"
            expected_keys = {
                "schema_version",
                "sequence",
                "blob",
                "length",
                "sha256",
            }
            if (
                not isinstance(manifest, dict)
                or set(manifest) != expected_keys
                or manifest.get("schema_version") != SCHEMA_VERSION
                or type(manifest.get("sequence")) is not int
                or manifest.get("sequence") != sequence
                or manifest.get("blob") != blob_name
                or type(manifest.get("length")) is not int
                or not MIN_RECORD_LENGTH
                <= manifest.get("length")
                <= MAX_RECORD_LENGTH
                or not isinstance(manifest.get("sha256"), str)
                or re.fullmatch(r"[0-9a-f]{64}", manifest.get("sha256")) is None
            ):
                raise BioLockoutStoreError(
                    "latest bio-lockout manifest failed strict validation"
                )
            payload = self._validate_payload(
                self._read_private_file(directory, blob_name, MAX_RECORD_LENGTH)
            )
            digest = hashlib.sha256(payload).hexdigest()
            if len(payload) != manifest["length"] or digest != manifest["sha256"]:
                raise BioLockoutStoreError(
                    "latest bio-lockout generation does not match its manifest"
                )
            return BioLockoutGeneration(sequence, payload, len(payload), digest)
        finally:
            os.close(directory)

    def commit(self, payload: bytes) -> BioLockoutGeneration:
        """Append and publish one complete generation, retaining all predecessors."""
        payload = self._validate_payload(payload)
        directory = self._open_root()
        pending_names: list[str] = []
        try:
            highest_artifact = 0
            for name in os.listdir(directory):
                match = GENERATION_RE.fullmatch(name)
                if match is not None:
                    highest_artifact = max(highest_artifact, int(match.group(1)))
            sequence = highest_artifact + 1
            if sequence > 99999999999999999999:
                raise BioLockoutStoreError("bio-lockout generation space is exhausted")
            stem = f"generation-{sequence:020d}"
            blob_name = f"{stem}.hrlb"
            manifest_name = f"{stem}.json"
            digest = hashlib.sha256(payload).hexdigest()
            nonce = secrets.token_hex(16)
            pending_blob = f".pending-{nonce}.hrlb"
            pending_manifest = f".pending-{nonce}.json"
            pending_names.extend((pending_blob, pending_manifest))

            self._write_private_file(directory, pending_blob, payload)
            if blob_name in os.listdir(directory):
                raise BioLockoutStoreError("bio-lockout generation collision")
            os.rename(
                pending_blob,
                blob_name,
                src_dir_fd=directory,
                dst_dir_fd=directory,
            )
            pending_names.remove(pending_blob)
            os.fsync(directory)

            manifest = json.dumps(
                {
                    "schema_version": SCHEMA_VERSION,
                    "sequence": sequence,
                    "blob": blob_name,
                    "length": len(payload),
                    "sha256": digest,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii") + b"\n"
            self._write_private_file(directory, pending_manifest, manifest)
            if manifest_name in os.listdir(directory):
                raise BioLockoutStoreError("bio-lockout manifest collision")
            os.rename(
                pending_manifest,
                manifest_name,
                src_dir_fd=directory,
                dst_dir_fd=directory,
            )
            pending_names.remove(pending_manifest)
            os.fsync(directory)
            return BioLockoutGeneration(sequence, payload, len(payload), digest)
        finally:
            for pending_name in pending_names:
                try:
                    os.unlink(pending_name, dir_fd=directory)
                except FileNotFoundError:
                    pass
            os.close(directory)
