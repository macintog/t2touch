# SPDX-License-Identifier: GPL-2.0-only
"""Crash-safe storage for one creation-time T2 activation generation.

Secret bytes are accepted only in caller-owned mutable storage.  They are
never represented in manifests or return values and are wiped on every exit.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


ACTIVATION_SECRET_LENGTH = 16
MAX_SAVED_KEYBAG_BYTES = 1024 * 1024
MANIFEST_SCHEMA_VERSION = 1


class ActivationBundleError(RuntimeError):
    pass


@dataclass(frozen=True)
class ActivationBundle:
    generation: str
    directory: Path
    activation_secret_path: Path
    activation_secret_sha256: str
    keybag_path: Path
    keybag_sha256: str
    keybag_length: int
    manifest_path: Path
    manifest_sha256: str


def _canonical_uuid(value: str, label: str) -> str:
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, TypeError, ValueError) as error:
        raise ActivationBundleError(f"{label} is invalid") from error
    if parsed.int == 0 or str(parsed) != value:
        raise ActivationBundleError(f"{label} is invalid")
    return value


def _sha256(value: str, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ActivationBundleError(f"{label} is invalid")
    return value


def _wipe(value: object) -> None:
    if isinstance(value, bytearray):
        value[:] = b"\0" * len(value)


def _open_flags(access: int) -> int:
    flags = access | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _require_directory(path: Path, label: str) -> None:
    try:
        info = path.stat(follow_symlinks=False)
    except OSError as error:
        raise ActivationBundleError(f"{label} is unavailable") from error
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise ActivationBundleError(f"{label} is not private and caller-owned")


def _sync_directory(path: Path) -> None:
    try:
        descriptor = os.open(
            path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise ActivationBundleError("activation bundle directory sync failed") from error


def _write_exclusive(path: Path, content: bytearray | bytes) -> None:
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            _open_flags(os.O_WRONLY | os.O_CREAT | os.O_EXCL),
            0o600,
        )
        view = memoryview(content)
        try:
            offset = 0
            while offset < len(view):
                written = os.write(descriptor, view[offset:])
                if written <= 0:
                    raise ActivationBundleError("activation bundle write made no progress")
                offset += written
        finally:
            view.release()
        os.fsync(descriptor)
    except OSError as error:
        raise ActivationBundleError("activation bundle file commit failed") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _write_or_repair_private(
    directory: Path, path: Path, content: bytearray | bytes, label: str
) -> None:
    """Converge a crash-left private file to journal-authorized bytes."""

    if os.path.lexists(path):
        observed = bytearray()
        try:
            observed = _read_private(path, exact_length=None, label=label)
            if observed == content:
                return
        except ActivationBundleError:
            pass
        finally:
            _wipe(observed)
        info = path.stat(follow_symlinks=False)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            raise ActivationBundleError(f"partial {label} metadata is unsafe")
        try:
            path.unlink()
            _sync_directory(directory)
        except OSError as error:
            raise ActivationBundleError(f"partial {label} cannot be retired") from error
    _write_exclusive(path, content)


def _read_private(path: Path, *, exact_length: int | None, label: str) -> bytearray:
    descriptor = -1
    result = bytearray()
    try:
        descriptor = os.open(path, _open_flags(os.O_RDONLY))
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
            or not 0 < info.st_size <= MAX_SAVED_KEYBAG_BYTES
            or (exact_length is not None and info.st_size != exact_length)
        ):
            raise ActivationBundleError(f"{label} metadata is unsafe")
        while len(result) < info.st_size:
            block = os.read(descriptor, min(65536, info.st_size - len(result)))
            if not block:
                raise ActivationBundleError(f"{label} read was short")
            result.extend(block)
        return result
    except OSError as error:
        _wipe(result)
        raise ActivationBundleError(f"{label} cannot be read safely") from error
    except BaseException:
        _wipe(result)
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)


@contextmanager
def activation_secret(
    path: Path, expected_sha256: str
) -> Iterator[bytearray]:
    """Yield one verified secret in bounded mutable storage, then wipe it."""

    expected_sha256 = _sha256(expected_sha256, "activation secret digest")
    secret = _read_private(
        path, exact_length=ACTIVATION_SECRET_LENGTH, label="activation secret"
    )
    try:
        if hashlib.sha256(secret).hexdigest() != expected_sha256:
            raise ActivationBundleError("activation secret digest differs")
        if not any(secret):
            raise ActivationBundleError("activation secret is reserved")
        yield secret
    finally:
        _wipe(secret)


class ActivationBundleStore:
    """Own one pending-to-final activation bundle transaction."""

    def __init__(
        self,
        *,
        root: Path,
        operation_id: str,
        account_uuid: str,
        linux_uid: int,
    ) -> None:
        _require_directory(root, "activation bundle root")
        self.root = root
        self.operation_id = _canonical_uuid(operation_id, "operation ID")
        self.account_uuid = _canonical_uuid(account_uuid, "account UUID")
        if type(linux_uid) is not int or not 0 < linux_uid < (1 << 32) - 1:
            raise ActivationBundleError("Linux UID is invalid")
        self.linux_uid = linux_uid
        self.pending_directory = root / f".{operation_id}.pending"
        self.final_directory = root / operation_id
        self.pending_secret_path = self.pending_directory / "activation.secret"
        self.final_secret_path = self.final_directory / "activation.secret"
        self.final_keybag_path = self.final_directory / "user.kb"
        self.final_manifest_path = self.final_directory / "manifest.json"

    def stage(self, secret: bytearray) -> str:
        """Persist the creation external form before any SEP mutation."""

        try:
            if (
                not isinstance(secret, bytearray)
                or len(secret) != ACTIVATION_SECRET_LENGTH
                or not any(secret)
            ):
                raise ActivationBundleError("activation secret buffer is invalid")
            if os.path.lexists(self.pending_directory) or os.path.lexists(
                self.final_directory
            ):
                raise ActivationBundleError("activation bundle generation already exists")
            digest = hashlib.sha256(secret).hexdigest()
            try:
                os.mkdir(self.pending_directory, 0o700)
            except OSError as error:
                raise ActivationBundleError(
                    "pending activation generation cannot be created"
                ) from error
            _require_directory(self.pending_directory, "pending activation generation")
            _write_exclusive(self.pending_secret_path, secret)
            with activation_secret(self.pending_secret_path, digest):
                pass
            _sync_directory(self.pending_directory)
            return digest
        finally:
            _wipe(secret)

    @contextmanager
    def staged_secret(self, expected_sha256: str) -> Iterator[bytearray]:
        """Recover only this operation's already-durable pending secret."""

        _require_directory(self.pending_directory, "pending activation generation")
        with activation_secret(self.pending_secret_path, expected_sha256) as secret:
            yield secret

    def commit(
        self,
        saved_keybag: bytearray,
        *,
        expected_keybag_sha256: str,
        activation_secret_sha256: str,
        bag_uuid: str,
    ) -> ActivationBundle:
        """Complete, verify, and atomically publish the staged generation."""

        try:
            expected_keybag_sha256 = _sha256(
                expected_keybag_sha256, "saved keybag digest"
            )
            activation_secret_sha256 = _sha256(
                activation_secret_sha256, "activation secret digest"
            )
            bag_uuid = _canonical_uuid(bag_uuid, "bag UUID")
            if (
                not isinstance(saved_keybag, bytearray)
                or not 0 < len(saved_keybag) <= MAX_SAVED_KEYBAG_BYTES
            ):
                raise ActivationBundleError("saved keybag buffer is invalid")
            if hashlib.sha256(saved_keybag).hexdigest() != expected_keybag_sha256:
                raise ActivationBundleError("saved keybag differs from expected digest")
            if os.path.lexists(self.final_directory):
                if os.path.lexists(self.pending_directory):
                    raise ActivationBundleError(
                        "pending and final activation generations both exist"
                    )
                return self.published(
                    expected_keybag_sha256=expected_keybag_sha256,
                    activation_secret_sha256=activation_secret_sha256,
                    bag_uuid=bag_uuid,
                    expected_keybag_length=len(saved_keybag),
                )
            _require_directory(self.pending_directory, "pending activation generation")
            with activation_secret(
                self.pending_secret_path, activation_secret_sha256
            ):
                pass

            keybag_path = self.pending_directory / "user.kb"
            manifest_path = self.pending_directory / "manifest.json"
            try:
                names = {entry.name for entry in os.scandir(self.pending_directory)}
            except OSError as error:
                raise ActivationBundleError(
                    "pending activation generation cannot be enumerated"
                ) from error
            if not names <= {"activation.secret", "user.kb", "manifest.json"}:
                raise ActivationBundleError(
                    "pending activation generation has unexpected artifacts"
                )
            _write_or_repair_private(
                self.pending_directory, keybag_path, saved_keybag, "saved keybag"
            )
            observed_keybag = _read_private(
                keybag_path, exact_length=len(saved_keybag), label="saved keybag"
            )
            try:
                if hashlib.sha256(observed_keybag).hexdigest() != expected_keybag_sha256:
                    raise ActivationBundleError("committed keybag digest differs")
            finally:
                _wipe(observed_keybag)

            manifest = {
                "schema_version": MANIFEST_SCHEMA_VERSION,
                "phase": "complete",
                "operation_id": self.operation_id,
                "linux_uid": self.linux_uid,
                "account_uuid": self.account_uuid,
                "bag_uuid": bag_uuid,
                "activation_secret_length": ACTIVATION_SECRET_LENGTH,
                "activation_secret_sha256": activation_secret_sha256,
                "keybag_length": len(saved_keybag),
                "keybag_sha256": expected_keybag_sha256,
            }
            encoded_manifest = json.dumps(
                manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ).encode("ascii")
            _write_or_repair_private(
                self.pending_directory,
                manifest_path,
                encoded_manifest,
                "activation manifest",
            )
            observed_manifest = _read_private(
                manifest_path,
                exact_length=len(encoded_manifest),
                label="activation manifest",
            )
            try:
                if observed_manifest != encoded_manifest:
                    raise ActivationBundleError("activation manifest differs")
            finally:
                _wipe(observed_manifest)
            with activation_secret(
                self.pending_secret_path, activation_secret_sha256
            ):
                pass
            _sync_directory(self.pending_directory)
            try:
                os.rename(self.pending_directory, self.final_directory)
            except OSError as error:
                raise ActivationBundleError(
                    "activation bundle publication failed"
                ) from error
            _sync_directory(self.root)
            return ActivationBundle(
                generation=self.operation_id,
                directory=self.final_directory,
                activation_secret_path=self.final_secret_path,
                activation_secret_sha256=activation_secret_sha256,
                keybag_path=self.final_keybag_path,
                keybag_sha256=expected_keybag_sha256,
                keybag_length=len(saved_keybag),
                manifest_path=self.final_manifest_path,
                manifest_sha256=hashlib.sha256(encoded_manifest).hexdigest(),
            )
        finally:
            _wipe(saved_keybag)

    def published(
        self,
        *,
        expected_keybag_sha256: str,
        activation_secret_sha256: str,
        bag_uuid: str,
        expected_keybag_length: int,
    ) -> ActivationBundle:
        """Reconcile an already-renamed generation without secret disclosure."""

        expected_keybag_sha256 = _sha256(
            expected_keybag_sha256, "saved keybag digest"
        )
        activation_secret_sha256 = _sha256(
            activation_secret_sha256, "activation secret digest"
        )
        bag_uuid = _canonical_uuid(bag_uuid, "bag UUID")
        if (
            type(expected_keybag_length) is not int
            or not 0 < expected_keybag_length <= MAX_SAVED_KEYBAG_BYTES
        ):
            raise ActivationBundleError("saved keybag length is invalid")
        _require_directory(self.final_directory, "final activation generation")
        try:
            names = {entry.name for entry in os.scandir(self.final_directory)}
        except OSError as error:
            raise ActivationBundleError(
                "final activation generation cannot be enumerated"
            ) from error
        if names != {"activation.secret", "user.kb", "manifest.json"}:
            raise ActivationBundleError("final activation generation is incomplete")
        with activation_secret(self.final_secret_path, activation_secret_sha256):
            pass
        keybag = _read_private(
            self.final_keybag_path,
            exact_length=expected_keybag_length,
            label="saved keybag",
        )
        try:
            if hashlib.sha256(keybag).hexdigest() != expected_keybag_sha256:
                raise ActivationBundleError("published keybag digest differs")
        finally:
            _wipe(keybag)
        manifest = _read_private(
            self.final_manifest_path,
            exact_length=None,
            label="activation manifest",
        )
        try:
            try:
                parsed = json.loads(manifest)
            except (json.JSONDecodeError, UnicodeDecodeError) as error:
                raise ActivationBundleError("activation manifest is invalid") from error
            expected = {
                "schema_version": MANIFEST_SCHEMA_VERSION,
                "phase": "complete",
                "operation_id": self.operation_id,
                "linux_uid": self.linux_uid,
                "account_uuid": self.account_uuid,
                "bag_uuid": bag_uuid,
                "activation_secret_length": ACTIVATION_SECRET_LENGTH,
                "activation_secret_sha256": activation_secret_sha256,
                "keybag_length": expected_keybag_length,
                "keybag_sha256": expected_keybag_sha256,
            }
            canonical = json.dumps(
                expected,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("ascii")
            if parsed != expected or bytes(manifest) != canonical:
                raise ActivationBundleError("activation manifest differs")
            manifest_sha256 = hashlib.sha256(manifest).hexdigest()
        finally:
            _wipe(manifest)
        return ActivationBundle(
            generation=self.operation_id,
            directory=self.final_directory,
            activation_secret_path=self.final_secret_path,
            activation_secret_sha256=activation_secret_sha256,
            keybag_path=self.final_keybag_path,
            keybag_sha256=expected_keybag_sha256,
            keybag_length=expected_keybag_length,
            manifest_path=self.final_manifest_path,
            manifest_sha256=manifest_sha256,
        )
