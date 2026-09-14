# SPDX-License-Identifier: GPL-2.0-only
"""Atomic first Linux-owned user mapping commit after AKS provisioning."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import uuid
from pathlib import Path

import t2_user_mapping


class UserMappingStoreError(RuntimeError):
    pass


class InitialUserMappingStore:
    def __init__(
        self,
        *,
        path: Path,
        operation_id: str,
        linux_uid: int,
        linux_account_generation: str,
        apple_uid: int,
        keybag_path: Path,
        bundle_generation: str | None = None,
        activation_secret_path: Path | None = None,
        activation_secret_sha256: str | None = None,
        unlock_mode: str = "password-on-demand",
    ) -> None:
        self.path = path
        self.operation_id = operation_id
        self.linux_uid = linux_uid
        self.linux_account_generation = linux_account_generation
        self.apple_uid = apple_uid
        self.keybag_path = keybag_path
        self.bundle_generation = bundle_generation
        self.activation_secret_path = activation_secret_path
        self.activation_secret_sha256 = activation_secret_sha256
        self.unlock_mode = unlock_mode

    def _read_private_digest(
        self,
        path: Path,
        *,
        expected_length: int | None,
        exact_mode_0600: bool,
        label: str,
    ) -> str:
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags)
        except OSError as error:
            raise UserMappingStoreError(
                f"committed {label} cannot be opened safely"
            ) from error
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_nlink != 1
                or info.st_mode & 0o077
                or (exact_mode_0600 and stat.S_IMODE(info.st_mode) != 0o600)
                or not 0 < info.st_size <= 1024 * 1024
                or (expected_length is not None and info.st_size != expected_length)
            ):
                raise UserMappingStoreError(f"committed {label} metadata is unsafe")
            digest = hashlib.sha256()
            remaining = info.st_size
            while remaining:
                block = os.read(descriptor, min(remaining, 65536))
                if not block:
                    raise UserMappingStoreError(f"committed {label} read was short")
                digest.update(block)
                remaining -= len(block)
            return digest.hexdigest()
        finally:
            os.close(descriptor)

    def _read_keybag_digest(self) -> str:
        return self._read_private_digest(
            self.keybag_path,
            expected_length=None,
            exact_mode_0600=self.bundle_generation is not None,
            label="keybag",
        )

    def _activation_authority(self) -> tuple[str, str, str] | None:
        values = (
            self.bundle_generation,
            self.activation_secret_path,
            self.activation_secret_sha256,
        )
        if all(value is None for value in values):
            return None
        if any(value is None for value in values):
            raise UserMappingStoreError("activation bundle authority is incomplete")
        assert self.bundle_generation is not None
        assert self.activation_secret_path is not None
        assert self.activation_secret_sha256 is not None
        observed = self._read_private_digest(
            self.activation_secret_path,
            expected_length=16,
            exact_mode_0600=True,
            label="activation secret",
        )
        if observed != self.activation_secret_sha256:
            raise UserMappingStoreError(
                "activation secret digest differs from committed file"
            )
        return (
            self.bundle_generation,
            str(self.activation_secret_path),
            observed,
        )

    def _encoded_mapping(
        self,
        *,
        account_uuid: str,
        bag_uuid: str,
        keybag_sha256: str,
        enabled: bool,
    ) -> bytes:
        activation = self._activation_authority()
        entry: dict[str, object] = {
            "linux_uid": self.linux_uid,
            "linux_account_generation": self.linux_account_generation,
            "apple_uid": self.apple_uid,
            "account_uuid": account_uuid,
            "bag_uuid": bag_uuid,
            "keybag_path": str(self.keybag_path),
            "keybag_sha256": keybag_sha256,
            "unlock_mode": self.unlock_mode,
            "capabilities": ["enroll", "identity-management", "verify"],
            "enabled": enabled,
        }
        if activation is not None:
            bundle_generation, activation_secret_path, activation_digest = activation
            entry.update(
                {
                    "bundle_generation": bundle_generation,
                    "activation_secret_path": activation_secret_path,
                    "activation_secret_sha256": activation_digest,
                    "activation_secret_length": 16,
                }
            )
        document = {
            "schema_version": (
                t2_user_mapping.SCHEMA_VERSION
                if activation is not None
                else t2_user_mapping.LEGACY_SCHEMA_VERSION
            ),
            "mappings": [entry],
        }
        encoded = json.dumps(
            document, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
        try:
            parsed = t2_user_mapping.parse(encoded)
        except t2_user_mapping.UserMappingError as error:
            raise UserMappingStoreError("initial mapping does not satisfy policy") from error
        if len(parsed.mappings) != 1 or parsed.mappings[0].enabled is not enabled:
            raise UserMappingStoreError("initial mapping enable state is inconsistent")
        return encoded

    def commit(
        self, *, account_uuid: str, bag_uuid: str, keybag_sha256: str
    ) -> str:
        try:
            parsed_operation = uuid.UUID(self.operation_id)
        except (AttributeError, TypeError, ValueError) as error:
            raise UserMappingStoreError("mapping operation ID is invalid") from error
        if str(parsed_operation) != self.operation_id or parsed_operation.int == 0:
            raise UserMappingStoreError("mapping operation ID is invalid")
        observed_keybag_sha256 = self._read_keybag_digest()
        if observed_keybag_sha256 != keybag_sha256:
            raise UserMappingStoreError("mapping keybag digest differs from committed file")
        encoded = self._encoded_mapping(
            account_uuid=account_uuid,
            bag_uuid=bag_uuid,
            keybag_sha256=keybag_sha256,
            enabled=False,
        )

        parent = self.path.parent
        info = parent.stat(follow_symlinks=False)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_mode & 0o022
        ):
            raise UserMappingStoreError("mapping parent directory is unsafe")
        temporary = parent / f".{self.path.name}.{self.operation_id}.tmp"
        if os.path.lexists(self.path):
            flags = os.O_RDONLY | os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                existing_descriptor = os.open(self.path, flags)
            except OSError as error:
                raise UserMappingStoreError(
                    "existing mapping cannot be opened safely"
                ) from error
            try:
                existing_info = os.fstat(existing_descriptor)
                if (
                    not stat.S_ISREG(existing_info.st_mode)
                    or existing_info.st_uid != os.geteuid()
                    or existing_info.st_nlink != 1
                    or existing_info.st_mode & 0o077
                    or existing_info.st_size != len(encoded)
                ):
                    raise UserMappingStoreError("existing mapping metadata differs")
                existing = b""
                while len(existing) < existing_info.st_size:
                    block = os.read(
                        existing_descriptor, existing_info.st_size - len(existing)
                    )
                    if not block:
                        raise UserMappingStoreError("existing mapping read was short")
                    existing += block
            finally:
                os.close(existing_descriptor)
            if existing != encoded:
                raise UserMappingStoreError("existing mapping content differs")
            return hashlib.sha256(existing).hexdigest()
        if os.path.lexists(temporary):
            raise UserMappingStoreError("mapping transaction file already exists")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(temporary, flags, 0o600)
        committed = False
        try:
            offset = 0
            while offset < len(encoded):
                written = os.write(descriptor, encoded[offset:])
                if written <= 0:
                    raise UserMappingStoreError("mapping write made no progress")
                offset += written
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = -1
            os.rename(temporary, self.path)
            directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            committed = True
            return hashlib.sha256(encoded).hexdigest()
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if not committed and os.path.lexists(temporary):
                temporary.unlink()

    def enable_after_reboot(
        self,
        *,
        disabled_mapping_generation: str,
        account_uuid: str,
        bag_uuid: str,
        keybag_sha256: str,
    ) -> str:
        """Atomically promote only this exact verified disabled mapping."""

        try:
            parsed_operation = uuid.UUID(self.operation_id)
        except (AttributeError, TypeError, ValueError) as error:
            raise UserMappingStoreError("mapping operation ID is invalid") from error
        if str(parsed_operation) != self.operation_id or parsed_operation.int == 0:
            raise UserMappingStoreError("mapping operation ID is invalid")
        if self._read_keybag_digest() != keybag_sha256:
            raise UserMappingStoreError("mapping keybag changed before enable")
        disabled = self._encoded_mapping(
            account_uuid=account_uuid,
            bag_uuid=bag_uuid,
            keybag_sha256=keybag_sha256,
            enabled=False,
        )
        enabled = self._encoded_mapping(
            account_uuid=account_uuid,
            bag_uuid=bag_uuid,
            keybag_sha256=keybag_sha256,
            enabled=True,
        )
        if hashlib.sha256(disabled).hexdigest() != disabled_mapping_generation:
            raise UserMappingStoreError("disabled mapping generation is not exact")

        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(self.path, flags)
        except OSError as error:
            raise UserMappingStoreError("disabled mapping cannot be opened") from error
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_nlink != 1
                or info.st_mode & 0o077
                or info.st_size not in {len(disabled), len(enabled)}
            ):
                raise UserMappingStoreError("disabled mapping metadata differs")
            current = bytearray()
            while len(current) < info.st_size:
                block = os.read(descriptor, info.st_size - len(current))
                if not block:
                    raise UserMappingStoreError("disabled mapping read was short")
                current.extend(block)
        finally:
            os.close(descriptor)
        enabled_generation = hashlib.sha256(enabled).hexdigest()
        if current == enabled:
            return enabled_generation
        if current != disabled:
            raise UserMappingStoreError("mapping changed before enable")

        parent = self.path.parent
        parent_info = parent.stat(follow_symlinks=False)
        if (
            not stat.S_ISDIR(parent_info.st_mode)
            or parent_info.st_uid != os.geteuid()
            or parent_info.st_mode & 0o022
        ):
            raise UserMappingStoreError("mapping parent directory is unsafe")
        temporary = parent / f".{self.path.name}.{self.operation_id}.enable.tmp"
        if os.path.lexists(temporary):
            raise UserMappingStoreError("mapping enable transaction already exists")
        write_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            write_flags |= os.O_NOFOLLOW
        output = os.open(temporary, write_flags, 0o600)
        committed = False
        try:
            offset = 0
            while offset < len(enabled):
                written = os.write(output, enabled[offset:])
                if written <= 0:
                    raise UserMappingStoreError("mapping enable write made no progress")
                offset += written
            os.fsync(output)
            os.close(output)
            output = -1
            os.replace(temporary, self.path)
            directory_fd = os.open(
                parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
            )
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            committed = True
            return enabled_generation
        finally:
            if output >= 0:
                os.close(output)
            if not committed and os.path.lexists(temporary):
                temporary.unlink()


class ReplacementUserMappingStore(InitialUserMappingStore):
    """Archive one exact legacy authority before atomically replacing it.

    The archive is synced before the canonical rename.  A crash can therefore
    leave either the old or new canonical mapping, but never a new mapping
    without the exact old bytes already preserved for reconciliation.
    """

    def __init__(
        self,
        *,
        old_mapping_generation: str,
        old_account_uuid: str,
        old_bag_uuid: str,
        archive_root: Path,
        **keywords: object,
    ) -> None:
        super().__init__(**keywords)  # type: ignore[arg-type]
        try:
            parsed_operation = uuid.UUID(self.operation_id)
            parsed_old_account = uuid.UUID(old_account_uuid)
            parsed_old_bag = uuid.UUID(old_bag_uuid)
        except (AttributeError, TypeError, ValueError) as error:
            raise UserMappingStoreError(
                "replacement mapping identifiers are invalid"
            ) from error
        if (
            parsed_operation.int == 0
            or str(parsed_operation) != self.operation_id
            or parsed_old_account.int == 0
            or str(parsed_old_account) != old_account_uuid
            or parsed_old_bag.int == 0
            or str(parsed_old_bag) != old_bag_uuid
            or not isinstance(old_mapping_generation, str)
            or len(old_mapping_generation) != 64
            or any(character not in "0123456789abcdef" for character in old_mapping_generation)
        ):
            raise UserMappingStoreError("replacement mapping identifiers are invalid")
        self.old_mapping_generation = old_mapping_generation
        self.old_account_uuid = old_account_uuid
        self.old_bag_uuid = old_bag_uuid
        self.archive_root = archive_root
        self.archive_directory = archive_root / self.operation_id
        self.archive_path = self.archive_directory / "users.before.json"

    @staticmethod
    def _sync_directory(path: Path) -> None:
        descriptor = os.open(
            path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @staticmethod
    def _require_private_directory(path: Path, label: str) -> None:
        try:
            info = path.stat(follow_symlinks=False)
        except OSError as error:
            raise UserMappingStoreError(f"{label} is unavailable") from error
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise UserMappingStoreError(f"{label} is not private and caller-owned")

    @staticmethod
    def _read_private(path: Path, label: str) -> bytes:
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags)
        except OSError as error:
            raise UserMappingStoreError(f"{label} cannot be opened safely") from error
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600
                or not 0 < info.st_size <= t2_user_mapping.MAX_FILE_SIZE
            ):
                raise UserMappingStoreError(f"{label} metadata is unsafe")
            content = bytearray()
            while len(content) < info.st_size:
                block = os.read(descriptor, info.st_size - len(content))
                if not block:
                    raise UserMappingStoreError(f"{label} read was short")
                content.extend(block)
            if len(content) != info.st_size:
                raise UserMappingStoreError(f"{label} changed while being read")
            return bytes(content)
        finally:
            os.close(descriptor)

    @staticmethod
    def _write_exclusive(path: Path, content: bytes) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags, 0o600)
        try:
            offset = 0
            while offset < len(content):
                written = os.write(descriptor, content[offset:])
                if written <= 0:
                    raise UserMappingStoreError("mapping write made no progress")
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _validate_old_mapping(self, content: bytes) -> None:
        if hashlib.sha256(content).hexdigest() != self.old_mapping_generation:
            raise UserMappingStoreError("canonical old mapping generation differs")
        try:
            parsed = t2_user_mapping.parse(content)
        except t2_user_mapping.UserMappingError as error:
            raise UserMappingStoreError("canonical old mapping is invalid") from error
        if parsed.schema_version != t2_user_mapping.LEGACY_SCHEMA_VERSION or len(
            parsed.mappings
        ) != 1:
            raise UserMappingStoreError("canonical old mapping is not one legacy authority")
        old = parsed.mappings[0]
        if (
            not old.enabled
            or old.linux_uid != self.linux_uid
            or old.linux_account_generation != self.linux_account_generation
            or old.apple_uid != self.apple_uid
            or old.account_uuid != self.old_account_uuid
            or old.bag_uuid != self.old_bag_uuid
            or old.unlock_mode != self.unlock_mode
        ):
            raise UserMappingStoreError("canonical old mapping authority differs")
        if self._read_private_digest(
            Path(old.keybag_path),
            expected_length=None,
            exact_mode_0600=False,
            label="old keybag",
        ) != old.keybag_sha256:
            raise UserMappingStoreError("canonical old keybag digest differs")

    def _archive(self, old: bytes) -> None:
        self._require_private_directory(self.archive_root, "mapping archive root")
        if not os.path.lexists(self.archive_directory):
            try:
                os.mkdir(self.archive_directory, 0o700)
            except OSError as error:
                raise UserMappingStoreError(
                    "mapping archive generation cannot be created"
                ) from error
            self._sync_directory(self.archive_root)
        self._require_private_directory(
            self.archive_directory, "mapping archive generation"
        )
        try:
            names = {entry.name for entry in os.scandir(self.archive_directory)}
        except OSError as error:
            raise UserMappingStoreError("mapping archive cannot be enumerated") from error
        if not names <= {self.archive_path.name, "replacement.before-delete.jsonl"}:
            raise UserMappingStoreError("mapping archive has unexpected entries")
        if os.path.lexists(self.archive_path):
            if self._read_private(self.archive_path, "archived old mapping") != old:
                raise UserMappingStoreError("archived old mapping differs")
        else:
            try:
                self._write_exclusive(self.archive_path, old)
            except OSError as error:
                raise UserMappingStoreError("old mapping archive failed") from error
        self._sync_directory(self.archive_directory)
        self._sync_directory(self.archive_root)

    def commit(
        self, *, account_uuid: str, bag_uuid: str, keybag_sha256: str
    ) -> str:
        observed_keybag_sha256 = self._read_keybag_digest()
        if observed_keybag_sha256 != keybag_sha256:
            raise UserMappingStoreError("mapping keybag differs from committed bundle")
        replacement = self._encoded_mapping(
            account_uuid=account_uuid,
            bag_uuid=bag_uuid,
            keybag_sha256=keybag_sha256,
            enabled=False,
        )
        replacement_generation = hashlib.sha256(replacement).hexdigest()
        parent = self.path.parent
        self._require_private_directory(parent, "mapping parent directory")

        current = self._read_private(self.path, "canonical mapping")
        if current == replacement:
            archive = self._read_private(self.archive_path, "archived old mapping")
            self._validate_old_mapping(archive)
            return replacement_generation
        self._validate_old_mapping(current)
        self._archive(current)

        temporary = parent / f".{self.path.name}.{self.operation_id}.replace.tmp"
        if os.path.lexists(temporary):
            if self._read_private(temporary, "replacement mapping transaction") != replacement:
                raise UserMappingStoreError("replacement mapping transaction differs")
        else:
            try:
                self._write_exclusive(temporary, replacement)
            except OSError as error:
                raise UserMappingStoreError("replacement mapping staging failed") from error
        try:
            os.replace(temporary, self.path)
            self._sync_directory(parent)
        except OSError as error:
            raise UserMappingStoreError("replacement mapping publication failed") from error
        if self._read_private(self.path, "replacement mapping") != replacement:
            raise UserMappingStoreError("replacement mapping read-back differs")
        return replacement_generation
