# SPDX-License-Identifier: GPL-2.0-only
"""Fail-closed persistent mapping model for already-provisioned Apple users.

This module deliberately performs no keybag, SEP, Catacomb, or account action.
It validates the private administrator-owned authority that future multi-user
brokers must reconcile against live state before selecting a target.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import uuid
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any


SCHEMA_VERSION = 2
LEGACY_SCHEMA_VERSION = 1
ROOT_UID = 0
MAX_FILE_SIZE = 1024 * 1024
MAX_MAPPINGS = 64
UINT32_MAX = (1 << 32) - 1
INT32_MAX = (1 << 31) - 1
KEYBAG_ROOT = PurePosixPath("/var/lib/t2-touchid/users")
CAPABILITIES = frozenset({"verify", "enroll", "identity-management"})
UNLOCK_MODES = frozenset({"password-on-demand", "host-encrypted-credential"})
SAFE_BASENAME = re.compile(r"[A-Za-z0-9_.-]{1,128}\Z", re.ASCII)


class UserMappingError(ValueError):
    """Raised when persistent mapping authority is unsafe or ambiguous."""


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise UserMappingError("mapping JSON contains a duplicate key")
        result[key] = value
    return result


def _unsigned(value: Any, label: str, *, minimum: int) -> int:
    if type(value) is not int or not minimum <= value < UINT32_MAX:
        raise UserMappingError(f"{label} is outside the permitted numeric range")
    return value


def _sha256(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise UserMappingError(f"{label} is not a lowercase SHA-256 digest")
    return value


def _canonical_uuid(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise UserMappingError(f"{label} is not a canonical UUID")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as error:
        raise UserMappingError(f"{label} is not a canonical UUID") from error
    if parsed.int == 0 or str(parsed) != value:
        raise UserMappingError(f"{label} is not a canonical nonzero UUID")
    return value


def _legacy_keybag_path(value: Any, linux_uid: int) -> str:
    expected = KEYBAG_ROOT / str(linux_uid) / "user.kb"
    if not isinstance(value, str) or PurePosixPath(value) != expected:
        raise UserMappingError(
            "keybag path must use the target UID's private canonical location"
        )
    return value


def _bundle_path(
    value: Any,
    linux_uid: int,
    bundle_generation: str,
    filename: str,
    label: str,
) -> str:
    expected = (
        KEYBAG_ROOT
        / str(linux_uid)
        / "identities"
        / bundle_generation
        / filename
    )
    if not isinstance(value, str) or PurePosixPath(value) != expected:
        raise UserMappingError(
            f"{label} must use the target UID's private canonical generation"
        )
    return value


@dataclass(frozen=True)
class UserMapping:
    linux_uid: int
    linux_account_generation: str
    apple_uid: int
    account_uuid: str
    bag_uuid: str
    keybag_path: str
    keybag_sha256: str
    unlock_mode: str
    capabilities: frozenset[str]
    enabled: bool
    bundle_generation: str | None = None
    activation_secret_path: str | None = None
    activation_secret_sha256: str | None = None
    activation_secret_length: int | None = None

    @property
    def special_bag_alias(self) -> int:
        """Return the derived Apple alias; it is never caller-controlled."""

        return -self.apple_uid

    def permits(self, capability: str) -> bool:
        if capability not in CAPABILITIES:
            raise UserMappingError("requested capability is unknown")
        return self.enabled and capability in self.capabilities


@dataclass(frozen=True)
class UserMappingSet:
    generation: str
    mappings: tuple[UserMapping, ...]
    schema_version: int = LEGACY_SCHEMA_VERSION

    def resolve(self, linux_uid: int, capability: str) -> UserMapping:
        _unsigned(linux_uid, "target Linux UID", minimum=1)
        if capability not in CAPABILITIES:
            raise UserMappingError("requested capability is unknown")
        selected = [item for item in self.mappings if item.linux_uid == linux_uid]
        if len(selected) != 1:
            raise UserMappingError("target Linux UID has no unique protected mapping")
        if not selected[0].permits(capability):
            raise UserMappingError("target mapping does not permit this capability")
        return selected[0]

    def redacted_summary(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "mapping_count": len(self.mappings),
            "enabled_mapping_count": sum(item.enabled for item in self.mappings),
            "password_on_demand_count": sum(
                item.unlock_mode == "password-on-demand" for item in self.mappings
            ),
            "host_encrypted_credential_count": sum(
                item.unlock_mode == "host-encrypted-credential"
                for item in self.mappings
            ),
            "identifiers_redacted": True,
        }


def _parse_mapping(value: Any, schema_version: int) -> UserMapping:
    legacy_fields = {
        "linux_uid",
        "linux_account_generation",
        "apple_uid",
        "account_uuid",
        "bag_uuid",
        "keybag_path",
        "keybag_sha256",
        "unlock_mode",
        "capabilities",
        "enabled",
    }
    activation_fields = {
        "bundle_generation",
        "activation_secret_path",
        "activation_secret_sha256",
        "activation_secret_length",
    }
    expected_fields = (
        legacy_fields
        if schema_version == LEGACY_SCHEMA_VERSION
        else legacy_fields | activation_fields
    )
    if not isinstance(value, dict) or set(value) != expected_fields:
        raise UserMappingError("mapping entry fields are incomplete or unsupported")
    linux_uid = _unsigned(value["linux_uid"], "Linux UID", minimum=1)
    apple_uid = _unsigned(value["apple_uid"], "Apple UID", minimum=10)
    if apple_uid > INT32_MAX:
        raise UserMappingError("Apple UID cannot form a signed AKS alias")
    unlock_mode = value["unlock_mode"]
    if not isinstance(unlock_mode, str) or unlock_mode not in UNLOCK_MODES:
        raise UserMappingError("unlock mode is unsupported")
    capabilities = value["capabilities"]
    if (
        not isinstance(capabilities, list)
        or any(not isinstance(item, str) for item in capabilities)
        or len(capabilities) != len(set(capabilities))
        or capabilities != sorted(capabilities)
        or any(item not in CAPABILITIES for item in capabilities)
    ):
        raise UserMappingError("capabilities must be a sorted unique supported list")
    if type(value["enabled"]) is not bool:
        raise UserMappingError("mapping enabled state must be Boolean")
    account_uuid = _canonical_uuid(value["account_uuid"], "Apple account UUID")
    bundle_generation = None
    activation_secret_path = None
    activation_secret_sha256 = None
    activation_secret_length = None
    if schema_version == SCHEMA_VERSION:
        bundle_generation = _canonical_uuid(
            value["bundle_generation"], "activation bundle generation"
        )
        activation_secret_path = _bundle_path(
            value["activation_secret_path"],
            linux_uid,
            bundle_generation,
            "activation.secret",
            "activation secret path",
        )
        activation_secret_sha256 = _sha256(
            value["activation_secret_sha256"], "activation secret digest"
        )
        if value["activation_secret_length"] != 16 or type(
            value["activation_secret_length"]
        ) is not int:
            raise UserMappingError("activation secret length must be exactly 16")
        activation_secret_length = 16
        keybag_path = _bundle_path(
            value["keybag_path"],
            linux_uid,
            bundle_generation,
            "user.kb",
            "keybag path",
        )
    else:
        keybag_path = _legacy_keybag_path(value["keybag_path"], linux_uid)
    return UserMapping(
        linux_uid=linux_uid,
        linux_account_generation=_sha256(
            value["linux_account_generation"], "Linux account generation"
        ),
        apple_uid=apple_uid,
        account_uuid=account_uuid,
        bag_uuid=_canonical_uuid(value["bag_uuid"], "AKS bag UUID"),
        keybag_path=keybag_path,
        keybag_sha256=_sha256(value["keybag_sha256"], "keybag digest"),
        unlock_mode=unlock_mode,
        capabilities=frozenset(capabilities),
        enabled=value["enabled"],
        bundle_generation=bundle_generation,
        activation_secret_path=activation_secret_path,
        activation_secret_sha256=activation_secret_sha256,
        activation_secret_length=activation_secret_length,
    )


def parse(data: bytes) -> UserMappingSet:
    if not isinstance(data, bytes) or not 0 < len(data) <= MAX_FILE_SIZE:
        raise UserMappingError("mapping file size is invalid")
    try:
        document = json.loads(
            data.decode("utf-8"), object_pairs_hook=_object_without_duplicate_keys
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        raise UserMappingError("mapping file is not strict UTF-8 JSON") from error
    if (
        not isinstance(document, dict)
        or set(document) != {"schema_version", "mappings"}
        or type(document["schema_version"]) is not int
        or document["schema_version"]
        not in {LEGACY_SCHEMA_VERSION, SCHEMA_VERSION}
        or not isinstance(document["mappings"], list)
        or len(document["mappings"]) > MAX_MAPPINGS
    ):
        raise UserMappingError("mapping document schema is unsupported")
    schema_version = document["schema_version"]
    mappings = tuple(
        _parse_mapping(item, schema_version) for item in document["mappings"]
    )
    unique_fields = [
        ("linux_uid", "Linux UID"),
        ("apple_uid", "Apple UID"),
        ("account_uuid", "Apple account UUID"),
        ("bag_uuid", "AKS bag UUID"),
        ("keybag_path", "keybag path"),
    ]
    if schema_version == SCHEMA_VERSION:
        unique_fields.extend(
            [
                ("bundle_generation", "activation bundle generation"),
                ("activation_secret_path", "activation secret path"),
            ]
        )
    for attribute, label in unique_fields:
        values = [getattr(item, attribute) for item in mappings]
        if len(values) != len(set(values)):
            raise UserMappingError(f"{label} is mapped more than once")
    return UserMappingSet(hashlib.sha256(data).hexdigest(), mappings, schema_version)


def serialize(mappings: tuple[UserMapping, ...]) -> bytes:
    """Return the one canonical administrator-written mapping document."""

    if not isinstance(mappings, tuple) or any(
        not isinstance(item, UserMapping) for item in mappings
    ):
        raise UserMappingError("mapping serialization input is invalid")
    try:
        ordered = tuple(sorted(mappings, key=lambda item: item.linux_uid))
        activation_rows = tuple(
            all(
                value is not None
                for value in (
                    item.bundle_generation,
                    item.activation_secret_path,
                    item.activation_secret_sha256,
                    item.activation_secret_length,
                )
            )
            for item in ordered
        )
        if any(activation_rows) and not all(activation_rows):
            raise UserMappingError(
                "legacy and activation mappings cannot share one document"
            )
        schema_version = (
            SCHEMA_VERSION
            if activation_rows and all(activation_rows)
            else LEGACY_SCHEMA_VERSION
        )

        def serialized_mapping(item: UserMapping) -> dict[str, object]:
            result: dict[str, object] = {
                "linux_uid": item.linux_uid,
                "linux_account_generation": item.linux_account_generation,
                "apple_uid": item.apple_uid,
                "account_uuid": item.account_uuid,
                "bag_uuid": item.bag_uuid,
                "keybag_path": item.keybag_path,
                "keybag_sha256": item.keybag_sha256,
                "unlock_mode": item.unlock_mode,
                "capabilities": sorted(item.capabilities),
                "enabled": item.enabled,
            }
            if schema_version == SCHEMA_VERSION:
                result.update(
                    {
                        "bundle_generation": item.bundle_generation,
                        "activation_secret_path": item.activation_secret_path,
                        "activation_secret_sha256": item.activation_secret_sha256,
                        "activation_secret_length": item.activation_secret_length,
                    }
                )
            return result

        document = {
            "schema_version": schema_version,
            "mappings": [serialized_mapping(item) for item in ordered],
        }
        encoded = (
            json.dumps(
                document,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            )
            + "\n"
        ).encode("ascii")
    except (AttributeError, TypeError, ValueError) as error:
        raise UserMappingError("mapping serialization failed") from error
    parsed = parse(encoded)
    if parsed.mappings != ordered:
        raise UserMappingError("mapping serialization did not round trip")
    return encoded


def _secure_file(info: os.stat_result) -> bool:
    return (
        stat.S_ISREG(info.st_mode)
        and info.st_uid == ROOT_UID
        and info.st_nlink == 1
        and not info.st_mode & 0o077
        and 0 < info.st_size <= MAX_FILE_SIZE
    )


def _same_file(before: os.stat_result, after: os.stat_result) -> bool:
    fields = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_uid",
        "st_gid",
        "st_nlink",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
    )
    return all(getattr(before, field) == getattr(after, field) for field in fields)


def _load_descriptor(descriptor: int) -> UserMappingSet:
    if type(descriptor) is not int or descriptor < 0:
        raise UserMappingError("mapping descriptor is invalid")
    try:
        before = os.fstat(descriptor)
        if not _secure_file(before):
            raise UserMappingError("mapping file is not private and root-owned")
        os.lseek(descriptor, 0, os.SEEK_SET)
        data = bytearray()
        while len(data) <= MAX_FILE_SIZE:
            block = os.read(
                descriptor, min(65536, MAX_FILE_SIZE + 1 - len(data))
            )
            if not block:
                break
            data.extend(block)
        after = os.fstat(descriptor)
        if len(data) != before.st_size or not _same_file(before, after):
            raise UserMappingError("mapping file changed while it was being read")
        return parse(bytes(data))
    except OSError as error:
        raise UserMappingError("mapping file cannot be read safely") from error


def load_at(directory_descriptor: int, name: str) -> UserMappingSet:
    """Load one protected basename relative to an already trusted directory."""

    if (
        type(directory_descriptor) is not int
        or directory_descriptor < 0
        or not isinstance(name, str)
        or SAFE_BASENAME.fullmatch(name) is None
        or name in {".", ".."}
    ):
        raise UserMappingError("mapping location is invalid")
    descriptor = -1
    try:
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(name, flags, dir_fd=directory_descriptor)
        return _load_descriptor(descriptor)
    except OSError as error:
        raise UserMappingError("mapping file cannot be read safely") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def load(path: Path) -> UserMappingSet:
    descriptor = -1
    try:
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        return _load_descriptor(descriptor)
    except OSError as error:
        raise UserMappingError("mapping file cannot be read safely") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
