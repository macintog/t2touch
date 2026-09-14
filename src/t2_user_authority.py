# SPDX-License-Identifier: GPL-2.0-only
"""Load runtime user authority only from protected mapping and E4 evidence."""

from __future__ import annotations

import hashlib
import json
import fcntl
import os
import stat
import uuid
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import t2_enrollment_journal
import t2_linux_account
import t2_user_mapping
import t2_user_readiness


MAPPING_PATH = Path("/var/lib/t2-touchid/users.json")
USERS_ROOT = Path("/var/lib/t2-touchid/users")
MAX_AUTHORITY_SIZE = 16 * 1024
MAX_JOURNAL_SIZE = 8 * 1024 * 1024
AUTHORITY_MODE = "T2_TOUCHID_AUTHORITY_MODE"
COMPATIBILITY_MODE = "macos-control-oracle"
COMPATIBILITY_REBIND = "compatibility-account-rebind.json"


class UserAuthorityError(RuntimeError):
    pass


class UserAuthorityReadbackError(UserAuthorityError):
    """Publication committed, but its exact protected readback did not load."""

    pass


@dataclass(frozen=True, repr=False)
class RuntimeUserAuthority:
    mapping_set: t2_user_mapping.UserMappingSet
    selected: t2_user_mapping.UserMapping
    persistent: t2_user_readiness.PersistentEvidence
    enrollment_journal: Path
    origin: str = "linux-native-e4"


def _compatibility_runtime_mapping(
    disabled: t2_user_mapping.UserMapping,
) -> t2_user_mapping.UserMapping:
    """Expose one proven Apple-control identity set to the common product path."""

    if not isinstance(disabled, t2_user_mapping.UserMapping) or disabled.enabled:
        raise UserAuthorityError("compatibility mapping is not disabled")
    return replace(
        disabled,
        unlock_mode="host-encrypted-credential",
        capabilities=t2_user_mapping.CAPABILITIES,
        enabled=True,
    )


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise UserAuthorityError("authority manifest contains a duplicate key")
        result[key] = value
    return result


def _private_directory(path: Path) -> None:
    try:
        info = path.stat(follow_symlinks=False)
    except OSError as error:
        raise UserAuthorityError("authority directory is unavailable") from error
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != 0
        or info.st_mode & 0o077
    ):
        raise UserAuthorityError("authority directory is not private and root-owned")


def _read_manifest(path: Path) -> dict[str, Any]:
    descriptor = -1
    try:
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_nlink != 1
            or info.st_mode & 0o077
            or not 0 < info.st_size <= MAX_AUTHORITY_SIZE
        ):
            raise UserAuthorityError(
                "authority manifest is not a private root-owned regular file"
            )
        data = bytearray()
        while len(data) < info.st_size:
            block = os.read(descriptor, info.st_size - len(data))
            if not block:
                raise UserAuthorityError("authority manifest read was short")
            data.extend(block)
        if os.read(descriptor, 1):
            raise UserAuthorityError("authority manifest grew while being read")
        try:
            value = json.loads(data.decode("utf-8"), object_pairs_hook=_object)
        except (UnicodeError, json.JSONDecodeError) as error:
            raise UserAuthorityError("authority manifest is not strict JSON") from error
    except OSError as error:
        raise UserAuthorityError("authority manifest cannot be read safely") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not isinstance(value, dict):
        raise UserAuthorityError("authority manifest has the wrong type")
    return value


def _read_private_bytes(path: Path, maximum: int) -> bytes:
    descriptor = -1
    try:
        flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_nlink != 1
            or info.st_mode & 0o077
            or not 0 < info.st_size <= maximum
        ):
            raise UserAuthorityError("authority source file is unsafe")
        fcntl.flock(descriptor, fcntl.LOCK_SH)
        data = bytearray()
        while len(data) < info.st_size:
            block = os.read(descriptor, info.st_size - len(data))
            if not block:
                raise UserAuthorityError("authority source read was short")
            data.extend(block)
        if os.read(descriptor, 1):
            raise UserAuthorityError("authority source changed while being read")
        return bytes(data)
    except OSError as error:
        raise UserAuthorityError("authority source cannot be read safely") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _write_exclusive(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    complete = False
    try:
        offset = 0
        while offset < len(data):
            written = os.write(descriptor, data[offset:])
            if written <= 0:
                raise UserAuthorityError("authority write made no progress")
            offset += written
        os.fsync(descriptor)
        complete = True
    finally:
        os.close(descriptor)
        if not complete and os.path.lexists(path):
            path.unlink()


def _bound_history(
    mapping_set: t2_user_mapping.UserMappingSet,
    selected: t2_user_mapping.UserMapping,
    history: t2_enrollment_journal.EnrollmentHistory,
    target_linux_uid: int,
) -> None:
    baseline = history.baseline
    if (
        history.phase
        is not t2_enrollment_journal.EnrollmentPhase.POST_REBOOT_VERIFIED
        or history.reconciled_snapshot_sha256 is None
        or history.post_reboot_linux_boot_uuid is None
        or history.terminal_identity_uuid is None
        or baseline["caller_linux_uid"] != target_linux_uid
        or baseline["target_linux_uid"] != target_linux_uid
        or baseline["apple_uid"] != selected.apple_uid
        or baseline["account_uuid"] != selected.account_uuid
        or baseline["bag_uuid"] != selected.bag_uuid
        or baseline["mapping_generation"] != mapping_set.generation
    ):
        raise UserAuthorityError("runtime authority bindings do not reconcile")


def load(
    target_linux_uid: int,
    *,
    mapping_path: Path = MAPPING_PATH,
    users_root: Path = USERS_ROOT,
) -> RuntimeUserAuthority:
    """Resolve one UID from root-owned mapping and post-reboot enrollment proof."""

    if os.geteuid() != 0:
        raise UserAuthorityError("runtime user authority requires root")
    try:
        t2_user_mapping._unsigned(target_linux_uid, "target Linux UID", minimum=1)
    except t2_user_mapping.UserMappingError as error:
        raise UserAuthorityError(str(error)) from error
    if (
        not isinstance(mapping_path, Path)
        or not mapping_path.is_absolute()
        or not isinstance(users_root, Path)
        or not users_root.is_absolute()
    ):
        raise UserAuthorityError("authority paths must be absolute")
    _private_directory(users_root)
    user_root = users_root / str(target_linux_uid)
    _private_directory(user_root)
    manifest_path = user_root / "authority.json"
    manifest = _read_manifest(manifest_path)
    fields = {
        "schema_version",
        "linux_uid",
        "mapping_generation",
        "enrollment_operation_id",
        "enrollment_head_hash",
        "reconciliation_snapshot_sha256",
        "enrollment_journal",
    }
    if set(manifest) != fields or manifest["schema_version"] != 1:
        raise UserAuthorityError("authority manifest schema is unsupported")
    if manifest["linux_uid"] != target_linux_uid:
        raise UserAuthorityError("authority manifest belongs to another Linux UID")
    try:
        mapping_generation = t2_user_mapping._sha256(
            manifest["mapping_generation"], "mapping generation"
        )
        head_hash = t2_user_mapping._sha256(
            manifest["enrollment_head_hash"], "enrollment journal head"
        )
        snapshot = t2_user_mapping._sha256(
            manifest["reconciliation_snapshot_sha256"],
            "reconciliation snapshot",
        )
        operation_id = t2_user_mapping._canonical_uuid(
            manifest["enrollment_operation_id"], "enrollment operation ID"
        )
    except t2_user_mapping.UserMappingError as error:
        raise UserAuthorityError(str(error)) from error
    expected_name = f"{operation_id}.jsonl"
    if manifest["enrollment_journal"] != expected_name:
        raise UserAuthorityError("authority journal name is not operation-derived")
    journal_path = user_root / expected_name

    try:
        mapping_set = t2_user_mapping.load(mapping_path)
        selected = mapping_set.resolve(target_linux_uid, "verify")
        history = t2_enrollment_journal.read(journal_path)
    except (
        t2_user_mapping.UserMappingError,
        t2_enrollment_journal.EnrollmentJournalError,
    ) as error:
        raise UserAuthorityError("protected runtime authority is invalid") from error
    if (
        mapping_set.generation != mapping_generation
        or history.operation_id != operation_id
        or history.head_hash != head_hash
        or history.reconciled_snapshot_sha256 != snapshot
    ):
        raise UserAuthorityError("runtime authority bindings do not reconcile")
    _bound_history(mapping_set, selected, history, target_linux_uid)
    return RuntimeUserAuthority(
        mapping_set,
        selected,
        t2_user_readiness.PersistentEvidence(
            selected.linux_account_generation,
            selected.keybag_sha256,
            selected.apple_uid,
            selected.account_uuid,
            selected.bag_uuid,
            True,
        ),
        journal_path,
    )


def load_compatibility(
    target_linux_uid: int,
    *,
    state_root: Path = Path("/var/lib/t2-touchid"),
) -> RuntimeUserAuthority:
    """Build runtime authority from the immutable Apple-control proofs.

    The protected mapping stays disabled on disk. Compatibility authority is
    enabled only in memory; caller-bound mutation policy remains mandatory.
    """

    if os.geteuid() != 0:
        raise UserAuthorityError("runtime user authority requires root")
    if not isinstance(state_root, Path) or not state_root.is_absolute():
        raise UserAuthorityError("compatibility state root is invalid")
    try:
        import t2_apple_control_alias_discriminator as alias_discriminator
        import t2_apple_control_alias_reconciliation as alias_reconciliation
        import t2_apple_control_alias_unlock as alias_unlock
        import t2_apple_control_discriminator as keybag_discriminator

        evidence = keybag_discriminator.read_oracle_import(
            state_root, target_linux_uid
        )
        oracle_root = state_root / "oracle"
        matched = alias_discriminator.read_matched_keybag_proof(
            oracle_root / "apple-control-discriminator.jsonl", evidence
        )
        bind = alias_reconciliation.read_ambiguous_bind_proof(
            oracle_root, evidence, matched
        )
        reconciled = alias_reconciliation.read_reconciled_alias_proof(
            oracle_root, evidence, bind
        )
        unlocked = alias_unlock.read_completed_unlock_proof(
            oracle_root / "apple-control-alias-unlock.jsonl",
            evidence,
            reconciled,
        )
        disabled_set = t2_user_mapping.load(state_root / "users.json")
    except (OSError, ValueError, RuntimeError) as error:
        raise UserAuthorityError(
            "compatibility authority proof chain is invalid"
        ) from error
    if (
        disabled_set.generation != evidence.mapping_generation
        or len(disabled_set.mappings) != 1
        or disabled_set.mappings[0].linux_uid != target_linux_uid
        or disabled_set.mappings[0].enabled
    ):
        raise UserAuthorityError("compatibility mapping is not exact and disabled")
    disabled = disabled_set.mappings[0]
    selected = _compatibility_runtime_mapping(disabled)
    binding = {
        "schema_version": 1,
        "origin": keybag_discriminator.ORIGIN,
        "disabled_mapping_generation": disabled_set.generation,
        "import_operation_id": evidence.import_operation_id,
        "keybag_operation_id": matched.operation_id,
        "bind_operation_id": bind.operation_id,
        "reconciliation_operation_id": reconciled.operation_id,
        "state_blob_sha256": reconciled.state_blob_sha256,
        "unlock_operation_id": unlocked.operation_id,
    }
    generation = hashlib.sha256(
        json.dumps(
            binding, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
    ).hexdigest()
    rebind_path = state_root / "users" / str(target_linux_uid) / COMPATIBILITY_REBIND
    if os.path.lexists(rebind_path):
        rebind = _read_manifest(rebind_path)
        fields = {
            "schema_version",
            "origin",
            "operation_id",
            "linux_uid",
            "previous_account_generation",
            "current_account_generation",
            "disabled_mapping_generation",
            "base_authority_generation",
            "import_operation_id",
        }
        try:
            operation_id = t2_user_mapping._canonical_uuid(
                rebind.get("operation_id"), "account rebind operation ID"
            )
            previous_generation = t2_user_mapping._sha256(
                rebind.get("previous_account_generation"),
                "previous Linux account generation",
            )
            current_generation = t2_user_mapping._sha256(
                rebind.get("current_account_generation"),
                "current Linux account generation",
            )
        except t2_user_mapping.UserMappingError as error:
            raise UserAuthorityError(
                "compatibility account rebind is invalid"
            ) from error
        if (
            set(rebind) != fields
            or rebind["schema_version"] != 1
            or rebind["origin"] != keybag_discriminator.ORIGIN
            or rebind["linux_uid"] != target_linux_uid
            or previous_generation != selected.linux_account_generation
            or current_generation == previous_generation
            or rebind["disabled_mapping_generation"] != disabled_set.generation
            or rebind["base_authority_generation"] != generation
            or rebind["import_operation_id"] != evidence.import_operation_id
        ):
            raise UserAuthorityError(
                "compatibility account rebind does not match its authority"
            )
        selected = replace(
            selected, linux_account_generation=current_generation
        )
        binding["account_rebind_operation_id"] = operation_id
        binding["current_linux_account_generation"] = current_generation
        generation = hashlib.sha256(
            json.dumps(
                binding, sort_keys=True, separators=(",", ":"), ensure_ascii=True
            ).encode("ascii")
        ).hexdigest()
    mapping_set = t2_user_mapping.UserMappingSet(
        generation, (selected,), disabled_set.schema_version
    )
    return RuntimeUserAuthority(
        mapping_set,
        selected,
        t2_user_readiness.PersistentEvidence(
            selected.linux_account_generation,
            selected.keybag_sha256,
            selected.apple_uid,
            selected.account_uuid,
            selected.bag_uuid,
            True,
        ),
        oracle_root / "apple-control-alias-unlock.jsonl",
        keybag_discriminator.ORIGIN,
    )


def publish_compatibility_account_rebind(
    target_linux_uid: int,
    *,
    state_root: Path = Path("/var/lib/t2-touchid"),
) -> Path:
    """Bind an intact legacy control authority to the current account schema."""

    if os.geteuid() != 0:
        raise UserAuthorityError("compatibility account rebind requires root")
    authority = load_compatibility(target_linux_uid, state_root=state_root)
    current = t2_linux_account.collect(target_linux_uid)
    previous = authority.selected.linux_account_generation
    if current.generation == previous:
        raise UserAuthorityError("compatibility account already has current binding")
    user_root = state_root / "users" / str(target_linux_uid)
    _private_directory(user_root)
    path = user_root / COMPATIBILITY_REBIND
    if os.path.lexists(path):
        raise UserAuthorityError("compatibility account rebind already exists")
    provenance = _read_manifest(user_root / "apple-control-import.json")
    operation_id = str(uuid.uuid4())
    document = {
        "schema_version": 1,
        "origin": authority.origin,
        "operation_id": operation_id,
        "linux_uid": target_linux_uid,
        "previous_account_generation": previous,
        "current_account_generation": current.generation,
        "disabled_mapping_generation": provenance.get("mapping_generation"),
        "base_authority_generation": authority.mapping_set.generation,
        "import_operation_id": provenance.get("operation_id"),
    }
    encoded = json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    _write_exclusive(path, encoded)
    rebound = load_compatibility(target_linux_uid, state_root=state_root)
    if (
        rebound.selected.linux_account_generation != current.generation
        or rebound.mapping_set.generation == authority.mapping_set.generation
    ):
        raise UserAuthorityError("compatibility account rebind did not verify")
    return path


def load_runtime(target_linux_uid: int) -> RuntimeUserAuthority:
    """Load the explicitly configured native or compatibility authority."""

    mode = os.environ.get(AUTHORITY_MODE, "linux-native")
    if mode == "linux-native":
        return load(target_linux_uid)
    if mode == COMPATIBILITY_MODE:
        return load_compatibility(target_linux_uid)
    raise UserAuthorityError("runtime authority mode is unsupported")


def publish(
    target_linux_uid: int,
    source_journal: Path,
    *,
    mapping_path: Path = MAPPING_PATH,
    users_root: Path = USERS_ROOT,
) -> RuntimeUserAuthority:
    """Atomically publish one immutable E4 journal as runtime authority."""

    if os.geteuid() != 0:
        raise UserAuthorityError("runtime user authority requires root")
    if not isinstance(source_journal, Path) or not source_journal.is_absolute():
        raise UserAuthorityError("enrollment journal path must be absolute")
    try:
        mapping_set = t2_user_mapping.load(mapping_path)
        selected = mapping_set.resolve(target_linux_uid, "verify")
        source_history = t2_enrollment_journal.read(source_journal)
    except (
        t2_user_mapping.UserMappingError,
        t2_enrollment_journal.EnrollmentJournalError,
    ) as error:
        raise UserAuthorityError("publish source authority is invalid") from error
    _bound_history(mapping_set, selected, source_history, target_linux_uid)
    _private_directory(users_root)
    user_root = users_root / str(target_linux_uid)
    _private_directory(user_root)

    journal_bytes = _read_private_bytes(source_journal, MAX_JOURNAL_SIZE)
    journal_name = f"{source_history.operation_id}.jsonl"
    journal_path = user_root / journal_name
    if os.path.lexists(journal_path):
        if _read_private_bytes(journal_path, MAX_JOURNAL_SIZE) != journal_bytes:
            raise UserAuthorityError("published enrollment journal collides")
    else:
        _write_exclusive(journal_path, journal_bytes)
    try:
        copied_history = t2_enrollment_journal.read(journal_path)
    except t2_enrollment_journal.EnrollmentJournalError as error:
        raise UserAuthorityError("published enrollment journal is invalid") from error
    if copied_history != source_history:
        raise UserAuthorityError("published enrollment journal changed")

    manifest = {
        "schema_version": 1,
        "linux_uid": target_linux_uid,
        "mapping_generation": mapping_set.generation,
        "enrollment_operation_id": copied_history.operation_id,
        "enrollment_head_hash": copied_history.head_hash,
        "reconciliation_snapshot_sha256": (
            copied_history.reconciled_snapshot_sha256
        ),
        "enrollment_journal": journal_name,
    }
    encoded = json.dumps(
        manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    temporary = user_root / f".authority.{copied_history.operation_id}.tmp"
    if os.path.lexists(temporary):
        if _read_private_bytes(temporary, MAX_AUTHORITY_SIZE) != encoded:
            raise UserAuthorityError("authority publication transaction collides")
    else:
        _write_exclusive(temporary, encoded)
    committed = False
    try:
        os.replace(temporary, user_root / "authority.json")
        directory_fd = os.open(
            user_root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
        )
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        committed = True
    finally:
        if not committed and os.path.lexists(temporary):
            temporary.unlink()
    try:
        return load(
            target_linux_uid, mapping_path=mapping_path, users_root=users_root
        )
    except UserAuthorityError as error:
        raise UserAuthorityReadbackError(
            "published runtime authority failed protected readback"
        ) from error
