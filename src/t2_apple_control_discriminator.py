# SPDX-License-Identifier: GPL-2.0-only
"""One-shot Apple-control keybag UUID discriminator.

This module deliberately has no alias-bind, password, mapping-promotion, or
biometric operation.  It loads one imported saved keybag, reads its UUID twice
through the exclusive AKS transport, compares it privately, and unloads it.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

import t2_catacomb_store
import t2_mutation_journal as journal
import t2_user_mapping


STATE_ROOT = Path("/var/lib/t2-touchid")
ORIGIN = "macos-control-oracle-v1"
PROVENANCE_KEYS = {
    "schema_version", "origin", "operation_id", "linux_uid",
    "linux_account_generation", "apple_uid", "account_uuid", "bag_uuid",
    "keybag_sha256", "keybag_archive_sha256", "catacomb_capture_sha256",
    "catacomb_backup_sha256", "catacomb_component_sha256", "identity_count",
    "keybag_source_view_count", "mapped_candidate_count", "mapping_generation",
    "mapping_enabled", "sep_keybag_uuid_verified", "import_complete",
}
COMPLETION_KEYS = {
    "mapping_generation", "mapping_enabled", "sep_keybag_uuid_verified",
    "import_complete",
}


class AppleControlDiscriminatorError(RuntimeError):
    pass


class DiscriminatorTransport(Protocol):
    runtime_generation: str

    def load_keybag(self, keybag_path: str) -> int: ...
    def bag_uuid(self, handle: int) -> str: ...
    def unload_keybag(self, handle: int) -> int: ...


@dataclass(frozen=True, repr=False)
class OracleEvidence:
    import_operation_id: str
    mapping_generation: str
    linux_uid: int
    apple_uid: int
    bag_uuid: str
    keybag_path: str
    keybag_sha256: str


@dataclass(frozen=True)
class DiscriminatorResult:
    outcome: str
    uuid_matched: bool
    handle_released: bool
    reconciliation_required: bool

    def public_summary(self) -> dict[str, object]:
        return {
            "outcome": self.outcome,
            "uuid_matched": self.uuid_matched,
            "handle_released": self.handle_released,
            "reconciliation_required": self.reconciliation_required,
            "mapping_enabled": False,
            "live_operation_scope": "load-double-uuid-unload",
            "identifiers_redacted": True,
        }


def _private_buffer(path: Path, maximum: int = 16 * 1024 * 1024) -> bytearray:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_nlink != 1
            or info.st_mode & 0o077
            or not 0 < info.st_size <= maximum
        ):
            raise AppleControlDiscriminatorError(
                "protected oracle artifact metadata is unsafe"
            )
        value = bytearray()
        while len(value) <= maximum:
            block = os.read(descriptor, min(65536, maximum + 1 - len(value)))
            if not block:
                break
            value.extend(block)
        if len(value) != info.st_size:
            raise AppleControlDiscriminatorError(
                "protected oracle artifact changed during read"
            )
        return value
    except OSError as error:
        raise AppleControlDiscriminatorError(
            "protected oracle artifact cannot be opened"
        ) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _private_bytes(path: Path, maximum: int = 16 * 1024 * 1024) -> bytes:
    value = _private_buffer(path, maximum)
    try:
        return bytes(value)
    finally:
        value[:] = b"\0" * len(value)


def _document(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(_private_bytes(path, 1024 * 1024))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise AppleControlDiscriminatorError(
            "protected oracle metadata is not valid JSON"
        ) from error
    if not isinstance(value, dict):
        raise AppleControlDiscriminatorError("protected oracle metadata is invalid")
    return value


def _sha256(path: Path) -> str:
    value = _private_buffer(path)
    try:
        return hashlib.sha256(value).hexdigest()
    finally:
        value[:] = b"\0" * len(value)


def _uuid(value: object, label: str) -> str:
    try:
        parsed = uuid.UUID(value)  # type: ignore[arg-type]
    except (AttributeError, TypeError, ValueError) as error:
        raise AppleControlDiscriminatorError(f"{label} is invalid") from error
    if parsed.int == 0 or str(parsed) != value:
        raise AppleControlDiscriminatorError(f"{label} is invalid")
    return str(parsed)


def _digest(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise AppleControlDiscriminatorError(f"{label} is invalid")
    return value


def read_oracle_import(state_root: Path, linux_uid: int) -> OracleEvidence:
    """Read back every imported artifact needed by the live discriminator."""
    if not isinstance(state_root, Path) or not state_root.is_absolute():
        raise AppleControlDiscriminatorError("state root is invalid")
    if type(linux_uid) is not int or not 1 <= linux_uid < (1 << 32) - 1:
        raise AppleControlDiscriminatorError("Linux UID is invalid")
    mapping_data = _private_bytes(state_root / "users.json", 1024 * 1024)
    try:
        mapping_set = t2_user_mapping.parse(mapping_data)
    except t2_user_mapping.UserMappingError as error:
        raise AppleControlDiscriminatorError("protected mapping is invalid") from error
    if len(mapping_set.mappings) != 1:
        raise AppleControlDiscriminatorError("oracle mapping is not unique")
    selected = mapping_set.mappings[0]
    if selected.linux_uid != linux_uid or selected.enabled:
        raise AppleControlDiscriminatorError("oracle mapping is not disabled and bound")

    provenance = _document(
        state_root / "users" / str(linux_uid) / "apple-control-import.json"
    )
    intent = _document(state_root / "oracle" / "apple-control-import-intent.json")
    if (
        set(provenance) != PROVENANCE_KEYS
        or set(intent) != PROVENANCE_KEYS - COMPLETION_KEYS
        or {key: provenance[key] for key in intent} != intent
        or provenance["schema_version"] != 1
        or provenance["origin"] != ORIGIN
        or provenance["mapping_enabled"] is not False
        or provenance["sep_keybag_uuid_verified"] is not False
        or provenance["import_complete"] is not True
        or provenance["mapping_generation"] != mapping_set.generation
    ):
        raise AppleControlDiscriminatorError("oracle provenance is not exact")

    operation_id = _uuid(provenance["operation_id"], "import operation ID")
    bag_uuid = _uuid(provenance["bag_uuid"], "oracle bag UUID")
    keybag_sha256 = _digest(provenance["keybag_sha256"], "keybag digest")
    component_hashes = provenance["catacomb_component_sha256"]
    expected_names = {
        "master.cat", "biolockout.cat", f"user_{selected.apple_uid:08x}.cat"
    }
    if (
        type(provenance["linux_uid"]) is not int
        or provenance["linux_uid"] != selected.linux_uid
        or type(provenance["apple_uid"]) is not int
        or provenance["apple_uid"] != selected.apple_uid
        or provenance["account_uuid"] != selected.account_uuid
        or bag_uuid != selected.bag_uuid
        or keybag_sha256 != selected.keybag_sha256
        or provenance["linux_account_generation"]
        != selected.linux_account_generation
        or not isinstance(component_hashes, dict)
        or set(component_hashes) != expected_names
    ):
        raise AppleControlDiscriminatorError("oracle bindings are inconsistent")
    for name in expected_names:
        _digest(component_hashes[name], f"{name} digest")

    keybag_path = Path(selected.keybag_path)
    if _sha256(keybag_path) != keybag_sha256:
        raise AppleControlDiscriminatorError("saved keybag digest changed")
    for field, suffix in (
        ("keybag_archive_sha256", ".keybags.tar.gz"),
        ("catacomb_capture_sha256", ".catacomb.tar.gz"),
    ):
        digest = _digest(provenance[field], field)
        if _sha256(state_root / "oracle" / f"{digest}{suffix}") != digest:
            raise AppleControlDiscriminatorError("captured oracle archive changed")
    backup_digest = _digest(
        provenance["catacomb_backup_sha256"], "Catacomb backup digest"
    )
    if _sha256(state_root / "backups" / f"{backup_digest}.tar.gz") != backup_digest:
        raise AppleControlDiscriminatorError("normalized Catacomb backup changed")
    try:
        components = t2_catacomb_store.CatacombStore(
            state_root / "catacomb", selected.apple_uid
        ).read_committed_components()
    except t2_catacomb_store.CatacombStoreError as error:
        raise AppleControlDiscriminatorError("local Catacomb is invalid") from error
    if {
        name: hashlib.sha256(data).hexdigest() for name, data in components.items()
    } != component_hashes:
        raise AppleControlDiscriminatorError("local Catacomb changed after import")
    return OracleEvidence(
        operation_id, mapping_set.generation, selected.linux_uid,
        selected.apple_uid, bag_uuid, selected.keybag_path, keybag_sha256,
    )


def _baseline(evidence: OracleEvidence, linux_boot_uuid: str, runtime: str) -> dict[str, Any]:
    return {
        "operation_kind": "apple-control-uuid-discriminator",
        "origin": ORIGIN,
        "import_operation_id": evidence.import_operation_id,
        "mapping_generation": evidence.mapping_generation,
        "linux_boot_uuid": _uuid(linux_boot_uuid, "Linux boot UUID"),
        "runtime_generation": _uuid(runtime, "AKS runtime generation"),
        "linux_uid": evidence.linux_uid,
        "apple_uid": evidence.apple_uid,
        "bag_uuid": evidence.bag_uuid,
        "keybag_sha256": evidence.keybag_sha256,
        "operation_scope": "load-double-uuid-unload",
        "mapping_enabled": False,
    }


def _append(path: Path, operation_id: str, milestone: str, evidence: dict[str, Any], *, exclusive: bool = False) -> None:
    try:
        journal.append(path, operation_id, milestone, evidence, exclusive=exclusive)
    except (OSError, journal.JournalError) as error:
        raise AppleControlDiscriminatorError(
            "discriminator journal cannot advance safely"
        ) from error


def _unknown(path: Path, operation_id: str, runtime: str, stage: str, reason: str) -> None:
    try:
        _append(path, operation_id, "APPLE_CONTROL_DISCRIMINATOR_OUTCOME_UNKNOWN", {
            "runtime_generation": runtime, "stage": stage, "reason": reason,
            "retry_before_reboot_permitted": False,
        })
    except BaseException:
        pass


def run(
    *,
    journal_path: Path,
    evidence: OracleEvidence,
    linux_boot_uuid: str,
    transport: DiscriminatorTransport,
    operation_id: str | None = None,
) -> DiscriminatorResult:
    """Run exactly load, two UUID reads (inside transport), and unload once."""
    operation_id = operation_id or str(uuid.uuid4())
    _uuid(operation_id, "discriminator operation ID")
    runtime = _uuid(transport.runtime_generation, "AKS runtime generation")
    _append(
        journal_path, operation_id, "APPLE_CONTROL_DISCRIMINATOR_BASELINE",
        _baseline(evidence, linux_boot_uuid, runtime), exclusive=True,
    )
    _append(journal_path, operation_id, "APPLE_CONTROL_KEYBAG_LOAD_INTENT", {
        "runtime_generation": runtime,
        "keybag_sha256": evidence.keybag_sha256,
        "mutation_possible": True,
    })
    handle: int | None = None
    unload_attempted = False
    try:
        handle = transport.load_keybag(evidence.keybag_path)
        if type(handle) is not int or not 1 <= handle <= 0x7FFFFFFF:
            raise AppleControlDiscriminatorError("transport returned an invalid handle")
        _append(journal_path, operation_id, "APPLE_CONTROL_KEYBAG_HANDLE_OBSERVED", {
            "runtime_generation": runtime, "handle": handle,
        })
        observed = transport.bag_uuid(handle)
        observed = _uuid(observed, "observed keybag UUID")
        matched = observed == evidence.bag_uuid
        _append(journal_path, operation_id, "APPLE_CONTROL_KEYBAG_UUID_OBSERVED", {
            "runtime_generation": runtime, "handle": handle,
            "double_read_equal": True, "bag_uuid_matches": matched,
        })
        _append(journal_path, operation_id, "APPLE_CONTROL_KEYBAG_UNLOAD_INTENT", {
            "runtime_generation": runtime, "handle": handle,
            "mutation_possible": True,
        })
        unload_attempted = True
        status = transport.unload_keybag(handle)
        if type(status) is not int or status != 0:
            raise AppleControlDiscriminatorError("keybag unload did not succeed")
        handle = None
        _append(journal_path, operation_id, "APPLE_CONTROL_KEYBAG_HANDLE_RELEASED", {
            "runtime_generation": runtime, "command_status": 0,
        })
        outcome = "matched" if matched else "mismatched"
        _append(journal_path, operation_id, "APPLE_CONTROL_DISCRIMINATOR_COMPLETE", {
            "runtime_generation": runtime, "outcome": outcome,
            "bag_uuid_matches": matched, "mapping_promoted": False,
        })
        return DiscriminatorResult(outcome, matched, True, False)
    except BaseException as error:
        if handle is not None and not unload_attempted:
            try:
                _append(journal_path, operation_id, "APPLE_CONTROL_KEYBAG_UNLOAD_INTENT", {
                    "runtime_generation": runtime, "handle": handle,
                    "mutation_possible": True,
                })
            except BaseException:
                pass
            unload_attempted = True
            try:
                transport.unload_keybag(handle)
                handle = None
            except BaseException:
                pass
        _unknown(
            journal_path, operation_id, runtime,
            "unload" if unload_attempted and handle is not None else "live-discriminator",
            "transport-or-journal-failure",
        )
        raise AppleControlDiscriminatorError(
            "Apple-control discriminator outcome is unknown; do not retry before reboot"
        ) from error
