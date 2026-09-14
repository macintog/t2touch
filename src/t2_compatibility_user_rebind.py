# SPDX-License-Identifier: GPL-2.0-only
"""One-shot recovery of an empty loaded compatibility biometric user.

This adapts T1Bridge's guarded whole-user removal only.  T2 component
selection and restoration remain separate, evidence-gated operations because
command 0x31 is not a generic user selector on the reference bridgeOS build.
"""

from __future__ import annotations

import hashlib
import os
import stat
import struct
import uuid
from dataclasses import dataclass, field
from pathlib import Path

import t2_bridge_inventory
import t2_bridge_wire as wire
import t2_catacomb_bridge
import t2_catacomb_codec
import t2_catacomb_protocol
import t2_catacomb_store
import t2_mutation_journal


class CompatibilityUserRebindError(RuntimeError):
    """Raised when the empty-user reset cannot be proven safe or complete."""


@dataclass(frozen=True, repr=False)
class CanonicalAuthority:
    identity_records: frozenset[tuple[int, str]]
    master_enrollment_count: int
    component_hashes: tuple[str, ...]
    user_secure_data: bytes
    master_archive: bytes

    @property
    def identity_count(self) -> int:
        return len(self.identity_records)


D225_TERMINAL_MILESTONES = (
    "BASELINE_RECONCILED",
    "REMOVE_USER_INTENT",
    "REMOVE_USER_ACCEPTED",
    "POST_STATE_OBSERVED",
    "USER_LOAD_INTENT",
    "USER_LOAD_REPLY_REJECTED",
    "MASTER_EXPORT_PREPARE_INTENT",
    "MASTER_EXPORT_PREPARED",
    "MASTER_EXPORT_COMPLETE_INTENT",
    "MASTER_EXPORT_CAPTURED",
    "MASTER_EXPORT_CONFIRM_INTENT",
    "MASTER_EXPORT_CONFIRMED",
    "MASTER_SETTLED",
    "SAVED_USER_RELOAD_INTENT",
    "SAVED_USER_RELOAD_REPLY_REJECTED",
    "MISSING_USER_PREPARE_INTENT",
    "MISSING_USER_PREPARE_ACCEPTED",
    "MISSING_USER_PREPARE_POST_STATE_REJECTED",
    "MISSING_MASTER_PREPARE_INTENT",
    "MISSING_MASTER_PREPARE_ACCEPTED",
    "MISSING_USER_REPREPARE_INTENT",
    "MISSING_USER_REPREPARE_ACCEPTED",
    "BRIDGE_CLIENT_VERSION_SELECTED",
    "MISSING_COMPONENT_SEQUENCE_OBSERVED",
)


@dataclass(frozen=True, repr=False)
class RetainedMasterSeed:
    """Private, offline-only input for a future fresh-generation restore."""

    secure_data: bytes = field(repr=False)
    candidate_archive: bytes = field(repr=False)
    source_record_count: int
    source_head_hash: str = field(repr=False)
    authority_generation: str = field(repr=False)
    source_linux_boot_uuid: str
    current_linux_boot_uuid: str
    canonical_identity_count: int

    def __repr__(self) -> str:
        return (
            "RetainedMasterSeed(source_record_count="
            f"{self.source_record_count}, canonical_identity_count="
            f"{self.canonical_identity_count}, different_boot=True, "
            "private=True)"
        )


@dataclass(frozen=True, repr=False)
class RetainedMasterRestorePlan:
    """Private two-load plan admitted only by an exact cold live surface."""

    master_secure_data: bytes = field(repr=False)
    user_secure_data: bytes = field(repr=False)
    candidate_master_archive: bytes = field(repr=False)
    expected_identity_records: frozenset[tuple[int, str]] = field(repr=False)
    expected_identity_count: int
    current_linux_boot_uuid: str
    source_head_hash: str = field(repr=False)

    def __repr__(self) -> str:
        return (
            "RetainedMasterRestorePlan(expected_identity_count="
            f"{self.expected_identity_count}, cold_loadable=True, "
            "private=True)"
        )


def plan_retained_master_restore(
    canonical: CanonicalAuthority,
    seed: RetainedMasterSeed,
    preflight_surface: dict[str, object],
) -> RetainedMasterRestorePlan:
    """Admit the retained-master hypothesis without exposing a dispatcher."""

    if (
        not isinstance(canonical, CanonicalAuthority)
        or not isinstance(seed, RetainedMasterSeed)
        or not isinstance(preflight_surface, dict)
        or set(preflight_surface)
        != {
            "per_user_identity_count",
            "global_identity_count",
            "user_states",
            "group_state_count",
        }
        or seed.canonical_identity_count != canonical.identity_count
        or seed.authority_generation is None
        or seed.source_linux_boot_uuid == seed.current_linux_boot_uuid
        or seed.source_record_count != len(D225_TERMINAL_MILESTONES)
    ):
        raise CompatibilityUserRebindError(
            "retained master restore plan inputs are invalid"
        )
    try:
        user_ids = {user_id for user_id, _identity_uuid in canonical.identity_records}
        if len(user_ids) != 1:
            raise CompatibilityUserRebindError(
                "retained master restore ownership is ambiguous"
            )
        apple_user_id = next(iter(user_ids))
        candidate = t2_catacomb_codec.decode_master_catacomb(
            seed.candidate_archive
        )
    except CompatibilityUserRebindError:
        raise
    except (TypeError, ValueError, t2_catacomb_codec.CatacombCodecError) as error:
        raise CompatibilityUserRebindError(
            "retained master restore material is invalid"
        ) from error
    cold_states = {
        (("master", 0xFFFFFFFF, 1),),
        (("master", 0xFFFFFFFF, 1), ("user", apple_user_id, 1)),
    }
    if (
        preflight_surface["per_user_identity_count"] != 0
        or preflight_surface["global_identity_count"] != 0
        or preflight_surface["group_state_count"] != 0
        or preflight_surface["user_states"] not in cold_states
    ):
        raise CompatibilityUserRebindError(
            "retained master restore requires an exact cold and loadable surface"
        )
    if (
        candidate.secure_data != seed.secure_data
        or candidate.enrollment_count != canonical.identity_count
        or not canonical.user_secure_data
    ):
        raise CompatibilityUserRebindError(
            "retained master restore material does not match canonical authority"
        )
    return RetainedMasterRestorePlan(
        seed.secure_data,
        canonical.user_secure_data,
        seed.candidate_archive,
        canonical.identity_records,
        canonical.identity_count,
        seed.current_linux_boot_uuid,
        seed.source_head_hash,
    )


def _read_private_regular(path: Path, maximum: int = 1024 * 1024) -> bytes:
    descriptor = -1
    try:
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or before.st_mode & 0o077
            or not 0 < before.st_size <= maximum
        ):
            raise CompatibilityUserRebindError(
                "retained master artifact is not private and caller-owned"
            )
        data = bytearray()
        while len(data) < before.st_size:
            block = os.read(descriptor, min(65536, before.st_size - len(data)))
            if not block:
                raise CompatibilityUserRebindError(
                    "retained master artifact read was short"
                )
            data.extend(block)
        after = os.fstat(descriptor)
        if (
            len(data) != before.st_size
            or any(
                getattr(before, name) != getattr(after, name)
                for name in (
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
            )
        ):
            raise CompatibilityUserRebindError(
                "retained master artifact changed during read"
            )
        return bytes(data)
    except CompatibilityUserRebindError:
        raise
    except OSError as error:
        raise CompatibilityUserRebindError(
            "retained master artifact is unavailable"
        ) from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def build_retained_master_seed(
    canonical: CanonicalAuthority,
    *,
    authority_generation: str,
    current_linux_boot_uuid: str,
    source_journal_path: Path,
) -> RetainedMasterSeed:
    """Rebind D225's retained master envelope entirely offline.

    This function has no Bridge lease and no dispatch callback. The returned
    archive is only a candidate input; it is not written into the canonical
    Catacomb store.
    """

    try:
        current_boot = str(uuid.UUID(current_linux_boot_uuid))
    except (AttributeError, TypeError, ValueError) as error:
        raise CompatibilityUserRebindError(
            "current Linux boot identity is invalid"
        ) from error
    if (
        not isinstance(canonical, CanonicalAuthority)
        or canonical.identity_count <= 0
        or canonical.identity_count != canonical.master_enrollment_count
        or not isinstance(authority_generation, str)
        or len(authority_generation) != 64
        or any(character not in "0123456789abcdef" for character in authority_generation)
        or current_boot != current_linux_boot_uuid
        or uuid.UUID(current_boot).int == 0
        or not isinstance(source_journal_path, Path)
        or not source_journal_path.is_absolute()
    ):
        raise CompatibilityUserRebindError(
            "retained master seed inputs are invalid"
        )
    try:
        user_ids = {user_id for user_id, _identity_uuid in canonical.identity_records}
        if len(user_ids) != 1:
            raise CompatibilityUserRebindError(
                "canonical authority has ambiguous Apple-user ownership"
            )
        apple_user_id = next(iter(user_ids))
        records = t2_mutation_journal.read(source_journal_path)
    except CompatibilityUserRebindError:
        raise
    except (TypeError, ValueError, t2_mutation_journal.JournalError) as error:
        raise CompatibilityUserRebindError(
            "retained master source journal is invalid"
        ) from error
    if (
        len(records) != len(D225_TERMINAL_MILESTONES)
        or tuple(record["milestone"] for record in records)
        != D225_TERMINAL_MILESTONES
    ):
        raise CompatibilityUserRebindError(
            "retained master source journal is not at the exact D225 boundary"
        )
    baseline = records[0]["evidence"]
    captured = records[9]["evidence"]
    terminal = records[-1]["evidence"]
    source_boot = baseline.get("linux_boot_uuid")
    try:
        source_boot = str(uuid.UUID(source_boot))
    except (AttributeError, TypeError, ValueError) as error:
        raise CompatibilityUserRebindError(
            "retained master source boot identity is invalid"
        ) from error
    if source_boot == current_boot:
        raise CompatibilityUserRebindError(
            "retained master seed requires a different Linux boot"
        )
    if (
        baseline.get("operation_kind")
        != "compatibility-empty-user-rebind"
        or baseline.get("authority_generation") != authority_generation
        or baseline.get("canonical_identity_count") != canonical.identity_count
        or baseline.get("canonical_master_enrollment_count")
        != canonical.master_enrollment_count
        or baseline.get("canonical_component_hashes")
        != list(canonical.component_hashes)
        or terminal.get("user_states")
        != [["master", 0xFFFFFFFF, 3], ["user", apple_user_id, 7]]
        or terminal.get("per_user_identity_count") != 0
        or terminal.get("global_identity_count") != 0
        or terminal.get("group_state_count") != 0
        or terminal.get("saved_user_load_permitted") is not False
        or terminal.get("retry_permitted") is not False
    ):
        raise CompatibilityUserRebindError(
            "retained master source does not match canonical authority"
        )
    artifact = source_journal_path.parent / "intermediate-master-after-remove.cat"
    retained_bytes = _read_private_regular(artifact)
    if (
        hashlib.sha256(retained_bytes).hexdigest()
        != captured.get("encoded_sha256")
    ):
        raise CompatibilityUserRebindError(
            "retained master artifact differs from its source journal"
        )
    try:
        retained = t2_catacomb_codec.decode_master_catacomb(retained_bytes)
        canonical_master = t2_catacomb_codec.decode_master_catacomb(
            canonical.master_archive
        )
        candidate_bytes = canonical_master.encode(
            secure_data=retained.secure_data,
            enrollment_count=canonical.identity_count,
        )
        candidate = t2_catacomb_codec.decode_master_catacomb(candidate_bytes)
    except t2_catacomb_codec.CatacombCodecError as error:
        raise CompatibilityUserRebindError(
            "retained master candidate is not a valid Catacomb archive"
        ) from error
    if (
        retained.enrollment_count != 0
        or not retained.secure_data
        or hashlib.sha256(retained.secure_data).hexdigest()
        != captured.get("secure_data_sha256")
        or captured.get("encoded_enrollment_count") != 0
        or retained.secure_data == canonical_master.secure_data
        or candidate.secure_data != retained.secure_data
        or candidate.enrollment_count != canonical.identity_count
        or candidate_bytes in {canonical.master_archive, retained_bytes}
        or candidate.encode() != candidate_bytes
    ):
        raise CompatibilityUserRebindError(
            "retained master candidate did not reconcile"
        )
    return RetainedMasterSeed(
        retained.secure_data,
        candidate_bytes,
        len(records),
        records[-1]["record_hash"],
        authority_generation,
        source_boot,
        current_boot,
        canonical.identity_count,
    )


def read_canonical_authority(
    store: t2_catacomb_store.CatacombStore,
    apple_user_id: int,
    *,
    expected_account_uuid: str,
    expected_keybag_uuid: str,
) -> CanonicalAuthority:
    """Validate the saved Catacomb without exposing identity identifiers."""
    components = store.read_committed_components()
    user = t2_catacomb_codec.decode_user_catacomb(
        components[f"user_{apple_user_id:08x}.cat"], apple_user_id
    )
    master = t2_catacomb_codec.decode_master_catacomb(components["master.cat"])
    t2_catacomb_codec.decode_biolockout_catacomb(components["biolockout.cat"])
    if (
        not user.identities
        or user.account_uuid != expected_account_uuid
        or user.keybag_uuid != expected_keybag_uuid
        or master.enrollment_count != len(user.identities)
    ):
        raise CompatibilityUserRebindError(
            "canonical compatibility Catacomb does not match its authority"
        )
    return CanonicalAuthority(
        frozenset((identity.user_id, identity.uuid) for identity in user.identities),
        master.enrollment_count,
        tuple(sorted(hashlib.sha256(value).hexdigest() for value in components.values())),
        user.secure_data,
        components["master.cat"],
    )


def _output(reply: object, events: object, label: str, apple_user_id: int) -> bytes:
    try:
        t2_bridge_inventory.require_preparation_service_events(events, apple_user_id)
    except t2_bridge_inventory.BridgeInventoryError as error:
        raise CompatibilityUserRebindError(
            f"{label} emitted an unexpected service event"
        ) from error
    if type(reply) is not list or len(reply) not in (1, 2) or reply[0] != 0:
        raise CompatibilityUserRebindError(f"{label} did not succeed")
    output = b"" if len(reply) == 1 else reply[1]
    if wire.is_biometric_nil_output(output):
        output = b""
    if type(output) is not bytes:
        raise CompatibilityUserRebindError(f"{label} output is malformed")
    return output


def _reply_diagnostics(reply: object) -> dict[str, object]:
    """Return status and response shape without retaining response contents."""
    if type(reply) is not list:
        return {"reply_type": type(reply).__name__, "reply_items": None}
    result: dict[str, object] = {"reply_type": "list", "reply_items": len(reply)}
    if reply and type(reply[0]) is int and not isinstance(reply[0], bool):
        result["status"] = reply[0]
    if len(reply) > 1:
        output = reply[1]
        if type(output) is bytes:
            result["output_type"] = "bytes"
            result["output_length"] = len(output)
        elif wire.is_biometric_nil_output(output):
            result["output_type"] = "nil-sentinel"
            result["output_length"] = 0
        else:
            result["output_type"] = type(output).__name__
            result["output_length"] = None
    return result


def _surface_once(lease, apple_user_id: int) -> dict[str, object]:
    commands = (
        ("per_user", 0x42, struct.pack("<I", apple_user_id), 20 * 10),
        ("global", 0x51, b"", 40 * 10),
        ("users", 0x3C, b"", 4096),
        (
            "groups",
            0x50,
            b"",
            t2_catacomb_protocol.GROUP_STATE_RECORD.size * 10,
        ),
    )
    outputs: dict[str, bytes] = {}
    for label, command, data, capacity in commands:
        reply, events = lease.biometric_command(
            command,
            version=1,
            value=0,
            data=data,
            output_capacity=capacity,
        )
        outputs[label] = _output(reply, events, f"{label} read", apple_user_id)

    per_user = outputs["per_user"]
    global_identities = outputs["global"]
    if len(per_user) % 20 or len(global_identities) % 40:
        raise CompatibilityUserRebindError("identity-list bytes are malformed")
    per_user_records = tuple(
        per_user[offset : offset + 20] for offset in range(0, len(per_user), 20)
    )
    global_records = tuple(
        global_identities[offset : offset + 40]
        for offset in range(0, len(global_identities), 40)
    )
    if (
        len(set(per_user_records)) != len(per_user_records)
        or len(set(global_records)) != len(global_records)
        or any(struct.unpack_from("<I", record)[0] != apple_user_id for record in per_user_records)
    ):
        raise CompatibilityUserRebindError("identity-list association is invalid")
    try:
        user_states = t2_catacomb_protocol.parse_user_states(outputs["users"])
        group_states = t2_catacomb_protocol.parse_group_states(outputs["groups"])
    except t2_catacomb_protocol.CatacombProtocolError as error:
        raise CompatibilityUserRebindError("Catacomb state bytes are malformed") from error
    return {
        "raw": outputs,
        "per_user_identity_count": len(per_user_records),
        "global_identity_count": len(global_records),
        "user_states": tuple(
            (record.component.kind.value, record.component.user_id, record.state)
            for record in user_states
        ),
        "group_state_count": len(group_states),
    }


def read_stable_surface(lease, apple_user_id: int) -> dict[str, object]:
    """Read the reset-relevant surface twice over one Bridge generation."""
    dispatched = False
    try:
        generation = lease.connection_generation
        if str(uuid.UUID(generation)) != generation:
            raise CompatibilityUserRebindError("Bridge generation is invalid")
        dispatched = True
        first = _surface_once(lease, apple_user_id)
        second = _surface_once(lease, apple_user_id)
        if lease.connection_generation != generation or first["raw"] != second["raw"]:
            raise CompatibilityUserRebindError(
                "empty-user recovery surface changed between collections"
            )
        return {key: value for key, value in first.items() if key != "raw"}
    except BaseException as error:
        if dispatched:
            try:
                lease.invalidate()
            except BaseException:
                pass
        if isinstance(error, CompatibilityUserRebindError):
            raise
        raise CompatibilityUserRebindError(
            "empty-user recovery surface collection failed"
        ) from error


def _append(
    path: Path,
    operation_id: str,
    milestone: str,
    evidence: dict[str, object],
    previous: dict[str, object] | None,
) -> dict[str, object]:
    if previous is None:
        return t2_mutation_journal.append(
            path, operation_id, milestone, evidence, exclusive=True
        )
    return t2_mutation_journal.append(
        path,
        operation_id,
        milestone,
        evidence,
        expected_record_count=int(previous["sequence"]) + 1,
        expected_previous_hash=str(previous["record_hash"]),
    )


def reset_empty_loaded_user_once(
    lease,
    *,
    apple_user_id: int,
    canonical: CanonicalAuthority,
    authority_generation: str,
    linux_boot_uuid: str,
    journal_path: Path,
) -> dict[str, object]:
    """Remove exactly one proven-empty loaded biometric user, then stop.

    A fixed exclusive journal is the retry barrier.  Intent is durable before
    command 0x48; any interruption or malformed reply leaves enough evidence
    to prohibit a second dispatch.
    """
    if (
        type(apple_user_id) is not int
        or not 0 <= apple_user_id < 0xFFFFFFFF
        or not isinstance(canonical, CanonicalAuthority)
        or canonical.identity_count <= 0
        or canonical.identity_count != canonical.master_enrollment_count
        or any(
            user_id != apple_user_id or str(uuid.UUID(identity_uuid)) != identity_uuid
            for user_id, identity_uuid in canonical.identity_records
        )
        or type(canonical.user_secure_data) is not bytes
        or not canonical.user_secure_data
        or type(canonical.master_archive) is not bytes
        or not canonical.master_archive
        or not isinstance(authority_generation, str)
        or len(authority_generation) != 64
        or str(uuid.UUID(linux_boot_uuid)) != linux_boot_uuid
        or not isinstance(journal_path, Path)
        or not journal_path.is_absolute()
    ):
        raise CompatibilityUserRebindError("empty-user recovery inputs are invalid")

    baseline = read_stable_surface(lease, apple_user_id)
    by_component = {
        (kind, user_id): state for kind, user_id, state in baseline["user_states"]
    }
    expected_components = {
        ("master", 0xFFFFFFFF),
        ("user", apple_user_id),
    }
    if (
        baseline["per_user_identity_count"] != 0
        or baseline["global_identity_count"] != 0
        or set(by_component) != expected_components
        or len(baseline["user_states"]) != 2
        or any(state not in {0x03, 0x07} for state in by_component.values())
        or baseline["group_state_count"] != 0
    ):
        raise CompatibilityUserRebindError(
            "live compatibility state is not the exact empty loaded-user recovery baseline"
        )

    operation_id = str(uuid.uuid4())
    head = _append(
        journal_path,
        operation_id,
        "BASELINE_RECONCILED",
        {
            "operation_kind": "compatibility-empty-user-rebind",
            "linux_boot_uuid": linux_boot_uuid,
            "authority_generation": authority_generation,
            "canonical_identity_count": canonical.identity_count,
            "canonical_master_enrollment_count": canonical.master_enrollment_count,
            "canonical_component_hashes": list(canonical.component_hashes),
            "live_per_user_identity_count": 0,
            "live_global_identity_count": 0,
            "live_user_states": [list(item) for item in baseline["user_states"]],
            "live_group_state_count": 0,
            "identifiers_redacted": True,
        },
        None,
    )
    head = _append(
        journal_path,
        operation_id,
        "REMOVE_USER_INTENT",
        {
            "command": 0x48,
            "wrapper_version": 1,
            "input_layout": "uid_le32",
            "input_length": 4,
            "output_capacity": 0,
        },
        head,
    )

    try:
        reply, events = lease.biometric_command(
            0x48,
            version=1,
            value=0,
            data=struct.pack("<I", apple_user_id),
            output_capacity=0,
        )
    except BaseException as error:
        _append(
            journal_path,
            operation_id,
            "REMOVE_USER_OUTCOME_UNKNOWN",
            {"dispatch_attempted": True, "retry_permitted": False},
            head,
        )
        raise CompatibilityUserRebindError(
            "remove-user transport outcome is unknown; do not retry"
        ) from error

    try:
        output = _output(reply, events, "remove user", apple_user_id)
        if output:
            raise CompatibilityUserRebindError("remove user returned unexpected output")
    except CompatibilityUserRebindError:
        _append(
            journal_path,
            operation_id,
            "REMOVE_USER_REPLY_REJECTED",
            {"reply_received": True, "retry_permitted": False},
            head,
        )
        raise
    head = _append(
        journal_path,
        operation_id,
        "REMOVE_USER_ACCEPTED",
        {"status": 0, "output_length": 0, "retry_permitted": False},
        head,
    )

    try:
        observed = read_stable_surface(lease, apple_user_id)
    except CompatibilityUserRebindError:
        _append(
            journal_path,
            operation_id,
            "POST_STATE_UNAVAILABLE",
            {"remove_user_accepted": True, "retry_permitted": False},
            head,
        )
        raise
    _append(
        journal_path,
        operation_id,
        "POST_STATE_OBSERVED",
        {
            "per_user_identity_count": observed["per_user_identity_count"],
            "global_identity_count": observed["global_identity_count"],
            "user_states": [list(item) for item in observed["user_states"]],
            "group_state_count": observed["group_state_count"],
            "remove_user_accepted": True,
            "restoration_attempted": False,
        },
        head,
    )
    return {
        "schema_version": 1,
        "operation": "compatibility-empty-user-rebind",
        "remove_user_accepted": True,
        "restoration_attempted": False,
        **observed,
        "identifiers_redacted": True,
    }


def _write_private_exclusive(path: Path, data: bytes) -> str:
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
                raise CompatibilityUserRebindError(
                    "intermediate master write made no progress"
                )
            offset += written
        os.fsync(descriptor)
        complete = True
    finally:
        os.close(descriptor)
        if not complete and os.path.lexists(path):
            path.unlink()
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)
    return hashlib.sha256(data).hexdigest()


def settle_removed_master_once(
    lease,
    *,
    apple_user_id: int,
    canonical: CanonicalAuthority,
    authority_generation: str,
    linux_boot_uuid: str,
    journal_path: Path,
) -> dict[str, object]:
    """Export and confirm the dirty master left by whole-user removal."""
    records = t2_mutation_journal.read(journal_path)
    expected_milestones = [
        "BASELINE_RECONCILED",
        "REMOVE_USER_INTENT",
        "REMOVE_USER_ACCEPTED",
        "POST_STATE_OBSERVED",
        "USER_LOAD_INTENT",
        "USER_LOAD_REPLY_REJECTED",
    ]
    baseline_evidence = records[0]["evidence"] if records else {}
    if (
        [record["milestone"] for record in records] != expected_milestones
        or baseline_evidence.get("linux_boot_uuid") != linux_boot_uuid
        or baseline_evidence.get("authority_generation") != authority_generation
        or baseline_evidence.get("canonical_component_hashes")
        != list(canonical.component_hashes)
        or baseline_evidence.get("canonical_identity_count")
        != canonical.identity_count
    ):
        raise CompatibilityUserRebindError(
            "recovery journal is not at the dirty-master settlement boundary"
        )
    current = read_stable_surface(lease, apple_user_id)
    if current != {
        "per_user_identity_count": 0,
        "global_identity_count": 0,
        "user_states": (("master", 0xFFFFFFFF, 0x07),),
        "group_state_count": 0,
    }:
        raise CompatibilityUserRebindError(
            "live state changed before dirty-master settlement"
        )

    operation_id = str(records[0]["operation_id"])
    head = records[-1]
    descriptor = t2_catacomb_protocol.CatacombComponent.master().descriptor
    transport = t2_catacomb_bridge.CatacombBridgeTransport(
        lease,
        protocol_version=2,
        connection_generation=lease.connection_generation,
    )
    secure_blob: bytearray | None = None
    encoded: bytearray | None = None
    try:
        head = _append(
            journal_path,
            operation_id,
            "MASTER_EXPORT_PREPARE_INTENT",
            {
                "component": "master",
                "descriptor_sha256": hashlib.sha256(descriptor).hexdigest(),
            },
            head,
        )
        _status, expected_length = transport.prepare(descriptor)
        head = _append(
            journal_path,
            operation_id,
            "MASTER_EXPORT_PREPARED",
            {"component": "master", "expected_length": expected_length},
            head,
        )
        head = _append(
            journal_path,
            operation_id,
            "MASTER_EXPORT_COMPLETE_INTENT",
            {"component": "master"},
            head,
        )
        _status, secure_blob = transport.complete(descriptor)
        if len(secure_blob) != expected_length:
            raise CompatibilityUserRebindError(
                "intermediate master export length changed"
            )
        master = t2_catacomb_codec.decode_master_catacomb(
            canonical.master_archive
        )
        encoded = bytearray(
            master.encode(
                secure_data=bytes(secure_blob),
                enrollment_count=0,
            )
        )
        artifact = journal_path.parent / "intermediate-master-after-remove.cat"
        encoded_hash = _write_private_exclusive(artifact, bytes(encoded))
        head = _append(
            journal_path,
            operation_id,
            "MASTER_EXPORT_CAPTURED",
            {
                "component": "master",
                "secure_data_sha256": hashlib.sha256(secure_blob).hexdigest(),
                "encoded_sha256": encoded_hash,
                "encoded_enrollment_count": 0,
            },
            head,
        )
        head = _append(
            journal_path,
            operation_id,
            "MASTER_EXPORT_CONFIRM_INTENT",
            {"component": "master", "intermediate_persisted": True},
            head,
        )
        transport.confirm(descriptor)
        head = _append(
            journal_path,
            operation_id,
            "MASTER_EXPORT_CONFIRMED",
            {"component": "master", "status": 0},
            head,
        )
    except BaseException as error:
        try:
            _append(
                journal_path,
                operation_id,
                "MASTER_SETTLE_OUTCOME_UNKNOWN",
                {"retry_permitted": False},
                head,
            )
        except BaseException:
            pass
        if isinstance(error, CompatibilityUserRebindError):
            raise
        raise CompatibilityUserRebindError(
            "dirty-master settlement did not complete; do not retry"
        ) from error
    finally:
        if secure_blob is not None:
            secure_blob[:] = b"\0" * len(secure_blob)
        if encoded is not None:
            encoded[:] = b"\0" * len(encoded)

    observed = read_stable_surface(lease, apple_user_id)
    if observed != {
        "per_user_identity_count": 0,
        "global_identity_count": 0,
        "user_states": (("master", 0xFFFFFFFF, 0x03),),
        "group_state_count": 0,
    }:
        _append(
            journal_path,
            operation_id,
            "MASTER_SETTLE_POST_STATE_REJECTED",
            {
                "user_states": [list(item) for item in observed["user_states"]],
                "per_user_identity_count": observed["per_user_identity_count"],
                "global_identity_count": observed["global_identity_count"],
                "group_state_count": observed["group_state_count"],
                "retry_permitted": False,
            },
            head,
        )
        raise CompatibilityUserRebindError(
            "dirty-master confirmation produced an unexpected state"
        )
    _append(
        journal_path,
        operation_id,
        "MASTER_SETTLED",
        {
            "user_states": [["master", 0xFFFFFFFF, 0x03]],
            "identity_count": 0,
            "group_state_count": 0,
        },
        head,
    )
    return {
        "schema_version": 1,
        "operation": "compatibility-removed-master-settlement",
        "master_state": 3,
        "identity_count": 0,
        "saved_user_load_permitted": True,
        "identifiers_redacted": True,
    }


def prepare_missing_user_once(
    lease,
    *,
    apple_user_id: int,
    canonical: CanonicalAuthority,
    authority_generation: str,
    linux_boot_uuid: str,
    journal_path: Path,
) -> dict[str, object]:
    """Admit only the user component that command 0x48 removed."""
    records = t2_mutation_journal.read(journal_path)
    expected_milestones = [
        "BASELINE_RECONCILED",
        "REMOVE_USER_INTENT",
        "REMOVE_USER_ACCEPTED",
        "POST_STATE_OBSERVED",
        "USER_LOAD_INTENT",
        "USER_LOAD_REPLY_REJECTED",
        "MASTER_EXPORT_PREPARE_INTENT",
        "MASTER_EXPORT_PREPARED",
        "MASTER_EXPORT_COMPLETE_INTENT",
        "MASTER_EXPORT_CAPTURED",
        "MASTER_EXPORT_CONFIRM_INTENT",
        "MASTER_EXPORT_CONFIRMED",
        "MASTER_SETTLED",
        "SAVED_USER_RELOAD_INTENT",
        "SAVED_USER_RELOAD_REPLY_REJECTED",
    ]
    baseline_evidence = records[0]["evidence"] if records else {}
    if (
        [record["milestone"] for record in records] != expected_milestones
        or baseline_evidence.get("linux_boot_uuid") != linux_boot_uuid
        or baseline_evidence.get("authority_generation") != authority_generation
        or baseline_evidence.get("canonical_component_hashes")
        != list(canonical.component_hashes)
        or baseline_evidence.get("canonical_identity_count")
        != canonical.identity_count
    ):
        raise CompatibilityUserRebindError(
            "recovery journal is not at the missing-user preparation boundary"
        )
    current = read_stable_surface(lease, apple_user_id)
    if current != {
        "per_user_identity_count": 0,
        "global_identity_count": 0,
        "user_states": (("master", 0xFFFFFFFF, 0x03),),
        "group_state_count": 0,
    }:
        raise CompatibilityUserRebindError(
            "live state changed before missing-user preparation"
        )
    operation_id = str(records[0]["operation_id"])
    head = records[-1]
    head = _append(
        journal_path,
        operation_id,
        "MISSING_USER_PREPARE_INTENT",
        {
            "command": 0x31,
            "wrapper_version": 1,
            "component": "selected-user",
            "input_layout": "uid_le32",
            "input_length": 4,
            "output_capacity": 0,
        },
        head,
    )
    try:
        reply, events = lease.biometric_command(
            0x31,
            version=1,
            value=0,
            data=struct.pack("<I", apple_user_id),
            output_capacity=0,
        )
    except BaseException as error:
        _append(
            journal_path,
            operation_id,
            "MISSING_USER_PREPARE_OUTCOME_UNKNOWN",
            {"dispatch_attempted": True, "retry_permitted": False},
            head,
        )
        raise CompatibilityUserRebindError(
            "missing-user preparation outcome is unknown; do not retry"
        ) from error
    try:
        output = _output(reply, events, "missing user preparation", apple_user_id)
        if output:
            raise CompatibilityUserRebindError(
                "missing user preparation returned unexpected output"
            )
    except CompatibilityUserRebindError:
        _append(
            journal_path,
            operation_id,
            "MISSING_USER_PREPARE_REPLY_REJECTED",
            {"reply_received": True, "retry_permitted": False},
            head,
        )
        raise
    head = _append(
        journal_path,
        operation_id,
        "MISSING_USER_PREPARE_ACCEPTED",
        {"status": 0, "output_length": 0, "retry_permitted": False},
        head,
    )
    observed = read_stable_surface(lease, apple_user_id)
    by_component = {
        (kind, user_id): state for kind, user_id, state in observed["user_states"]
    }
    user_state = by_component.get(("user", apple_user_id))
    if (
        observed["per_user_identity_count"] != 0
        or observed["global_identity_count"] != 0
        or observed["group_state_count"] != 0
        or by_component.get(("master", 0xFFFFFFFF)) != 0x03
        or user_state not in {0x01, 0x05}
        or len(by_component) != 2
    ):
        _append(
            journal_path,
            operation_id,
            "MISSING_USER_PREPARE_POST_STATE_REJECTED",
            {
                "user_states": [list(item) for item in observed["user_states"]],
                "per_user_identity_count": observed["per_user_identity_count"],
                "global_identity_count": observed["global_identity_count"],
                "group_state_count": observed["group_state_count"],
                "retry_permitted": False,
            },
            head,
        )
        raise CompatibilityUserRebindError(
            "missing-user preparation produced an unexpected state"
        )
    _append(
        journal_path,
        operation_id,
        "MISSING_USER_PREPARED",
        {
            "user_states": [list(item) for item in observed["user_states"]],
            "identity_count": 0,
            "group_state_count": 0,
            "saved_user_load_permitted": True,
        },
        head,
    )
    return {
        "schema_version": 1,
        "operation": "compatibility-missing-user-preparation",
        "master_state": 3,
        "user_state": user_state,
        "identity_count": 0,
        "saved_user_load_permitted": True,
        "identifiers_redacted": True,
    }


def prepare_missing_components_once(
    lease,
    *,
    apple_user_id: int,
    canonical: CanonicalAuthority,
    authority_generation: str,
    linux_boot_uuid: str,
    journal_path: Path,
    preflight_surface: dict[str, object],
) -> dict[str, object]:
    """Run the proven pre-client T2 master-then-user missing-component sequence."""
    records = t2_mutation_journal.read(journal_path)
    expected_milestones = [
        "BASELINE_RECONCILED",
        "REMOVE_USER_INTENT",
        "REMOVE_USER_ACCEPTED",
        "POST_STATE_OBSERVED",
        "USER_LOAD_INTENT",
        "USER_LOAD_REPLY_REJECTED",
        "MASTER_EXPORT_PREPARE_INTENT",
        "MASTER_EXPORT_PREPARED",
        "MASTER_EXPORT_COMPLETE_INTENT",
        "MASTER_EXPORT_CAPTURED",
        "MASTER_EXPORT_CONFIRM_INTENT",
        "MASTER_EXPORT_CONFIRMED",
        "MASTER_SETTLED",
        "SAVED_USER_RELOAD_INTENT",
        "SAVED_USER_RELOAD_REPLY_REJECTED",
        "MISSING_USER_PREPARE_INTENT",
        "MISSING_USER_PREPARE_ACCEPTED",
        "MISSING_USER_PREPARE_POST_STATE_REJECTED",
    ]
    baseline_evidence = records[0]["evidence"] if records else {}
    if (
        [record["milestone"] for record in records] != expected_milestones
        or baseline_evidence.get("linux_boot_uuid") != linux_boot_uuid
        or baseline_evidence.get("authority_generation") != authority_generation
        or baseline_evidence.get("canonical_component_hashes")
        != list(canonical.component_hashes)
        or baseline_evidence.get("canonical_identity_count")
        != canonical.identity_count
    ):
        raise CompatibilityUserRebindError(
            "recovery journal is not at the missing-component sequence boundary"
        )
    if preflight_surface != {
        "per_user_identity_count": 0,
        "global_identity_count": 0,
        "user_states": (("master", 0xFFFFFFFF, 0x03),),
        "group_state_count": 0,
    }:
        raise CompatibilityUserRebindError(
            "live state changed before missing-component preparation"
        )
    if getattr(lease, "client_version", None) != 0:
        raise CompatibilityUserRebindError(
            "missing-component sequence requires deferred client selection"
        )
    try:
        t2_bridge_inventory.attest_preclient_protocol(lease, apple_user_id)
    except t2_bridge_inventory.BridgeInventoryError as error:
        raise CompatibilityUserRebindError(
            "missing-component protocol preflight failed"
        ) from error
    operation_id = str(records[0]["operation_id"])
    head = records[-1]
    for milestone, component_id, component_name in (
        ("MISSING_MASTER_PREPARE_INTENT", 0xFFFFFFFF, "master"),
        ("MISSING_USER_REPREPARE_INTENT", apple_user_id, "selected-user"),
    ):
        head = _append(
            journal_path,
            operation_id,
            milestone,
            {
                "command": 0x31,
                "wrapper_version": 1,
                "component": component_name,
                "input_layout": "component_le32",
                "input_length": 4,
                "output_capacity": 0,
            },
            head,
        )
        try:
            reply, events = lease.biometric_command(
                0x31,
                version=1,
                value=0,
                data=struct.pack("<I", component_id),
                output_capacity=0,
            )
        except BaseException as error:
            _append(
                journal_path,
                operation_id,
                "MISSING_COMPONENT_SEQUENCE_OUTCOME_UNKNOWN",
                {"component": component_name, "retry_permitted": False},
                head,
            )
            raise CompatibilityUserRebindError(
                "missing-component sequence outcome is unknown; do not retry"
            ) from error
        try:
            output = _output(
                reply,
                events,
                f"{component_name} missing-component preparation",
                apple_user_id,
            )
            if output:
                raise CompatibilityUserRebindError(
                    "missing-component preparation returned unexpected output"
                )
        except CompatibilityUserRebindError:
            _append(
                journal_path,
                operation_id,
                "MISSING_COMPONENT_SEQUENCE_REPLY_REJECTED",
                {
                    "component": component_name,
                    "retry_permitted": False,
                    **_reply_diagnostics(reply),
                },
                head,
            )
            raise
        head = _append(
            journal_path,
            operation_id,
            (
                "MISSING_MASTER_PREPARE_ACCEPTED"
                if component_name == "master"
                else "MISSING_USER_REPREPARE_ACCEPTED"
            ),
            {
                "component": component_name,
                **_reply_diagnostics(reply),
            },
            head,
        )

    try:
        selected_version = lease.select_client_version()
    except BaseException as error:
        _append(
            journal_path,
            operation_id,
            "CLIENT_VERSION_SELECTION_FAILED",
            {"commands_accepted": True, "retry_permitted": False},
            head,
        )
        raise CompatibilityUserRebindError(
            "missing-component commands succeeded but client selection failed"
        ) from error
    head = _append(
        journal_path,
        operation_id,
        "BRIDGE_CLIENT_VERSION_SELECTED",
        {"client_version": selected_version},
        head,
    )
    observed = read_stable_surface(lease, apple_user_id)
    by_component = {
        (kind, user_id): state for kind, user_id, state in observed["user_states"]
    }
    user_state = by_component.get(("user", apple_user_id))
    load_permitted = (
        observed["per_user_identity_count"] == 0
        and observed["global_identity_count"] == 0
        and observed["group_state_count"] == 0
        and by_component.get(("master", 0xFFFFFFFF)) in {0x03, 0x07}
        and user_state in {0x01, 0x05}
        and len(by_component) == 2
    )
    _append(
        journal_path,
        operation_id,
        "MISSING_COMPONENT_SEQUENCE_OBSERVED",
        {
            "user_states": [list(item) for item in observed["user_states"]],
            "per_user_identity_count": observed["per_user_identity_count"],
            "global_identity_count": observed["global_identity_count"],
            "group_state_count": observed["group_state_count"],
            "saved_user_load_permitted": load_permitted,
            "retry_permitted": False,
        },
        head,
    )
    return {
        "schema_version": 1,
        "operation": "compatibility-missing-component-sequence",
        "identity_count": observed["per_user_identity_count"],
        "user_states": observed["user_states"],
        "saved_user_load_permitted": load_permitted,
        "identifiers_redacted": True,
    }


def restore_saved_user_once(
    lease,
    *,
    apple_user_id: int,
    canonical: CanonicalAuthority,
    authority_generation: str,
    linux_boot_uuid: str,
    journal_path: Path,
) -> dict[str, object]:
    """Load the journal-bound saved user after a successful whole-user reset."""
    records = t2_mutation_journal.read(journal_path)
    expected_milestones = [
        "BASELINE_RECONCILED",
        "REMOVE_USER_INTENT",
        "REMOVE_USER_ACCEPTED",
        "POST_STATE_OBSERVED",
        "USER_LOAD_INTENT",
        "USER_LOAD_REPLY_REJECTED",
        "MASTER_EXPORT_PREPARE_INTENT",
        "MASTER_EXPORT_PREPARED",
        "MASTER_EXPORT_COMPLETE_INTENT",
        "MASTER_EXPORT_CAPTURED",
        "MASTER_EXPORT_CONFIRM_INTENT",
        "MASTER_EXPORT_CONFIRMED",
        "MASTER_SETTLED",
        "SAVED_USER_RELOAD_INTENT",
        "SAVED_USER_RELOAD_REPLY_REJECTED",
        "MISSING_USER_PREPARE_INTENT",
        "MISSING_USER_PREPARE_ACCEPTED",
        "MISSING_USER_PREPARE_POST_STATE_REJECTED",
        "MISSING_MASTER_PREPARE_INTENT",
        "MISSING_MASTER_PREPARE_ACCEPTED",
        "MISSING_USER_REPREPARE_INTENT",
        "MISSING_USER_REPREPARE_ACCEPTED",
        "BRIDGE_CLIENT_VERSION_SELECTED",
        "MISSING_COMPONENT_SEQUENCE_OBSERVED",
    ]
    if [record["milestone"] for record in records] != expected_milestones:
        raise CompatibilityUserRebindError(
            "empty-user recovery journal is not at the saved-user restore boundary"
        )
    baseline_evidence = records[0]["evidence"]
    post_evidence = records[3]["evidence"]
    expected_post_states = [["master", 0xFFFFFFFF, 0x07]]
    if (
        baseline_evidence.get("operation_kind")
        != "compatibility-empty-user-rebind"
        or baseline_evidence.get("linux_boot_uuid") != linux_boot_uuid
        or baseline_evidence.get("authority_generation") != authority_generation
        or baseline_evidence.get("canonical_identity_count") != canonical.identity_count
        or baseline_evidence.get("canonical_master_enrollment_count")
        != canonical.master_enrollment_count
        or baseline_evidence.get("canonical_component_hashes")
        != list(canonical.component_hashes)
        or post_evidence
        != {
            "per_user_identity_count": 0,
            "global_identity_count": 0,
            "user_states": expected_post_states,
            "group_state_count": 0,
            "remove_user_accepted": True,
            "restoration_attempted": False,
        }
    ):
        raise CompatibilityUserRebindError(
            "empty-user recovery journal does not match the saved authority"
        )
    prepared_evidence = records[-1]["evidence"]
    if prepared_evidence.get("saved_user_load_permitted") is not True:
        raise CompatibilityUserRebindError(
            "missing-component sequence did not produce a loadable user"
        )
    prepared_states = prepared_evidence.get("user_states")
    if prepared_states not in (
        [["master", 0xFFFFFFFF, 0x03], ["user", apple_user_id, 0x01]],
        [["master", 0xFFFFFFFF, 0x03], ["user", apple_user_id, 0x05]],
    ):
        raise CompatibilityUserRebindError(
            "missing-user preparation evidence is not loadable"
        )
    current = read_stable_surface(lease, apple_user_id)
    if current != {
        "per_user_identity_count": 0,
        "global_identity_count": 0,
        "user_states": tuple(tuple(item) for item in prepared_states),
        "group_state_count": 0,
    }:
        raise CompatibilityUserRebindError(
            "live state changed after empty-user reset; refusing saved-user load"
        )

    operation_id = str(records[0]["operation_id"])
    head = records[-1]
    head = _append(
        journal_path,
        operation_id,
        "SAVED_USER_RELOAD_INTENT",
        {
            "command": 0x40,
            "wrapper_version": 1,
            "component": "selected-user",
            "secure_data_sha256": hashlib.sha256(
                canonical.user_secure_data
            ).hexdigest(),
            "expected_identity_count": canonical.identity_count,
        },
        head,
    )
    try:
        reply, events = lease.biometric_command(
            0x40,
            version=1,
            value=0,
            data=canonical.user_secure_data,
            output_capacity=0,
        )
    except BaseException as error:
        _append(
            journal_path,
            operation_id,
            "SAVED_USER_RELOAD_OUTCOME_UNKNOWN",
            {"dispatch_attempted": True, "retry_permitted": False},
            head,
        )
        raise CompatibilityUserRebindError(
            "saved-user load transport outcome is unknown; do not retry"
        ) from error
    try:
        output = _output(reply, events, "saved user load", apple_user_id)
        if output:
            raise CompatibilityUserRebindError(
                "saved user load returned unexpected output"
            )
    except CompatibilityUserRebindError:
        _append(
            journal_path,
            operation_id,
            "SAVED_USER_RELOAD_REPLY_REJECTED",
            {
                "reply_received": True,
                "retry_permitted": False,
                **_reply_diagnostics(reply),
            },
            head,
        )
        raise
    head = _append(
        journal_path,
        operation_id,
        "SAVED_USER_RELOAD_ACCEPTED",
        {"status": 0, "output_length": 0, "retry_permitted": False},
        head,
    )

    try:
        live = t2_bridge_inventory.collect_stable_private_inventory(
            lease, apple_user_id
        )
        live_records = frozenset(
            (record["user_id"], record["identity_uuid"])
            for record in live["per_user_identity_records"]
        )
        observed = read_stable_surface(lease, apple_user_id)
    except BaseException as error:
        _append(
            journal_path,
            operation_id,
            "SAVED_USER_RELOAD_POST_STATE_UNAVAILABLE",
            {"saved_user_load_accepted": True, "retry_permitted": False},
            head,
        )
        raise CompatibilityUserRebindError(
            "saved-user load succeeded but post-state is unavailable"
        ) from error
    by_component = {
        (kind, user_id): state for kind, user_id, state in observed["user_states"]
    }
    if (
        live_records != canonical.identity_records
        or observed["per_user_identity_count"] != canonical.identity_count
        or observed["global_identity_count"] != canonical.identity_count
        or observed["group_state_count"] != 0
        or set(by_component)
        != {("master", 0xFFFFFFFF), ("user", apple_user_id)}
        or any(state not in {0x03, 0x07} for state in by_component.values())
    ):
        _append(
            journal_path,
            operation_id,
            "SAVED_USER_RELOAD_POST_STATE_REJECTED",
            {
                "saved_user_load_accepted": True,
                "per_user_identity_count": observed["per_user_identity_count"],
                "global_identity_count": observed["global_identity_count"],
                "group_state_count": observed["group_state_count"],
                "user_states": [list(item) for item in observed["user_states"]],
                "retry_permitted": False,
            },
            head,
        )
        raise CompatibilityUserRebindError(
            "saved-user load did not reproduce the canonical identity set"
        )
    master_state = by_component[("master", 0xFFFFFFFF)]
    user_state = by_component[("user", apple_user_id)]
    _append(
        journal_path,
        operation_id,
        "SAVED_USER_RELOAD_RECONCILED",
        {
            "identity_count": canonical.identity_count,
            "global_identity_count": observed["global_identity_count"],
            "group_state_count": 0,
            "user_states": [list(item) for item in observed["user_states"]],
            "master_persistence_required": bool(master_state & 0x04),
            "user_persistence_required": bool(user_state & 0x04),
            "identifiers_redacted": True,
        },
        head,
    )
    return {
        "schema_version": 1,
        "operation": "compatibility-saved-user-restore",
        "identity_count": canonical.identity_count,
        "master_state": master_state,
        "user_state": user_state,
        "master_persistence_required": bool(master_state & 0x04),
        "user_persistence_required": bool(user_state & 0x04),
        "identifiers_redacted": True,
    }
