#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Reconcile private live SEP inventory with a copied macOS Catacomb archive."""

from __future__ import annotations

import hashlib
import plistlib
import tarfile
import uuid
from pathlib import Path
from typing import Any


class BaselineError(RuntimeError):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_symbolic_mode(value: str) -> int:
    if len(value) != 10 or value[0] != "-":
        raise BaselineError("Catacomb component is not a regular file")
    mode = 0
    for character, bit in zip(value[1:], (0o400, 0o200, 0o100, 0o040, 0o020, 0o010, 0o004, 0o002, 0o001)):
        if character != "-":
            expected = "r" if bit & 0o444 else "w" if bit & 0o222 else "x"
            if character != expected:
                raise BaselineError("Catacomb component has special permission bits")
            mode |= bit
    return mode


def parse_source_metadata(data: bytes, expected_names: set[str]) -> dict[str, dict[str, int]]:
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise BaselineError("source-stat.txt is not UTF-8") from error
    result = {}
    for line in lines:
        fields = line.split(maxsplit=4)
        if len(fields) != 5:
            continue
        mode_text, owner, _size, _mtime, source_path = fields
        name = source_path.rsplit("/", 1)[-1]
        if name not in expected_names:
            continue
        if name in result:
            raise BaselineError(f"duplicate source metadata for {name}")
        if owner != "root:wheel":
            raise BaselineError(f"unexpected source owner for {name}")
        result[name] = {
            "mode": parse_symbolic_mode(mode_text),
            "uid": 0,
            "gid": 0,
        }
    if set(result) != expected_names:
        raise BaselineError("source-stat.txt is missing Catacomb component metadata")
    return result


def parse_tar_metadata(
    members: dict[str, tuple[tarfile.TarInfo, bytes]],
    expected_names: set[str],
) -> dict[str, dict[str, int]]:
    """Validate metadata retained by early raw Catacomb exports."""
    result = {}
    for name in sorted(expected_names):
        member, _data = members[name]
        if (
            member.uid != 0
            or member.gid != 0
            or member.uname not in ("", "root")
            or member.gname not in ("", "wheel")
            or member.mode & ~0o777
        ):
            raise BaselineError(f"unsafe archived source metadata for {name}")
        result[name] = {"mode": member.mode, "uid": 0, "gid": 0}
    return result


class KeyedArchive:
    def __init__(self, data: bytes, name: str) -> None:
        try:
            value = plistlib.loads(data)
        except plistlib.InvalidFileException as error:
            raise BaselineError(f"{name} is not a plist") from error
        if not isinstance(value, dict) or value.get("$archiver") != "NSKeyedArchiver":
            raise BaselineError(f"{name} is not a keyed archive")
        self.top = value.get("$top")
        self.objects = value.get("$objects")
        if not isinstance(self.top, dict) or not isinstance(self.objects, list):
            raise BaselineError(f"{name} has a malformed keyed archive")

    def dereference(self, value: Any) -> Any:
        if not isinstance(value, plistlib.UID):
            return value
        if value.data >= len(self.objects):
            raise BaselineError("keyed-archive reference is out of range")
        return self.objects[value.data]

    def uuid(self, value: Any) -> str:
        value = self.dereference(value)
        if isinstance(value, bytes):
            raw = value
        elif isinstance(value, dict):
            raw = value.get("NS.uuidbytes")
        else:
            raw = None
        if not isinstance(raw, bytes) or len(raw) != 16:
            raise BaselineError("keyed archive contains an invalid UUID")
        return str(uuid.UUID(bytes=raw))


def read_host_archive(path: Path, apple_uid: int) -> dict[str, Any]:
    expected_names = {
        "master.cat",
        "biolockout.cat",
        f"user_{apple_uid:08x}.cat",
    }
    members: dict[str, tuple[tarfile.TarInfo, bytes]] = {}
    source_stat = None
    try:
        archive = tarfile.open(path, "r:*")
    except (OSError, tarfile.TarError) as error:
        raise BaselineError(f"cannot open Catacomb archive: {error}") from error
    with archive:
        for member in archive.getmembers():
            name = member.name.rsplit("/", 1)[-1]
            if name == "source-stat.txt":
                if source_stat is not None or not member.isfile() or member.size > 65536:
                    raise BaselineError("invalid or duplicate source-stat.txt")
                stream = archive.extractfile(member)
                if stream is None:
                    raise BaselineError("cannot read source-stat.txt")
                source_stat = stream.read()
                continue
            if name not in expected_names:
                continue
            if name in members:
                raise BaselineError(f"duplicate Catacomb component {name}")
            if not member.isfile() or member.size > 1024 * 1024:
                raise BaselineError(f"unsafe Catacomb component {name}")
            stream = archive.extractfile(member)
            if stream is None:
                raise BaselineError(f"cannot read Catacomb component {name}")
            members[name] = (member, stream.read())
    if set(members) != expected_names:
        raise BaselineError(
            "archive does not contain exactly master, user, and biolockout components"
        )
    if source_stat is None:
        # The original dedicated macOS exporter preserved root:wheel metadata
        # in tar headers but omitted the later source-stat.txt sidecar.
        source_metadata = parse_tar_metadata(members, expected_names)
    else:
        source_metadata = parse_source_metadata(source_stat, expected_names)

    user_name = f"user_{apple_uid:08x}.cat"
    user = KeyedArchive(members[user_name][1], user_name)
    if user.top.get("CatacombVersion") != 0x30000:
        raise BaselineError("unsupported user Catacomb version")
    if user.top.get("CatacombUserID") != apple_uid:
        raise BaselineError("user Catacomb belongs to another Apple UID")
    identity_array = user.dereference(user.top.get("CatacombIdentityList"))
    if not isinstance(identity_array, dict) or not isinstance(
        identity_array.get("NS.objects"), list
    ):
        raise BaselineError("user Catacomb has no valid identity list")
    identities = []
    for reference in identity_array["NS.objects"]:
        identity = user.dereference(reference)
        if not isinstance(identity, dict):
            raise BaselineError("user Catacomb identity is malformed")
        identity_uid = identity.get("BKIdentityUserID")
        entity = identity.get("BKIdentityEntityNumber")
        if identity_uid != apple_uid or not isinstance(entity, int) or entity < 0:
            raise BaselineError("user Catacomb identity owner/entity is invalid")
        identities.append(
            {
                "user_id": identity_uid,
                "uuid": user.uuid(identity.get("BKIdentityUUID")),
                "entity": entity,
            }
        )
    identities.sort(key=lambda item: (item["user_id"], item["uuid"]))
    if len({item["uuid"] for item in identities}) != len(identities):
        raise BaselineError("user Catacomb contains duplicate identity UUIDs")

    master = KeyedArchive(members["master.cat"][1], "master.cat")
    if master.top.get("CatacombVersion") != 0x30000:
        raise BaselineError("unsupported master Catacomb version")
    generation = master.top.get("CatacombEnrollmentCount")
    if not isinstance(generation, int) or generation < 0:
        raise BaselineError("master Catacomb has an invalid generation hint")

    components = []
    for name in sorted(expected_names):
        _member, data = members[name]
        components.append(
            {
                "name": name,
                "sha256": sha256(data),
                **source_metadata[name],
            }
        )
    return {
        "account_uuid": user.uuid(user.top.get("CatacombUserUUID")),
        "bag_uuid": user.uuid(user.top.get("CatacombUserKeybagUUID")),
        "identity_records": identities,
        "master_enrollment_count": generation,
        "host_components": components,
        "archive_sha256": sha256(path.read_bytes()),
    }


def build_baseline(
    *,
    host: dict[str, Any],
    live: dict[str, Any],
    caller_linux_uid: int,
    target_linux_uid: int,
    linux_boot_uuid: str,
    mapping_generation: str,
    backup_reference: str,
    password_fallback_verified: bool,
) -> dict[str, Any]:
    apple_uid = live.get("apple_uid")
    if not isinstance(apple_uid, int) or apple_uid < 0:
        raise BaselineError("live inventory has an invalid Apple UID")
    if live.get("double_collection_equal") is not True:
        raise BaselineError("live inventory is not stable")
    live_identities = {
        (item.get("user_id"), item.get("identity_uuid"))
        for item in live.get("per_user_identity_records", [])
        if isinstance(item, dict)
    }
    host_identities = {
        (item["user_id"], item["uuid"]) for item in host["identity_records"]
    }
    catacomb = live.get("catacomb")
    absent_initialization = (
        isinstance(catacomb, dict)
        and catacomb.get("present") is False
        and live_identities == set()
        and (
            (
                len(host_identities) == 1
                and catacomb.get("uuid")
                == "00000000-0000-0000-0000-000000000000"
                and catacomb.get("hash") == "0" * 64
                and catacomb.get("user_states")
                == [
                    {
                        "kind": "master",
                        "user_id": 0xFFFFFFFF,
                        "state": 3,
                        "needs_save": False,
                    }
                ]
            )
            or (
                not host_identities
                and isinstance(catacomb.get("user_states"), list)
                and len(catacomb["user_states"]) == 2
                and {
                    (
                        item.get("kind"),
                        item.get("user_id"),
                        item.get("state"),
                        item.get("needs_save"),
                    )
                    for item in catacomb["user_states"]
                    if isinstance(item, dict)
                }
                == {
                    ("master", 0xFFFFFFFF, 3, False),
                    ("user", apple_uid, 3, False),
                }
            )
        )
    )
    if live_identities != host_identities and not absent_initialization:
        raise BaselineError("live SEP and host Catacomb identities disagree")
    if not isinstance(catacomb, dict) or (
        catacomb.get("present") is not True and not absent_initialization
    ):
        raise BaselineError("live SEP Catacomb component is absent")
    maximum = live.get("maximum_capacity")
    if not isinstance(maximum, int) or maximum < len(host_identities):
        raise BaselineError("live identity capacity is invalid")
    if live.get("biometric_protocol_version") != 2:
        raise BaselineError("baseline requires biometric protocol version 2")
    if type(password_fallback_verified) is not bool:
        raise BaselineError("password fallback attestation is not Boolean")
    return {
        "baseline_version": 1,
        "caller_linux_uid": caller_linux_uid,
        "target_linux_uid": target_linux_uid,
        "apple_uid": apple_uid,
        "account_uuid": host["account_uuid"],
        "bag_uuid": host["bag_uuid"],
        "linux_boot_uuid": linux_boot_uuid,
        "connection_generation": live["connection_generation"],
        "bridge_boot_uuid": live.get("bridge_boot_uuid"),
        "protocol_version": 2,
        "policy_decision": "authorized",
        "identity_records": host["identity_records"],
        "capacity": {"used": len(host_identities), "maximum": maximum},
        "sep_catacomb": {
            "present": not absent_initialization,
            "uuid": None if absent_initialization else catacomb["uuid"],
            "hash": None if absent_initialization else catacomb["hash"],
        },
        "host_components": host["host_components"],
        "master_enrollment_count": host["master_enrollment_count"],
        "mapping_generation": mapping_generation,
        "backup_references": [
            {"reference": backup_reference, "sha256": host["archive_sha256"]}
        ],
        "double_collection_equal": True,
        "password_fallback_verified": password_fallback_verified,
    }


def build_linux_native_empty_baseline(
    *,
    live: dict[str, Any],
    caller_linux_uid: int,
    target_linux_uid: int,
    linux_boot_uuid: str,
    mapping_generation: str,
    account_uuid: str,
    bag_uuid: str,
    password_fallback_verified: bool,
) -> dict[str, Any]:
    """Build the first-enrollment baseline without an imported Catacomb."""
    apple_uid = live.get("apple_uid")
    if not isinstance(apple_uid, int) or isinstance(apple_uid, bool) or apple_uid < 0:
        raise BaselineError("live inventory has an invalid Apple UID")
    if live.get("double_collection_equal") is not True:
        raise BaselineError("live inventory is not stable")
    if live.get("biometric_protocol_version") != 2:
        raise BaselineError("Linux-native baseline requires biometric protocol version 2")
    if live.get("per_user_identity_records") != [] or live.get(
        "global_identity_records"
    ) != []:
        raise BaselineError("Linux-native baseline is not an empty identity namespace")
    maximum = live.get("maximum_capacity")
    free = live.get("configured_user_free_capacity")
    if (
        not isinstance(maximum, int)
        or isinstance(maximum, bool)
        or maximum <= 0
        or not isinstance(free, int)
        or isinstance(free, bool)
        or not 0 <= free <= maximum
    ):
        raise BaselineError("live identity capacity is invalid")

    catacomb = live.get("catacomb")
    if not isinstance(catacomb, dict) or catacomb.get("present") is not False:
        raise BaselineError("Linux-native baseline requires an absent Catacomb")
    catacomb_uuid = catacomb.get("uuid")
    try:
        parsed_catacomb_uuid = uuid.UUID(catacomb_uuid)
    except (AttributeError, TypeError, ValueError) as error:
        raise BaselineError("live Catacomb namespace UUID is invalid") from error
    if str(parsed_catacomb_uuid) != catacomb_uuid or parsed_catacomb_uuid.int == 0:
        raise BaselineError("live Catacomb namespace UUID is invalid")
    states = catacomb.get("user_states")
    expected_states = {
        ("master", 0xFFFFFFFF, 0, False),
        ("user", apple_uid, 0, False),
    }
    valid_states = isinstance(states, list) and len(states) == 2
    normalized_states = set()
    for state in states if isinstance(states, list) else []:
        if (
            not isinstance(state, dict)
            or set(state) != {"kind", "user_id", "state", "needs_save"}
            or not isinstance(state["kind"], str)
            or not isinstance(state["user_id"], int)
            or isinstance(state["user_id"], bool)
            or not isinstance(state["state"], int)
            or isinstance(state["state"], bool)
            or type(state["needs_save"]) is not bool
        ):
            valid_states = False
            continue
        normalized_states.add(
            (
                state["kind"],
                state["user_id"],
                state["state"],
                state["needs_save"],
            )
        )
    if not valid_states or normalized_states != expected_states:
        raise BaselineError("Linux-native Catacomb state is not explicitly empty")

    for value, field in ((account_uuid, "account UUID"), (bag_uuid, "bag UUID")):
        try:
            parsed = uuid.UUID(value)
        except (AttributeError, TypeError, ValueError) as error:
            raise BaselineError(f"{field} is invalid") from error
        if str(parsed) != value or parsed.int == 0:
            raise BaselineError(f"{field} is invalid")
    if password_fallback_verified is not True:
        raise BaselineError("password fallback has not been verified")

    return {
        "baseline_version": 2,
        "caller_linux_uid": caller_linux_uid,
        "target_linux_uid": target_linux_uid,
        "apple_uid": apple_uid,
        "account_uuid": account_uuid,
        "bag_uuid": bag_uuid,
        "linux_boot_uuid": linux_boot_uuid,
        "connection_generation": live["connection_generation"],
        "bridge_boot_uuid": live.get("bridge_boot_uuid"),
        "protocol_version": 2,
        "policy_decision": "authorized",
        "identity_records": [],
        "capacity": {"used": 0, "maximum": maximum},
        "sep_catacomb": {
            "present": False,
            "uuid": catacomb_uuid,
            "hash": None,
        },
        "host_components": [],
        "master_enrollment_count": 0,
        "mapping_generation": mapping_generation,
        "backup_references": [],
        "double_collection_equal": True,
        "password_fallback_verified": True,
    }


def build_linux_native_empty_baseline(
    *,
    live: dict[str, Any],
    caller_linux_uid: int,
    target_linux_uid: int,
    linux_boot_uuid: str,
    mapping_generation: str,
    account_uuid: str,
    bag_uuid: str,
    password_fallback_verified: bool,
) -> dict[str, Any]:
    """Build the first-enrollment baseline without an imported Catacomb."""
    apple_uid = live.get("apple_uid")
    if not isinstance(apple_uid, int) or isinstance(apple_uid, bool) or apple_uid < 0:
        raise BaselineError("live inventory has an invalid Apple UID")
    if live.get("double_collection_equal") is not True:
        raise BaselineError("live inventory is not stable")
    if live.get("biometric_protocol_version") != 2:
        raise BaselineError("Linux-native baseline requires biometric protocol version 2")
    if live.get("per_user_identity_records") != [] or live.get(
        "global_identity_records"
    ) != []:
        raise BaselineError("Linux-native baseline is not an empty identity namespace")
    maximum = live.get("maximum_capacity")
    free = live.get("configured_user_free_capacity")
    if (
        not isinstance(maximum, int)
        or isinstance(maximum, bool)
        or maximum <= 0
        or not isinstance(free, int)
        or isinstance(free, bool)
        or not 0 <= free <= maximum
    ):
        raise BaselineError("live identity capacity is invalid")

    catacomb = live.get("catacomb")
    if not isinstance(catacomb, dict) or catacomb.get("present") is not False:
        raise BaselineError("Linux-native baseline requires an absent Catacomb")
    catacomb_uuid = catacomb.get("uuid")
    try:
        parsed_catacomb_uuid = uuid.UUID(catacomb_uuid)
    except (AttributeError, TypeError, ValueError) as error:
        raise BaselineError("live Catacomb namespace UUID is invalid") from error
    if str(parsed_catacomb_uuid) != catacomb_uuid:
        raise BaselineError("live Catacomb namespace UUID is invalid")
    states = catacomb.get("user_states")
    expected_components = {
        ("master", 0xFFFFFFFF),
        ("user", apple_uid),
    }
    valid_states = isinstance(states, list) and len(states) == 2
    normalized_components = set()
    for state in states if isinstance(states, list) else []:
        if (
            not isinstance(state, dict)
            or set(state) != {"kind", "user_id", "state", "needs_save"}
            or not isinstance(state["kind"], str)
            or not isinstance(state["user_id"], int)
            or isinstance(state["user_id"], bool)
            or not isinstance(state["state"], int)
            or isinstance(state["state"], bool)
            or type(state["needs_save"]) is not bool
        ):
            valid_states = False
            continue
        normalized_components.add((state["kind"], state["user_id"]))
    if not valid_states:
        raise BaselineError("Linux-native Catacomb state schema is invalid")
    if normalized_components != expected_components:
        raise BaselineError("Linux-native Catacomb component set is not exactly prepared")
    # Exact host control flow requires bit 0 before it treats a component as
    # admitted. Bit 1 says whether secure data is already loaded. Bit 2 is the
    # save-dirty flag. Keep the failure classes value-free: the next hardware
    # observation can distinguish a prepared dirty component from an unknown
    # state or component-set problem without logging raw protocol values.
    if any(state["state"] & ~0x07 for state in states):
        raise BaselineError("Linux-native Catacomb state has unknown bits")
    if any(not state["state"] & 0x01 for state in states):
        raise BaselineError("Linux-native Catacomb component is not admitted")
    if any(
        state["needs_save"] is not bool(state["state"] & 0x04)
        for state in states
    ):
        raise BaselineError("Linux-native Catacomb save state is inconsistent")
    # D157 observes the exact same-generation missing-component preparation as
    # save-dirty. That is the expected volatile input to first persistence, not
    # evidence of a durable Catacomb: the independent absent hash, empty global
    # and per-user identity lists, stable double collection, and exact component
    # set remain mandatory above.

    for value, field in ((account_uuid, "account UUID"), (bag_uuid, "bag UUID")):
        try:
            parsed = uuid.UUID(value)
        except (AttributeError, TypeError, ValueError) as error:
            raise BaselineError(f"{field} is invalid") from error
        if str(parsed) != value or parsed.int == 0:
            raise BaselineError(f"{field} is invalid")
    if password_fallback_verified is not True:
        raise BaselineError("password fallback has not been verified")

    return {
        "baseline_version": 2,
        "caller_linux_uid": caller_linux_uid,
        "target_linux_uid": target_linux_uid,
        "apple_uid": apple_uid,
        "account_uuid": account_uuid,
        "bag_uuid": bag_uuid,
        "linux_boot_uuid": linux_boot_uuid,
        "connection_generation": live["connection_generation"],
        "bridge_boot_uuid": live.get("bridge_boot_uuid"),
        "protocol_version": 2,
        "policy_decision": "authorized",
        "identity_records": [],
        "capacity": {"used": 0, "maximum": maximum},
        "sep_catacomb": {
            "present": False,
            "uuid": catacomb_uuid,
            "hash": None,
        },
        "host_components": [],
        "master_enrollment_count": 0,
        "mapping_generation": mapping_generation,
        "backup_references": [],
        "double_collection_equal": True,
        "password_fallback_verified": True,
    }


def build_linux_native_existing_baseline(
    *,
    host: dict[str, Any],
    live: dict[str, Any],
    caller_linux_uid: int,
    target_linux_uid: int,
    linux_boot_uuid: str,
    mapping_generation: str,
    account_uuid: str,
    bag_uuid: str,
    authority_reference: str,
    authority_sha256: str,
    password_fallback_verified: bool,
) -> dict[str, Any]:
    """Build an existing-state baseline rooted in Linux-native E4 evidence.

    Baseline version 1 already represents a durable Catacomb generation and
    drives the proven add-one reconciliation/finalization path.  The source
    reference here is the immutable E4 enrollment journal rather than a macOS
    archive; its protected head hash occupies the existing verified-source
    digest field.
    """
    if host.get("account_uuid") != account_uuid or host.get("bag_uuid") != bag_uuid:
        raise BaselineError("Linux-native host binding changed")
    if not isinstance(authority_reference, str) or not authority_reference:
        raise BaselineError("Linux-native authority reference is invalid")
    if not isinstance(authority_sha256, str) or len(authority_sha256) != 64:
        raise BaselineError("Linux-native authority digest is invalid")
    try:
        bytes.fromhex(authority_sha256)
    except ValueError as error:
        raise BaselineError("Linux-native authority digest is invalid") from error
    rooted_host = dict(host)
    rooted_host["archive_sha256"] = authority_sha256
    return build_baseline(
        host=rooted_host,
        live=live,
        caller_linux_uid=caller_linux_uid,
        target_linux_uid=target_linux_uid,
        linux_boot_uuid=linux_boot_uuid,
        mapping_generation=mapping_generation,
        backup_reference=authority_reference,
        password_fallback_verified=password_fallback_verified,
    )
