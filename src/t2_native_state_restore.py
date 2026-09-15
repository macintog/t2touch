# SPDX-License-Identifier: GPL-2.0-only
"""Restore one committed Linux-native Catacomb generation for enrollment."""

from __future__ import annotations

import struct
import uuid

import t2_biolockout_store
import t2_bridge_inventory
import t2_bridge_wire as wire
import t2_catacomb_codec
import t2_catacomb_protocol
import t2_catacomb_store


class NativeStateRestoreError(RuntimeError):
    """Raised when the committed local state cannot be loaded exactly."""


class NativeStateServiceEventError(NativeStateRestoreError):
    """A restore-preparation command consumed an unrelated callback."""


IDENTITY_RECORD_SIZE = 20
MAX_IDENTITIES = 64
KNOWN_COMPONENT_STATE_BITS = 0x07
SECURELY_LOADED_STATE_BITS = 0x03


def is_cold_unloaded_inventory(live: object, apple_user_id: int) -> bool:
    """Recognize only a stable master-only bridgeOS restore generation.

    An empty loaded user can be an external deletion or corruption. It must
    never be treated as permission to restore the committed identities.
    """
    if not isinstance(live, dict):
        return False
    catacomb = live.get("catacomb")
    if not isinstance(catacomb, dict):
        return False
    states = catacomb.get("user_states")
    if (
        not isinstance(states, list)
        or len(states) != 1
        or not isinstance(states[0], dict)
        or type(states[0].get("state")) is not int
        or type(states[0].get("user_id")) is not int
        or states[0].get("needs_save") is not False
        or states[0].get("state") != 1
    ):
        return False
    return (
        live.get("double_collection_equal") is True
        and live.get("apple_uid") == apple_user_id
        and live.get("biometric_protocol_version") == 2
        and live.get("per_user_identity_records") == []
        and live.get("global_identity_records") == []
        and catacomb.get("present") is False
        and catacomb.get("uuid") == str(uuid.UUID(int=0))
        and catacomb.get("hash") == "0" * 64
        and states == [
            {"kind": "master", "user_id": 0xFFFFFFFF,
             "state": states[0]["state"], "needs_save": False}
        ]
    )


def _output(
    reply: object, events: object, label: str, apple_user_id: int
) -> bytes:
    try:
        t2_bridge_inventory.require_preparation_service_events(
            events, apple_user_id
        )
    except t2_bridge_inventory.BridgeInventoryError as error:
        raise NativeStateRestoreError(
            f"{label} emitted an unexpected service event"
        ) from error
    if type(reply) is not list or len(reply) not in (1, 2) or reply[0] != 0:
        raise NativeStateRestoreError(f"{label} did not succeed")
    output = b"" if len(reply) == 1 else reply[1]
    if wire.is_biometric_nil_output(output):
        output = b""
    if type(output) is not bytes:
        raise NativeStateRestoreError(f"{label} output is malformed")
    return output


def _states(
    lease, apple_user_id: int
) -> tuple[t2_catacomb_protocol.CatacombState, ...]:
    reply, events = lease.biometric_command(
        0x3C, version=1, value=0, data=b"", output_capacity=4096
    )
    try:
        return t2_catacomb_protocol.parse_user_states(
            _output(reply, events, "Catacomb-state read", apple_user_id)
        )
    except t2_catacomb_protocol.CatacombProtocolError as error:
        raise NativeStateRestoreError("Catacomb-state reply is invalid") from error


def _require_no_groups(lease, apple_user_id: int) -> None:
    reply, events = lease.biometric_command(
        0x50,
        version=1,
        value=0,
        data=b"",
        output_capacity=t2_catacomb_protocol.GROUP_STATE_RECORD.size * 10,
    )
    output = _output(reply, events, "group Catacomb-state read", apple_user_id)
    try:
        groups = t2_catacomb_protocol.parse_group_states(output)
    except t2_catacomb_protocol.CatacombProtocolError as error:
        raise NativeStateRestoreError("group Catacomb-state reply is invalid") from error
    if groups:
        raise NativeStateRestoreError("Linux-native restore found a group component")


def _load(lease, secure_data: bytes, label: str, apple_user_id: int) -> None:
    reply, events = lease.biometric_command(
        0x40,
        version=1,
        value=0,
        data=secure_data,
        output_capacity=0,
    )
    if _output(reply, events, label, apple_user_id):
        raise NativeStateRestoreError(f"{label} returned unexpected output")


def _load_biolockout(
    lease,
    store: t2_biolockout_store.BioLockoutStore,
    current: t2_biolockout_store.BioLockoutGeneration,
    apple_user_id: int,
) -> None:
    """Load the host head or recover a strictly newer SEP-owned generation."""

    reply, events = lease.biometric_command(
        0x4B,
        version=1,
        value=0,
        data=current.payload,
        output_capacity=0,
    )
    try:
        t2_bridge_inventory.require_preparation_service_events(
            events, apple_user_id
        )
    except t2_bridge_inventory.BridgeInventoryError as error:
        raise NativeStateRestoreError(
            "BioLockout load emitted an unexpected service event"
        ) from error
    if type(reply) is list and len(reply) in (1, 2) and reply[0] == 0:
        output = b"" if len(reply) == 1 else reply[1]
        if wire.is_biometric_nil_output(output):
            output = b""
        if type(output) is not bytes:
            raise NativeStateRestoreError(
                "BioLockout load output is malformed"
            )
        if output:
            raise NativeStateRestoreError(
                "BioLockout load returned unexpected output"
            )
        return
    if (
        type(reply) is not list
        or len(reply) not in (1, 2)
        or type(reply[0]) is not int
        or reply[0] == 0
    ):
        raise NativeStateRestoreError("BioLockout load reply is malformed")

    export_reply, export_events = lease.biometric_command(
        0x4A,
        version=1,
        value=0,
        data=b"",
        output_capacity=4096,
    )
    recovered_payload = _output(
        export_reply, export_events, "BioLockout export", apple_user_id
    )
    if (
        not recovered_payload.startswith(b"HRLB")
        or recovered_payload == current.payload
    ):
        raise NativeStateRestoreError(
            "SEP did not provide a newer BioLockout generation"
        )
    recovered = store.commit(recovered_payload)
    recovered_reply, recovered_events = lease.biometric_command(
        0x4B,
        version=1,
        value=0,
        data=recovered.payload,
        output_capacity=0,
    )
    if _output(
        recovered_reply,
        recovered_events,
        "recovered BioLockout load",
        apple_user_id,
    ):
        raise NativeStateRestoreError(
            "recovered BioLockout load returned unexpected output"
        )


def _identities(lease, apple_user_id: int) -> set[tuple[int, str]]:
    reply, events = lease.biometric_command(
        0x42,
        version=1,
        value=0,
        data=struct.pack("<I", apple_user_id),
        output_capacity=MAX_IDENTITIES * IDENTITY_RECORD_SIZE,
    )
    output = _output(reply, events, "identity read", apple_user_id)
    if len(output) % IDENTITY_RECORD_SIZE:
        raise NativeStateRestoreError("identity read output is malformed")
    records = []
    for offset in range(0, len(output), IDENTITY_RECORD_SIZE):
        user_id = struct.unpack_from("<I", output, offset)[0]
        if user_id != apple_user_id:
            raise NativeStateRestoreError("identity read returned another user")
        records.append(
            (user_id, str(uuid.UUID(bytes=output[offset + 4 : offset + 20])))
        )
    unique = set(records)
    if len(unique) != len(records):
        raise NativeStateRestoreError("identity read returned a duplicate")
    return unique


def _component_map(
    states: tuple[t2_catacomb_protocol.CatacombState, ...],
    apple_user_id: int,
    *,
    allow_master_only: bool = False,
) -> dict[t2_catacomb_protocol.CatacombComponent, t2_catacomb_protocol.CatacombState]:
    by_component = {record.component: record for record in states}
    master = t2_catacomb_protocol.CatacombComponent.master()
    expected = {
        master,
        t2_catacomb_protocol.CatacombComponent.user(apple_user_id),
    }
    actual = set(by_component)
    if (
        (actual != expected and not (allow_master_only and actual == {master}))
        or len(by_component) != len(states)
    ):
        raise NativeStateRestoreError("Linux-native component set changed")
    return by_component


def _securely_loaded(record: t2_catacomb_protocol.CatacombState) -> bool:
    return (
        not record.state & ~KNOWN_COMPONENT_STATE_BITS
        and record.state & SECURELY_LOADED_STATE_BITS
        == SECURELY_LOADED_STATE_BITS
    )


def restore_for_enrollment(
    lease,
    *,
    apple_user_id: int,
    catacomb_store: t2_catacomb_store.CatacombStore,
    biolockout_store: t2_biolockout_store.BioLockoutStore,
) -> int:
    """Load master, selected user, and the rolling BioLockout head.

    This adapts T1Bridge's master-before-user restore discipline while keeping
    the T2 protocol-v2 component model and Linux append-only BioLockout owner.
    It performs no enrollment mutation.
    """
    try:
        components = catacomb_store.read_committed_components()
        user_name = f"user_{apple_user_id:08x}.cat"
        master = t2_catacomb_codec.decode_master_catacomb(components["master.cat"])
        user = t2_catacomb_codec.decode_user_catacomb(
            components[user_name], apple_user_id
        )
        states = _states(lease, apple_user_id)
        _require_no_groups(lease, apple_user_id)
        master_component = t2_catacomb_protocol.CatacombComponent.master()
        user_component = t2_catacomb_protocol.CatacombComponent.user(apple_user_id)
        by_component = _component_map(
            states, apple_user_id, allow_master_only=True
        )
        if (
            by_component[master_component].state & ~KNOWN_COMPONENT_STATE_BITS
            or not by_component[master_component].state & 0x01
        ):
            raise NativeStateRestoreError("master Catacomb is not loadable")
        committed_identities = {
            (identity.user_id, identity.uuid) for identity in user.identities
        }
        if len(committed_identities) != len(user.identities):
            raise NativeStateRestoreError(
                "committed user Catacomb contains duplicate identities"
            )
        live_identities = _identities(lease, apple_user_id)
        if live_identities and live_identities != committed_identities:
            raise NativeStateRestoreError(
                "live identities differ from the committed user Catacomb"
            )
        if live_identities and user_component not in by_component:
            raise NativeStateRestoreError(
                "live identities exist without the selected user Catacomb"
            )
        if live_identities and any(
            not _securely_loaded(by_component[component])
            for component in (master_component, user_component)
        ):
            raise NativeStateRestoreError(
                "live identity Catacomb is not securely loaded"
            )
        if not live_identities:
            # A true cold bridgeOS generation advertises only a loadable master
            # (state 1). Loading it makes the committed user blob admissible.
            # By contrast, an already-loaded user with no live identities is
            # the D206 no-Catacomb corruption and must never be overwritten.
            if (
                user_component in by_component
                and by_component[user_component].state & 0x02
                and committed_identities
            ):
                raise NativeStateRestoreError(
                    "live identities are absent while the committed Catacomb reports loaded; cold bridgeOS restart required"
                )
            if (
                user_component in by_component
                and committed_identities
                and by_component[user_component].state != 0x01
            ):
                raise NativeStateRestoreError(
                    "selected user Catacomb is not loadable"
                )
            if not committed_identities and user_component in by_component:
                if any(
                    not _securely_loaded(by_component[component])
                    for component in (master_component, user_component)
                ):
                    raise NativeStateRestoreError(
                        "empty Linux-native Catacomb is not securely loaded"
                    )
            elif by_component[master_component].state == 0x01:
                _load(
                    lease,
                    master.secure_data,
                    "master Catacomb load",
                    apple_user_id,
                )
            if committed_identities or user_component not in by_component:
                after_master = _component_map(
                    _states(lease, apple_user_id),
                    apple_user_id,
                    allow_master_only=True,
                )
                if after_master[master_component].state != 0x03:
                    raise NativeStateRestoreError("master Catacomb did not load")
                if (
                    user_component in after_master
                    and after_master[user_component].state != 0x01
                ):
                    raise NativeStateRestoreError(
                        "selected user Catacomb is not loadable"
                    )
                _load(
                    lease,
                    user.secure_data,
                    "selected user Catacomb load",
                    apple_user_id,
                )
        final_states = _component_map(_states(lease, apple_user_id), apple_user_id)
        if any(not _securely_loaded(record) for record in final_states.values()):
            raise NativeStateRestoreError("Linux-native Catacomb did not load securely")
        _require_no_groups(lease, apple_user_id)
        if _identities(lease, apple_user_id) != committed_identities:
            raise NativeStateRestoreError(
                "restored identities differ from the committed user Catacomb"
            )
        rolling = biolockout_store.current()
        if rolling is None:
            raise NativeStateRestoreError("rolling BioLockout authority is absent")
        _load_biolockout(lease, biolockout_store, rolling, apple_user_id)
        return len(committed_identities)
    except NativeStateRestoreError:
        try:
            lease.invalidate()
        except BaseException:
            pass
        raise
    except BaseException as error:
        try:
            lease.invalidate()
        except BaseException:
            pass
        raise NativeStateRestoreError("Linux-native state restore failed") from error
