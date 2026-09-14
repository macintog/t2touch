# SPDX-License-Identifier: GPL-2.0-only
"""Project reconciled T2 identities onto neutral durable fprint handles."""

from __future__ import annotations

from dataclasses import dataclass

import t2_user_broker_inventory
import t2_fprint_identity

# Compatibility exports for callers that only need the concurrent capacity.
# Neutral handles are five stable slots rather than anatomy labels. Membership
# still uses ``is_finger_name`` so every boundary shares one validator.
FINGER_NAMES = tuple(
    t2_fprint_identity.handle(value)
    for value in range(1, t2_fprint_identity.MAX_ENROLLED_IDENTITIES + 1)
)


def is_finger_name(value: object) -> bool:
    return t2_fprint_identity.is_handle(value)


class FprintProjectionError(ValueError):
    pass


@dataclass(frozen=True)
class FprintProjection:
    finger_names: tuple[str, ...]
    reconciled_identity_count: int
    unassigned_identity_count: int
    duplicate_finger_name_count: int
    complete: bool

    def public(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "finger_names": list(self.finger_names),
            "reconciled_identity_count": self.reconciled_identity_count,
            "unassigned_identity_count": self.unassigned_identity_count,
            "duplicate_finger_name_count": self.duplicate_finger_name_count,
            "complete": self.complete,
            "finger_names_are_presentation_metadata": True,
            "identifiers_redacted": True,
        }


def project(value: object) -> FprintProjection:
    """Return a complete projection only when every identity maps uniquely."""

    try:
        inventory = t2_user_broker_inventory.parse_public_inventory(value)
    except t2_user_broker_inventory.UserBrokerInventoryError as error:
        raise FprintProjectionError(
            "fprint projection requires exact reconciled inventory"
        ) from error
    recognized = [
        identity.name
        for identity in inventory.identities
        if is_finger_name(identity.name)
    ]
    unassigned = inventory.identity_count - len(recognized)
    duplicates = len(recognized) - len(set(recognized))
    complete = unassigned == 0 and duplicates == 0
    ordered = t2_fprint_identity.ordered(recognized) if complete else ()
    if complete and len(ordered) != inventory.identity_count:
        raise FprintProjectionError("fprint projection is internally inconsistent")
    return FprintProjection(
        ordered,
        inventory.identity_count,
        unassigned,
        duplicates,
        complete,
    )
