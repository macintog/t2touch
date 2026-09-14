# SPDX-License-Identifier: GPL-2.0-only
"""Neutral, durable fprint handles for opaque T2 identities.

The handle says which enrolled identity record Linux is referring to.  It
never describes, or constrains, the operator's anatomy.  The private UUID is
still the mutation and match authority behind every handle.
"""

from __future__ import annotations

import re

# The T2 archive format can represent more records than the user-facing
# product exposes. Match macOS's five independent fingerprint slots.
MAX_ENROLLED_IDENTITIES = 5
MAX_FINGER_NUMBER = MAX_ENROLLED_IDENTITIES
_HANDLE = re.compile(r"finger-([1-9][0-9]{0,8})")

# fprintd 1.94.x validates these strings in its example enrollment client
# before issuing D-Bus.  The facade may accept one as legacy call syntax, but
# it must allocate and persist a neutral handle instead of retaining the
# anatomical assertion.
LEGACY_ENROLLMENT_REQUESTS = frozenset(
    f"{side}-{finger}"
    for side in ("left", "right")
    for finger in (
        "thumb",
        "index-finger",
        "middle-finger",
        "ring-finger",
        "little-finger",
    )
)


class FprintIdentityError(ValueError):
    pass


def number(value: object) -> int:
    """Return the canonical positive number in one neutral handle."""

    if not isinstance(value, str):
        raise FprintIdentityError("finger handle is not text")
    match = _HANDLE.fullmatch(value)
    if match is None:
        raise FprintIdentityError("finger handle is not canonical")
    result = int(match.group(1))
    if not 1 <= result <= MAX_FINGER_NUMBER:
        raise FprintIdentityError("finger handle number is outside policy")
    return result


def is_handle(value: object) -> bool:
    try:
        number(value)
    except FprintIdentityError:
        return False
    return True


def handle(value: int) -> str:
    if type(value) is not int or not 1 <= value <= MAX_FINGER_NUMBER:
        raise FprintIdentityError("finger handle number is outside policy")
    return f"finger-{value}"


def display_name(value: object) -> str:
    return f"Finger {number(value)}"


def ordered(values: object) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)):
        raise FprintIdentityError("finger handle collection has the wrong type")
    names = tuple(values)
    if any(not is_handle(name) for name in names) or len(names) != len(set(names)):
        raise FprintIdentityError("finger handles are invalid or duplicated")
    return tuple(sorted(names, key=number))


def next_handle(values: object) -> str:
    """Return the lowest free slot from a complete current inventory.

    Existing handles never move when another slot is deleted. A later
    enrollment reuses only the vacant slot, matching the five-slot product
    model while keeping every retained identity's name stable.
    """

    names = ordered(values)
    occupied = set(names)
    for slot in range(1, MAX_ENROLLED_IDENTITIES + 1):
        candidate = handle(slot)
        if candidate not in occupied:
            return candidate
    raise FprintIdentityError("fingerprint slot capacity is exhausted")


def is_enrollment_request(value: object) -> bool:
    return is_handle(value) or value in LEGACY_ENROLLMENT_REQUESTS
