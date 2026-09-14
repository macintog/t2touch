#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Inspect board identities in an Apple bridgeOS BuildManifest.

The parser deliberately has no model allowlist.  A manifest is evidence about
firmware packaging; it is not, by itself, a claim that a protocol works on
every identity in that package.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import json
from pathlib import Path
import plistlib
from typing import Any, Iterable


class ManifestError(ValueError):
    """The manifest is malformed, ambiguous, or does not match a selector."""


@dataclass(frozen=True, order=True)
class BridgeFirmwareIdentity:
    product_type: str
    target: str
    target_type: str
    board_id: str
    chip_id: str
    product_version: str
    build_version: str
    sep_path: str

    @property
    def bridge_generation(self) -> str:
        """Return iBridge's major generation without assigning semantics."""
        prefix, separator, _model = self.product_type.partition(",")
        if not separator or not prefix.startswith("iBridge"):
            raise ManifestError(f"invalid bridge product type: {self.product_type!r}")
        generation = prefix.removeprefix("iBridge")
        if not generation.isdecimal():
            raise ManifestError(f"invalid bridge generation: {self.product_type!r}")
        return generation

    def public_dict(self) -> dict[str, str]:
        result = asdict(self)
        result["bridge_generation"] = self.bridge_generation
        return result


def _required_string(mapping: dict[str, Any], key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value:
        raise ManifestError(f"missing or invalid {key}")
    return value


def _normalized_hex(value: str, key: str) -> str:
    try:
        number = int(value, 16)
    except ValueError as error:
        raise ManifestError(f"invalid {key}: {value!r}") from error
    if number < 0:
        raise ManifestError(f"invalid {key}: {value!r}")
    width = max(2, len(value.removeprefix("0x").removeprefix("0X")))
    return f"0x{number:0{width}X}"


def parse_build_manifest(manifest: dict[str, Any]) -> tuple[BridgeFirmwareIdentity, ...]:
    """Return unique firmware identities, rejecting conflicting duplicates."""
    product_version = _required_string(manifest, "ProductVersion")
    build_version = _required_string(manifest, "ProductBuildVersion")
    raw_identities = manifest.get("BuildIdentities")
    if not isinstance(raw_identities, list) or not raw_identities:
        raise ManifestError("missing or invalid BuildIdentities")

    identities: dict[tuple[str, str, str, str, str], BridgeFirmwareIdentity] = {}
    for raw in raw_identities:
        if not isinstance(raw, dict):
            raise ManifestError("BuildIdentities entry is not a dictionary")
        manifest_items = raw.get("Manifest")
        if not isinstance(manifest_items, dict):
            raise ManifestError("identity has no Manifest dictionary")
        sep = manifest_items.get("SEP")
        if not isinstance(sep, dict) or not isinstance(sep.get("Info"), dict):
            raise ManifestError("identity has no SEP component")
        sep_path = _required_string(sep["Info"], "Path")

        identity = BridgeFirmwareIdentity(
            product_type=_required_string(raw, "Ap,ProductType"),
            target=_required_string(raw, "Ap,Target"),
            target_type=_required_string(raw, "Ap,TargetType"),
            board_id=_normalized_hex(_required_string(raw, "ApBoardID"), "ApBoardID"),
            chip_id=_normalized_hex(_required_string(raw, "ApChipID"), "ApChipID"),
            product_version=product_version,
            build_version=build_version,
            sep_path=sep_path,
        )
        identity.bridge_generation
        key = (
            identity.product_type,
            identity.target,
            identity.target_type,
            identity.board_id,
            identity.chip_id,
        )
        previous = identities.get(key)
        if previous is not None and previous != identity:
            raise ManifestError(f"conflicting duplicate identity: {key!r}")
        identities[key] = identity

    return tuple(sorted(identities.values()))


def load_build_manifest(path: Path) -> tuple[BridgeFirmwareIdentity, ...]:
    try:
        with path.open("rb") as stream:
            manifest = plistlib.load(stream)
    except (OSError, plistlib.InvalidFileException) as error:
        raise ManifestError(f"cannot read BuildManifest: {error}") from error
    if not isinstance(manifest, dict):
        raise ManifestError("BuildManifest root is not a dictionary")
    return parse_build_manifest(manifest)


def select_identities(
    identities: Iterable[BridgeFirmwareIdentity],
    *,
    product_type: str | None = None,
    target_type: str | None = None,
    board_id: str | None = None,
) -> tuple[BridgeFirmwareIdentity, ...]:
    normalized_board = _normalized_hex(board_id, "board ID") if board_id else None
    selected = tuple(
        identity
        for identity in identities
        if (product_type is None or identity.product_type == product_type)
        and (target_type is None or identity.target_type == target_type)
        and (normalized_board is None or identity.board_id == normalized_board)
    )
    if not selected:
        raise ManifestError("no firmware identity matches the supplied selectors")
    return selected


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--product-type")
    parser.add_argument("--target-type")
    parser.add_argument("--board-id")
    parser.add_argument(
        "--all",
        action="store_true",
        help="show every unique identity (otherwise at least one selector is required)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    if not args.all and not (args.product_type or args.target_type or args.board_id):
        parser.error("supply an identity selector or explicitly request --all")
    try:
        identities = load_build_manifest(args.manifest)
        if not args.all:
            identities = select_identities(
                identities,
                product_type=args.product_type,
                target_type=args.target_type,
                board_id=args.board_id,
            )
    except ManifestError as error:
        parser.error(str(error))
    print(json.dumps([identity.public_dict() for identity in identities], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
