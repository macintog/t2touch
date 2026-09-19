#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Audit or archive recognized obsolete Touch ID executables, never by glob."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat


MANIFEST = Path(__file__).with_name("retired-tools.json")


def safe_directory(path: Path, owner: int, *, create: bool = False) -> None:
    if create:
        # Check each existing ancestor before creating anything beneath it.
        safe_directory(path.parent, owner)
        path.mkdir(mode=0o700, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner or info.st_mode & 0o022:
        raise RuntimeError(f"unsafe retirement directory: {path}")
    if path != path.parent:
        safe_directory(path.parent, owner)


def file_bytes(path: Path, owner: int) -> tuple[bytes, os.stat_result]:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != owner
            or info.st_nlink != 1
            or info.st_mode & 0o022
            or info.st_size > 4 * 1024 * 1024
        ):
            raise RuntimeError("not an unmodified-ownership regular executable")
        return stream.read(), info


def retire(prefix: Path, archive: Path, tools: dict, *, apply: bool = False,
           owner: int = 0) -> list[dict]:
    """Archive exact historical bytes before unlinking an obsolete PATH copy."""
    safe_directory(prefix, owner)
    results = []
    for name, entry in sorted(tools.items()):
        if not name.startswith("t2-") or Path(name).name != name:
            raise ValueError("invalid retired tool name")
        path = prefix / name
        if not os.path.lexists(path):
            continue
        result = {"path": str(path)}
        try:
            content, info = file_bytes(path, owner)
        except (OSError, RuntimeError):
            result["status"] = "preserved-ownership-conflict"
            results.append(result)
            continue
        digest = hashlib.sha256(content).hexdigest()
        result["sha256"] = digest
        if digest not in entry["sha256"]:
            result["status"] = "preserved-unrecognized-content"
            results.append(result)
            continue
        result["status"] = "would-archive"
        if apply:
            safe_directory(archive, owner, create=True)
            generation = archive / digest
            safe_directory(generation, owner, create=True)
            destination = generation / name
            if os.path.lexists(destination):
                retained, _ = file_bytes(destination, owner)
                if retained != content:
                    raise RuntimeError("retired tool archive differs; refusing removal")
            else:
                descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                     | os.O_NOFOLLOW, 0o600)
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(content)
                    stream.flush()
                    os.fsync(stream.fileno())
            # Persist the archive name before removing the original, including
            # across filesystems. An interrupted copy never licenses removal.
            for parent in (generation, archive, archive.parent):
                directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
            current, current_info = file_bytes(path, owner)
            if (current_info.st_dev, current_info.st_ino) != (info.st_dev, info.st_ino) or current != content:
                raise RuntimeError("retired tool changed during archival")
            path.unlink()
            result.update(status="archived", archive=str(destination))
        results.append(result)
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="archive recognized copies; default is audit only")
    args = parser.parse_args()
    if args.apply and os.geteuid() != 0:
        parser.error("--apply requires root")
    manifest = json.loads(MANIFEST.read_text())
    results = retire(Path("/usr/local/sbin"), Path("/var/lib/t2-touchid/retired-tools"),
                     manifest["tools"], apply=args.apply)
    print(json.dumps({"schema_version": 1, "applied": args.apply, "tools": results}, indent=2))
    # Unknown/local edits are reported and preserved, not an excuse to prevent
    # upgrading the active stack. There is deliberately no force-delete switch.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
