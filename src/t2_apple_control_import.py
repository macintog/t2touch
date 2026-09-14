# SPDX-License-Identifier: GPL-2.0-only
"""Import a macOS control capture without treating it as Linux-owned state."""

from __future__ import annotations

import dataclasses
import hashlib
import gzip
import io
import json
import os
import re
import stat
import tarfile
import uuid
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

import t2_catacomb_local
import t2_catacomb_codec
import t2_catacomb_oracle
import t2_user_mapping
import t2_user_mapping_store


STATE_ROOT = Path("/var/lib/t2-touchid")
MAX_ARCHIVE_SIZE = 16 * 1024 * 1024
MAX_MEMBER_SIZE = 1024 * 1024
MAX_ARCHIVE_MEMBERS = 256
MAX_MAP_SIZE = 64 * 1024
MAX_MAP_ENTRIES = 128
MAX_SAVED_KEYBAG_SIZE = 16_000
CANDIDATE = re.compile(r"candidate-[0-9]{4}\Z", re.ASCII)
ORIGIN = "macos-control-oracle-v1"


class AppleControlImportError(RuntimeError):
    pass


@dataclass(repr=False)
class KeybagSelection:
    saved_keybag: bytearray
    saved_keybag_sha256: str
    archive_sha256: str
    source_view_count: int
    mapped_candidate_count: int

    def wipe(self) -> None:
        self.saved_keybag[:] = b"\0" * len(self.saved_keybag)


@dataclass(repr=False)
class CatacombSelection:
    normalized_archive: bytearray
    capture_sha256: str
    normalized_sha256: str
    account_uuid: str
    bag_uuid: str
    component_sha256: dict[str, str]
    identity_count: int

    def wipe(self) -> None:
        self.normalized_archive[:] = b"\0" * len(self.normalized_archive)


@dataclass(frozen=True, repr=False)
class OracleImportPlan:
    linux_uid: int
    linux_account_generation: str
    apple_uid: int
    account_uuid: str
    bag_uuid: str
    keybag_sha256: str
    keybag_archive_sha256: str
    catacomb_capture_sha256: str
    catacomb_backup_sha256: str
    catacomb_component_sha256: dict[str, str]
    identity_count: int
    keybag_source_view_count: int
    mapped_candidate_count: int
    operation_id: str

    def public_summary(self) -> dict[str, object]:
        return {
            "schema_version": 1,
            "origin": ORIGIN,
            "identity_count": self.identity_count,
            "keybag_source_view_count": self.keybag_source_view_count,
            "keybag_unique_payload_count": 1,
            "mapped_candidate_count": self.mapped_candidate_count,
            "mapping_enabled": False,
            "import_reconciled": True,
            "live_operation_performed": False,
            "identifiers_redacted": True,
        }


def _private_file(path: Path, maximum: int) -> bytearray:
    descriptor = -1
    data = bytearray()
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
            raise AppleControlImportError(
                "control archive is not a private caller-owned regular file"
            )
        while len(data) <= maximum:
            block = os.read(descriptor, min(65536, maximum + 1 - len(data)))
            if not block:
                break
            data.extend(block)
        after = os.fstat(descriptor)
        stable_before = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_uid,
            before.st_gid,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        stable_after = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_uid,
            after.st_gid,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if len(data) != before.st_size or stable_before != stable_after:
            raise AppleControlImportError("control archive changed during read")
        return data
    except AppleControlImportError:
        data[:] = b"\0" * len(data)
        raise
    except OSError as error:
        data[:] = b"\0" * len(data)
        raise AppleControlImportError("control archive cannot be read safely") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _safe_member_name(name: str) -> PurePosixPath:
    if not isinstance(name, str) or not name or "\0" in name:
        raise AppleControlImportError("keybag archive member name is invalid")
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or str(path) != name.rstrip("/"):
        raise AppleControlImportError("keybag archive member path is unsafe")
    return path


def _parse_map(data: bytes) -> dict[str, PurePosixPath]:
    if not 0 < len(data) <= MAX_MAP_SIZE:
        raise AppleControlImportError("keybag candidate map size is invalid")
    try:
        lines = data.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise AppleControlImportError("keybag candidate map is not UTF-8") from error
    result: dict[str, PurePosixPath] = {}
    for line in lines:
        if not line:
            continue
        fields = line.split("\t")
        if len(fields) != 2 or CANDIDATE.fullmatch(fields[0]) is None:
            raise AppleControlImportError("keybag candidate map entry is malformed")
        candidate, source_text = fields
        source = PurePosixPath(source_text)
        if (
            candidate in result
            or not source.is_absolute()
            or ".." in source.parts
            or str(source) != source_text
        ):
            raise AppleControlImportError("keybag candidate map is ambiguous")
        result[candidate] = source
        if len(result) > MAX_MAP_ENTRIES:
            raise AppleControlImportError("keybag candidate map is oversized")
    if not result:
        raise AppleControlImportError("keybag candidate map is empty")
    return result


def read_keybag_archive(path: Path) -> KeybagSelection:
    """Select one unique direct user.kb payload from a complete mapped archive."""

    if not isinstance(path, Path) or not path.is_absolute():
        raise AppleControlImportError("keybag archive path must be absolute")
    raw = _private_file(path, MAX_ARCHIVE_SIZE)
    archive_digest = hashlib.sha256(raw).hexdigest()
    map_data: bytes | None = None
    direct: dict[str, bytes] = {}
    roots: set[str] = set()
    roots_with_files: set[str] = set()
    member_count = 0
    total_size = 0
    try:
        try:
            archive = tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz")
        except (OSError, tarfile.TarError) as error:
            raise AppleControlImportError("keybag archive is not valid gzip tar") from error
        with archive:
            for member in archive.getmembers():
                member_count += 1
                if member_count > MAX_ARCHIVE_MEMBERS:
                    raise AppleControlImportError("keybag archive has too many members")
                member_path = _safe_member_name(member.name)
                if not (member.isdir() or member.isfile()):
                    raise AppleControlImportError("keybag archive has unsafe member type")
                if member.size < 0 or member.size > MAX_MEMBER_SIZE:
                    raise AppleControlImportError("keybag archive member size is unsafe")
                total_size += member.size
                if total_size > MAX_ARCHIVE_SIZE:
                    raise AppleControlImportError("keybag archive expands beyond policy")
                parts = member_path.parts
                candidate: str | None = None
                if len(parts) >= 2 and parts[0] == "state" and CANDIDATE.fullmatch(parts[1]):
                    candidate = parts[1]
                    roots.add(candidate)
                    if member.isfile():
                        roots_with_files.add(candidate)
                if not member.isfile():
                    continue
                stream = archive.extractfile(member)
                if stream is None:
                    raise AppleControlImportError("keybag archive member is unreadable")
                data = stream.read(MAX_MEMBER_SIZE + 1)
                if len(data) != member.size:
                    raise AppleControlImportError("keybag archive member changed length")
                if member_path == PurePosixPath("state/path-map.txt"):
                    if map_data is not None:
                        raise AppleControlImportError("keybag archive has duplicate map")
                    map_data = data
                elif candidate is not None and len(parts) == 2:
                    if candidate in direct:
                        raise AppleControlImportError("keybag candidate is duplicated")
                    direct[candidate] = data
        if map_data is None:
            raise AppleControlImportError("keybag archive has no candidate map")
        mapping = _parse_map(map_data)
        if set(mapping) != roots or set(mapping) != roots_with_files:
            raise AppleControlImportError(
                "keybag map and candidate payload graph do not correspond"
            )
        user_candidates = [
            candidate
            for candidate, source in mapping.items()
            if source.name == "user.kb"
        ]
        if not user_candidates:
            raise AppleControlImportError("keybag archive has no user.kb view")
        if any(candidate not in direct for candidate in user_candidates):
            raise AppleControlImportError("user.kb candidate is not a direct file")
        payloads = [direct[candidate] for candidate in user_candidates]
        first = payloads[0]
        if (
            not 0 < len(first) <= MAX_SAVED_KEYBAG_SIZE
            or any(payload != first for payload in payloads[1:])
        ):
            raise AppleControlImportError("user.kb views are empty, oversized, or distinct")
        return KeybagSelection(
            bytearray(first),
            hashlib.sha256(first).hexdigest(),
            archive_digest,
            len(user_candidates),
            len(mapping),
        )
    finally:
        raw[:] = b"\0" * len(raw)


def _normalized_catacomb_archive(
    components: dict[str, bytes], metadata: dict[str, tarfile.TarInfo]
) -> bytearray:
    listing = bytearray()
    for name in sorted(components):
        member = metadata[name]
        listing.extend(
            (
                f"{stat.filemode(stat.S_IFREG | member.mode)} root:wheel "
                f"{member.size} {int(member.mtime)} {member.name}\n"
            ).encode("utf-8")
        )
    output = io.BytesIO()
    with gzip.GzipFile(fileobj=output, mode="wb", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w") as archive:
            for name, data in sorted(components.items()):
                info = tarfile.TarInfo(f"capture/{name}")
                info.size = len(data)
                info.mode = metadata[name].mode
                info.uid = 0
                info.gid = 0
                info.uname = "root"
                info.gname = "wheel"
                info.mtime = 0
                archive.addfile(info, io.BytesIO(data))
            info = tarfile.TarInfo("capture/source-stat.txt")
            info.size = len(listing)
            info.mode = 0o600
            info.uid = 0
            info.gid = 0
            info.uname = "root"
            info.gname = "wheel"
            info.mtime = 0
            archive.addfile(info, io.BytesIO(listing))
    listing[:] = b"\0" * len(listing)
    return bytearray(output.getvalue())


def read_catacomb_control_archive(path: Path, apple_uid: int) -> CatacombSelection:
    """Validate the direct system-Catacomb tar and normalize its metadata."""

    if not isinstance(path, Path) or not path.is_absolute():
        raise AppleControlImportError("Catacomb archive path must be absolute")
    try:
        t2_user_mapping._unsigned(apple_uid, "Apple UID", minimum=10)
    except t2_user_mapping.UserMappingError as error:
        raise AppleControlImportError(str(error)) from error
    expected = {
        "master.cat",
        "biolockout.cat",
        f"user_{apple_uid:08x}.cat",
    }
    raw = _private_file(path, MAX_ARCHIVE_SIZE)
    capture_digest = hashlib.sha256(raw).hexdigest()
    components: dict[str, bytes] = {}
    metadata: dict[str, tarfile.TarInfo] = {}
    member_count = 0
    total_size = 0
    try:
        try:
            archive = tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz")
        except (OSError, tarfile.TarError) as error:
            raise AppleControlImportError(
                "Catacomb control archive is not valid gzip tar"
            ) from error
        with archive:
            for member in archive.getmembers():
                member_count += 1
                if member_count > MAX_ARCHIVE_MEMBERS:
                    raise AppleControlImportError(
                        "Catacomb control archive has too many members"
                    )
                member_path = _safe_member_name(member.name)
                if not (member.isdir() or member.isfile()):
                    raise AppleControlImportError(
                        "Catacomb control archive has unsafe member type"
                    )
                if member.size < 0 or member.size > MAX_MEMBER_SIZE:
                    raise AppleControlImportError(
                        "Catacomb control member size is unsafe"
                    )
                total_size += member.size
                if total_size > MAX_ARCHIVE_SIZE:
                    raise AppleControlImportError(
                        "Catacomb control archive expands beyond policy"
                    )
                if not member.isfile():
                    continue
                name = member_path.name
                if (
                    name not in expected
                    or len(member_path.parts) < 3
                    or member_path.parts[:2] != ("Library", "Catacomb")
                    or name in components
                    or member.uid != 0
                    or member.gid != 0
                    or member.mode & 0o133
                    or not 0 < member.size <= MAX_MEMBER_SIZE
                ):
                    raise AppleControlImportError(
                        "Catacomb control component metadata is unsafe"
                    )
                stream = archive.extractfile(member)
                if stream is None:
                    raise AppleControlImportError(
                        "Catacomb control component is unreadable"
                    )
                data = stream.read(MAX_MEMBER_SIZE + 1)
                if len(data) != member.size:
                    raise AppleControlImportError(
                        "Catacomb control component changed length"
                    )
                components[name] = data
                metadata[name] = member
        if set(components) != expected:
            raise AppleControlImportError(
                "Catacomb control component set is incomplete"
            )

        user_name = f"user_{apple_uid:08x}.cat"
        user = t2_catacomb_codec.decode_user_catacomb(
            components[user_name], apple_uid
        )
        master = t2_catacomb_codec.decode_master_catacomb(
            components["master.cat"]
        )
        biolockout = t2_catacomb_codec.decode_biolockout_catacomb(
            components["biolockout.cat"]
        )
        user_oracle = t2_catacomb_oracle.read_user(
            components[user_name], apple_uid
        )
        master_oracle = t2_catacomb_oracle.read_master(components["master.cat"])
        biolockout_oracle = t2_catacomb_oracle.read_biolockout(
            components["biolockout.cat"]
        )
        if (
            user_oracle["account_uuid"] != user.account_uuid
            or user_oracle["keybag_uuid"] != user.keybag_uuid
            or user_oracle["identities"]
            != [dataclasses.asdict(identity) for identity in user.identities]
            or master_oracle["enrollment_count"] != master.enrollment_count
            or master_oracle["secure_sha256"]
            != hashlib.sha256(master.secure_data).hexdigest()
            or biolockout_oracle["secure_sha256"]
            != hashlib.sha256(biolockout.secure_data).hexdigest()
        ):
            raise AppleControlImportError(
                "Catacomb codec and independent oracle disagree"
            )
        normalized = _normalized_catacomb_archive(components, metadata)
        return CatacombSelection(
            normalized_archive=normalized,
            capture_sha256=capture_digest,
            normalized_sha256=hashlib.sha256(normalized).hexdigest(),
            account_uuid=user.account_uuid,
            bag_uuid=user.keybag_uuid,
            component_sha256={
                name: hashlib.sha256(data).hexdigest()
                for name, data in components.items()
            },
            identity_count=len(user.identities),
        )
    except (t2_catacomb_codec.CatacombCodecError, t2_catacomb_oracle.OracleError) as error:
        raise AppleControlImportError("Catacomb control component is invalid") from error
    finally:
        raw[:] = b"\0" * len(raw)


def _canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def _operation_id(intent: dict[str, Any]) -> str:
    digest = hashlib.sha256(b"t2-apple-control-import-v1\0" + _canonical_json(intent))
    return str(uuid.UUID(bytes=digest.digest()[:16], version=5))


def build_plan(
    *,
    keybag_archive: Path,
    catacomb_archive: Path,
    linux_uid: int,
    linux_account_generation: str,
    apple_uid: int,
) -> tuple[OracleImportPlan, KeybagSelection, CatacombSelection]:
    try:
        t2_user_mapping._unsigned(linux_uid, "Linux UID", minimum=1)
        t2_user_mapping._unsigned(apple_uid, "Apple UID", minimum=10)
        t2_user_mapping._sha256(
            linux_account_generation, "Linux account generation"
        )
    except t2_user_mapping.UserMappingError as error:
        raise AppleControlImportError(str(error)) from error
    selection = read_keybag_archive(keybag_archive)
    catacomb: CatacombSelection | None = None
    try:
        catacomb = read_catacomb_control_archive(catacomb_archive, apple_uid)
        if not 1 <= catacomb.identity_count <= 5:
            raise AppleControlImportError(
                "Catacomb control archive has an invalid identity count"
            )
        intent = {
            "schema_version": 1,
            "origin": ORIGIN,
            "linux_uid": linux_uid,
            "linux_account_generation": linux_account_generation,
            "apple_uid": apple_uid,
            "account_uuid": catacomb.account_uuid,
            "bag_uuid": catacomb.bag_uuid,
            "keybag_sha256": selection.saved_keybag_sha256,
            "keybag_archive_sha256": selection.archive_sha256,
            "catacomb_capture_sha256": catacomb.capture_sha256,
            "catacomb_backup_sha256": catacomb.normalized_sha256,
            "catacomb_component_sha256": catacomb.component_sha256,
            "identity_count": catacomb.identity_count,
            "keybag_source_view_count": selection.source_view_count,
            "mapped_candidate_count": selection.mapped_candidate_count,
        }
        plan = OracleImportPlan(
            linux_uid=linux_uid,
            linux_account_generation=linux_account_generation,
            apple_uid=apple_uid,
            account_uuid=catacomb.account_uuid,
            bag_uuid=catacomb.bag_uuid,
            keybag_sha256=selection.saved_keybag_sha256,
            keybag_archive_sha256=selection.archive_sha256,
            catacomb_capture_sha256=catacomb.capture_sha256,
            catacomb_backup_sha256=catacomb.normalized_sha256,
            catacomb_component_sha256=catacomb.component_sha256,
            identity_count=catacomb.identity_count,
            keybag_source_view_count=selection.source_view_count,
            mapped_candidate_count=selection.mapped_candidate_count,
            operation_id=_operation_id(intent),
        )
        return plan, selection, catacomb
    except BaseException:
        selection.wipe()
        if catacomb is not None:
            catacomb.wipe()
        raise


def _private_directory(path: Path, *, create: bool) -> None:
    created = False
    if create:
        try:
            path.mkdir(mode=0o700)
            created = True
        except FileExistsError:
            pass
    try:
        info = path.stat(follow_symlinks=False)
    except OSError as error:
        raise AppleControlImportError("oracle import directory is unavailable") from error
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o077
    ):
        raise AppleControlImportError(
            "oracle import directory is not private and caller-owned"
        )
    if created:
        _sync_directory(path.parent)


def _sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_exclusive_or_equal(path: Path, data: bytes | bytearray) -> None:
    payload = bytes(data)
    if os.path.lexists(path):
        existing = _private_file(path, max(len(payload), 1))
        try:
            if existing != payload:
                raise AppleControlImportError("existing oracle import file differs")
        finally:
            existing[:] = b"\0" * len(existing)
        return
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    complete = False
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise AppleControlImportError("oracle import write made no progress")
            offset += written
        os.fsync(descriptor)
        complete = True
    finally:
        os.close(descriptor)
        if not complete and os.path.lexists(path):
            path.unlink()
    _sync_directory(path.parent)


def _copy_exclusive_or_equal(
    source: Path, destination: Path, expected_sha256: str
) -> None:
    data = _private_file(source, MAX_ARCHIVE_SIZE)
    try:
        if hashlib.sha256(data).hexdigest() != expected_sha256:
            raise AppleControlImportError("control archive digest changed before copy")
        _write_exclusive_or_equal(destination, data)
    finally:
        data[:] = b"\0" * len(data)


def _intent(plan: OracleImportPlan) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "origin": ORIGIN,
        "operation_id": plan.operation_id,
        "linux_uid": plan.linux_uid,
        "linux_account_generation": plan.linux_account_generation,
        "apple_uid": plan.apple_uid,
        "account_uuid": plan.account_uuid,
        "bag_uuid": plan.bag_uuid,
        "keybag_sha256": plan.keybag_sha256,
        "keybag_archive_sha256": plan.keybag_archive_sha256,
        "catacomb_capture_sha256": plan.catacomb_capture_sha256,
        "catacomb_backup_sha256": plan.catacomb_backup_sha256,
        "catacomb_component_sha256": plan.catacomb_component_sha256,
        "identity_count": plan.identity_count,
        "keybag_source_view_count": plan.keybag_source_view_count,
        "mapped_candidate_count": plan.mapped_candidate_count,
    }


def import_control_archives(
    *,
    keybag_archive: Path,
    catacomb_archive: Path,
    linux_uid: int,
    linux_account_generation: str,
    apple_uid: int,
    state_root: Path = STATE_ROOT,
) -> tuple[OracleImportPlan, dict[str, object]]:
    """Atomically converge one imported control generation with mapping disabled."""

    if not isinstance(state_root, Path) or not state_root.is_absolute():
        raise AppleControlImportError("oracle import state root is invalid")
    plan, selection, catacomb = build_plan(
        keybag_archive=keybag_archive,
        catacomb_archive=catacomb_archive,
        linux_uid=linux_uid,
        linux_account_generation=linux_account_generation,
        apple_uid=apple_uid,
    )
    try:
        _private_directory(state_root, create=False)
        backups = state_root / "backups"
        oracle = state_root / "oracle"
        users = state_root / "users"
        user_root = users / str(linux_uid)
        for directory in (backups, oracle, users, user_root):
            _private_directory(directory, create=True)
        intent = _intent(plan)
        _write_exclusive_or_equal(
            oracle / "apple-control-import-intent.json", _canonical_json(intent)
        )
        catacomb_capture = (
            oracle / f"{plan.catacomb_capture_sha256}.catacomb.tar.gz"
        )
        catacomb_backup = backups / f"{plan.catacomb_backup_sha256}.tar.gz"
        keybag_backup = oracle / f"{plan.keybag_archive_sha256}.keybags.tar.gz"
        _copy_exclusive_or_equal(
            catacomb_archive, catacomb_capture, plan.catacomb_capture_sha256
        )
        _write_exclusive_or_equal(catacomb_backup, catacomb.normalized_archive)
        _copy_exclusive_or_equal(
            keybag_archive, keybag_backup, plan.keybag_archive_sha256
        )
        keybag_path = user_root / "user.kb"
        _write_exclusive_or_equal(keybag_path, selection.saved_keybag)
        host, store = t2_catacomb_local.provision_from_backup(
            catacomb_backup, state_root / "catacomb", apple_uid
        )
        if (
            host["account_uuid"] != plan.account_uuid
            or host["bag_uuid"] != plan.bag_uuid
            or {
                item["name"]: item["sha256"]
                for item in host["host_components"]
            }
            != plan.catacomb_component_sha256
            or len(store.read_committed_components())
            != len(plan.catacomb_component_sha256)
        ):
            raise AppleControlImportError("committed Catacomb no longer matches plan")
        mapping_writer = t2_user_mapping_store.InitialUserMappingStore(
            path=state_root / "users.json",
            operation_id=plan.operation_id,
            linux_uid=linux_uid,
            linux_account_generation=linux_account_generation,
            apple_uid=apple_uid,
            keybag_path=keybag_path,
        )
        mapping_generation = mapping_writer.commit(
            account_uuid=plan.account_uuid,
            bag_uuid=plan.bag_uuid,
            keybag_sha256=plan.keybag_sha256,
        )
        complete = {
            **intent,
            "mapping_generation": mapping_generation,
            "mapping_enabled": False,
            "sep_keybag_uuid_verified": False,
            "import_complete": True,
        }
        _write_exclusive_or_equal(
            user_root / "apple-control-import.json", _canonical_json(complete)
        )
        return plan, plan.public_summary()
    except (
        OSError,
        t2_catacomb_local.LocalCatacombError,
        t2_user_mapping_store.UserMappingStoreError,
    ) as error:
        raise AppleControlImportError("oracle import transaction failed") from error
    finally:
        selection.wipe()
        catacomb.wipe()
