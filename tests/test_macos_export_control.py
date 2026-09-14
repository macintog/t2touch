#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Focused hardware-free checks for the macOS export wrapper boundary."""

import io
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
WRAPPER = ROOT / "tools/macos/macos-export-apple-control.sh"


def write_archive(path: Path, members: dict[str, bytes]) -> None:
    with tarfile.open(path, "w:gz") as archive:
        for name, payload in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            info.mode = 0o600
            archive.addfile(info, io.BytesIO(payload))


def write_executable(path: Path, body: str) -> None:
    path.write_text(body, encoding="utf-8")
    path.chmod(0o755)


class MacOSExportControlTests(unittest.TestCase):
    def run_fixture(
        self,
        keybag_members: dict[str, bytes],
        catacomb_members: dict[str, bytes],
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            fixture = Path(directory)
            wrapper = fixture / WRAPPER.name
            shutil.copy2(WRAPPER, wrapper)

            for helper in (
                "macos-export-keybags.sh",
                "macos-export-touchid-catacomb.sh",
            ):
                write_executable(fixture / helper, "#!/bin/sh\nexit 0\n")

            write_archive(fixture / "t2-keybags.tar.gz", keybag_members)
            write_archive(
                fixture / "t2-touchid-catacomb.tar.gz",
                catacomb_members,
            )

            mock_bin = fixture / "bin"
            mock_bin.mkdir()
            write_executable(mock_bin / "uname", "#!/bin/sh\necho Darwin\n")
            write_executable(
                mock_bin / "date",
                "#!/bin/sh\n"
                "if [ \"${1-}\" = +%s ]; then echo 100; else exec /usr/bin/date \"$@\"; fi\n",
            )
            write_executable(
                mock_bin / "stat",
                "#!/bin/sh\n"
                "if [ \"${1-}\" = -f ] && [ \"${2-}\" = %m ]; then "
                "echo 100; else exec /usr/bin/stat \"$@\"; fi\n",
            )
            write_executable(mock_bin / "sync", "#!/bin/sh\nexit 0\n")

            environment = os.environ.copy()
            environment["PATH"] = f"{mock_bin}:{environment['PATH']}"
            return subprocess.run(
                [str(wrapper)],
                check=False,
                capture_output=True,
                text=True,
                env=environment,
            )

    def test_wrapper_rejects_structurally_empty_archives(self):
        valid_keybag = {
            "state/path-map.txt": b"candidate-0001\t/private/example/user.kb\n",
            "state/candidate-0001": b"synthetic-keybag",
        }
        valid_catacomb = {
            "Library/Catacomb/example/user_00000001.cat": b"synthetic-cat",
        }

        fixtures = (
            (valid_keybag, valid_catacomb, True),
            ({"state/candidate-0001": b"payload"}, valid_catacomb, False),
            (
                {"state/path-map.txt": b"candidate-0001\t/private/example/user.kb\n"},
                valid_catacomb,
                False,
            ),
            (valid_keybag, {"Library/Catacomb/example/README": b"none"}, False),
        )

        for keybag, catacomb, accepted in fixtures:
            with self.subTest(accepted=accepted, keybag=tuple(keybag), catacomb=tuple(catacomb)):
                result = self.run_fixture(keybag, catacomb)
                self.assertEqual(result.returncode == 0, accepted, result.stderr)


if __name__ == "__main__":
    unittest.main()
