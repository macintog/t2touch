#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only

from pathlib import Path
import hashlib
from email.parser import BytesParser
import unittest
import os
import subprocess
import tempfile
import zipfile

from packaging.markers import default_environment
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name


ROOT = Path(__file__).resolve().parents[1]
WHEEL = ROOT / "vendor/python/pymobiledevice3-11.1.3-py3-none-any.whl"
WHEEL_SHA256 = "281fb1ff69751004bbc001ad304197b05cb64b51929f4e07cfb494bac6027e07"
SOURCE_COMMIT = "4fcfdd82ffcf30b6a11460b505fadb5579e7b2bb"


class ProvenanceLockTests(unittest.TestCase):
    def test_wheel_dependencies_are_locked_for_each_ci_python(self):
        with zipfile.ZipFile(WHEEL) as wheel:
            metadata_name = next(
                name for name in wheel.namelist() if name.endswith(".dist-info/METADATA")
            )
            metadata = BytesParser().parsebytes(wheel.read(metadata_name))
        requirements = [Requirement(value) for value in metadata.get_all("Requires-Dist", [])]
        lock = [
            Requirement(line.rstrip(" \\"))
            for line in (ROOT / "requirements-hashed.txt").read_text().splitlines()
            if line and not line.startswith(("#", " ", "\t"))
        ]
        for version in ("3.12", "3.14"):
            environment = {
                **default_environment(),
                "python_version": version,
                "python_full_version": f"{version}.0",
                "sys_platform": "linux",
                "platform_system": "Linux",
                "platform_machine": "x86_64",
                "extra": "",
            }
            active = {
                canonicalize_name(item.name): item
                for item in lock
                if item.marker is None or item.marker.evaluate(environment)
            }
            for requirement in requirements:
                if requirement.marker and not requirement.marker.evaluate(environment):
                    continue
                with self.subTest(python=version, requirement=str(requirement)):
                    name = canonicalize_name(requirement.name)
                    self.assertIn(name, active)
                    pins = list(active[name].specifier)
                    self.assertEqual(len(pins), 1)
                    self.assertEqual(pins[0].operator, "==")
                    self.assertIn(pins[0].version, requirement.specifier)

    def test_backend_bootstrap_precedes_runtime_and_failure_stops_install(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / "calls"
            python = root / "python"
            python.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$CALLS"\nexit "${FAIL_BOOTSTRAP:-0}"\n')
            python.chmod(0o755)
            for failure in (0, 7):
                log.unlink(missing_ok=True)
                result = subprocess.run(
                    [str(ROOT / "tools/install-python-deps.sh"), str(python)],
                    cwd=directory,
                    env={**os.environ, "CALLS": str(log), "FAIL_BOOTSTRAP": str(failure)},
                    check=False,
                )
                self.assertEqual(result.returncode, failure)
                calls = log.read_text().splitlines()
                self.assertEqual(len(calls), 1 if failure else 2)
                self.assertIn("--require-hashes --only-binary=:all:", calls[0])
                self.assertIn("requirements-build-hashed.txt", calls[0])
                if not failure:
                    self.assertIn("--require-hashes --no-build-isolation", calls[1])
                    self.assertIn("requirements-hashed.txt", calls[1])

    def test_hashed_lock_covers_the_full_venv(self):
        hashed = (ROOT / "requirements-hashed.txt").read_text(encoding="utf-8")
        installer = (ROOT / "install.sh").read_text(encoding="utf-8")
        provenance = (ROOT / "docs/PROVENANCE.md").read_text(encoding="utf-8")
        source = (ROOT / "vendor/python/SOURCE.txt").read_text(encoding="utf-8")

        self.assertIn("dbus-next==0.2.3", hashed)
        self.assertIn(
            "--hash=sha256:58948f9aff9db08316734c0be2a120f6dc502124d9642f55e90ac82ffb16a18b",
            hashed,
        )
        self.assertIn("cryptography==50.0.1", hashed)
        self.assertIn("construct==2.10.70", hashed)
        self.assertIn(
            "pymobiledevice3 @ file:vendor/python/pymobiledevice3-11.1.3-py3-none-any.whl",
            hashed,
        )
        self.assertIn(f"--hash=sha256:{WHEEL_SHA256}", hashed)
        self.assertIn("6d6da2f7e1f5815efaac7500bbf4ad2c353e1a786f9cf2e5edcc85734f3cbccc", hashed)
        self.assertNotIn("git+https://github.com/doronz88/pymobiledevice3.git", hashed)
        self.assertNotRegex(hashed, r"(?m)^pymobiledevice3==")

        requirement_lines = [
            line
            for line in hashed.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        self.assertGreaterEqual(len(requirement_lines), 2)
        current = []
        stanzas = []
        for line in requirement_lines:
            if current and not line.startswith((" ", "\t")):
                stanzas.append(current)
                current = [line]
            else:
                current.append(line)
        if current:
            stanzas.append(current)
        self.assertGreaterEqual(len(stanzas), 90)
        for stanza in stanzas:
            blob = "\n".join(stanza)
            self.assertIn("--hash=sha256:", blob, blob.splitlines()[0])

        self.assertIn("tools/install-python-deps.sh", installer)
        self.assertIn("requirements-hashed.txt", installer)
        self.assertIn("requirements-build-hashed.txt", installer)
        self.assertIn("vendor/python/pymobiledevice3-11.1.3-py3-none-any.whl", installer)
        self.assertNotIn(
            "git+https://github.com/doronz88/pymobiledevice3.git",
            installer,
        )
        self.assertEqual(installer.count("pip\" install"), 0)

        self.assertIn("--require-hashes", provenance)
        self.assertIn("no second unhashed", provenance)
        self.assertIn(SOURCE_COMMIT, provenance)
        self.assertIn(SOURCE_COMMIT, source)
        self.assertIn(WHEEL_SHA256, source)

        self.assertTrue(WHEEL.is_file(), WHEEL)
        self.assertEqual(hashlib.sha256(WHEEL.read_bytes()).hexdigest(), WHEEL_SHA256)


if __name__ == "__main__":
    unittest.main()
