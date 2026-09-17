#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Hardware-free checks for the biometric readiness gate."""

from pathlib import Path
import os
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "src/t2-biometric-ready.sh"


class BiometricReadyAssetTests(unittest.TestCase):
    def test_unvalidated_port_is_not_persisted(self):
        script = HELPER.read_text(encoding="utf-8")
        self.assertIn('validate_port "$port" || exit 1', script)
        self.assertNotIn('[[ $validated == 1 ]] || validate_port "$port"\n', script)
        self.assertIn("trap 'rm -f -- \"$temporary_port_file\"' EXIT", script)

    def test_failed_helo_keeps_gate_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "t2-touchid.conf"
            config.write_text(
                "T2_TOUCHID_USER=test\n"
                "T2_TOUCHID_HOST=2001:db8::1\n"
                "T2_TOUCHID_INTERFACE=eth0\n"
                f"T2_TOUCHID_PROJECT_DIR={root}\n",
                encoding="utf-8",
            )
            src = root / "src"
            src.mkdir()
            probe = src / "bridge-xpc-probe.py"
            probe.write_text("import sys; raise SystemExit(1)\n", encoding="utf-8")
            discover = src / "discover-biometric-port.py"
            discover.write_text("print(54321)\n", encoding="utf-8")
            venv_python = root / ".venv" / "bin" / "python"
            venv_python.parent.mkdir(parents=True)
            venv_python.write_text("#!/usr/bin/env python3\nimport runpy, sys\nrunpy.run_path(sys.argv[1])\n", encoding="utf-8")
            venv_python.chmod(0o755)
            port_file = root / "biometric-port"
            flock = root / "flock"
            flock.write_text(
                "#!/usr/bin/env bash\n"
                "while [[ $# -gt 0 ]]; do\n"
                "  case $1 in\n"
                "    --exclusive|--no-fork) shift ;;\n"
                "    --timeout) shift 2 ;;\n"
                "    *) shift; break ;;\n"
                "  esac\n"
                "done\n"
                "exec \"$@\"\n",
                encoding="utf-8",
            )
            flock.chmod(0o755)
            script = HELPER.read_text(encoding="utf-8")
            script = script.replace("/etc/t2-touchid.conf", str(config))
            script = script.replace("/var/lib/t2-touchid/biometric-port", str(port_file))
            script = script.replace("/usr/bin/flock", str(flock))
            script = script.replace("deadline=$((SECONDS + 45))", "deadline=$((SECONDS + 2))")
            runner = root / "ready.sh"
            runner.write_text(script, encoding="utf-8")
            runner.chmod(0o755)
            completed = subprocess.run(
                ["bash", str(runner)],
                env={**os.environ, "PATH": f"{root}:/usr/bin:/bin"},
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(completed.returncode, 0, completed.stderr)
            self.assertFalse(port_file.exists())


if __name__ == "__main__":
    unittest.main()
