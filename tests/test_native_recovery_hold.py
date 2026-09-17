# SPDX-License-Identifier: GPL-2.0-only
"""Recovery hold survives process/boot boundaries and fails closed on setup errors."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / 'tools/installer-services.sh'
OWNERS = ('t2-native-first-run', 't2-biometric-ready', 't2-touchid-post-reboot',
          't2-touchid-adaptive-sync', 'fprintd')


class NativeRecoveryHoldTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root / 'state'
        self.units = self.root / 'units'
        self.calls = self.root / 'calls'

    def run_helper(self, action, fail=''):
        return subprocess.run(['bash', '-c', '''
set -eu
source "$1"
state=$2
units=$3
calls=$4
fail=$5
systemctl() {
  printf '%s\\n' "$*" >>"$calls"
  if [[ $1 == daemon-reload || $1 == stop ]]; then
    # The hold must already be durable before touching the running services.
    test -f "$state/native-recovery-hold" || return 99
  fi
  [[ "$*" != "$fail" ]]
}
"$6" "$state" "$units"
''', 'fixture', str(HELPER), str(self.state), str(self.units), str(self.calls),
            fail, action], capture_output=True, text=True)

    def test_hold_survives_new_process_and_preserves_private_state(self):
        self.state.mkdir()
        journal = self.state / 'native-provisioning.jsonl'
        journal.write_text('ambiguous journal fixture\n')
        result = self.run_helper('hold_native_recovery')
        self.assertEqual(result.returncode, 0, result.stderr)
        marker = self.state / 'native-recovery-hold'
        self.assertEqual(marker.stat().st_mode & 0o777, 0o600)
        for owner in OWNERS:
            guard = self.units / f'{owner}.service.d/90-native-recovery.conf'
            self.assertEqual(guard.read_text(),
                             f'[Unit]\nConditionPathExists=!{marker}\n')
            # A fresh process still sees the persisted condition as false.
            observed = subprocess.run(['test', '!', '-e', str(marker)])
            self.assertNotEqual(observed.returncode, 0)
        self.assertIn('stop fprintd.service', self.calls.read_text())
        self.assertNotIn('start ', self.calls.read_text())
        self.assertEqual(journal.read_text(), 'ambiguous journal fixture\n')
        result = self.run_helper('resume_native_recovery')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(marker.exists())
        self.assertEqual(journal.read_text(), 'ambiguous journal fixture\n')
        self.assertEqual(self.run_helper('resume_native_recovery').returncode, 0)

    def test_reload_or_stop_failure_keeps_hold(self):
        for failure in ('daemon-reload', 'stop fprintd.service'):
            with self.subTest(failure=failure):
                result = self.run_helper('hold_native_recovery', fail=failure)
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue((self.state / 'native-recovery-hold').exists())

    def test_repeated_preparation_retains_hold(self):
        for _ in range(2):
            result = self.run_helper('hold_native_recovery')
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.state / 'native-recovery-hold').exists())

    def test_installer_sets_hold_before_writes_and_resumes_only_normal_path(self):
        text = (ROOT / 'install.sh').read_text()
        self.assertLess(text.index('hold_native_recovery ||'),
                        text.index('  native_mapping='))
        self.assertLess(text.index('hold_native_recovery ||'),
                        text.index('systemctl reload dbus.service'))
        recovery = text.index('    /usr/local/sbin/t2-sep-transport-load --prepare-native-recovery')
        completed = text.index('    if (( validated_recovery_upgrade ));', recovery - 1000)
        preserve = text.index('      /usr/local/sbin/t2-sep-transport-load\n', completed)
        self.assertLess(completed, preserve)
        self.assertLess(preserve, recovery)
        resume = text.index('  resume_native_recovery ||')
        self.assertIn('exit 0', text[recovery:resume])
        self.assertLess(resume, text.index('  start_linux_native_touchid_chain ||'))
