# SPDX-License-Identifier: GPL-2.0-only
"""Recovery hold survives process/boot boundaries and fails closed on setup errors."""
from pathlib import Path
import sys
import subprocess
import runpy
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / 'tools/installer-services.sh'
OWNERS = ('t2-native-first-run', 't2-biometric-ready', 't2-touchid-post-reboot',
          't2-touchid-adaptive-sync', 'fprintd')
sys.path.insert(0, str(ROOT / 'src'))

import test_native_state_recovery as recovery_fixtures
import t2_mutation_registry
import t2_native_state_recovery

check_resume = runpy.run_path(str(ROOT / 'tools/check-native-recovery-resume.py'))['check']


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

    def test_unfinished_recovery_cannot_release_hold(self):
        self.assertEqual(self.run_helper('hold_native_recovery').returncode, 0)
        mutations = self.state / 'mutations'
        mutations.mkdir(mode=0o700)
        path, _history, _user, _components = recovery_fixtures.NativeStateRecoveryTests().create(mutations)
        before = path.read_bytes()
        result = self.run_helper('resume_native_recovery')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Native-state recovery is unfinished', result.stderr)
        self.assertTrue((self.state / 'native-recovery-hold').exists())
        self.assertEqual(path.read_bytes(), before)
        self.assertNotIn('start ', self.calls.read_text())

    def test_pending_recovery_reestablishes_missing_hold(self):
        self.state.mkdir()
        mutations = self.state / 'mutations'
        mutations.mkdir(mode=0o700)
        recovery_fixtures.NativeStateRecoveryTests().create(mutations)
        result = self.run_helper('resume_native_recovery')
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue((self.state / 'native-recovery-hold').exists())

    def test_cold_restart_reports_physical_boundary_without_changing_journal(self):
        self.assertEqual(self.run_helper('hold_native_recovery').returncode, 0)
        mutations = self.state / 'mutations'
        mutations.mkdir(mode=0o700)
        fixture = recovery_fixtures.NativeStateRecoveryTests()
        path, history, _user, _components = fixture.create(mutations)
        fixture.advance_to_reprepared_rejection(path)
        t2_native_state_recovery._append(path, history.operation_id,
            'COLD_RESTART_PREPARED', {
                'source_linux_boot_uuid': recovery_fixtures.BOOT,
                'intermediate_master_sha256': '1' * 64,
                'candidate_master_sha256': '2' * 64,
                'identity_count': 1,
            })
        before = path.read_bytes()
        result = self.run_helper('resume_native_recovery')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('cold-restart-prepared', result.stderr)
        self.assertIn('Linux reboot alone may leave T2 warm', result.stderr)
        self.assertEqual(path.read_bytes(), before)
        self.assertTrue((self.state / 'native-recovery-hold').exists())

    def test_rejected_load_keeps_hold_without_suggesting_another_retry(self):
        self.assertEqual(self.run_helper('hold_native_recovery').returncode, 0)
        mutations = self.state / 'mutations'
        mutations.mkdir(mode=0o700)
        fixture = recovery_fixtures.NativeStateRecoveryTests()
        path, _history, _user, _components = fixture.create(mutations)
        fixture.advance_to_canonical_user_rejection(path, direct=True)
        before = path.read_bytes()
        result = self.run_helper('resume_native_recovery')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Do not repeat recovery', result.stderr)
        self.assertNotIn('Resume:', result.stderr)
        self.assertTrue((self.state / 'native-recovery-hold').exists())
        self.assertEqual(path.read_bytes(), before)
        self.assertNotIn('start ', self.calls.read_text())

    def test_completed_recovery_and_other_owners_can_resume(self):
        self.state.mkdir()
        (self.state / 'mutations').mkdir(mode=0o700)
        entries = (
            t2_mutation_registry.MutationEntry(
                t2_native_state_recovery.KIND, 'complete', False, False),
            t2_mutation_registry.MutationEntry('enroll', 'reconciled', True, True),
        )
        # Other owners retain their own normal post-reboot reconciliation gate.
        with patch.object(t2_mutation_registry, 'scan', return_value=entries):
            self.assertTrue(check_resume(self.state))

    def test_invalid_journal_or_dangling_directory_keeps_hold(self):
        for dangling in (False, True):
            with self.subTest(dangling=dangling):
                self.assertEqual(self.run_helper('hold_native_recovery').returncode, 0)
                mutations = self.state / 'mutations'
                if dangling:
                    mutations.symlink_to(self.state / 'missing')
                else:
                    mutations.mkdir(mode=0o700)
                    (mutations / 'invalid.jsonl').write_text('invalid')
                result = self.run_helper('resume_native_recovery')
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('Cannot validate mutation journals', result.stderr)
                self.assertTrue((self.state / 'native-recovery-hold').exists())
                if dangling:
                    mutations.unlink()
                else:
                    (mutations / 'invalid.jsonl').unlink()
                    mutations.rmdir()

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
