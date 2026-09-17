# SPDX-License-Identifier: GPL-2.0-only
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class PamRollbackTests(unittest.TestCase):
    def run_case(self, *, restored=False, conflict=False, system_conflict=False, check=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            pam = root / 'pam'
            backups = root / 'backups'
            pam.mkdir()
            backups.mkdir()
            for name in ('sudo', 'polkit-1', 'system-auth'):
                (backups / f'{name}.original').write_text('original\n')
                (backups / f'{name}.installed').write_text('managed\n')
                (pam / name).write_text('original\n' if restored else 'managed\n')
            if conflict:
                (pam / 'polkit-1').write_text('customized\n')
            if system_conflict:
                (pam / 'system-auth').write_text('customized\n')
            elif not restored:
                (pam / 'system-auth').write_text('original\nauth [success=ignore default=1] pam_succeed_if.so quiet service = sudo\nauth optional pam_exec.so quiet seteuid /usr/local/sbin/t2-pam-unlock\n')
            before = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob('*') if p.is_file()}
            source = (ROOT / 'tools/rollback-pam.sh').read_text()
            source = source.replace('[[ $EUID -eq 0 ]] || { echo "Run with sudo." >&2; exit 1; }', ':')
            source = source.replace('/var/lib/t2-touchid/pam-backups', str(backups)).replace('/etc/pam.d', str(pam))
            source = source.replace('/run/lock/t2-touchid-pam.lock', str(root / 'lock')).replace('/etc/security/t2-touchid-sudo-prompt', str(root / 'prompt'))
            command = 'install() { command install -m 0644 "${@: -2}"; }; chown() { :; };\n' + source
            result = subprocess.run(['bash', '-c', command, 'fixture', *(['--check'] if check else [])], text=True, capture_output=True)
            if conflict or system_conflict:
                self.assertNotEqual(result.returncode, 0)
            else:
                self.assertEqual(result.returncode, 0, result.stderr)
            if conflict or system_conflict or check:
                after = {str(p.relative_to(root)): p.read_bytes() for p in root.rglob('*') if p.is_file() and p.name != 'lock'}
                self.assertEqual(before, after)
            else:
                for name in ('sudo', 'polkit-1', 'system-auth'):
                    self.assertEqual((pam / name).read_text(), 'original\n')
                    self.assertFalse((backups / f'{name}.original').exists())

    def test_restores_managed_stacks(self):
        self.run_case()

    def test_already_restored_original_is_safe_to_resume(self):
        self.run_case(restored=True)

    def test_later_stack_conflict_does_not_partially_restore(self):
        self.run_case(conflict=True)

    def test_system_auth_conflict_does_not_partially_restore(self):
        self.run_case(system_conflict=True)

    def test_preflight_is_read_only(self):
        self.run_case(check=True)

    def test_uninstall_checks_pam_before_services_and_modules(self):
        source = (ROOT / 'uninstall.sh').read_text()
        pam = source.index('"$source_dir/tools/rollback-pam.sh"')
        self.assertLess(pam, source.index('systemctl disable --now'))
        self.assertLess(pam, source.index('dkms remove'))


if __name__ == '__main__':
    unittest.main()
