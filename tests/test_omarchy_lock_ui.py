import importlib.util
from pathlib import Path
import unittest

path = Path(__file__).resolve().parents[1] / 'tools/install-omarchy-lock-ui.py'
spec = importlib.util.spec_from_file_location('lock_ui', path)
ui = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ui)

SERVICE = '''  property bool fingerprintConfigured: false
    lockRequested = true
    armBlankTimer()
    fingerprintAuthenticating = true
    id: fingerprintPam
    config: "omarchy-lock-fingerprint"
        fingerprintConfigured: root.fingerprintConfigured
      fingerprintConfigured: root.fingerprintConfigured
grep -qi finger
'''
VIEW = '''  property bool fingerprintConfigured: false
    BorderSurface {
'''

class IntegrationTests(unittest.TestCase):
    def test_applies_once_and_uses_pam_message_without_translation_matching(self):
        service, view = ui.transform(SERVICE, VIEW)
        self.assertEqual(ui.transform(service, view), (service, view))
        self.assertIn('onPamMessage:', service)
        self.assertIn('!root.fingerprintWakeUsed', service)
        self.assertIn('root.fingerprintMessage = message', service)
        self.assertIn('Preparing fingerprint reader', view)
        self.assertNotIn('grep -qi finger', service)
        self.assertIn('Text.PlainText', view)

    def test_changed_source_is_not_partially_patched(self):
        with self.assertRaises(ValueError):
            ui.transform(SERVICE.replace('id: fingerprintPam', 'id: newPam'), VIEW)
        with self.assertRaises(ValueError):
            ui.transform(SERVICE, VIEW.replace('BorderSurface', 'NewSurface'))

    def test_polkit_shows_supplementary_prompt_without_guessing_readiness(self):
        original = '  property string currentSupplementary: ""\n    Rectangle {\n      width: Math.min(justificationText.implicitWidth'
        changed = ui.transform_polkit(original)
        self.assertIn('root.currentSupplementary || "Preparing fingerprint reader…"', changed)
        self.assertEqual(ui.transform_polkit(changed), changed)
        with self.assertRaises(ValueError):
            ui.transform_polkit(original.replace('justificationText', 'changedId'))

    def test_partial_install_is_not_overwritten(self):
        service, _ = ui.transform(SERVICE, VIEW)
        with self.assertRaises(ValueError):
            ui.transform(service, VIEW)

    def test_restore_rewrites_from_receipt(self):
        import hashlib
        import json
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'LockView.qml'
            patched = b'patched\n'
            target.write_bytes(patched)
            backup = Path(directory) / 'backup'
            backup.mkdir()
            original = backup / 'LockView.qml'
            original.write_text('original\n', encoding='utf-8')
            (backup / 'receipt.json').write_text(
                json.dumps({
                    'paths': [str(target)],
                    'installed_sha256': [hashlib.sha256(patched).hexdigest()],
                }) + '\n',
                encoding='utf-8',
            )
            ui.restore_from_receipt(backup)
            self.assertEqual(target.read_text(encoding='utf-8'), 'original\n')

    def test_restore_validates_all_backups_before_first_write(self):
        import hashlib
        import json
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as directory:
            service = Path(directory) / 'Service.qml'
            view = Path(directory) / 'LockView.qml'
            service.write_text('service-patched\n', encoding='utf-8')
            view.write_text('view-patched\n', encoding='utf-8')
            backup = Path(directory) / 'backup'
            backup.mkdir()
            (backup / 'Service.qml').write_text('service-original\n', encoding='utf-8')
            (backup / 'receipt.json').write_text(
                json.dumps({
                    'paths': [str(service), str(view)],
                    'installed_sha256': [
                        hashlib.sha256(b'service-patched\n').hexdigest(),
                        hashlib.sha256(b'view-patched\n').hexdigest(),
                    ],
                }) + '\n',
                encoding='utf-8',
            )
            with self.assertRaises(SystemExit):
                ui.restore_from_receipt(backup)
            self.assertEqual(service.read_text(encoding='utf-8'), 'service-patched\n')
            self.assertEqual(view.read_text(encoding='utf-8'), 'view-patched\n')

    def test_restore_refuses_when_current_hashes_differ(self):
        import hashlib
        import json
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'LockView.qml'
            target.write_text('later-omarchy-update\n', encoding='utf-8')
            backup = Path(directory) / 'backup'
            backup.mkdir()
            (backup / 'LockView.qml').write_text('original\n', encoding='utf-8')
            (backup / 'receipt.json').write_text(
                json.dumps({
                    'paths': [str(target)],
                    'installed_sha256': [
                        hashlib.sha256(b'patched\n').hexdigest()
                    ],
                }) + '\n',
                encoding='utf-8',
            )
            with self.assertRaises(SystemExit):
                ui.restore_from_receipt(backup)
            self.assertEqual(
                target.read_text(encoding='utf-8'), 'later-omarchy-update\n'
            )

    def test_restore_rolls_back_if_a_later_write_fails(self):
        import hashlib
        import json
        import tempfile
        from pathlib import Path
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as directory:
            service = Path(directory) / 'Service.qml'
            view = Path(directory) / 'LockView.qml'
            service.write_text('service-patched\n', encoding='utf-8')
            view.write_text('view-patched\n', encoding='utf-8')
            backup = Path(directory) / 'backup'
            backup.mkdir()
            (backup / 'Service.qml').write_text('service-original\n', encoding='utf-8')
            (backup / 'LockView.qml').write_text('view-original\n', encoding='utf-8')
            (backup / 'receipt.json').write_text(
                json.dumps({
                    'paths': [str(service), str(view)],
                    'installed_sha256': [
                        hashlib.sha256(b'service-patched\n').hexdigest(),
                        hashlib.sha256(b'view-patched\n').hexdigest(),
                    ],
                }) + '\n',
                encoding='utf-8',
            )
            real_write = ui.atomic_write
            calls = {'count': 0}

            def flaky(path, data, mode, owner=None):
                calls['count'] += 1
                if path == view and calls['count'] == 2:
                    raise OSError('simulated write failure')
                return real_write(path, data, mode, owner)

            with patch.object(ui, 'atomic_write', side_effect=flaky):
                with self.assertRaises(OSError):
                    ui.restore_from_receipt(backup)
            self.assertEqual(service.read_text(encoding='utf-8'), 'service-patched\n')
            self.assertEqual(view.read_text(encoding='utf-8'), 'view-patched\n')

if __name__ == '__main__':
    unittest.main()
