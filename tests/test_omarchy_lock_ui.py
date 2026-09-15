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

if __name__ == '__main__':
    unittest.main()
