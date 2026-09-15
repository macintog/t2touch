"""Exercise device layouts without relying on the host's GPUs or card numbers."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'src/t2-hyprland-drm-devices.sh'

class DeviceSelectionTests(unittest.TestCase):
    def select(self, cards, override=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            drm = root / 'sys/class/drm'
            dev = root / 'dev/dri'
            drm.mkdir(parents=True)
            dev.mkdir(parents=True)
            for name, driver, internal in cards:
                device = drm / name / 'device'
                device.mkdir(parents=True)
                target = root / 'drivers' / driver
                target.mkdir(parents=True, exist_ok=True)
                (device / 'driver').symlink_to(target)
                (dev / name).touch()
                if internal:
                    connector = drm / (name + '-eDP-1')
                    connector.mkdir()
                    (connector / 'status').write_text('connected\n')
            script = SCRIPT.read_text().replace('/sys/class/drm', str(drm)).replace('/dev/dri', str(dev))
            # Regular fixture files represent DRM character devices; driver
            # links and connector discovery use the real filesystem operations.
            script = script.replace('[ -c ', '[ -f ')
            env = os.environ.copy()
            env.pop('AQ_DRM_DEVICES', None)
            if override is not None:
                env['AQ_DRM_DEVICES'] = override
            result = subprocess.run(['sh'], input=script + '\nprintf "%s" "${AQ_DRM_DEVICES:-}"\n', text=True, env=env, capture_output=True, check=True)
            return result.stdout.replace(str(dev), '/dev/dri')

    def test_excludes_fallback_with_renumbered_native_gpu(self):
        self.assertEqual(self.select([('card8','simple-framebuffer',False),('card12','i915',True)]), '/dev/dri/card12')

    def test_native_only_keeps_compositor_default(self):
        self.assertEqual(self.select([('card4','amdgpu',True)]), '')

    def test_fallback_only_keeps_working_default(self):
        self.assertEqual(self.select([('card3','simple-framebuffer',False)]), '')

    def test_preserves_explicit_operator_devices(self):
        self.assertEqual(self.select([('card0','simpledrm',False),('card1','i915',True)], '/custom/gpu'), '/custom/gpu')

    def test_retains_external_native_gpu_after_internal_gpu(self):
        self.assertEqual(self.select([('card0','amdgpu',False),('card1','simpledrm',False),('card9','i915',True)]), '/dev/dri/card9:/dev/dri/card0')

    def test_explicit_empty_override_keeps_compositor_default(self):
        self.assertEqual(self.select([('card0','simpledrm',False),('card1','i915',True)], ''), '')

    def test_no_devices_keeps_default(self):
        self.assertEqual(self.select([]), '')

if __name__ == '__main__':
    unittest.main()
