#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Hardware-free checks for kernel transport audit remediations."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "src/t2_sep_transport.c").read_text(encoding="utf-8")
DKMS = (ROOT / "dkms.conf").read_text(encoding="utf-8")


class SepTransportAssetTests(unittest.TestCase):
    def test_probe_does_not_free_dma_after_lost_ool_reply(self):
        self.assertIn("bool *sent", SOURCE)
        self.assertIn("OOL input registration reply lost; reboot before retry", SOURCE)
        self.assertIn("sep->acm_ool_in = NULL", SOURCE)
        self.assertIn("sep->acm_ool_out = NULL", SOURCE)

    def test_unbind_marks_device_dead_and_krefs_sep(self):
        self.assertIn("struct kref kref", SOURCE)
        self.assertIn("WRITE_ONCE(sep->removed, true)", SOURCE)
        self.assertIn("return -ENODEV", SOURCE)
        self.assertIn("pcim_iomap_region", SOURCE)
        self.assertNotIn("pcim_iomap_regions", SOURCE)

    def test_module_params_are_copied_under_the_param_lock(self):
        stamp = SOURCE.split("t2_aks_stamp_verify_platform_data", 1)[1].split(
            "static unsigned int t2_sep_poll_timeout_us", 1
        )[0]
        self.assertIn("kernel_param_lock(THIS_MODULE)", stamp)
        self.assertIn("memcpy(cdhash_hex, aks_platform_cdhash, sizeof(cdhash_hex))", stamp)
        self.assertIn("kernel_param_unlock(THIS_MODULE)", stamp)
        self.assertNotIn("hex2bin(cdhash, aks_platform_cdhash", stamp)

    def test_reply_recorders_pass_real_request_length(self):
        self.assertIn(
            "t2_aks_unload_keybag_request_matches(\n"
            "\t\t\t   request, request_length, sep->aks_provisioning_session",
            SOURCE,
        )
        self.assertIn(
            "t2_aks_unload_keybag_request_matches(\n"
            "\t\t\t   request, request_length, sep->aks_runtime_session",
            SOURCE,
        )
        self.assertIn(
            "const u8 *request, size_t request_length,\n"
            "\tconst u8 *response, size_t response_length)",
            SOURCE,
        )

    def test_release_uses_a_shorter_mailbox_skip_limit(self):
        self.assertIn("sep->tight_mailbox = true", SOURCE)
        self.assertIn("sep->tight_mailbox ? 4 : 32", SOURCE)
        self.assertIn("T2_SEP_RELEASE_TIMEOUT_US", SOURCE)
        self.assertIn("sep->io_deadline_active = true", SOURCE)

    def test_dkms_documents_the_kernel_floor(self):
        self.assertIn("Linux >= 6.12", DKMS)
        self.assertIn("BUILD_EXCLUSIVE_KERNEL=", DKMS)
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("Linux 6.12 or newer headers", readme)


if __name__ == "__main__":
    unittest.main()
