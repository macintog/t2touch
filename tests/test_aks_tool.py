# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class AKSToolTests(unittest.TestCase):
    def test_recovery_open_passes_both_kernel_admission_layers(self) -> None:
        # Compile the actual dispatch and runtime preflight blocks. A mock of
        # userspace's exchange misses a kernel rejection before SEP dispatch.
        kernel = (ROOT / "src/t2_sep_transport.c").read_text()
        dispatch = kernel.split("\tif (operation == 0x03 &&", 1)[1].split(
            "\tif (operation == 0x04 &&", 1
        )[0]
        preflight = kernel.split("static int t2_aks_runtime_preflight_locked", 1)[1]
        load = preflight.split("\tcase 0x03:", 1)[1].split("\tcase 0x05:", 1)[0]
        harness = r'''
#include <assert.h>
#include <errno.h>
#include "t2_aks_protocol.h"
typedef uint8_t u8;
enum { T2_AKS_REPLACEMENT_PHASE_NONE = 0,
       T2_AKS_REPLACEMENT_PHASE_RECOVER = 3 };
struct owner {
    int aks_replacement_phase;
    uint64_t aks_replacement_session;
    uint8_t aks_replacement_new_uuid[16];
    bool aks_runtime_poisoned, aks_runtime_handle_active;
};
static int dispatch(struct owner *sep, u8 operation,
                    const u8 *request_body, size_t request_body_length) {
''' + "\tif (operation == 0x03 &&" + dispatch + r'''
    return 0;
}
static int preflight(struct owner *sep, const u8 *request, size_t request_length) {
''' + load + r'''
}
int main(void) {
    struct owner owner = {0};
    uint8_t request[32] = {0};
    owner.aks_replacement_phase = T2_AKS_REPLACEMENT_PHASE_RECOVER;
    owner.aks_replacement_session = 7;
    owner.aks_replacement_new_uuid[0] = 42;
    request[4] = 7; request[12] = 16; request[16] = 42;
    assert(dispatch(&owner, 3, request, 32) == 0);
    assert(preflight(&owner, request, 32) == 0);
    request[4] = 8;
    assert(dispatch(&owner, 3, request, 32) == -EACCES);
    assert(preflight(&owner, request, 32) == -EACCES);
    request[4] = 7; request[16] = 43;
    assert(dispatch(&owner, 3, request, 32) == -EACCES);
    assert(preflight(&owner, request, 32) == -EACCES);
    request[16] = 42;
    owner.aks_replacement_phase = T2_AKS_REPLACEMENT_PHASE_NONE;
    assert(dispatch(&owner, 3, request, 32) == -EACCES);
    assert(preflight(&owner, request, 32) == -EACCES);
    memset(request, 0, sizeof(request));
    request[4] = 1; request[12] = 3;
    memcpy(request + 16, "bag", 3);
    assert(dispatch(&owner, 3, request, 20) == 0);
    assert(preflight(&owner, request, 20) == 0);
    request[4] = 7;
    assert(dispatch(&owner, 3, request, 20) == -EACCES);
    assert(preflight(&owner, request, 20) == -EACCES);
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "admission.c"
            executable = Path(directory) / "admission"
            source.write_text(harness)
            subprocess.run(
                ["cc", "-O2", "-Wall", "-Wextra", "-Werror",
                 "-I", str(ROOT / "src"), str(source), "-o", str(executable)],
                check=True,
            )
            subprocess.run([str(executable)], check=True)

    def test_load_keybag_uses_exact_kernel_response_capacity(self) -> None:
        source = (ROOT / "src/t2-aks-tool.c").read_text(encoding="utf-8")
        function = source.split("static int load_keybag", 1)[1].split(
            "static int", 1
        )[0]

        self.assertIn("unsigned char response[8] = { 0 };", function)
        self.assertIn(".response_capacity = sizeof(response)", function)

    def test_compatibility_load_and_alias_bind_share_one_owner(self) -> None:
        source = (ROOT / "src/t2-aks-tool.c").read_text(encoding="utf-8")
        loader = (ROOT / "src/t2-keybag-load.sh").read_text(encoding="utf-8")

        self.assertIn("static int load_system_keybag", source)
        self.assertIn(
            "load_system_keybag(fd, argv[2], argv[3], argv[4])", source
        )
        self.assertIn("load-system-keybag", loader)
        self.assertNotIn("$TOOL set-system-keybag", loader)

    def test_two_keybag_unlock_hardens_and_wipes_one_secret(self) -> None:
        source = (ROOT / "src/t2-aks-tool.c").read_text(encoding="utf-8")
        service = (ROOT / "src/t2-credential-unlock.sh").read_text(
            encoding="utf-8"
        )

        self.assertIn("unlock-keybags-stdin", source)
        self.assertIn("setrlimit(RLIMIT_CORE", source)
        self.assertIn("prctl(PR_SET_DUMPABLE", source)
        self.assertIn("mlock(secret, size)", source)
        self.assertIn("mlock(request, exchange.request_length)", source)
        self.assertIn("explicit_bzero(secret, sizeof(secret))", source)
        self.assertIn("munlock(request, exchange.request_length)", source)
        self.assertIn("munlock(secret, sizeof(secret))", source)
        self.assertIn("static ssize_t read_secret_line", source)
        self.assertIn("if (errno == EINTR)", source)
        self.assertIn('getenv("PAM_TTY")', source)
        self.assertIn("O_NOFOLLOW", source)
        self.assertIn("S_ISCHR", source)
        self.assertIn(
            '"$TOOL" unlock-keybags-stdin "$session" "$handle" "$special"',
            service,
        )
        self.assertNotIn('"$TOOL" unlock-keybag-stdin', service)

    def test_alias_bind_uses_exact_status_response_capacity(self) -> None:
        source = (ROOT / "src/t2-aks-tool.c").read_text(encoding="utf-8")
        kernel = (ROOT / "src/t2_sep_transport.c").read_text(encoding="utf-8")
        function = source.split("static int set_system_keybag", 1)[1].split(
            "static int", 1
        )[0]

        self.assertIn("unsigned char response[4] = { 0 };", function)
        self.assertIn("exchange.response_length != sizeof(response)", function)
        self.assertIn(
            "exchange.operation == 0x0d && exchange.response_capacity != 4",
            kernel,
        )
        self.assertIn("exchange.response_capacity && !exchange.response", kernel)

    def test_unlock_uses_exact_lock_state_response_capacity(self) -> None:
        source = (ROOT / "src/t2-aks-tool.c").read_text(encoding="utf-8")
        function = source.split("static int unlock_keybag_secret", 1)[1].split(
            "static int", 1
        )[0]

        self.assertIn("unsigned char response[16] = { 0 };", function)
        self.assertIn("exchange.response_length != sizeof(response)", function)

    def test_verify_password_acm_wire_layout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "t2-aks-tool-unit"
            subprocess.run(
                [
                    "cc",
                    "-O2",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    str(ROOT / "tests/t2_aks_tool_unit.c"),
                    "-o",
                    str(executable),
                ],
                check=True,
            )
            subprocess.run([str(executable)], check=True)

    def test_verify_secret_kernel_allowlist(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "t2-aks-protocol-unit"
            subprocess.run(
                [
                    "cc",
                    "-O2",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    str(ROOT / "tests/t2_aks_protocol_unit.c"),
                    "-o",
                    str(executable),
                ],
                check=True,
            )
            subprocess.run([str(executable)], check=True)

    def test_acm_kernel_lifecycle_contract(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "t2-acm-lifecycle-unit"
            subprocess.run(
                [
                    "cc",
                    "-O2",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    str(ROOT / "tests/t2_acm_lifecycle_unit.c"),
                    "-o",
                    str(executable),
                ],
                check=True,
            )
            subprocess.run([str(executable)], check=True)


if __name__ == "__main__":
    unittest.main()
