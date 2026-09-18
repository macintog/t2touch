# SPDX-License-Identifier: GPL-2.0-only
"""Privacy and schema checks for performance-event journal relaying."""

from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import unittest
from unittest.mock import patch


MODULE_PATH = Path(__file__).resolve().parents[1] / "src/t2_performance.py"
SPEC = importlib.util.spec_from_file_location("t2_performance_test", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class PerformanceRelayTests(unittest.TestCase):
    def test_transport_profile_is_opt_in_and_preserves_failure(self):
        output = io.StringIO()
        with patch.dict(MODULE.os.environ, {}, clear=True), redirect_stderr(output):
            with MODULE.transport_phase("aks", "op_21"):
                pass
        self.assertEqual(output.getvalue(), "")
        failure = RuntimeError("sensitive diagnostic must not be logged")
        with patch.dict(MODULE.os.environ, {"T2_TOUCHID_PROFILE_IO": "1"}), redirect_stderr(output):
            with self.assertRaises(RuntimeError) as raised:
                with MODULE.transport_phase("acm", "op_01"):
                    raise failure
        self.assertIs(raised.exception, failure)
        event = json.loads(output.getvalue().removeprefix("T2_PERF_EVENT "))
        self.assertEqual(set(event), MODULE._FIELDS)
        self.assertEqual((event["operation"], event["phase"], event["outcome"]), ("acm", "op_01", "error"))
        self.assertNotIn("sensitive", output.getvalue())

    def test_exact_event_is_relayed_canonically(self):
        event = {
            "schema_version": 1,
            "operation": "native_match",
            "phase": "worker_start",
            "duration_ms": 12.5,
            "outcome": "ok",
        }
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertTrue(
                MODULE.relay(
                    b"T2_PERF_EVENT "
                    + json.dumps(event).encode("utf-8")
                )
            )
        self.assertEqual(
            output.getvalue(),
            "T2_PERF_EVENT "
            + json.dumps(event, separators=(",", ":"), sort_keys=True)
            + "\n",
        )
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertTrue(
                MODULE.relay(
                    bytearray(
                        b"T2_PERF_EVENT "
                        + json.dumps(event).encode("utf-8")
                    )
                )
            )
        self.assertTrue(output.getvalue().startswith("T2_PERF_EVENT "))

    def test_non_schema_content_is_not_relayed(self):
        records = (
            b"diagnostic",
            b'T2_PERF_EVENT {"secret":"opaque-identity"}',
            b'T2_PERF_EVENT {"schema_version":1,"operation":"native_match",'
            b'"phase":"worker start","duration_ms":1,"outcome":"ok"}',
            b'T2_PERF_EVENT {"schema_version":1,"operation":"native_match",'
            b'"phase":"worker_start","duration_ms":NaN,"outcome":"ok"}',
        )
        output = io.StringIO()
        with redirect_stdout(output):
            for record in records:
                with self.subTest(record=record):
                    self.assertFalse(MODULE.relay(record))
        self.assertEqual(output.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
