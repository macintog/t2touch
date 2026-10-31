# SPDX-License-Identifier: GPL-2.0-only
import importlib.util
import json
import sys
import unittest
from pathlib import Path


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))
SPEC = importlib.util.spec_from_file_location(
    "t2_fprint_enrollment_worker", SOURCE / "t2-fprint-enrollment-worker.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader
SPEC.loader.exec_module(MODULE)

import t2_catacomb_bridge as catacomb_bridge
import t2_catacomb_protocol as catacomb_protocol
import t2_enrollment_persistence_operation as persistence_operation
import t2_fprint_worker as fprint_worker


def _chain(*errors: BaseException) -> BaseException:
    """Link errors so that errors[0].__cause__ is errors[1], and so on."""
    for outer, inner in zip(errors, errors[1:]):
        outer.__cause__ = inner
    return errors[0]


class EnrollmentWorkerReportTests(unittest.TestCase):
    def test_detail_reports_project_messages_along_the_cause_chain(self):
        error = _chain(
            fprint_worker.FprintWorkerError(
                "enrollment stopped", stage="recover-terminal-identity"
            ),
            persistence_operation.PersistenceOperationError(
                "Catacomb persistence stopped at prepare; reconciliation is required"
            ),
            catacomb_bridge.CatacombBridgeError(
                "Catacomb command emitted an unexpected service event"
            ),
        )
        self.assertEqual(
            MODULE._exception_classes(error),
            "FprintWorkerError>PersistenceOperationError>CatacombBridgeError",
        )
        self.assertEqual(
            json.loads(MODULE._exception_detail(error)),
            [
                "enrollment stopped",
                "Catacomb persistence stopped at prepare; reconciliation is required",
                "Catacomb command emitted an unexpected service event",
            ],
        )

    def test_detail_includes_protocol_errors_and_drops_foreign_messages(self):
        error = _chain(
            fprint_worker.FprintWorkerError("enrollment stopped"),
            catacomb_bridge.CatacombBridgeError("Catacomb prepare reply is invalid"),
            catacomb_protocol.CatacombProtocolError(
                "Catacomb prepare returned nonzero status"
            ),
            OSError(111, "Connection refused: /run/t2-touchid/private/socket"),
            ValueError("expected message frame, received type 7"),
        )
        self.assertEqual(
            json.loads(MODULE._exception_detail(error)),
            [
                "enrollment stopped",
                "Catacomb prepare reply is invalid",
                "Catacomb prepare returned nonzero status",
            ],
        )

    def test_detail_sanitizes_and_bounds_messages(self):
        long_message = "x" * 500
        error = _chain(
            fprint_worker.FprintWorkerError("tab\there\nnewline é end"),
            catacomb_bridge.CatacombBridgeError(long_message),
            catacomb_bridge.CatacombBridgeError(""),
        )
        detail = json.loads(MODULE._exception_detail(error))
        self.assertEqual(detail[0], "tabherenewline  end")
        self.assertEqual(detail[1], "x" * MODULE._DETAIL_MAX_MESSAGE)
        self.assertEqual(detail[2], "<empty>")

    def test_detail_stops_at_the_message_limit_and_on_cycles(self):
        errors = [
            catacomb_bridge.CatacombBridgeError(f"message {index}")
            for index in range(MODULE._DETAIL_MAX_MESSAGES + 3)
        ]
        _chain(*errors)
        self.assertEqual(
            len(json.loads(MODULE._exception_detail(errors[0]))),
            MODULE._DETAIL_MAX_MESSAGES,
        )
        first = catacomb_bridge.CatacombBridgeError("first")
        second = catacomb_bridge.CatacombBridgeError("second")
        first.__cause__ = second
        second.__cause__ = first
        self.assertEqual(
            json.loads(MODULE._exception_detail(first)), ["first", "second"]
        )

    def test_detail_without_project_errors_is_an_empty_list(self):
        self.assertEqual(
            MODULE._exception_detail(RuntimeError("/etc/t2-touchid.conf")), "[]"
        )


if __name__ == "__main__":
    unittest.main()
