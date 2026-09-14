# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import os
import socket
import sys
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))

import t2_enrollment_coordinator as coordinator
import t2_enrollment_protocol as enrollment_protocol
import t2_fprint_worker as worker
import t2_fprint_worker_protocol as protocol
import t2_ipc_session as ipc
import t2_linux_account as account
import t2_polkit_grant as polkit
import t2_user_broker as broker


def request():
    subject = polkit.read_process_subject(os.getpid(), os.getuid())
    return protocol.StartRequest(
        "finger-2",
        subject,
        account.AccountEvidence(subject.uid, "a" * 64),
        ipc.SessionEvidence(
            "pidfd-session", "session-1", "wayland", "user", True, 1
        ),
    )


def transition(action, *, progress=None):
    return enrollment_protocol.EnrollmentTransition(
        action,
        enrollment_protocol.EnrollmentState.ACTIVE,
        progress_percent=progress,
    )


class Authorization:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


class Binder:
    def __init__(self, alias):
        self.alias = alias
        self.bound = False

    def verify_password_fallback(self):
        return True

    def bind(self, context):
        self.bound = len(context) == 16


class FprintWorkerTests(unittest.TestCase):
    def start_request(self, connection):
        descriptor = os.pidfd_open(os.getpid())
        try:
            protocol.send_start(connection, request(), descriptor)
        finally:
            os.close(descriptor)

    def run_worker(self, right, **overrides):
        result = []

        def target():
            try:
                result.append(worker.serve_once(right, **overrides))
            except BaseException as error:
                result.append(error)

        thread = threading.Thread(target=target)
        thread.start()
        return thread, result

    def dependencies(self, operation):
        authorization = Authorization()
        selected = SimpleNamespace(
            unlock_mode="host-encrypted-credential",
            special_bag_alias=-501,
        )
        authority = SimpleNamespace(selected=selected)

        def authorization_factory(peer, **arguments):
            self.assertEqual(peer.subject, request().caller)
            self.assertEqual(arguments["expected_account"], request().account)
            self.assertEqual(arguments["expected_session"], request().session)
            return authorization

        def broker_runner(_connection, **arguments):
            self.assertIs(arguments["authorization_manager"], authorization)
            value = arguments["consumer"](authority, SimpleNamespace())
            return broker.BrokerResult(SimpleNamespace(), True, value)

        class Enrollment:
            def __init__(self, _finger, _bind, cancel, feedback, fallback):
                self.cancel = cancel
                self.feedback = feedback
                if fallback is not True:
                    raise AssertionError("fallback not verified")

            def __call__(self, _authority, _live):
                return operation(self.cancel, self.feedback)

        return {
            "authorization_factory": authorization_factory,
            "binder_factory": Binder,
            "broker_runner": broker_runner,
            "enrollment_consumer_factory": Enrollment,
        }, authorization

    def test_success_streams_initial_progress_and_terminal(self):
        def operation(_cancel, feedback):
            feedback(
                transition(
                    enrollment_protocol.EnrollmentAction.PROGRESS,
                    progress=25,
                )
            )
            return coordinator.EnrollmentCoordinatorResult(
                "identity-observed", True, True, True
            )

        dependencies, authorization = self.dependencies(operation)
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        thread, result = self.run_worker(right, **dependencies)
        self.start_request(left)
        updates = [protocol.receive_update(left) for _ in range(3)]
        thread.join(timeout=5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(
            [update.status for update in updates],
            [None, "enroll-stage-passed", "enroll-completed"],
        )
        self.assertIsInstance(result[0], coordinator.EnrollmentCoordinatorResult)
        self.assertTrue(authorization.closed)

    def test_cancel_packet_drives_cooperative_reconciled_failure(self):
        entered = threading.Event()

        def operation(cancel, _feedback):
            entered.set()
            while not cancel():
                pass
            return coordinator.EnrollmentCoordinatorResult(
                "cancelled", True, False, True
            )

        dependencies, _authorization = self.dependencies(operation)
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        thread, result = self.run_worker(right, **dependencies)
        self.start_request(left)
        initial = protocol.receive_update(left)
        self.assertIsNone(initial.status)
        self.assertTrue(entered.wait(timeout=2))
        protocol.send_cancel(left)
        terminal = protocol.receive_update(left)
        thread.join(timeout=5)
        self.assertEqual(terminal.status, "enroll-failed")
        self.assertIsInstance(result[0], coordinator.EnrollmentCoordinatorResult)

    def test_authorization_or_broker_failure_emits_terminal_unknown(self):
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(left.close)
        self.addCleanup(right.close)

        def fail(_peer, **_arguments):
            raise ipc.IPCSessionError("denied")

        thread, result = self.run_worker(right, authorization_factory=fail)
        self.start_request(left)
        terminal = protocol.receive_update(left)
        thread.join(timeout=5)
        self.assertEqual(terminal.status, "enroll-unknown-error")
        self.assertIsInstance(result[0], worker.FprintWorkerError)

    def test_mapping_without_worker_credential_never_constructs_binder(self):
        authorization = Authorization()
        authority = SimpleNamespace(
            selected=SimpleNamespace(
                unlock_mode="manual-password",
                special_bag_alias=-501,
            )
        )

        def authorization_factory(peer, **_arguments):
            return authorization

        def broker_runner(_connection, **arguments):
            arguments["consumer"](authority, SimpleNamespace())

        binder_factory = mock.Mock()
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        thread, result = self.run_worker(
            right,
            authorization_factory=authorization_factory,
            binder_factory=binder_factory,
            broker_runner=broker_runner,
        )
        self.start_request(left)
        terminal = protocol.receive_update(left)
        thread.join(timeout=5)
        self.assertEqual(terminal.status, "enroll-unknown-error")
        binder_factory.assert_not_called()
        self.assertTrue(authorization.closed)
        self.assertIsInstance(result[0], worker.FprintWorkerError)

    def test_typed_capacity_refusal_emits_data_full(self):
        def operation(_cancel, _feedback):
            raise broker.UserBrokerError("consumer failed") from (
                worker.t2_fprint_enrollment_consumer.FprintEnrollmentDataFullError(
                    "capacity exhausted"
                )
            )

        dependencies, authorization = self.dependencies(operation)
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        thread, result = self.run_worker(right, **dependencies)
        self.start_request(left)
        updates = [protocol.receive_update(left) for _ in range(2)]
        thread.join(timeout=5)
        self.assertEqual(
            [update.status for update in updates],
            [None, "enroll-data-full"],
        )
        self.assertTrue(updates[-1].done)
        self.assertTrue(authorization.closed)
        self.assertIsInstance(result[0], worker.FprintWorkerError)

    def test_native_addition_waits_for_identity_match_before_terminal(self):
        authorization = Authorization()
        authority = SimpleNamespace(
            mapping_set=object(), selected=SimpleNamespace()
        )
        expected = coordinator.EnrollmentCoordinatorResult(
            "identity-observed", True, True, True
        )
        native = SimpleNamespace()
        native._configuration = mock.Mock(
            return_value={"apple_uid": 501, "linux_uid": request().caller.uid}
        )

        def native_run(**arguments):
            self.assertEqual(arguments["credential"], bytearray())
            self.assertIs(arguments["authorization_session"], authorization)
            self.assertIs(arguments["authorization_authority"], authority)
            self.assertIs(arguments["existing_authority"], authority)
            arguments["on_started"]()
            arguments["on_feedback"](
                transition(
                    enrollment_protocol.EnrollmentAction.PROGRESS,
                    progress=100,
                )
            )
            return expected

        native._run = native_run
        match_called = False

        def native_addition_match(_cancellation, on_event, linux_uid):
            nonlocal match_called
            match_called = True
            self.assertEqual(linux_uid, request().caller.uid)
            on_event({"event_kind": "match_armed"})

        binder = mock.Mock(side_effect=AssertionError("compatibility binder used"))
        broker_runner = mock.Mock(side_effect=AssertionError("compatibility broker used"))

        def authorization_factory(_peer, **_arguments):
            return authorization

        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        with (
            mock.patch.dict(
                os.environ, {"T2_TOUCHID_AUTHORITY_MODE": "linux-native"}
            ),
            mock.patch.object(worker, "_native_enrollment_module", return_value=native),
            mock.patch.object(worker.t2_user_authority, "load", return_value=authority),
        ):
            thread, result = self.run_worker(
                right,
                authorization_factory=authorization_factory,
                binder_factory=binder,
                broker_runner=broker_runner,
                native_addition_match=native_addition_match,
            )
            self.start_request(left)
            updates = [protocol.receive_update(left) for _ in range(5)]
            thread.join(timeout=5)
        self.assertEqual(
            [(item.status, item.done, item.finger_needed) for item in updates],
            [
                (None, False, True),
                ("enroll-stage-passed", False, True),
                (None, False, False),
                (None, False, True),
                ("enroll-completed", True, False),
            ],
        )
        self.assertEqual(result, [expected])
        self.assertTrue(match_called)
        binder.assert_not_called()
        broker_runner.assert_not_called()
        self.assertTrue(authorization.closed)

    def test_addition_verification_budget_starts_only_after_five_placements(self):
        budget = worker._AdditionMatchAttemptBudget()
        for placement in range(5):
            now = float(placement * 10)
            budget.accept(
                {"event_kind": "status", "status_semantics": "finger-present"},
                now=now,
            )
            budget.accept(
                {"event_kind": "status", "status_semantics": "finger-present"},
                now=now,
            )
            if placement < 4:
                self.assertFalse(budget.expired(now=now + 100))
            budget.accept(
                {"event_kind": "status", "status_semantics": "finger-removed"},
                now=now + 0.1,
            )
        self.assertFalse(budget.expired(now=40.9))
        self.assertTrue(budget.expired(now=41.0))
        budget.accept(
            {
                "event_kind": "match_result",
                "matched": True,
                "matches_required_identity": True,
            },
            now=41.0,
        )
        self.assertFalse(budget.expired(now=100.0))

    def test_failed_addition_match_rolls_back_before_reporting_failure(self):
        authorization = Authorization()
        authority = SimpleNamespace(mapping_set=object(), selected=SimpleNamespace())
        observed = coordinator.EnrollmentCoordinatorResult(
            "identity-observed", True, True, True
        )
        native = SimpleNamespace()
        native._configuration = mock.Mock(
            return_value={"apple_uid": 501, "linux_uid": request().caller.uid}
        )

        def native_run(**arguments):
            arguments["on_started"]()
            arguments["on_feedback"](
                transition(
                    enrollment_protocol.EnrollmentAction.PROGRESS,
                    progress=100,
                )
            )
            return observed

        native._run = native_run
        rollback = mock.Mock()
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        with (
            mock.patch.dict(
                os.environ, {"T2_TOUCHID_AUTHORITY_MODE": "linux-native"}
            ),
            mock.patch.object(worker, "_native_enrollment_module", return_value=native),
            mock.patch.object(worker.t2_user_authority, "load", return_value=authority),
        ):
            thread, result = self.run_worker(
                right,
                authorization_factory=lambda _peer, **_arguments: authorization,
                binder_factory=mock.Mock(
                    side_effect=AssertionError("compatibility binder used")
                ),
                broker_runner=mock.Mock(
                    side_effect=AssertionError("compatibility broker used")
                ),
                native_addition_match=mock.Mock(
                    side_effect=worker.FprintWorkerError(
                        "addition match budget exhausted"
                    )
                ),
                native_addition_rollback=rollback,
            )
            self.start_request(left)
            updates = [protocol.receive_update(left) for _ in range(4)]
            thread.join(timeout=5)

        rollback.assert_called_once_with(request().caller.uid)
        self.assertEqual(updates[-1].status, "enroll-failed")
        self.assertTrue(updates[-1].done)
        self.assertEqual(result[0].outcome, "failed")

    def test_native_100_percent_terminal_fault_recovers_without_replay(self):
        authorization = Authorization()
        authority = SimpleNamespace(
            mapping_set=object(), selected=SimpleNamespace()
        )
        recovered = coordinator.EnrollmentCoordinatorResult(
            "identity-observed", True, True, True
        )
        native = SimpleNamespace()
        native._configuration = mock.Mock(
            return_value={"apple_uid": 501, "linux_uid": request().caller.uid}
        )

        def native_run(**arguments):
            arguments["on_started"]()
            arguments["on_feedback"](
                transition(
                    enrollment_protocol.EnrollmentAction.PROGRESS,
                    progress=100,
                )
            )
            raise RuntimeError("terminal event rejected")

        native._run = native_run
        native._run_observed_identity_recovery = mock.Mock(
            return_value={
                "enrollment_succeeded": True,
                "observed_identity_recovered": True,
                "fingerprint_mutation_performed": False,
                "persistence_ready": True,
                "reconciliation_complete": True,
            }
        )

        def native_addition_match(_cancellation, on_event, _linux_uid):
            on_event({"event_kind": "match_armed"})

        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        with (
            mock.patch.dict(
                os.environ, {"T2_TOUCHID_AUTHORITY_MODE": "linux-native"}
            ),
            mock.patch.object(worker, "_native_enrollment_module", return_value=native),
            mock.patch.object(worker.t2_user_authority, "load", return_value=authority),
        ):
            thread, result = self.run_worker(
                right,
                authorization_factory=lambda _peer, **_arguments: authorization,
                binder_factory=mock.Mock(
                    side_effect=AssertionError("compatibility binder used")
                ),
                broker_runner=mock.Mock(
                    side_effect=AssertionError("compatibility broker used")
                ),
                native_addition_match=native_addition_match,
            )
            self.start_request(left)
            updates = [protocol.receive_update(left) for _ in range(5)]
            thread.join(timeout=5)

        self.assertEqual(result, [recovered])
        native._run_observed_identity_recovery.assert_called_once_with(
            configuration={"apple_uid": 501, "linux_uid": request().caller.uid},
            mapping_set=authority.mapping_set,
            selected=authority.selected,
            identity_name=None,
        )
        self.assertEqual(updates[-1].status, "enroll-completed")
        self.assertTrue(updates[-1].done)

    def test_native_first_enrollment_publishes_authority_before_success(self):
        authorization = Authorization()
        mapping_set = object()
        selected = SimpleNamespace(
            linux_account_generation="a" * 64,
            keybag_sha256="b" * 64,
            apple_uid=501,
            account_uuid="00000000-0000-0000-0000-000000000001",
            bag_uuid="00000000-0000-0000-0000-000000000002",
        )
        authority = SimpleNamespace(mapping_set=mapping_set, selected=selected)
        expected = coordinator.EnrollmentCoordinatorResult(
            "identity-observed", True, True, True
        )
        native = SimpleNamespace()
        native.PROVISIONING_JOURNAL = Path(
            "/var/lib/t2-touchid/native-provisioning.jsonl"
        )
        native._configuration = mock.Mock(
            return_value={"apple_uid": 501, "linux_uid": request().caller.uid}
        )
        native._load_provisioned_authority = mock.Mock(
            return_value=(mapping_set, selected, object())
        )

        def native_run(**arguments):
            self.assertIsNone(arguments["existing_authority"])
            arguments["on_started"]()
            arguments["on_feedback"](
                transition(
                    enrollment_protocol.EnrollmentAction.PROGRESS,
                    progress=100,
                )
            )
            return expected

        native._run = native_run
        native._run_post_reboot_verification = mock.Mock(
            return_value={
                "enrollment_runtime_verified": True,
                "runtime_authority_published": True,
            }
        )
        addition = mock.Mock(
            side_effect=AssertionError("first enrollment used addition match")
        )

        def authorization_factory(_peer, **_arguments):
            return authorization

        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        with (
            mock.patch.dict(
                os.environ, {"T2_TOUCHID_AUTHORITY_MODE": "linux-native"}
            ),
            mock.patch.object(worker, "_native_enrollment_module", return_value=native),
            mock.patch.object(
                worker.t2_user_authority,
                "load",
                side_effect=worker.t2_user_authority.UserAuthorityError("missing"),
            ),
            mock.patch.object(
                worker.t2_user_authority,
                "RuntimeUserAuthority",
                return_value=authority,
            ),
        ):
            thread, result = self.run_worker(
                right,
                authorization_factory=authorization_factory,
                binder_factory=mock.Mock(
                    side_effect=AssertionError("compatibility binder used")
                ),
                broker_runner=mock.Mock(
                    side_effect=AssertionError("compatibility broker used")
                ),
                native_addition_match=addition,
            )
            self.start_request(left)
            updates = [protocol.receive_update(left) for _ in range(4)]
            thread.join(timeout=5)

        self.assertEqual(
            [(item.status, item.done, item.finger_needed) for item in updates],
            [
                (None, False, True),
                ("enroll-stage-passed", False, True),
                (None, False, False),
                ("enroll-completed", True, False),
            ],
        )
        self.assertEqual(result, [expected])
        native._run_post_reboot_verification.assert_called_once_with(
            configuration={"apple_uid": 501, "linux_uid": request().caller.uid},
            mapping_set=mapping_set,
            selected=selected,
            credential=bytearray(),
            require_different_boot=False,
        )
        addition.assert_not_called()
        self.assertTrue(authorization.closed)


if __name__ == "__main__":
    unittest.main()
