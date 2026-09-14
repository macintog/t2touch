# SPDX-License-Identifier: GPL-2.0-only
"""Fail-closed translation from T2 enrollment state to the fprint ABI."""

from __future__ import annotations

from dataclasses import dataclass

import t2_enrollment_coordinator
import t2_enrollment_protocol


class FprintEnrollmentRuntimeError(RuntimeError):
    pass


@dataclass(frozen=True)
class EnrollmentUpdate:
    status: str | None
    done: bool
    finger_present: bool
    finger_needed: bool
    progress_percent: int | None = None


class EnrollmentRuntime:
    """Reduce trusted coordinator feedback into documented fprint statuses."""

    def __init__(self) -> None:
        self.finger_present = False
        self.finger_needed = True
        self.last_progress = -1
        self.finished = False

    def _update(self, status: str | None = None) -> EnrollmentUpdate:
        return EnrollmentUpdate(
            status,
            False,
            self.finger_present,
            self.finger_needed,
            self.last_progress if self.last_progress >= 0 else None,
        )

    def initial(self) -> EnrollmentUpdate:
        if self.finished or self.last_progress != -1:
            raise FprintEnrollmentRuntimeError(
                "initial enrollment state is no longer available"
            )
        return self._update()

    def accept(self, transition: object) -> EnrollmentUpdate:
        if self.finished:
            raise FprintEnrollmentRuntimeError(
                "enrollment feedback arrived after completion"
            )
        if not isinstance(
            transition, t2_enrollment_protocol.EnrollmentTransition
        ):
            raise FprintEnrollmentRuntimeError(
                "enrollment feedback has the wrong type"
            )
        action = transition.action
        if action is t2_enrollment_protocol.EnrollmentAction.FINGER_PRESENT:
            self.finger_present = True
            self.finger_needed = False
            return self._update()
        if action is t2_enrollment_protocol.EnrollmentAction.FINGER_REMOVED:
            self.finger_present = False
            self.finger_needed = True
            return self._update()
        if action is t2_enrollment_protocol.EnrollmentAction.PROGRESS:
            progress = transition.progress_percent
            if (
                type(progress) is not int
                or not 0 <= progress <= 100
            ):
                raise FprintEnrollmentRuntimeError(
                    "enrollment progress is invalid"
                )
            # BiometricKit may revise its internal coverage estimate downward
            # after a weak touch.  This percentage is presentation only; the
            # journaled protocol and final identity readback own correctness.
            # Preserve the last visible high-water instead of allowing a UI
            # regression to poison the active enrollment transaction.
            if progress <= self.last_progress:
                return self._update()
            self.last_progress = progress
            # Progress can be delivered after the paired removal callback.
            # Preserve presence as the source of truth so a completed sample
            # cannot strand the UI in a non-actionable preparing state.
            self.finger_needed = not self.finger_present
            return self._update("enroll-stage-passed")
        statuses = {
            t2_enrollment_protocol.EnrollmentAction.REMOVE_AND_RETRY: (
                "enroll-remove-and-retry"
            ),
            t2_enrollment_protocol.EnrollmentAction.RETRY_SCAN: (
                "enroll-retry-scan"
            ),
            t2_enrollment_protocol.EnrollmentAction.RETRY_SMALL_COVERAGE: (
                "enroll-finger-not-centered"
            ),
            t2_enrollment_protocol.EnrollmentAction.DIRTY_SENSOR: (
                "enroll-retry-scan"
            ),
        }
        if action in statuses:
            # Retry may be reported before the paired finger-removed event.
            # Never project the impossible state "finger present" and
            # "finger needed" simultaneously; the later removal callback
            # re-arms the touch cue while the retained retry status tells the
            # UI to reposition.
            self.finger_needed = not self.finger_present
            return self._update(statuses[action])
        if action in {
            t2_enrollment_protocol.EnrollmentAction.CONTINUE,
            t2_enrollment_protocol.EnrollmentAction.IGNORE_TELEMETRY,
            t2_enrollment_protocol.EnrollmentAction.IGNORE_AUXILIARY,
            t2_enrollment_protocol.EnrollmentAction.IGNORE_PHASE,
        }:
            return self._update()
        raise FprintEnrollmentRuntimeError(
            "terminal or identity feedback bypassed final reconciliation"
        )

    def begin_identity_verification(self) -> EnrollmentUpdate:
        """Keep additional enrollment live until its new identity matches."""

        if self.finished or self.last_progress != 100:
            raise FprintEnrollmentRuntimeError(
                "identity verification requires completed capture"
            )
        self.finger_present = False
        self.finger_needed = False
        return self._update()

    def accept_identity_verification_event(
        self, event: object
    ) -> EnrollmentUpdate | None:
        """Project only placement state from the untrusted live match stream."""

        if self.finished or not isinstance(event, dict):
            raise FprintEnrollmentRuntimeError(
                "identity verification feedback is invalid"
            )
        if event.get("event_kind") == "match_armed":
            self.finger_present = False
            self.finger_needed = True
            return self._update()
        semantics = event.get("status_semantics")
        if semantics == "finger-present":
            self.finger_present = True
            self.finger_needed = False
            return self._update()
        if semantics == "finger-removed":
            self.finger_present = False
            self.finger_needed = True
            return self._update()
        if (
            event.get("event_kind") == "match_result"
            and event.get("result_valid") is True
            and event.get("no_match") is True
            and event.get("no_match_image_quality") is True
        ):
            self.finger_present = False
            self.finger_needed = True
            return self._update("enroll-retry-scan")
        return None

    def finish(self, result: object) -> EnrollmentUpdate:
        if self.finished:
            raise FprintEnrollmentRuntimeError(
                "enrollment completed more than once"
            )
        if not isinstance(
            result, t2_enrollment_coordinator.EnrollmentCoordinatorResult
        ):
            raise FprintEnrollmentRuntimeError(
                "enrollment result has the wrong type"
            )
        successful = (
            result.outcome == "identity-observed"
            and result.policy_satisfied is True
            and result.persistence_ready is True
            and result.reconciliation_complete is True
        )
        reconciled_failure = (
            result.outcome in {"cancelled", "failed", "timed-out"}
            and result.persistence_ready is False
            and result.reconciliation_complete is True
        )
        status = (
            "enroll-completed"
            if successful
            else "enroll-failed"
            if reconciled_failure
            else "enroll-unknown-error"
        )
        self.finished = True
        self.finger_present = False
        self.finger_needed = False
        progress = (
            100
            if successful
            else self.last_progress
            if self.last_progress >= 0
            else None
        )
        return EnrollmentUpdate(status, True, False, False, progress)

    def refuse_pre_dispatch(self, reason: object) -> EnrollmentUpdate:
        """Translate only a typed refusal proven before enrollment dispatch."""
        if self.finished:
            raise FprintEnrollmentRuntimeError(
                "enrollment completed more than once"
            )
        if (
            self.last_progress != -1
            or self.finger_present
            or self.finger_needed is not True
            or reason != "capacity-exhausted"
        ):
            raise FprintEnrollmentRuntimeError(
                "pre-dispatch enrollment refusal is invalid"
            )
        self.finished = True
        self.finger_present = False
        self.finger_needed = False
        return EnrollmentUpdate("enroll-data-full", True, False, False)

    def fail_unknown(self) -> EnrollmentUpdate:
        if self.finished:
            raise FprintEnrollmentRuntimeError(
                "enrollment completed more than once"
            )
        self.finished = True
        self.finger_present = False
        self.finger_needed = False
        progress = self.last_progress if self.last_progress >= 0 else None
        return EnrollmentUpdate(
            "enroll-unknown-error", True, False, False, progress
        )
