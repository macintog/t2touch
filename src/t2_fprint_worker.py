# SPDX-License-Identifier: GPL-2.0-only
"""Credential-scoped worker core for one caller-bound fprint enrollment."""

from __future__ import annotations

import json
import importlib.util
import os
import selectors
import socket
import stat
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

import t2_enrollment_journal
import t2_enrollment_coordinator
import t2_fprint_enrollment_consumer
import t2_fprint_enrollment_runtime
import t2_fprint_worker_protocol
import t2_ipc_session
import t2_mutation_journal
import t2_mutation_registry
import t2_system_credential
import t2_user_broker
import t2_user_authority
import t2_user_readiness


WORKER_ROOT = Path("/run/t2-touchid/workers")
MUTATION_ROOT = Path("/var/lib/t2-touchid/mutations")
NATIVE_MATCH_ROOT = Path("/var/lib/t2-touchid/native-match")
MATCH_EVENT_PREFIX = b"T2_MATCH_EVENT "
ADDITION_MATCH_MAX_PLACEMENTS = 5
ADDITION_MATCH_SETTLE_SECONDS = 1.0


class FprintWorkerError(RuntimeError):
    def __init__(self, message: str, *, stage: str = "outside-request") -> None:
        super().__init__(message)
        self.stage = stage


class _AdditionMatchAttemptBudget:
    """Bound post-enrollment verification without timing out the first touch."""

    def __init__(self) -> None:
        self.finger_present = False
        self.placement_count = 0
        self.deadline: float | None = None
        self.required_match_observed = False

    def accept(self, event: dict[str, object], *, now: float) -> None:
        semantics = event.get("status_semantics")
        if semantics == "finger-present" and not self.finger_present:
            self.finger_present = True
            self.placement_count += 1
            if self.placement_count >= ADDITION_MATCH_MAX_PLACEMENTS:
                self.deadline = now + ADDITION_MATCH_SETTLE_SECONDS
        elif semantics == "finger-removed":
            self.finger_present = False
        if (
            event.get("event_kind") == "match_result"
            and event.get("matched") is True
            and event.get("matches_required_identity") is True
        ):
            self.required_match_observed = True

    def expired(self, *, now: float) -> bool:
        return (
            self.deadline is not None
            and not self.required_match_observed
            and now >= self.deadline
        )


def _native_enrollment_module():
    path = Path(__file__).resolve().with_name("t2-native-enroll.py")
    specification = importlib.util.spec_from_file_location(
        "t2_fprint_native_enrollment", path
    )
    if specification is None or specification.loader is None:
        raise FprintWorkerError("native enrollment owner is unavailable")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def _native_mode() -> bool:
    return os.environ.get("T2_TOUCHID_AUTHORITY_MODE") == "linux-native"


def _pending_addition_journal() -> Path:
    t2_mutation_registry.scan(MUTATION_ROOT)
    candidates = []
    for path in MUTATION_ROOT.glob("*.jsonl"):
        records = t2_mutation_journal.read(path)
        evidence = records[0].get("evidence") if records else None
        if (
            not isinstance(evidence, dict)
            or evidence.get("operation_kind") != "enroll"
        ):
            continue
        history = t2_enrollment_journal.validate_history(records)
        if (
            history.phase is t2_enrollment_journal.EnrollmentPhase.RECONCILED
            and history.baseline.get("baseline_version") == 1
            and history.terminal_identity_uuid is not None
        ):
            candidates.append(path)
    if len(candidates) != 1:
        raise FprintWorkerError(
            "additional enrollment requires one reconciled identity"
        )
    return candidates[0]


def _native_addition_match(
    cancellation: threading.Event,
    on_event,
    linux_uid: int,
) -> None:
    """Match only the new identity before fprintd reports enrollment success."""

    if (
        not isinstance(cancellation, threading.Event)
        or not callable(on_event)
        or type(linux_uid) is not int
        or linux_uid <= 0
    ):
        raise FprintWorkerError("additional match dependency is invalid")
    addition_journal = _pending_addition_journal()
    try:
        output_root = NATIVE_MATCH_ROOT.stat(follow_symlinks=False)
    except OSError as error:
        raise FprintWorkerError("native match artifact root is unavailable") from error
    if (
        not stat.S_ISDIR(output_root.st_mode)
        or output_root.st_uid != 0
        or output_root.st_mode & 0o077
    ):
        raise FprintWorkerError("native match artifact root is unsafe")
    token = str(uuid.uuid4())
    public_result = NATIVE_MATCH_ROOT / f"fprint-addition-match-{token}.json"
    private_events = NATIVE_MATCH_ROOT / (
        f"private-fprint-addition-match-events-{token}.json"
    )
    diagnostic = NATIVE_MATCH_ROOT / f"fprint-addition-match-{token}.stderr"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(public_result, flags, 0o600)
    try:
        diagnostic_descriptor = os.open(diagnostic, flags, 0o600)
    except BaseException:
        os.close(descriptor)
        raise
    process = None
    budget = _AdditionMatchAttemptBudget()
    attempt_budget_exhausted = False

    def accept_event(event: dict[str, object]) -> None:
        budget.accept(event, now=time.monotonic())
        on_event(event)

    try:
        environment = os.environ.copy()
        # The root transient worker has already pinned and authorized this
        # caller.  The nested fixed-purpose CLI retains its sudo-origin guard,
        # so forward that exact UID rather than relying on a shell environment
        # that systemd intentionally does not provide.
        environment["SUDO_UID"] = str(linux_uid)
        process = subprocess.Popen(
            [
                sys.executable,
                str(Path(__file__).resolve().with_name("t2-native-match.py")),
                "--addition-journal",
                str(addition_journal),
                "--private-match-events-output",
                str(private_events),
            ],
            stdin=subprocess.DEVNULL,
            stdout=descriptor,
            stderr=subprocess.PIPE,
            close_fds=True,
            env=environment,
        )
    except BaseException:
        os.close(diagnostic_descriptor)
        raise
    finally:
        os.close(descriptor)
    assert process.stderr is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stderr, selectors.EVENT_READ)
    try:
        while process.poll() is None:
            if cancellation.is_set():
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                break
            if budget.expired(now=time.monotonic()):
                attempt_budget_exhausted = True
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                break
            for _key, _mask in selector.select(timeout=0.1):
                line = process.stderr.readline()
                _write_diagnostic(diagnostic_descriptor, line)
                if not line.startswith(MATCH_EVENT_PREFIX):
                    continue
                try:
                    event = json.loads(line[len(MATCH_EVENT_PREFIX) :])
                except (UnicodeDecodeError, json.JSONDecodeError):
                    continue
                if isinstance(event, dict):
                    accept_event(event)
        for line in process.stderr:
            _write_diagnostic(diagnostic_descriptor, line)
            if not line.startswith(MATCH_EVENT_PREFIX):
                continue
            try:
                event = json.loads(line[len(MATCH_EVENT_PREFIX) :])
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            if isinstance(event, dict):
                accept_event(event)
    finally:
        selector.close()
        process.stderr.close()
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        try:
            os.fsync(diagnostic_descriptor)
        finally:
            os.close(diagnostic_descriptor)
    if cancellation.is_set():
        raise FprintWorkerError("additional identity match was cancelled")
    if attempt_budget_exhausted:
        raise FprintWorkerError(
            "additional identity did not verify within five placements"
        )
    if process.returncode != 0:
        raise FprintWorkerError("additional identity match did not complete")
    history = t2_enrollment_journal.read(addition_journal)
    if history.phase is not t2_enrollment_journal.EnrollmentPhase.ADDITION_VERIFIED:
        raise FprintWorkerError("additional identity match was not journaled")


def _native_addition_rollback(linux_uid: int) -> None:
    """Run the fixed-purpose compensation after addition verification fails."""

    if type(linux_uid) is not int or linux_uid <= 0:
        raise FprintWorkerError("addition rollback caller is invalid")
    environment = os.environ.copy()
    environment["SUDO_UID"] = str(linux_uid)
    try:
        completed = subprocess.run(
            [
                sys.executable,
                str(Path(__file__).resolve().with_name("t2-touchid-manage.py")),
                "rollback-unverified-addition",
            ],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            check=False,
            timeout=180,
            env=environment,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise FprintWorkerError(
            "unverified addition rollback could not start"
        ) from error
    try:
        result = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise FprintWorkerError(
            "unverified addition rollback produced no valid result"
        ) from error
    if (
        completed.returncode != 0
        or not isinstance(result, dict)
        or result.get("unverified_addition_rolled_back") is not True
        or result.get("local_catacomb_reconciled") is not True
        or result.get("identifiers_redacted") is not True
    ):
        raise FprintWorkerError(
            "unverified addition rollback requires recovery"
        )


def _write_diagnostic(descriptor: int, payload: bytes) -> None:
    """Retain one complete child stderr fragment in its root-private file."""

    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if written <= 0:
            raise FprintWorkerError("additional match diagnostic write stopped")
        offset += written


def native_enrollment_context(linux_uid: int):
    """Resolve the exact native enrollment owner and its current authority.

    A fresh installation has a complete provisioned mapping before its first
    fingerprint exists, so it cannot yet publish E4 runtime authority.  Keep
    that bootstrap resolution identical for the facade preflight and the
    detached worker; the worker still re-runs it after the caller handoff.
    """

    if type(linux_uid) is not int or linux_uid <= 0 or not _native_mode():
        raise FprintWorkerError("native enrollment authority is unavailable")
    native = _native_enrollment_module()
    configuration = native._configuration(trusted_linux_uid=linux_uid)
    try:
        authority = t2_user_authority.load(linux_uid)
        existing_authority = authority
    except t2_user_authority.UserAuthorityError:
        mapping_set, selected, _history = native._load_provisioned_authority(
            linux_uid, configuration["apple_uid"]
        )
        authority = t2_user_authority.RuntimeUserAuthority(
            mapping_set,
            selected,
            t2_user_readiness.PersistentEvidence(
                selected.linux_account_generation,
                selected.keybag_sha256,
                selected.apple_uid,
                selected.account_uuid,
                selected.bag_uuid,
                True,
            ),
            native.PROVISIONING_JOURNAL,
        )
        existing_authority = None
    return native, configuration, authority, existing_authority


def _capacity_exhausted(error: BaseException) -> bool:
    current: BaseException | None = error
    seen: set[int] = set()
    while current is not None and id(current) not in seen:
        if isinstance(
            current,
            t2_fprint_enrollment_consumer.FprintEnrollmentDataFullError,
        ):
            return True
        seen.add(id(current))
        cause = current.__cause__
        current = cause if isinstance(cause, BaseException) else None
    return False


def _cancel_listener(
    connection: socket.socket,
    cancel_event: threading.Event,
    completed_event: threading.Event,
) -> None:
    try:
        t2_fprint_worker_protocol.receive_cancel(connection)
    except (
        t2_fprint_worker_protocol.FprintWorkerPeerClosed,
        t2_fprint_worker_protocol.FprintWorkerProtocolError,
    ):
        pass
    finally:
        if not completed_event.is_set():
            cancel_event.set()


def serve_once(
    connection: socket.socket,
    *,
    authorization_factory=t2_ipc_session.AuthorizationSession.from_peer,
    binder_factory=t2_system_credential.CredentialPasswordBinder,
    broker_runner=t2_user_broker.run_self_service,
    enrollment_consumer_factory=(
        t2_fprint_enrollment_consumer.EnrollmentConsumer
    ),
    native_addition_match=_native_addition_match,
    native_addition_rollback=_native_addition_rollback,
) -> t2_enrollment_coordinator.EnrollmentCoordinatorResult:
    """Run exactly one enrollment; every failure emits at most one terminal."""

    stage = "validate-dependencies"
    if (
        not callable(authorization_factory)
        or not callable(binder_factory)
        or not callable(broker_runner)
        or not callable(enrollment_consumer_factory)
        or not callable(native_addition_match)
        or not callable(native_addition_rollback)
    ):
        raise FprintWorkerError("worker dependency is unavailable")
    runtime = t2_fprint_enrollment_runtime.EnrollmentRuntime()
    cancel_event = threading.Event()
    completed_event = threading.Event()
    listener: threading.Thread | None = None
    authorization = None
    terminal_sent = False
    try:
        stage = "receive-request"
        request, pidfd = t2_fprint_worker_protocol.receive_start(connection)
        stage = "pin-caller"
        peer = t2_ipc_session.PinnedPeer.from_process_fd(
            pidfd,
            request.caller.pid,
            request.caller.uid,
        )
        if peer.subject != request.caller:
            peer.close()
            raise FprintWorkerError("worker caller changed after transfer")
        stage = "authorize-session"
        authorization = authorization_factory(
            peer,
            expected_uid=request.caller.uid,
            expected_session=request.session,
            expected_account=request.account,
        )
        listener = threading.Thread(
            target=_cancel_listener,
            args=(connection, cancel_event, completed_event),
            name="t2-fprint-worker-cancel",
            daemon=True,
        )
        listener.start()

        if _native_mode():
            stage = "resolve-native-authority"
            native, configuration, authority, existing_authority = (
                native_enrollment_context(request.caller.uid)
            )
            runtime_update_sent = False

            def started() -> None:
                nonlocal runtime_update_sent
                if not runtime_update_sent:
                    t2_fprint_worker_protocol.send_update(
                        connection, runtime.initial()
                    )
                    runtime_update_sent = True

            stage = "run-native-enrollment"
            try:
                result = native._run(
                    configuration=configuration,
                    mapping_set=authority.mapping_set,
                    selected=authority.selected,
                    credential=bytearray(),
                    identity_name=request.finger_name,
                    cancellation=cancel_event,
                    existing_authority=existing_authority,
                    on_started=started,
                    on_feedback=lambda transition: t2_fprint_worker_protocol.send_update(
                        connection, runtime.accept(transition)
                    ),
                    authorization_session=authorization,
                    authorization_authority=authority,
                )
            except BaseException as enrollment_error:
                # Some valid T2 captures reach the SEP-owned 100 percent
                # boundary and persist exactly one identity before the final
                # callback fails strict protocol reduction. The native owner
                # has already cancelled and journaled that ambiguity. Perform
                # the existing fresh-lease, no-replay recovery automatically;
                # it succeeds only for one stable built-in identity delta and
                # otherwise the original operation remains failed closed.
                if runtime.last_progress != 100:
                    raise
                stage = "recover-terminal-identity"
                try:
                    recovery = native._run_observed_identity_recovery(
                        configuration=configuration,
                        mapping_set=authority.mapping_set,
                        selected=authority.selected,
                        identity_name=None,
                    )
                except BaseException:
                    raise enrollment_error
                if any(
                    recovery.get(field) is not expected
                    for field, expected in (
                        ("enrollment_succeeded", True),
                        ("observed_identity_recovered", True),
                        ("fingerprint_mutation_performed", False),
                        ("persistence_ready", True),
                        ("reconciliation_complete", True),
                    )
                ):
                    raise enrollment_error
                result = t2_enrollment_coordinator.EnrollmentCoordinatorResult(
                    "identity-observed", True, True, True
                )
            if not runtime_update_sent:
                started()
            successful = (
                result.outcome == "identity-observed"
                and result.policy_satisfied is True
                and result.persistence_ready is True
                and result.reconciliation_complete is True
            )
            if existing_authority is None and successful:
                stage = "publish-initial-runtime-authority"
                t2_fprint_worker_protocol.send_update(
                    connection, runtime.begin_identity_verification()
                )
                publication = native._run_post_reboot_verification(
                    configuration=configuration,
                    mapping_set=authority.mapping_set,
                    selected=authority.selected,
                    credential=bytearray(),
                    require_different_boot=False,
                )
                if (
                    publication.get("enrollment_runtime_verified") is not True
                    or publication.get("runtime_authority_published") is not True
                ):
                    raise FprintWorkerError(
                        "initial enrollment runtime publication did not complete"
                    )
            elif successful:
                stage = "verify-native-addition"
                t2_fprint_worker_protocol.send_update(
                    connection, runtime.begin_identity_verification()
                )

                def match_event(event: object) -> None:
                    update = runtime.accept_identity_verification_event(event)
                    if update is not None:
                        t2_fprint_worker_protocol.send_update(connection, update)

                try:
                    native_addition_match(
                        cancel_event, match_event, request.caller.uid
                    )
                except BaseException as verification_error:
                    stage = "rollback-unverified-addition"
                    try:
                        native_addition_rollback(request.caller.uid)
                    except BaseException as rollback_error:
                        raise FprintWorkerError(
                            "unverified addition rollback requires recovery"
                        ) from rollback_error
                    result = (
                        t2_enrollment_coordinator.EnrollmentCoordinatorResult(
                            "failed", False, False, True
                        )
                    )
            final = runtime.finish(result)
            t2_fprint_worker_protocol.send_update(connection, final)
            terminal_sent = True
            return result

        def consume(authority, live):
            if cancel_event.is_set():
                raise FprintWorkerError(
                    "worker enrollment was cancelled before credential use"
                )
            if authority.selected.unlock_mode != "host-encrypted-credential":
                raise FprintWorkerError(
                    "mapped user has no worker-scoped credential authority"
                )
            binder = binder_factory(authority.selected.special_bag_alias)
            fallback_verified = binder.verify_password_fallback()
            t2_fprint_worker_protocol.send_update(
                connection, runtime.initial()
            )
            enrollment = enrollment_consumer_factory(
                request.finger_name,
                binder.bind,
                cancel_event.is_set,
                lambda transition: t2_fprint_worker_protocol.send_update(
                    connection, runtime.accept(transition)
                ),
                fallback_verified,
            )
            return enrollment(authority, live)

        stage = "run-compat-enrollment"
        result = broker_runner(
            None,
            operation="enroll",
            modification_allowed=True,
            consumer=consume,
            allow_user_interaction=True,
            collect_activation_authority=False,
            authorization_manager=authorization,
        )
        if (
            not isinstance(result, t2_user_broker.BrokerResult)
            or result.consumer_invoked is not True
            or not isinstance(
                result.value,
                t2_enrollment_coordinator.EnrollmentCoordinatorResult,
            )
        ):
            raise FprintWorkerError(
                "worker broker returned no enrollment result"
            )
        final = runtime.finish(result.value)
        t2_fprint_worker_protocol.send_update(connection, final)
        terminal_sent = True
        return result.value
    except BaseException as error:
        if not terminal_sent:
            try:
                update = (
                    runtime.refuse_pre_dispatch("capacity-exhausted")
                    if _capacity_exhausted(error)
                    else runtime.fail_unknown()
                )
                t2_fprint_worker_protocol.send_update(
                    connection, update
                )
            except BaseException:
                pass
        failure_stage = (
            error.stage
            if isinstance(error, FprintWorkerError)
            and error.stage != "outside-request"
            else stage
        )
        raise FprintWorkerError(
            "credential-scoped enrollment stopped", stage=failure_stage
        ) from error
    finally:
        completed_event.set()
        cancel_event.set()
        if authorization is not None:
            try:
                authorization.close()
            except BaseException:
                pass
        try:
            connection.shutdown(socket.SHUT_RD)
        except OSError:
            pass
        if listener is not None:
            listener.join(timeout=5)


def connect_endpoint(path: Path) -> socket.socket:
    """Connect only to the facade's operation-scoped private seqpacket path."""

    if not isinstance(path, Path) or not path.is_absolute():
        raise FprintWorkerError("worker endpoint path is invalid")
    try:
        relative = path.relative_to(WORKER_ROOT)
        operation_id = relative.stem
        parsed = uuid.UUID(operation_id)
        root = WORKER_ROOT.stat(follow_symlinks=False)
    except (OSError, ValueError, AttributeError) as error:
        raise FprintWorkerError("worker endpoint path is invalid") from error
    if (
        len(relative.parts) != 1
        or relative.suffix != ".sock"
        or str(parsed) != operation_id
        or parsed.int == 0
        or not stat.S_ISDIR(root.st_mode)
        or root.st_uid != os.geteuid()
        or root.st_mode & 0o077
    ):
        raise FprintWorkerError("worker endpoint path is unsafe")
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        connection.settimeout(30)
        connection.connect(str(path))
        connection.settimeout(None)
        return connection
    except BaseException:
        connection.close()
        raise
