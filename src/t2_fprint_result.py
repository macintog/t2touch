#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Validate probe results and project the resident worker's terminal record."""

from __future__ import annotations

import re


MAX_ENROLLED_IDENTITIES = 5
WORKER_TERMINAL_SCHEMA = 1
WORKER_TERMINAL_FIELDS = frozenset(
    {"schema_version", "selector", "verdict", "finger_name"}
)


def _is_finger_name(value: object) -> bool:
    return type(value) is str and re.fullmatch(r"finger-[1-5]", value) is not None


def verdict_from_probe_result(
    result: object, target_finger: str | None = None
) -> str:
    """Translate a full privacy-safe probe result into a fail-closed verdict."""

    if not isinstance(result, dict):
        raise RuntimeError("malformed T2 probe result")
    if target_finger is not None:
        gate = result.get("targeted_match_gate")
        post = result.get("targeted_match_post_attestation")
        if (
            target_finger == "any"
            or not _is_finger_name(target_finger)
            or not isinstance(gate, dict)
            or gate.get("finger_name") != target_finger
            or gate.get("single_identity_selected") is not True
            or gate.get("same_connection_inventory_stable") is not True
            or gate.get("local_live_reconciled") is not True
            or gate.get("identifiers_redacted") is not True
            or not isinstance(post, dict)
            or post.get("identity_state_unchanged") is not True
            or post.get("local_components_unchanged") is not True
            or post.get("per_user_inventory_unchanged") is not True
            or post.get("global_inventory_unchanged") is not True
            or post.get("identifiers_redacted") is not True
        ):
            raise RuntimeError("named T2 match attestation is incomplete")
    events = result.get("match_events", [])
    if not isinstance(events, list):
        raise RuntimeError("malformed T2 match event list")
    if result.get("match_cleanup_valid") is not True:
        raise RuntimeError("the T2 match did not close cleanly")
    if result.get("match_rejected") is True:
        raise RuntimeError("the T2 rejected match startup")
    verdict = None
    image_quality_rejected = False
    terminal_event = None
    repeated_terminal = False
    for event in events:
        if not isinstance(event, dict):
            raise RuntimeError("malformed T2 match event")
        if event.get("event_kind") != "match_result":
            continue
        if event.get("result_valid") is not True:
            raise RuntimeError("the T2 returned an invalid or unknown match result")
        if (
            event.get("matched") is True
            and event.get("no_match", False) is False
            and event.get("no_match_image_quality", False) is False
            and event.get("matches_enrolled_identity") is True
            and (
                target_finger is None
                or event.get("matches_selected_identity") is True
            )
        ):
            candidate = "verify-match"
        elif event.get("no_match") is True and event.get("matched") is False:
            if event.get("no_match_image_quality") is True:
                if verdict is not None:
                    raise RuntimeError("the T2 returned a retry after a terminal result")
                image_quality_rejected = True
                continue
            candidate = "verify-no-match"
        else:
            raise RuntimeError("the T2 returned an unclassifiable match result")
        if verdict is not None:
            same_identity = (
                target_finger is not None
                or (
                    terminal_event.get("matched_finger_name_present") is True
                    and event.get("matched_finger_name_present") is True
                    and _is_finger_name(event.get("matched_finger_name"))
                    and event["matched_finger_name"] == terminal_event.get("matched_finger_name")
                )
            )
            if (
                candidate != verdict
                or terminal_event.get("host_accepted_result") is not True
                or event.get("host_accepted_result") is not True
                or (candidate == "verify-match" and not same_identity)
                or (candidate == "verify-no-match" and (
                    terminal_event.get("no_match_matcher") is not True
                    or event.get("no_match_matcher") is not True
                ))
            ):
                raise RuntimeError("the T2 returned conflicting or unbound terminal results")
            repeated_terminal = True
        else:
            verdict, terminal_event = candidate, event
    if repeated_terminal:
        accepted = sum(event.get("event_kind") == "match_result"
                       and event.get("host_accepted_result") is True for event in events)
        generations = result.get("post_match_biolockout_generations")
        if (
            type(generations) is not list or len(generations) != accepted
            or any(type(generation) is not dict
                   or generation.get("linux_store_committed") is not True
                   or type(generation.get("match_result_generation")) is not int
                   or generation["match_result_generation"] != index
                   for index, generation in enumerate(generations, 1))
        ):
            raise RuntimeError("repeated T2 match results lack durable lockout state")
    if verdict is not None:
        return verdict
    if image_quality_rejected:
        raise RuntimeError(
            "the T2 match ended after image-quality retries without a verdict"
        )
    raise RuntimeError("the T2 match ended without a terminal verdict")


def resolved_any_finger_from_probe_result(result: object) -> str | None:
    """Return the canonical identity selected by an attested full result."""

    if not isinstance(result, dict):
        raise RuntimeError("malformed T2 probe result")
    gate = result.get("resolved_any_match_gate")
    post = result.get("resolved_any_match_post_attestation")
    if (
        not isinstance(gate, dict)
        or type(gate.get("identity_count")) is not int
        or not 1 <= gate["identity_count"] <= MAX_ENROLLED_IDENTITIES
        or gate.get("complete_named_inventory") is not True
        or gate.get("all_identities_selected") is not True
        or gate.get("same_connection_inventory_stable") is not True
        or gate.get("local_live_reconciled") is not True
        or gate.get("identifiers_redacted") is not True
        or not isinstance(post, dict)
        or post.get("identity_state_unchanged") is not True
        or post.get("local_components_unchanged") is not True
        or post.get("per_user_inventory_unchanged") is not True
        or post.get("global_inventory_unchanged") is not True
        or post.get("identifiers_redacted") is not True
    ):
        raise RuntimeError("resolved-any T2 match attestation is incomplete")
    if verdict_from_probe_result(result) == "verify-no-match":
        return None
    for event in result["match_events"]:
        if not isinstance(event, dict) or event.get("event_kind") != "match_result":
            continue
        if event.get("matched") is not True:
            continue
        finger_name = event.get("matched_finger_name")
        if (
            event.get("matches_enrolled_identity") is not True
            or event.get("matched_finger_name_present") is not True
            or not _is_finger_name(finger_name)
        ):
            raise RuntimeError("resolved-any T2 match result is incomplete")
        return finger_name
    raise RuntimeError("resolved-any T2 match result has no terminal identity")


def compact_worker_result(
    result: object,
    target_finger: str | None,
    resolve_any_finger: bool,
) -> dict[str, object]:
    """Validate the complete result before retaining only terminal semantics."""

    if target_finger is not None and resolve_any_finger:
        raise RuntimeError("native match identity selectors conflict")
    if not isinstance(result, dict) or any(
        result.get(field) is not expected
        for field, expected in (
            ("configured_identity_records_reconciled", True),
            ("bridge_os_transaction_released_after_match", True),
            ("termination_requested", False),
        )
    ):
        raise RuntimeError("native T2 match authority did not reconcile")
    if resolve_any_finger:
        finger_name = resolved_any_finger_from_probe_result(result)
        verdict = "verify-match" if finger_name is not None else "verify-no-match"
        selector = "resolve-any"
    else:
        verdict = verdict_from_probe_result(result, target_finger)
        finger_name = target_finger
        selector = "target" if target_finger is not None else "all"
    return {
        "schema_version": WORKER_TERMINAL_SCHEMA,
        "selector": selector,
        "verdict": verdict,
        "finger_name": finger_name,
    }


def validate_cancelled_probe_result(result: object, target_finger: str | None,
                                    resolve_any_finger: bool) -> None:
    """Prove reusable cleanup without turning cancellation into a verdict."""
    if type(result) is not dict or any(result.get(key) is not True for key in (
        "termination_requested", "configured_identity_records_reconciled",
        "bridge_os_transaction_released_after_match", "match_cleanup_valid",
        "post_cancel_callback_quiescent",
    )):
        raise RuntimeError("cancelled match cleanup is incomplete")
    if target_finger is not None or resolve_any_finger:
        key = ("targeted_match_post_attestation" if target_finger is not None
               else "resolved_any_match_post_attestation")
        post = result.get(key)
        if type(post) is not dict or any(post.get(field) is not True for field in (
            "identity_state_unchanged", "local_components_unchanged",
            "per_user_inventory_unchanged", "global_inventory_unchanged",
            "identifiers_redacted",
        )):
            raise RuntimeError("cancelled match identity attestation is incomplete")
    events = result.get("match_events")
    if type(events) is not list or any(type(event) is not dict for event in events):
        raise RuntimeError("cancelled match events are invalid")
    accepted = 0
    for event in events:
        if event.get("event_kind") == "match_result":
            if event.get("result_valid") is not True:
                raise RuntimeError("cancelled match contains an invalid result")
            accepted += event.get("host_accepted_result") is True
    generations = result.get("post_match_biolockout_generations", [])
    if (type(generations) is not list or len(generations) != accepted
            or any(type(g) is not dict or g.get("linux_store_committed") is not True
                   for g in generations)):
        raise RuntimeError("cancelled match has unpersisted lockout state")


def validate_worker_terminal_result(
    result: object,
    target_finger: str | None,
    resolve_any_finger: bool,
) -> tuple[str, str | None]:
    """Validate the exact bounded record accepted from the resident worker."""

    if (
        type(result) is not dict
        or set(result) != WORKER_TERMINAL_FIELDS
        or type(result.get("schema_version")) is not int
        or result.get("schema_version") != WORKER_TERMINAL_SCHEMA
        or result.get("verdict") not in {"verify-match", "verify-no-match"}
    ):
        raise RuntimeError("native T2 match terminal result is malformed")
    selector = result["selector"]
    finger_name = result["finger_name"]
    if resolve_any_finger:
        valid = (
            target_finger is None
            and selector == "resolve-any"
            and (
                (result["verdict"] == "verify-no-match" and finger_name is None)
                or (result["verdict"] == "verify-match" and _is_finger_name(finger_name))
            )
        )
    elif target_finger is not None:
        valid = (
            _is_finger_name(target_finger)
            and selector == "target"
            and finger_name == target_finger
        )
    else:
        valid = selector == "all" and finger_name is None
    if not valid:
        raise RuntimeError("native T2 match terminal selector is malformed")
    return result["verdict"], finger_name
