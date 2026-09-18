# SPDX-License-Identifier: GPL-2.0-only
"""Journaled recovery of a Linux-native retained-master generation.

This module owns only the protocol transaction.  The caller must retain the
mapped account's AKS/ACM authority and serialize it with other biometric work.
"""

from __future__ import annotations

import hashlib
import os
import stat
import struct
import uuid
from dataclasses import dataclass
from pathlib import Path

import t2_biolockout_store
import t2_bridge_inventory
import t2_bridge_wire as wire
import t2_catacomb_bridge
import t2_catacomb_codec
import t2_catacomb_protocol
import t2_compatibility_user_rebind
import t2_identity_inventory
import t2_mutation_journal
import t2_native_state_restore


KIND = "native-state-restore"
SUCCESS_MILESTONES = (
    "BASELINE_RECONCILED",
    "PREPARE_MASTER_INTENT",
    "PREPARE_MASTER_ACCEPTED",
    "PREPARE_USER_INTENT",
    "PREPARE_USER_ACCEPTED",
    "CLIENT_VERSION_SELECTED",
    "MISSING_COMPONENTS_RECONCILED",
    "SAVED_USER_LOAD_INTENT",
    "SAVED_USER_LOAD_ACCEPTED",
    "SAVED_USER_RECONCILED",
    "CATACOMB_PERSISTENCE_INTENT",
    "CATACOMB_PERSISTENCE_RECONCILED",
    "BIOLOCKOUT_LOAD_INTENT",
    "BIOLOCKOUT_RECONCILED",
    "RECOVERY_COMPLETE",
)
RESCUE_MILESTONES = (
    *SUCCESS_MILESTONES[:6],
    "MISSING_COMPONENTS_POST_STATE_REJECTED",
    "LOADED_EMPTY_USER_RECONCILED",
    "REMOVE_EMPTY_USER_INTENT",
    "REMOVE_EMPTY_USER_ACCEPTED",
    "REMOVED_USER_RECONCILED",
    "MASTER_EXPORT_PREPARE_INTENT",
    "MASTER_EXPORT_PREPARED",
    "MASTER_EXPORT_COMPLETE_INTENT",
    "MASTER_EXPORT_CAPTURED",
    "MASTER_EXPORT_CONFIRM_INTENT",
    "MASTER_EXPORT_CONFIRMED",
    "MASTER_SETTLED",
    "REPREPARE_MASTER_INTENT",
    "REPREPARE_MASTER_ACCEPTED",
    "REPREPARE_USER_INTENT",
    "REPREPARE_USER_ACCEPTED",
    "RECLIENT_VERSION_SELECTED",
    "MISSING_COMPONENTS_RECONCILED",
    *SUCCESS_MILESTONES[7:],
)
COLD_RESCUE_MILESTONES = (
    *RESCUE_MILESTONES[:23],
    "REPREPARED_COMPONENTS_POST_STATE_REJECTED",
    "COLD_RESTART_PREPARED",
    "COLD_SURFACE_RECONCILED",
    "RETAINED_MASTER_LOAD_INTENT",
    "RETAINED_MASTER_LOAD_ACCEPTED",
    "COLD_MASTER_RECONCILED",
    *SUCCESS_MILESTONES[7:],
)
CANONICAL_USER_MILESTONES = (
    "CANONICAL_USER_LOAD_INTENT",
    "CANONICAL_USER_LOAD_ACCEPTED",
    "SAVED_USER_RECONCILED",
    *SUCCESS_MILESTONES[10:],
)
CANONICAL_LOAD_MILESTONES = (
    "CANONICAL_MASTER_LOAD_INTENT",
    "CANONICAL_MASTER_LOAD_ACCEPTED",
    "CANONICAL_MASTER_RECONCILED",
    *CANONICAL_USER_MILESTONES,
)
CANONICAL_COLD_RESCUE_MILESTONES = (
    *COLD_RESCUE_MILESTONES[:26],
    *CANONICAL_LOAD_MILESTONES,
)
CANONICAL_REDIRECT_RESCUE_MILESTONES = (
    *COLD_RESCUE_MILESTONES[:29],
    "CANONICAL_RESTART_PREPARED",
    "CANONICAL_COLD_SURFACE_RECONCILED",
    *CANONICAL_LOAD_MILESTONES,
)
CANONICAL_REJECTION_RESCUE_MILESTONES = (
    *COLD_RESCUE_MILESTONES[:30],
    "SAVED_USER_LOAD_REPLY_REJECTED",
    "CANONICAL_RESTART_PREPARED",
    "CANONICAL_COLD_SURFACE_RECONCILED",
    *CANONICAL_LOAD_MILESTONES,
)
CANONICAL_DIRECT_MASTER_REPLY_RESCUE_MILESTONES = (
    *COLD_RESCUE_MILESTONES[:26],
    "CANONICAL_MASTER_LOAD_INTENT",
    "CANONICAL_MASTER_LOAD_REPLY_REJECTED",
    "CANONICAL_MASTER_REPLY_RECONCILED",
    *CANONICAL_USER_MILESTONES,
)
CANONICAL_REDIRECT_MASTER_REPLY_RESCUE_MILESTONES = (
    *COLD_RESCUE_MILESTONES[:29],
    "CANONICAL_RESTART_PREPARED",
    "CANONICAL_COLD_SURFACE_RECONCILED",
    "CANONICAL_MASTER_LOAD_INTENT",
    "CANONICAL_MASTER_LOAD_REPLY_REJECTED",
    "CANONICAL_MASTER_REPLY_RECONCILED",
    *CANONICAL_USER_MILESTONES,
)
CANONICAL_REJECTION_MASTER_REPLY_RESCUE_MILESTONES = (
    *COLD_RESCUE_MILESTONES[:30],
    "SAVED_USER_LOAD_REPLY_REJECTED",
    "CANONICAL_RESTART_PREPARED",
    "CANONICAL_COLD_SURFACE_RECONCILED",
    "CANONICAL_MASTER_LOAD_INTENT",
    "CANONICAL_MASTER_LOAD_REPLY_REJECTED",
    "CANONICAL_MASTER_REPLY_RECONCILED",
    *CANONICAL_USER_MILESTONES,
)
EMPTY_REPROVISION_MILESTONES = (
    *CANONICAL_REJECTION_MASTER_REPLY_RESCUE_MILESTONES[:37],
    "CANONICAL_USER_LOAD_REPLY_REJECTED",
    "EMPTY_REPROVISION_SURFACE_RECONCILED",
    "EMPTY_REPROVISION_MASTER_INTENT",
    "EMPTY_REPROVISION_MASTER_ACCEPTED",
    "EMPTY_REPROVISION_USER_INTENT",
    "EMPTY_REPROVISION_USER_ACCEPTED",
    "EMPTY_REPROVISION_CLIENT_SELECTED",
    "EMPTY_REPROVISION_READY",
    "EMPTY_REPROVISION_CATACOMBS_RECONCILED",
    "EMPTY_REPROVISION_BIOLOCKOUT_INTENT",
    "EMPTY_REPROVISION_BIOLOCKOUT_RECONCILED",
    "EMPTY_REPROVISION_COMPLETE",
)
# Current recovery loads the canonical master directly after the cold proof.
# Older journals first tried the derived master and crossed a second cold
# boundary. Both exact histories can reach the same proven user rejection;
# keep their prefixes distinct and share only the empty-reprovision suffix.
DIRECT_EMPTY_REPROVISION_MILESTONES = (
    *CANONICAL_DIRECT_MASTER_REPLY_RESCUE_MILESTONES[
        :CANONICAL_DIRECT_MASTER_REPLY_RESCUE_MILESTONES.index(
            "CANONICAL_USER_LOAD_ACCEPTED"
        )
    ],
    *EMPTY_REPROVISION_MILESTONES[
        EMPTY_REPROVISION_MILESTONES.index("CANONICAL_USER_LOAD_REPLY_REJECTED"):
    ],
)
FAILURE_MILESTONES = frozenset(
    {
        "PREPARE_MASTER_OUTCOME_UNKNOWN",
        "PREPARE_MASTER_REPLY_REJECTED",
        "PREPARE_USER_OUTCOME_UNKNOWN",
        "PREPARE_USER_REPLY_REJECTED",
        "CLIENT_VERSION_SELECTION_FAILED",
        "REMOVE_EMPTY_USER_OUTCOME_UNKNOWN",
        "REMOVE_EMPTY_USER_REPLY_REJECTED",
        "REMOVED_USER_POST_STATE_REJECTED",
        "MASTER_EXPORT_PREPARE_OUTCOME_UNKNOWN",
        "MASTER_EXPORT_COMPLETE_OUTCOME_UNKNOWN",
        "MASTER_EXPORT_CONFIRM_OUTCOME_UNKNOWN",
        "MASTER_SETTLE_POST_STATE_REJECTED",
        "REPREPARE_MASTER_OUTCOME_UNKNOWN",
        "REPREPARE_MASTER_REPLY_REJECTED",
        "REPREPARE_USER_OUTCOME_UNKNOWN",
        "REPREPARE_USER_REPLY_REJECTED",
        "RECLIENT_VERSION_SELECTION_FAILED",
        "RETAINED_MASTER_LOAD_OUTCOME_UNKNOWN",
        "RETAINED_MASTER_LOAD_REPLY_REJECTED",
        "RETAINED_MASTER_POST_STATE_REJECTED",
        "CANONICAL_MASTER_LOAD_OUTCOME_UNKNOWN",
        "CANONICAL_MASTER_LOAD_REPLY_REJECTED",
        "CANONICAL_MASTER_POST_STATE_REJECTED",
        "CANONICAL_USER_LOAD_OUTCOME_UNKNOWN",
        "CANONICAL_USER_LOAD_REPLY_REJECTED",
        "EMPTY_REPROVISION_MASTER_OUTCOME_UNKNOWN",
        "EMPTY_REPROVISION_MASTER_REPLY_REJECTED",
        "EMPTY_REPROVISION_USER_OUTCOME_UNKNOWN",
        "EMPTY_REPROVISION_USER_REPLY_REJECTED",
        "EMPTY_REPROVISION_CLIENT_SELECTION_FAILED",
        "EMPTY_REPROVISION_POST_STATE_REJECTED",
        "EMPTY_REPROVISION_BIOLOCKOUT_OUTCOME_UNKNOWN",
        "SAVED_USER_LOAD_OUTCOME_UNKNOWN",
        "SAVED_USER_LOAD_REPLY_REJECTED",
        "SAVED_USER_POST_STATE_REJECTED",
        "BIOLOCKOUT_LOAD_OUTCOME_UNKNOWN",
        "BIOLOCKOUT_POST_STATE_REJECTED",
    }
)
BASELINE_KEYS = frozenset(
    {
        "operation_kind",
        "apple_uid",
        "mapping_generation",
        "linux_boot_uuid",
        "connection_generation",
        "bridge_boot_uuid",
        "component_sha256",
        "identity_snapshot_sha256",
        "identity_count",
        "protocol_version",
        "double_collection_equal",
    }
)


class NativeStateRecoveryError(RuntimeError):
    """Raised when retained-master recovery is unsafe or incomplete."""


class NativeStateCommandRejected(NativeStateRecoveryError):
    """A well-formed command reply contains an explicit nonzero status."""

    def __init__(self, label: str, status: int):
        super().__init__(f"{label} was rejected")
        self.status = status


@dataclass(frozen=True)
class NativeStateRecoveryHistory:
    operation_id: str
    baseline: dict[str, object]
    milestone: str
    complete: bool
    blocked: bool
    component_sha256: dict[str, str]


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _require_sha256(value: object, field: str) -> None:
    if not isinstance(value, str) or len(value) != 64:
        raise NativeStateRecoveryError(f"{field} is invalid")
    try:
        bytes.fromhex(value)
    except ValueError as error:
        raise NativeStateRecoveryError(f"{field} is invalid") from error


def _canonical_uuid(value: object, field: str, *, nullable: bool = False) -> None:
    if nullable and value is None:
        return
    try:
        parsed = uuid.UUID(value)
    except (AttributeError, TypeError, ValueError) as error:
        raise NativeStateRecoveryError(f"{field} is invalid") from error
    if str(parsed) != value:
        raise NativeStateRecoveryError(f"{field} is invalid")


def _require_step_evidence(milestone: str, evidence: object) -> None:
    if not isinstance(evidence, dict):
        raise NativeStateRecoveryError("native-state recovery evidence is invalid")
    expected_keys = {
        "PREPARE_MASTER_INTENT": {"command", "component", "retry_permitted"},
        "PREPARE_MASTER_ACCEPTED": {"reply_received", "retry_permitted"},
        "PREPARE_USER_INTENT": {"command", "component", "retry_permitted"},
        "PREPARE_USER_ACCEPTED": {"reply_received", "retry_permitted"},
        "CLIENT_VERSION_SELECTED": {"client_version"},
        "MISSING_COMPONENTS_RECONCILED": {
            "master_state", "user_state", "identity_count", "group_state_count"
        },
        "MISSING_COMPONENTS_POST_STATE_REJECTED": {
            "stable_surface_rejected", "retry_permitted"
        },
        "REPREPARED_COMPONENTS_POST_STATE_REJECTED": {
            "stable_surface_rejected", "retry_permitted"
        },
        "LOADED_EMPTY_USER_RECONCILED": {
            "master_state", "user_state", "identity_count", "group_state_count"
        },
        "REMOVE_EMPTY_USER_INTENT": {
            "command", "component", "retry_permitted"
        },
        "REMOVE_EMPTY_USER_ACCEPTED": {"reply_received", "retry_permitted"},
        "REMOVED_USER_RECONCILED": {
            "master_state", "identity_count", "group_state_count"
        },
        "MASTER_EXPORT_PREPARE_INTENT": {
            "component", "descriptor_sha256", "retry_permitted"
        },
        "MASTER_EXPORT_PREPARED": {"component", "expected_length"},
        "MASTER_EXPORT_COMPLETE_INTENT": {"component", "retry_permitted"},
        "MASTER_EXPORT_CAPTURED": {
            "component", "secure_data_sha256", "encoded_sha256",
            "encoded_enrollment_count",
        },
        "MASTER_EXPORT_CONFIRM_INTENT": {"component", "retry_permitted"},
        "MASTER_EXPORT_CONFIRMED": {"component", "status"},
        "MASTER_SETTLED": {
            "master_state", "identity_count", "group_state_count"
        },
        "REPREPARE_MASTER_INTENT": {"command", "component", "retry_permitted"},
        "REPREPARE_MASTER_ACCEPTED": {"reply_received", "retry_permitted"},
        "REPREPARE_USER_INTENT": {"command", "component", "retry_permitted"},
        "REPREPARE_USER_ACCEPTED": {"reply_received", "retry_permitted"},
        "RECLIENT_VERSION_SELECTED": {"client_version"},
        "COLD_RESTART_PREPARED": {
            "source_linux_boot_uuid", "intermediate_master_sha256",
            "candidate_master_sha256", "identity_count",
        },
        "COLD_SURFACE_RECONCILED": {
            "different_linux_boot", "master_state", "user_state",
            "identity_count", "group_state_count",
        },
        "RETAINED_MASTER_LOAD_INTENT": {
            "command", "component", "secure_data_sha256", "identity_count",
            "retry_permitted",
        },
        "RETAINED_MASTER_LOAD_ACCEPTED": {
            "reply_received", "retry_permitted"
        },
        "COLD_MASTER_RECONCILED": {
            "master_state", "user_state", "identity_count", "group_state_count"
        },
        "CANONICAL_RESTART_PREPARED": {
            "source_linux_boot_uuid", "master_sha256", "master_secure_data_sha256",
            "user_secure_data_sha256", "identity_count",
        },
        "CANONICAL_COLD_SURFACE_RECONCILED": {
            "different_linux_boot", "master_state", "user_state",
            "identity_count", "group_state_count",
        },
        "CANONICAL_MASTER_LOAD_INTENT": {
            "command", "component", "secure_data_sha256", "identity_count",
            "retry_permitted",
        },
        "CANONICAL_MASTER_LOAD_ACCEPTED": {
            "reply_received", "retry_permitted"
        },
        "CANONICAL_MASTER_RECONCILED": {
            "master_state", "user_state", "identity_count", "group_state_count"
        },
        "CANONICAL_MASTER_REPLY_RECONCILED": {
            "master_state", "user_state", "identity_count", "group_state_count",
            "nonzero_reply", "load_replayed",
        },
        "CANONICAL_USER_LOAD_INTENT": {
            "command", "component", "secure_data_sha256", "identity_count",
            "retry_permitted",
        },
        "CANONICAL_USER_LOAD_ACCEPTED": {
            "reply_received", "retry_permitted"
        },
        "SAVED_USER_LOAD_INTENT": {
            "command", "component", "secure_data_sha256", "identity_count",
            "retry_permitted",
        },
        "SAVED_USER_LOAD_ACCEPTED": {"reply_received", "retry_permitted"},
        "SAVED_USER_RECONCILED": {"identity_count", "group_state_count"},
        "CATACOMB_PERSISTENCE_INTENT": {
            "persistence_required", "retry_permitted"
        },
        "BIOLOCKOUT_LOAD_INTENT": {"payload_sha256", "retry_permitted"},
        "BIOLOCKOUT_RECONCILED": {"payload_sha256"},
        "RECOVERY_COMPLETE": {
            "identity_count", "identifiers_redacted"
        },
        "EMPTY_REPROVISION_SURFACE_RECONCILED": {
            "master_state", "identity_count", "group_state_count"
        },
        "EMPTY_REPROVISION_MASTER_INTENT": {
            "command", "component", "retry_permitted"
        },
        "EMPTY_REPROVISION_MASTER_ACCEPTED": {
            "reply_received", "retry_permitted"
        },
        "EMPTY_REPROVISION_USER_INTENT": {
            "command", "component", "retry_permitted"
        },
        "EMPTY_REPROVISION_USER_ACCEPTED": {
            "reply_received", "retry_permitted"
        },
        "EMPTY_REPROVISION_CLIENT_SELECTED": {"client_version"},
        "EMPTY_REPROVISION_READY": {
            "master_state", "user_state", "identity_count", "group_state_count"
        },
        "EMPTY_REPROVISION_CATACOMBS_RECONCILED": {
            "identity_count", "master_enrollment_count", "component_sha256"
        },
        "EMPTY_REPROVISION_BIOLOCKOUT_INTENT": {
            "payload_sha256", "retry_permitted"
        },
        "EMPTY_REPROVISION_BIOLOCKOUT_RECONCILED": {"payload_sha256"},
        "EMPTY_REPROVISION_COMPLETE": {
            "identity_count", "fingerprint_reenrollment_required",
            "identifiers_redacted"
        },
    }
    if (
        milestone in {"CLIENT_VERSION_SELECTED", "RECLIENT_VERSION_SELECTED"}
        and set(evidence) == {"client_version", "reconnected"}
    ):
        if evidence["reconnected"] is not True:
            raise NativeStateRecoveryError(
                "native-state recovery evidence is invalid"
            )
        return
    if milestone == "CATACOMB_PERSISTENCE_RECONCILED":
        return
    if milestone in FAILURE_MILESTONES:
        if evidence.get("retry_permitted") is not False:
            raise NativeStateRecoveryError(
                "native-state recovery failure evidence is invalid"
            )
        if "reply_status" in evidence and (
            not milestone.endswith("_REPLY_REJECTED")
            or type(evidence["reply_status"]) is not int
            or not 0 < evidence["reply_status"] <= 0xFFFFFFFF
            or evidence.get("reply_received") is not True
        ):
            raise NativeStateRecoveryError("native-state recovery reply status is invalid")
        return
    keys = expected_keys.get(milestone)
    if keys is None or set(evidence) != keys:
        raise NativeStateRecoveryError("native-state recovery evidence is invalid")
    if milestone in {
        "PREPARE_MASTER_INTENT", "PREPARE_USER_INTENT",
        "REPREPARE_MASTER_INTENT", "REPREPARE_USER_INTENT",
        "EMPTY_REPROVISION_MASTER_INTENT", "EMPTY_REPROVISION_USER_INTENT",
    }:
        expected_component = (
            "master" if "MASTER" in milestone else "selected-user"
        )
        expected_command = 0x31
        if (
            evidence["command"] != expected_command
            or evidence["component"] != expected_component
            or evidence["retry_permitted"] is not False
        ):
            raise NativeStateRecoveryError(
                "native-state recovery evidence is invalid"
            )
    elif milestone == "REMOVE_EMPTY_USER_INTENT":
        if (
            evidence["command"] != 0x48
            or evidence["component"] != "selected-user"
            or evidence["retry_permitted"] is not False
        ):
            raise NativeStateRecoveryError(
                "native-state recovery evidence is invalid"
            )
    elif milestone in {
        "MISSING_COMPONENTS_POST_STATE_REJECTED",
        "REPREPARED_COMPONENTS_POST_STATE_REJECTED",
    }:
        if (
            evidence["stable_surface_rejected"] is not True
            or evidence["retry_permitted"] is not False
        ):
            raise NativeStateRecoveryError(
                "native-state recovery evidence is invalid"
            )
    elif milestone == "LOADED_EMPTY_USER_RECONCILED":
        if (
            evidence["master_state"] not in {3, 7}
            or evidence["user_state"] not in {3, 7}
            or evidence["identity_count"] != 0
            or evidence["group_state_count"] != 0
        ):
            raise NativeStateRecoveryError(
                "native-state recovery evidence is invalid"
            )
    elif milestone == "REMOVED_USER_RECONCILED":
        if evidence != {
            "master_state": 7,
            "identity_count": 0,
            "group_state_count": 0,
        }:
            raise NativeStateRecoveryError(
                "native-state recovery evidence is invalid"
            )
    elif milestone == "MASTER_EXPORT_PREPARE_INTENT":
        _require_sha256(evidence["descriptor_sha256"], "master descriptor")
        if (
            evidence["component"] != "master"
            or evidence["retry_permitted"] is not False
        ):
            raise NativeStateRecoveryError(
                "native-state recovery evidence is invalid"
            )
    elif milestone == "MASTER_EXPORT_PREPARED":
        if (
            evidence["component"] != "master"
            or type(evidence["expected_length"]) is not int
            or not 0
            < evidence["expected_length"]
            <= t2_catacomb_protocol.MAX_SECURE_BLOB_SIZE
        ):
            raise NativeStateRecoveryError(
                "native-state recovery evidence is invalid"
            )
    elif milestone == "MASTER_EXPORT_CAPTURED":
        _require_sha256(evidence["secure_data_sha256"], "master secure data")
        _require_sha256(evidence["encoded_sha256"], "intermediate master")
        if (
            evidence["component"] != "master"
            or evidence["encoded_enrollment_count"] != 0
        ):
            raise NativeStateRecoveryError(
                "native-state recovery evidence is invalid"
            )
    elif milestone in {
        "MASTER_EXPORT_COMPLETE_INTENT", "MASTER_EXPORT_CONFIRM_INTENT"
    }:
        if (
            evidence["component"] != "master"
            or evidence["retry_permitted"] is not False
        ):
            raise NativeStateRecoveryError(
                "native-state recovery evidence is invalid"
            )
    elif milestone == "MASTER_EXPORT_CONFIRMED":
        if evidence != {"component": "master", "status": 0}:
            raise NativeStateRecoveryError(
                "native-state recovery evidence is invalid"
            )
    elif milestone == "MASTER_SETTLED":
        if evidence != {
            "master_state": 3,
            "identity_count": 0,
            "group_state_count": 0,
        }:
            raise NativeStateRecoveryError(
                "native-state recovery evidence is invalid"
            )
    elif milestone == "COLD_RESTART_PREPARED":
        _canonical_uuid(evidence["source_linux_boot_uuid"], "source Linux boot UUID")
        _require_sha256(
            evidence["intermediate_master_sha256"], "intermediate master"
        )
        _require_sha256(evidence["candidate_master_sha256"], "candidate master")
        if type(evidence["identity_count"]) is not int or evidence[
            "identity_count"
        ] <= 0:
            raise NativeStateRecoveryError(
                "native-state recovery evidence is invalid"
            )
    elif milestone == "COLD_SURFACE_RECONCILED":
        if (
            evidence["different_linux_boot"] is not True
            or evidence["master_state"] != 1
            or evidence["user_state"] not in {None, 1}
            or evidence["identity_count"] != 0
            or evidence["group_state_count"] != 0
        ):
            raise NativeStateRecoveryError(
                "native-state recovery evidence is invalid"
            )
    elif milestone == "RETAINED_MASTER_LOAD_INTENT":
        _require_sha256(evidence["secure_data_sha256"], "retained master")
        if (
            evidence["command"] != 0x40
            or evidence["component"] != "master"
            or type(evidence["identity_count"]) is not int
            or evidence["identity_count"] <= 0
            or evidence["retry_permitted"] is not False
        ):
            raise NativeStateRecoveryError(
                "native-state recovery evidence is invalid"
            )
    elif milestone == "COLD_MASTER_RECONCILED":
        if (
            evidence["master_state"] != 3
            or evidence["user_state"] not in {None, 1}
            or evidence["identity_count"] != 0
            or evidence["group_state_count"] != 0
        ):
            raise NativeStateRecoveryError(
                "native-state recovery evidence is invalid"
            )
    elif milestone == "CANONICAL_RESTART_PREPARED":
        _canonical_uuid(evidence["source_linux_boot_uuid"], "source Linux boot UUID")
        _require_sha256(evidence["master_sha256"], "canonical master")
        _require_sha256(
            evidence["master_secure_data_sha256"], "canonical master secure data"
        )
        _require_sha256(
            evidence["user_secure_data_sha256"], "canonical user secure data"
        )
        if type(evidence["identity_count"]) is not int or evidence[
            "identity_count"
        ] <= 0:
            raise NativeStateRecoveryError(
                "native-state recovery evidence is invalid"
            )
    elif milestone == "CANONICAL_COLD_SURFACE_RECONCILED":
        if (
            evidence["different_linux_boot"] is not True
            or evidence["master_state"] != 1
            or evidence["user_state"] not in {None, 1}
            or evidence["identity_count"] != 0
            or evidence["group_state_count"] != 0
        ):
            raise NativeStateRecoveryError(
                "native-state recovery evidence is invalid"
            )
    elif milestone in {
        "CANONICAL_MASTER_LOAD_INTENT", "CANONICAL_USER_LOAD_INTENT"
    }:
        _require_sha256(evidence["secure_data_sha256"], "canonical payload")
        component = (
            "master" if milestone == "CANONICAL_MASTER_LOAD_INTENT"
            else "selected-user"
        )
        if (
            evidence["command"] != 0x40
            or evidence["component"] != component
            or type(evidence["identity_count"]) is not int
            or evidence["identity_count"] <= 0
            or evidence["retry_permitted"] is not False
        ):
            raise NativeStateRecoveryError(
                "native-state recovery evidence is invalid"
            )
    elif milestone == "CANONICAL_MASTER_RECONCILED":
        if (
            evidence["master_state"] != 3
            or evidence["user_state"] not in {None, 1}
            or evidence["identity_count"] != 0
            or evidence["group_state_count"] != 0
        ):
            raise NativeStateRecoveryError(
                "native-state recovery evidence is invalid"
            )
    elif milestone == "CANONICAL_MASTER_REPLY_RECONCILED":
        if evidence != {
            "master_state": 3,
            "user_state": None,
            "identity_count": 0,
            "group_state_count": 0,
            "nonzero_reply": True,
            "load_replayed": False,
        }:
            raise NativeStateRecoveryError(
                "native-state recovery evidence is invalid"
            )
    elif milestone == "SAVED_USER_LOAD_INTENT":
        _require_sha256(evidence["secure_data_sha256"], "saved-user payload")
        if (
            evidence["command"] != 0x40
            or evidence["component"] != "selected-user"
            or evidence["retry_permitted"] is not False
        ):
            raise NativeStateRecoveryError(
                "native-state recovery evidence is invalid"
            )
    elif milestone in {"BIOLOCKOUT_LOAD_INTENT", "BIOLOCKOUT_RECONCILED"}:
        _require_sha256(evidence["payload_sha256"], "BioLockout payload")
        if (
            milestone == "BIOLOCKOUT_LOAD_INTENT"
            and evidence["retry_permitted"] is not False
        ):
            raise NativeStateRecoveryError(
                "native-state recovery evidence is invalid"
            )
    elif milestone == "RECOVERY_COMPLETE":
        if evidence["identifiers_redacted"] is not True:
            raise NativeStateRecoveryError(
                "native-state recovery evidence is invalid"
            )
    elif milestone == "EMPTY_REPROVISION_CATACOMBS_RECONCILED":
        if (
            evidence["identity_count"] != 0
            or evidence["master_enrollment_count"] != 0
            or not isinstance(evidence["component_sha256"], dict)
        ):
            raise NativeStateRecoveryError(
                "empty reprovision persistence evidence is invalid"
            )
        for name, digest in evidence["component_sha256"].items():
            _require_sha256(digest, f"empty reprovision {name} digest")
    elif milestone == "EMPTY_REPROVISION_SURFACE_RECONCILED":
        if evidence != {
            "master_state": 3,
            "identity_count": 0,
            "group_state_count": 0,
        }:
            raise NativeStateRecoveryError(
                "empty reprovision surface evidence is invalid"
            )
    elif milestone == "EMPTY_REPROVISION_READY":
        if (
            evidence["master_state"] not in {3, 7}
            or evidence["user_state"] != 7
            or evidence["identity_count"] != 0
            or evidence["group_state_count"] != 0
        ):
            raise NativeStateRecoveryError(
                "empty reprovision ready evidence is invalid"
            )
    elif milestone in {
        "EMPTY_REPROVISION_BIOLOCKOUT_INTENT",
        "EMPTY_REPROVISION_BIOLOCKOUT_RECONCILED",
    }:
        _require_sha256(evidence["payload_sha256"], "BioLockout payload")
        if (
            milestone == "EMPTY_REPROVISION_BIOLOCKOUT_INTENT"
            and evidence["retry_permitted"] is not False
        ):
            raise NativeStateRecoveryError(
                "empty reprovision BioLockout evidence is invalid"
            )
    elif milestone == "EMPTY_REPROVISION_COMPLETE":
        if evidence != {
            "identity_count": 0,
            "fingerprint_reenrollment_required": True,
            "identifiers_redacted": True,
        }:
            raise NativeStateRecoveryError(
                "empty reprovision completion evidence is invalid"
            )
    elif "retry_permitted" in evidence and evidence["retry_permitted"] is not False:
        raise NativeStateRecoveryError("native-state recovery evidence is invalid")


def validate_history(records: list[dict[str, object]]) -> NativeStateRecoveryHistory:
    """Validate one exact append-only recovery history."""
    if not records:
        raise NativeStateRecoveryError("native-state recovery journal is empty")
    semantic = [
        record
        for record in records
        if not t2_mutation_journal.is_repair_milestone(record.get("milestone"))
    ]
    milestones = [record.get("milestone") for record in semantic]
    success_sequences = (
        SUCCESS_MILESTONES,
        RESCUE_MILESTONES,
        COLD_RESCUE_MILESTONES,
        CANONICAL_COLD_RESCUE_MILESTONES,
        CANONICAL_REDIRECT_RESCUE_MILESTONES,
        CANONICAL_REJECTION_RESCUE_MILESTONES,
        CANONICAL_DIRECT_MASTER_REPLY_RESCUE_MILESTONES,
        CANONICAL_REDIRECT_MASTER_REPLY_RESCUE_MILESTONES,
        CANONICAL_REJECTION_MASTER_REPLY_RESCUE_MILESTONES,
        EMPTY_REPROVISION_MILESTONES,
        DIRECT_EMPTY_REPROVISION_MILESTONES,
    )
    exact_prefix = any(
        milestones == list(sequence[: len(milestones)])
        for sequence in success_sequences
    )
    failure = milestones[-1] in FAILURE_MILESTONES
    if failure:
        prefix = milestones[:-1]
        if not any(
            prefix == list(sequence[: len(prefix)])
            for sequence in success_sequences
        ):
            raise NativeStateRecoveryError("native-state recovery history is invalid")
    elif not exact_prefix:
        raise NativeStateRecoveryError("native-state recovery history is invalid")
    first = semantic[0]
    evidence = first.get("evidence")
    if not isinstance(evidence, dict) or set(evidence) != BASELINE_KEYS:
        raise NativeStateRecoveryError("native-state recovery baseline is invalid")
    if (
        evidence.get("operation_kind") != KIND
        or type(evidence.get("apple_uid")) is not int
        or not 0 <= evidence["apple_uid"] <= 0x7FFFFFFF
        or type(evidence.get("identity_count")) is not int
        or evidence["identity_count"] <= 0
        or evidence.get("protocol_version") != 2
        or evidence.get("double_collection_equal") is not True
    ):
        raise NativeStateRecoveryError("native-state recovery baseline is invalid")
    _require_sha256(evidence.get("mapping_generation"), "mapping generation")
    _require_sha256(evidence.get("identity_snapshot_sha256"), "identity snapshot")
    _canonical_uuid(evidence.get("linux_boot_uuid"), "Linux boot UUID")
    _canonical_uuid(evidence.get("connection_generation"), "connection generation")
    _canonical_uuid(evidence.get("bridge_boot_uuid"), "bridge boot UUID", nullable=True)
    components = evidence.get("component_sha256")
    expected_names = {
        "master.cat",
        "biolockout.cat",
        f'user_{evidence["apple_uid"]:08x}.cat',
    }
    if not isinstance(components, dict) or set(components) != expected_names:
        raise NativeStateRecoveryError("native-state recovery components are invalid")
    for name, digest in components.items():
        _require_sha256(digest, f"{name} digest")
    for record in semantic[1:]:
        _require_step_evidence(
            str(record.get("milestone")), record.get("evidence")
        )
    operation_id = first.get("operation_id")
    _canonical_uuid(operation_id, "operation ID")
    if any(record.get("operation_id") != operation_id for record in records):
        raise NativeStateRecoveryError("native-state recovery operation changed")
    component_sha256 = dict(components)
    for record in semantic:
        if record.get("milestone") != "CATACOMB_PERSISTENCE_RECONCILED":
            continue
        persisted = record.get("evidence")
        if not isinstance(persisted, dict) or set(persisted) != {
            "persisted",
            "catacomb_clean",
            "component_sha256",
            "identity_snapshot_sha256",
        }:
            raise NativeStateRecoveryError(
                "Catacomb persistence evidence is invalid"
            )
        if (
            type(persisted["persisted"]) is not bool
            or persisted["catacomb_clean"] is not True
            or persisted["identity_snapshot_sha256"]
            != evidence["identity_snapshot_sha256"]
            or not isinstance(persisted["component_sha256"], dict)
            or set(persisted["component_sha256"]) != expected_names
        ):
            raise NativeStateRecoveryError(
                "Catacomb persistence evidence is invalid"
            )
        for name, digest in persisted["component_sha256"].items():
            _require_sha256(digest, f"persisted {name} digest")
        component_sha256 = dict(persisted["component_sha256"])
    milestone = str(milestones[-1])
    return NativeStateRecoveryHistory(
        str(operation_id), evidence, milestone,
        milestone in {"RECOVERY_COMPLETE", "EMPTY_REPROVISION_COMPLETE"},
        failure,
        component_sha256,
    )


def canonical_restart_is_resumable(records: list[dict[str, object]]) -> bool:
    """Identify only the hardware-proven derived-master redirect boundary."""
    history = validate_history(records)
    milestones = [
        record.get("milestone")
        for record in records
        if not t2_mutation_journal.is_repair_milestone(record.get("milestone"))
    ]
    return (
        history.milestone
        in {"COLD_MASTER_RECONCILED", "SAVED_USER_LOAD_REPLY_REJECTED"}
        and "COLD_SURFACE_RECONCILED" in milestones
        and "RETAINED_MASTER_LOAD_ACCEPTED" in milestones
        and "COLD_MASTER_RECONCILED" in milestones
    )


def canonical_master_reply_is_resumable(
    records: list[dict[str, object]],
) -> bool:
    """Retain the legacy API without admitting rejected master loads.

    Firmware can return corrupt-Catacomb status 0x8002 and still expose an
    empty master in state 3. That surface does not prove the archive loaded.
    Keep old histories readable, but never advance from this failed command.
    """
    validate_history(records)
    return False


def empty_reprovision_is_resumable(
    records: list[dict[str, object]],
) -> bool:
    """Admit only the proven incompatible-user path into empty reprovision."""
    history = validate_history(records)
    milestones = [
        record.get("milestone")
        for record in records
        if not t2_mutation_journal.is_repair_milestone(record.get("milestone"))
    ]
    rejection = next(record for record in reversed(records)
                     if not t2_mutation_journal.is_repair_milestone(record.get("milestone")))
    return (
        history.milestone == "CANONICAL_USER_LOAD_REPLY_REJECTED"
        # Older writers conflated malformed replies/events with rejection.
        # Preserve their journals, but do not infer loss authorization from
        # evidence that cannot establish an explicit firmware rejection.
        and type(rejection["evidence"].get("reply_status")) is int
        and 0 < rejection["evidence"]["reply_status"] <= 0xFFFFFFFF
        and any(
            milestones == list(sequence[: len(milestones)])
            for sequence in (
                EMPTY_REPROVISION_MILESTONES,
                DIRECT_EMPTY_REPROVISION_MILESTONES,
            )
        )
    )


def _append(
    path: Path,
    operation_id: str,
    milestone: str,
    evidence: dict[str, object],
) -> NativeStateRecoveryHistory:
    records = t2_mutation_journal.read(path)
    validate_history(records)
    previous = records[-1]
    t2_mutation_journal.append(
        path,
        operation_id,
        milestone,
        evidence,
        expected_record_count=len(records),
        expected_previous_hash=str(previous["record_hash"]),
    )
    return validate_history(t2_mutation_journal.read(path))


def create_journal(
    path: Path,
    operation_id: str,
    *,
    apple_user_id: int,
    mapping_generation: str,
    linux_boot_uuid: str,
    live: dict[str, object],
    components: dict[str, bytes],
    user: t2_catacomb_codec.UserCatacomb,
) -> NativeStateRecoveryHistory:
    if not is_retained_master_inventory(live, apple_user_id):
        raise NativeStateRecoveryError("live state is not an exact retained master")
    expected_names = {
        "master.cat",
        "biolockout.cat",
        f"user_{apple_user_id:08x}.cat",
    }
    if set(components) != expected_names or not user.identities:
        raise NativeStateRecoveryError("committed recovery authority is incomplete")
    identity_records = sorted(
        (identity.user_id, identity.uuid, identity.entity)
        for identity in user.identities
    )
    evidence = {
        "operation_kind": KIND,
        "apple_uid": apple_user_id,
        "mapping_generation": mapping_generation,
        "linux_boot_uuid": linux_boot_uuid,
        "connection_generation": live["connection_generation"],
        "bridge_boot_uuid": live.get("bridge_boot_uuid"),
        "component_sha256": {
            name: _sha256(components[name]) for name in sorted(components)
        },
        "identity_snapshot_sha256": _sha256(
            t2_mutation_journal.canonical(identity_records)
        ),
        "identity_count": len(identity_records),
        "protocol_version": 2,
        "double_collection_equal": True,
    }
    t2_mutation_journal.append(
        path,
        operation_id,
        "BASELINE_RECONCILED",
        evidence,
        exclusive=True,
    )
    return validate_history(t2_mutation_journal.read(path))


def require_authority_unchanged(
    history: NativeStateRecoveryHistory,
    *,
    apple_user_id: int,
    mapping_generation: str,
    components: dict[str, bytes],
    user: t2_catacomb_codec.UserCatacomb,
) -> None:
    identity_records = sorted(
        (identity.user_id, identity.uuid, identity.entity)
        for identity in user.identities
    )
    expected_hashes = {
        name: _sha256(data) for name, data in sorted(components.items())
    }
    baseline = history.baseline
    if (
        baseline["apple_uid"] != apple_user_id
        or baseline["mapping_generation"] != mapping_generation
        or history.component_sha256 != expected_hashes
        or baseline["identity_count"] != len(identity_records)
        or baseline["identity_snapshot_sha256"]
        != _sha256(t2_mutation_journal.canonical(identity_records))
    ):
        raise NativeStateRecoveryError("saved native authority changed during recovery")


def is_retained_master_inventory(live: object, apple_user_id: int) -> bool:
    """Recognize the hardware-observed state-3 master-only generation."""
    if not isinstance(live, dict):
        return False
    catacomb = live.get("catacomb")
    return (
        live.get("double_collection_equal") is True
        and live.get("apple_uid") == apple_user_id
        and live.get("biometric_protocol_version") == 2
        and live.get("per_user_identity_records") == []
        and live.get("global_identity_records") == []
        and isinstance(catacomb, dict)
        and catacomb.get("present") is False
        and catacomb.get("uuid") == str(uuid.UUID(int=0))
        and catacomb.get("hash") == "0" * 64
        and catacomb.get("user_states")
        == [
            {
                "kind": "master",
                "user_id": 0xFFFFFFFF,
                "state": 3,
                "needs_save": False,
            }
        ]
    )


def _reply_output(reply: object, events: object, label: str, apple_user_id: int) -> bytes:
    try:
        t2_bridge_inventory.require_preparation_service_events(events, apple_user_id)
    except t2_bridge_inventory.BridgeInventoryError as error:
        raise NativeStateRecoveryError(f"{label} emitted an unexpected event") from error
    if (
        type(reply) is not list or len(reply) not in (1, 2)
        or type(reply[0]) is not int or not 0 <= reply[0] <= 0xFFFFFFFF
    ):
        raise NativeStateRecoveryError(f"{label} returned malformed status")
    output = b"" if len(reply) == 1 else reply[1]
    if wire.is_biometric_nil_output(output):
        output = b""
    if type(output) is not bytes or output:
        raise NativeStateRecoveryError(f"{label} returned malformed output")
    if reply[0] != 0:
        raise NativeStateCommandRejected(label, reply[0])
    return output


def _record_reply_failure(
    path: Path, operation_id: str, command: str, error: NativeStateRecoveryError
) -> None:
    if isinstance(error, NativeStateCommandRejected):
        _append(path, operation_id, f"{command}_REPLY_REJECTED", {
            "reply_received": True, "retry_permitted": False,
            "reply_status": error.status,
        })
    else:
        _append(path, operation_id, f"{command}_OUTCOME_UNKNOWN", {
            "dispatch_attempted": True, "reply_received": True,
            "retry_permitted": False,
        })


def prepare_missing_components(
    lease,
    *,
    apple_user_id: int,
    journal_path: Path,
) -> NativeStateRecoveryHistory:
    """Run the observed pre-client master-then-user admission sequence once."""
    history = validate_history(t2_mutation_journal.read(journal_path))
    if (
        history.milestone
        not in {"BASELINE_RECONCILED", "PREPARE_MASTER_ACCEPTED"}
        or getattr(lease, "client_version", None) != 0
    ):
        raise NativeStateRecoveryError(
            "missing-component preparation is not at its initial boundary"
        )
    try:
        t2_bridge_inventory.attest_preclient_protocol(lease, apple_user_id)
    except t2_bridge_inventory.BridgeInventoryError as error:
        raise NativeStateRecoveryError("pre-client protocol attestation failed") from error
    commands = (
        (0xFFFFFFFF, "master", "PREPARE_MASTER_INTENT", "PREPARE_MASTER_ACCEPTED"),
        (apple_user_id, "selected-user", "PREPARE_USER_INTENT", "PREPARE_USER_ACCEPTED"),
    )
    if history.milestone == "PREPARE_MASTER_ACCEPTED":
        commands = commands[1:]
    for component, name, intent, accepted in commands:
        history = _append(
            journal_path,
            history.operation_id,
            intent,
            {"command": 0x31, "component": name, "retry_permitted": False},
        )
        try:
            reply, events = lease.biometric_command(
                0x31,
                version=1,
                value=0,
                data=struct.pack("<I", component),
                output_capacity=0,
            )
        except BaseException as error:
            _append(
                journal_path,
                history.operation_id,
                f"{intent.removesuffix('_INTENT')}_OUTCOME_UNKNOWN",
                {"dispatch_attempted": True, "retry_permitted": False},
            )
            raise NativeStateRecoveryError(
                f"{name} preparation outcome is unknown; do not retry"
            ) from error
        try:
            _reply_output(reply, events, f"{name} preparation", apple_user_id)
        except NativeStateRecoveryError as error:
            _record_reply_failure(journal_path, history.operation_id,
                                  intent.removesuffix('_INTENT'), error)
            raise
        history = _append(
            journal_path,
            history.operation_id,
            accepted,
            {"reply_received": True, "retry_permitted": False},
        )
    try:
        version = lease.select_client_version()
    except BaseException as error:
        _append(
            journal_path,
            history.operation_id,
            "CLIENT_VERSION_SELECTION_FAILED",
            {"commands_accepted": True, "retry_permitted": False},
        )
        raise NativeStateRecoveryError(
            "component preparation succeeded but client selection failed"
        ) from error
    history = _append(
        journal_path,
        history.operation_id,
        "CLIENT_VERSION_SELECTED",
        {"client_version": version},
    )
    return reconcile_missing_components(
        lease, apple_user_id=apple_user_id, journal_path=journal_path
    )


def reconcile_missing_components(
    lease,
    *,
    apple_user_id: int,
    journal_path: Path,
) -> NativeStateRecoveryHistory:
    """Prove the prepared component pair without repeating command 0x31."""
    history = validate_history(t2_mutation_journal.read(journal_path))
    if history.milestone not in {
        "CLIENT_VERSION_SELECTED",
        "PREPARE_USER_ACCEPTED",
    }:
        raise NativeStateRecoveryError(
            "missing-component readback is not at its accepted boundary"
        )
    if history.milestone == "PREPARE_USER_ACCEPTED":
        version = getattr(lease, "client_version", None)
        if version not in (1, 2):
            raise NativeStateRecoveryError(
                "missing-component readback requires a selected client"
            )
        history = _append(
            journal_path,
            history.operation_id,
            "CLIENT_VERSION_SELECTED",
            {"client_version": version, "reconnected": True},
        )
    surface = t2_compatibility_user_rebind.read_stable_surface(lease, apple_user_id)
    states = surface["user_states"]
    if (
        surface["per_user_identity_count"] != 0
        or surface["global_identity_count"] != 0
        or surface["group_state_count"] != 0
        or states
        not in {
            (("master", 0xFFFFFFFF, 3), ("user", apple_user_id, 1)),
            (("master", 0xFFFFFFFF, 3), ("user", apple_user_id, 5)),
            (("master", 0xFFFFFFFF, 7), ("user", apple_user_id, 1)),
            (("master", 0xFFFFFFFF, 7), ("user", apple_user_id, 5)),
        }
    ):
        _append(
            journal_path,
            history.operation_id,
            "MISSING_COMPONENTS_POST_STATE_REJECTED",
            {"stable_surface_rejected": True, "retry_permitted": False},
        )
        raise NativeStateRecoveryError(
            "missing-component preparation produced an unexpected state"
        )
    return _append(
        journal_path,
        history.operation_id,
        "MISSING_COMPONENTS_RECONCILED",
        {
            "master_state": states[0][2],
            "user_state": states[1][2],
            "identity_count": 0,
            "group_state_count": 0,
        },
    )


def reconcile_loaded_empty_user(
    lease,
    *,
    apple_user_id: int,
    journal_path: Path,
) -> NativeStateRecoveryHistory:
    """Bind the rejected preparation to one exact loaded-empty surface."""
    history = validate_history(t2_mutation_journal.read(journal_path))
    if history.milestone != "MISSING_COMPONENTS_POST_STATE_REJECTED":
        raise NativeStateRecoveryError(
            "loaded-empty reconciliation is not at its rejected boundary"
        )
    surface = t2_compatibility_user_rebind.read_stable_surface(
        lease, apple_user_id
    )
    states = surface["user_states"]
    if (
        any(
            surface[key] != 0
            for key in (
                "per_user_identity_count",
                "global_identity_count",
                "group_state_count",
            )
        )
        or len(states) != 2
        or states[0][0:2] != ("master", 0xFFFFFFFF)
        or states[1][0:2] != ("user", apple_user_id)
        or states[0][2] not in {3, 7}
        or states[1][2] not in {3, 7}
    ):
        raise NativeStateRecoveryError(
            "rejected preparation is not an exact loaded-empty user"
        )
    return _append(
        journal_path,
        history.operation_id,
        "LOADED_EMPTY_USER_RECONCILED",
        {
            "master_state": states[0][2],
            "user_state": states[1][2],
            "identity_count": 0,
            "group_state_count": 0,
        },
    )


def remove_loaded_empty_user(
    lease,
    *,
    apple_user_id: int,
    journal_path: Path,
) -> NativeStateRecoveryHistory:
    """Remove the journal-proven empty loaded user exactly once."""
    history = validate_history(t2_mutation_journal.read(journal_path))
    if history.milestone != "LOADED_EMPTY_USER_RECONCILED":
        raise NativeStateRecoveryError(
            "empty-user removal is not at its reconciled boundary"
        )
    surface = t2_compatibility_user_rebind.read_stable_surface(
        lease, apple_user_id
    )
    states = surface["user_states"]
    if (
        any(
            surface[key] != 0
            for key in (
                "per_user_identity_count",
                "global_identity_count",
                "group_state_count",
            )
        )
        or len(states) != 2
        or states[0][0:2] != ("master", 0xFFFFFFFF)
        or states[1][0:2] != ("user", apple_user_id)
        or states[0][2] not in {3, 7}
        or states[1][2] not in {3, 7}
    ):
        raise NativeStateRecoveryError(
            "loaded-empty user changed before removal"
        )
    history = _append(
        journal_path,
        history.operation_id,
        "REMOVE_EMPTY_USER_INTENT",
        {"command": 0x48, "component": "selected-user", "retry_permitted": False},
    )
    try:
        reply, events = lease.biometric_command(
            0x48,
            version=1,
            value=0,
            data=struct.pack("<I", apple_user_id),
            output_capacity=0,
        )
    except BaseException as error:
        _append(
            journal_path,
            history.operation_id,
            "REMOVE_EMPTY_USER_OUTCOME_UNKNOWN",
            {"dispatch_attempted": True, "retry_permitted": False},
        )
        raise NativeStateRecoveryError(
            "empty-user removal outcome is unknown; do not retry"
        ) from error
    try:
        _reply_output(reply, events, "empty-user removal", apple_user_id)
    except NativeStateRecoveryError as error:
        _record_reply_failure(journal_path, history.operation_id,
                              "REMOVE_EMPTY_USER", error)
        raise
    history = _append(
        journal_path,
        history.operation_id,
        "REMOVE_EMPTY_USER_ACCEPTED",
        {"reply_received": True, "retry_permitted": False},
    )
    return reconcile_removed_user(
        lease, apple_user_id=apple_user_id, journal_path=journal_path
    )


def reconcile_removed_user(
    lease,
    *,
    apple_user_id: int,
    journal_path: Path,
) -> NativeStateRecoveryHistory:
    """Prove accepted user removal without dispatching it again."""
    history = validate_history(t2_mutation_journal.read(journal_path))
    if history.milestone != "REMOVE_EMPTY_USER_ACCEPTED":
        raise NativeStateRecoveryError(
            "removed-user readback is not at its accepted boundary"
        )
    surface = t2_compatibility_user_rebind.read_stable_surface(
        lease, apple_user_id
    )
    expected = {
        "per_user_identity_count": 0,
        "global_identity_count": 0,
        "user_states": (("master", 0xFFFFFFFF, 7),),
        "group_state_count": 0,
    }
    if surface != expected:
        _append(
            journal_path,
            history.operation_id,
            "REMOVED_USER_POST_STATE_REJECTED",
            {"remove_accepted": True, "retry_permitted": False},
        )
        raise NativeStateRecoveryError(
            "empty-user removal produced an unexpected state"
        )
    return _append(
        journal_path,
        history.operation_id,
        "REMOVED_USER_RECONCILED",
        {"master_state": 7, "identity_count": 0, "group_state_count": 0},
    )


def _write_private_exclusive(path: Path, payload: bytes) -> str:
    parent = path.parent
    info = parent.stat(follow_symlinks=False)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_mode & 0o077
    ):
        raise NativeStateRecoveryError("recovery artifact directory is unsafe")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    complete = False
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise NativeStateRecoveryError(
                    "recovery artifact write made no progress"
                )
            offset += written
        os.fsync(descriptor)
        complete = True
    finally:
        os.close(descriptor)
        if not complete and os.path.lexists(path):
            path.unlink()
    directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return _sha256(payload)


def _read_private_regular(path: Path, maximum: int = 1024 * 1024) -> bytes:
    descriptor = -1
    try:
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or before.st_mode & 0o077
            or not 0 < before.st_size <= maximum
        ):
            raise NativeStateRecoveryError(
                "recovery artifact is not private and caller-owned"
            )
        payload = bytearray()
        while len(payload) < before.st_size:
            block = os.read(
                descriptor, min(65536, before.st_size - len(payload))
            )
            if not block:
                raise NativeStateRecoveryError("recovery artifact read was short")
            payload.extend(block)
        after = os.fstat(descriptor)
        if len(payload) != before.st_size or any(
            getattr(before, name) != getattr(after, name)
            for name in (
                "st_dev", "st_ino", "st_mode", "st_uid", "st_gid",
                "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns",
            )
        ):
            raise NativeStateRecoveryError(
                "recovery artifact changed during read"
            )
        return bytes(payload)
    except NativeStateRecoveryError:
        raise
    except OSError as error:
        raise NativeStateRecoveryError("recovery artifact is unavailable") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _write_or_verify_private(path: Path, payload: bytes) -> str:
    if os.path.lexists(path):
        existing = _read_private_regular(path)
        if existing != payload:
            raise NativeStateRecoveryError(
                "existing recovery candidate differs from derived authority"
            )
        return _sha256(existing)
    return _write_private_exclusive(path, payload)


def settle_removed_master(
    lease,
    *,
    apple_user_id: int,
    master_archive: bytes,
    artifact_path: Path,
    journal_path: Path,
) -> NativeStateRecoveryHistory:
    """Persist and confirm the dirty master left by user removal."""
    history = validate_history(t2_mutation_journal.read(journal_path))
    if history.milestone != "REMOVED_USER_RECONCILED":
        raise NativeStateRecoveryError(
            "master settlement is not at its removed-user boundary"
        )
    expected = {
        "per_user_identity_count": 0,
        "global_identity_count": 0,
        "user_states": (("master", 0xFFFFFFFF, 7),),
        "group_state_count": 0,
    }
    if t2_compatibility_user_rebind.read_stable_surface(
        lease, apple_user_id
    ) != expected:
        raise NativeStateRecoveryError("dirty master changed before settlement")
    descriptor = t2_catacomb_protocol.CatacombComponent.master().descriptor
    transport = t2_catacomb_bridge.CatacombBridgeTransport(
        lease,
        protocol_version=2,
        connection_generation=lease.connection_generation,
    )
    secure_blob: bytearray | None = None
    encoded: bytearray | None = None
    secure_hash = ""
    history = _append(
        journal_path,
        history.operation_id,
        "MASTER_EXPORT_PREPARE_INTENT",
        {
            "component": "master",
            "descriptor_sha256": _sha256(descriptor),
            "retry_permitted": False,
        },
    )
    try:
        _status, expected_length = transport.prepare(descriptor)
    except BaseException as error:
        _append(
            journal_path,
            history.operation_id,
            "MASTER_EXPORT_PREPARE_OUTCOME_UNKNOWN",
            {"dispatch_attempted": True, "retry_permitted": False},
        )
        raise NativeStateRecoveryError(
            "master export preparation outcome is unknown; do not retry"
        ) from error
    history = _append(
        journal_path,
        history.operation_id,
        "MASTER_EXPORT_PREPARED",
        {"component": "master", "expected_length": expected_length},
    )
    history = _append(
        journal_path,
        history.operation_id,
        "MASTER_EXPORT_COMPLETE_INTENT",
        {"component": "master", "retry_permitted": False},
    )
    try:
        _status, secure_blob = transport.complete(descriptor)
        if len(secure_blob) != expected_length:
            raise NativeStateRecoveryError(
                "settled master export length changed"
            )
        secure_hash = _sha256(bytes(secure_blob))
        master = t2_catacomb_codec.decode_master_catacomb(master_archive)
        encoded = bytearray(
            master.encode(secure_data=bytes(secure_blob), enrollment_count=0)
        )
        encoded_hash = _write_private_exclusive(artifact_path, bytes(encoded))
    except BaseException as error:
        _append(
            journal_path,
            history.operation_id,
            "MASTER_EXPORT_COMPLETE_OUTCOME_UNKNOWN",
            {"dispatch_attempted": True, "retry_permitted": False},
        )
        if isinstance(error, NativeStateRecoveryError):
            raise
        raise NativeStateRecoveryError(
            "master export completion outcome is unknown; do not retry"
        ) from error
    finally:
        if secure_blob is not None:
            secure_blob[:] = b"\0" * len(secure_blob)
        if encoded is not None:
            encoded[:] = b"\0" * len(encoded)
    history = _append(
        journal_path,
        history.operation_id,
        "MASTER_EXPORT_CAPTURED",
        {
            "component": "master",
            "secure_data_sha256": secure_hash,
            "encoded_sha256": encoded_hash,
            "encoded_enrollment_count": 0,
        },
    )
    history = _append(
        journal_path,
        history.operation_id,
        "MASTER_EXPORT_CONFIRM_INTENT",
        {"component": "master", "retry_permitted": False},
    )
    try:
        transport.confirm(descriptor)
    except BaseException as error:
        _append(
            journal_path,
            history.operation_id,
            "MASTER_EXPORT_CONFIRM_OUTCOME_UNKNOWN",
            {"dispatch_attempted": True, "retry_permitted": False},
        )
        raise NativeStateRecoveryError(
            "master export confirmation outcome is unknown; do not retry"
        ) from error
    history = _append(
        journal_path,
        history.operation_id,
        "MASTER_EXPORT_CONFIRMED",
        {"component": "master", "status": 0},
    )
    return reconcile_settled_master(
        lease, apple_user_id=apple_user_id, journal_path=journal_path
    )


def reconcile_settled_master(
    lease,
    *,
    apple_user_id: int,
    journal_path: Path,
) -> NativeStateRecoveryHistory:
    """Prove accepted master confirmation without replaying it."""
    history = validate_history(t2_mutation_journal.read(journal_path))
    if history.milestone != "MASTER_EXPORT_CONFIRMED":
        raise NativeStateRecoveryError(
            "master settlement readback is not at its accepted boundary"
        )
    expected = {
        "per_user_identity_count": 0,
        "global_identity_count": 0,
        "user_states": (("master", 0xFFFFFFFF, 3),),
        "group_state_count": 0,
    }
    if t2_compatibility_user_rebind.read_stable_surface(
        lease, apple_user_id
    ) != expected:
        _append(
            journal_path,
            history.operation_id,
            "MASTER_SETTLE_POST_STATE_REJECTED",
            {"confirmation_accepted": True, "retry_permitted": False},
        )
        raise NativeStateRecoveryError(
            "master confirmation produced an unexpected state"
        )
    return _append(
        journal_path,
        history.operation_id,
        "MASTER_SETTLED",
        {"master_state": 3, "identity_count": 0, "group_state_count": 0},
    )


def reprepare_missing_components(
    lease,
    *,
    apple_user_id: int,
    journal_path: Path,
) -> NativeStateRecoveryHistory:
    """Recreate components after the loaded-empty user was removed."""
    history = validate_history(t2_mutation_journal.read(journal_path))
    if history.milestone not in {"MASTER_SETTLED", "REPREPARE_MASTER_ACCEPTED"} or getattr(
        lease, "client_version", None
    ) != 0:
        raise NativeStateRecoveryError(
            "component repreparation is not at its settled pre-client boundary"
        )
    try:
        t2_bridge_inventory.attest_preclient_protocol(lease, apple_user_id)
    except t2_bridge_inventory.BridgeInventoryError as error:
        raise NativeStateRecoveryError("pre-client protocol attestation failed") from error
    commands = (
        (
            0xFFFFFFFF,
            "master",
            "REPREPARE_MASTER_INTENT",
            "REPREPARE_MASTER_ACCEPTED",
        ),
        (
            apple_user_id,
            "selected-user",
            "REPREPARE_USER_INTENT",
            "REPREPARE_USER_ACCEPTED",
        ),
    )
    if history.milestone == "REPREPARE_MASTER_ACCEPTED":
        commands = commands[1:]
    for component, name, intent, accepted in commands:
        history = _append(
            journal_path,
            history.operation_id,
            intent,
            {"command": 0x31, "component": name, "retry_permitted": False},
        )
        try:
            reply, events = lease.biometric_command(
                0x31,
                version=1,
                value=0,
                data=struct.pack("<I", component),
                output_capacity=0,
            )
        except BaseException as error:
            _append(
                journal_path,
                history.operation_id,
                f"{intent.removesuffix('_INTENT')}_OUTCOME_UNKNOWN",
                {"dispatch_attempted": True, "retry_permitted": False},
            )
            raise NativeStateRecoveryError(
                f"{name} repreparation outcome is unknown; do not retry"
            ) from error
        try:
            _reply_output(reply, events, f"{name} repreparation", apple_user_id)
        except NativeStateRecoveryError as error:
            _record_reply_failure(journal_path, history.operation_id,
                                  intent.removesuffix('_INTENT'), error)
            raise
        history = _append(
            journal_path,
            history.operation_id,
            accepted,
            {"reply_received": True, "retry_permitted": False},
        )
    try:
        version = lease.select_client_version()
    except BaseException as error:
        _append(
            journal_path,
            history.operation_id,
            "RECLIENT_VERSION_SELECTION_FAILED",
            {"commands_accepted": True, "retry_permitted": False},
        )
        raise NativeStateRecoveryError(
            "component repreparation succeeded but client selection failed"
        ) from error
    history = _append(
        journal_path,
        history.operation_id,
        "RECLIENT_VERSION_SELECTED",
        {"client_version": version},
    )
    return reconcile_reprepared_components(
        lease, apple_user_id=apple_user_id, journal_path=journal_path
    )


def reconcile_reprepared_components(
    lease,
    *,
    apple_user_id: int,
    journal_path: Path,
) -> NativeStateRecoveryHistory:
    """Prove the recreated pair without replaying accepted commands."""
    history = validate_history(t2_mutation_journal.read(journal_path))
    if history.milestone not in {
        "REPREPARE_USER_ACCEPTED", "RECLIENT_VERSION_SELECTED"
    }:
        raise NativeStateRecoveryError(
            "component repreparation readback is not at its accepted boundary"
        )
    if history.milestone == "REPREPARE_USER_ACCEPTED":
        version = getattr(lease, "client_version", None)
        if version not in (1, 2):
            raise NativeStateRecoveryError(
                "component repreparation readback requires a selected client"
            )
        history = _append(
            journal_path,
            history.operation_id,
            "RECLIENT_VERSION_SELECTED",
            {"client_version": version, "reconnected": True},
        )
    surface = t2_compatibility_user_rebind.read_stable_surface(
        lease, apple_user_id
    )
    states = surface["user_states"]
    if (
        any(
            surface[key] != 0
            for key in (
                "per_user_identity_count",
                "global_identity_count",
                "group_state_count",
            )
        )
        or states
        not in {
            (("master", 0xFFFFFFFF, 3), ("user", apple_user_id, 1)),
            (("master", 0xFFFFFFFF, 3), ("user", apple_user_id, 5)),
        }
    ):
        _append(
            journal_path,
            history.operation_id,
            "REPREPARED_COMPONENTS_POST_STATE_REJECTED",
            {"stable_surface_rejected": True, "retry_permitted": False},
        )
        raise NativeStateRecoveryError(
            "component repreparation produced an unexpected state"
        )
    return _append(
        journal_path,
        history.operation_id,
        "MISSING_COMPONENTS_RECONCILED",
        {
            "master_state": states[0][2],
            "user_state": states[1][2],
            "identity_count": 0,
            "group_state_count": 0,
        },
    )


def prepare_cold_restart(
    lease,
    *,
    apple_user_id: int,
    linux_boot_uuid: str,
    master_archive: bytes,
    user: t2_catacomb_codec.UserCatacomb,
    intermediate_path: Path,
    candidate_path: Path,
    journal_path: Path,
) -> NativeStateRecoveryHistory:
    """Derive the retained-master candidate without changing live state."""
    history = validate_history(t2_mutation_journal.read(journal_path))
    if history.milestone != "REPREPARED_COMPONENTS_POST_STATE_REJECTED":
        raise NativeStateRecoveryError(
            "cold restart preparation is not at its rejected boundary"
        )
    try:
        source_boot = str(uuid.UUID(linux_boot_uuid))
    except (AttributeError, TypeError, ValueError) as error:
        raise NativeStateRecoveryError("Linux boot UUID is invalid") from error
    if source_boot != linux_boot_uuid:
        raise NativeStateRecoveryError(
            "cold restart candidate must be prepared in the source Linux boot"
        )
    surface = t2_compatibility_user_rebind.read_stable_surface(
        lease, apple_user_id
    )
    if surface != {
        "per_user_identity_count": 0,
        "global_identity_count": 0,
        "user_states": (
            ("master", 0xFFFFFFFF, 3),
            ("user", apple_user_id, 7),
        ),
        "group_state_count": 0,
    }:
        raise NativeStateRecoveryError(
            "rejected repreparation is not the retained-master terminal surface"
        )
    records = t2_mutation_journal.read(journal_path)
    captured = next(
        (
            record["evidence"]
            for record in records
            if record.get("milestone") == "MASTER_EXPORT_CAPTURED"
        ),
        None,
    )
    intermediate = _read_private_regular(intermediate_path)
    if (
        not isinstance(captured, dict)
        or _sha256(intermediate) != captured.get("encoded_sha256")
    ):
        raise NativeStateRecoveryError(
            "intermediate master differs from its recovery journal"
        )
    try:
        retained = t2_catacomb_codec.decode_master_catacomb(intermediate)
        canonical = t2_catacomb_codec.decode_master_catacomb(master_archive)
        candidate_bytes = canonical.encode(
            secure_data=retained.secure_data,
            enrollment_count=len(user.identities),
        )
        candidate = t2_catacomb_codec.decode_master_catacomb(candidate_bytes)
    except t2_catacomb_codec.CatacombCodecError as error:
        raise NativeStateRecoveryError(
            "retained-master candidate is invalid"
        ) from error
    if (
        retained.enrollment_count != 0
        or not user.identities
        or retained.secure_data == canonical.secure_data
        or _sha256(retained.secure_data) != captured.get("secure_data_sha256")
        or candidate.secure_data != retained.secure_data
        or candidate.enrollment_count != len(user.identities)
        or candidate.encode() != candidate_bytes
    ):
        raise NativeStateRecoveryError(
            "retained-master candidate does not match saved authority"
        )
    candidate_hash = _write_or_verify_private(candidate_path, candidate_bytes)
    return _append(
        journal_path,
        history.operation_id,
        "COLD_RESTART_PREPARED",
        {
            "source_linux_boot_uuid": source_boot,
            "intermediate_master_sha256": _sha256(intermediate),
            "candidate_master_sha256": candidate_hash,
            "identity_count": len(user.identities),
        },
    )


def reconcile_cold_surface(
    lease,
    *,
    apple_user_id: int,
    linux_boot_uuid: str,
    journal_path: Path,
) -> NativeStateRecoveryHistory:
    """Require a different Linux boot and an exact cold loadable surface."""
    history = validate_history(t2_mutation_journal.read(journal_path))
    if history.milestone != "COLD_RESTART_PREPARED":
        raise NativeStateRecoveryError(
            "cold-surface readback is not at its prepared boundary"
        )
    prepared = next(
        record["evidence"]
        for record in t2_mutation_journal.read(journal_path)
        if record.get("milestone") == "COLD_RESTART_PREPARED"
    )
    source_boot = prepared["source_linux_boot_uuid"]
    try:
        current_boot = str(uuid.UUID(linux_boot_uuid))
    except (AttributeError, TypeError, ValueError) as error:
        raise NativeStateRecoveryError("Linux boot UUID is invalid") from error
    if current_boot != linux_boot_uuid or current_boot == source_boot:
        raise NativeStateRecoveryError(
            "retained-master recovery requires a different Linux boot"
        )
    surface = t2_compatibility_user_rebind.read_stable_surface(
        lease, apple_user_id
    )
    cold_states = {
        (("master", 0xFFFFFFFF, 1),),
        (("master", 0xFFFFFFFF, 1), ("user", apple_user_id, 1)),
    }
    if (
        any(
            surface[key] != 0
            for key in (
                "per_user_identity_count",
                "global_identity_count",
                "group_state_count",
            )
        )
        or surface["user_states"] not in cold_states
    ):
        raise NativeStateRecoveryError(
            "retained-master recovery requires an exact cold loadable surface"
        )
    user_state = 1 if len(surface["user_states"]) == 2 else None
    return _append(
        journal_path,
        history.operation_id,
        "COLD_SURFACE_RECONCILED",
        {
            "different_linux_boot": True,
            "master_state": 1,
            "user_state": user_state,
            "identity_count": 0,
            "group_state_count": 0,
        },
    )


def prepare_canonical_restart(
    lease,
    *,
    apple_user_id: int,
    linux_boot_uuid: str,
    master_archive: bytes,
    user: t2_catacomb_codec.UserCatacomb,
    journal_path: Path,
) -> NativeStateRecoveryHistory:
    """Redirect an already-loaded derived master to its canonical generation."""
    records = t2_mutation_journal.read(journal_path)
    history = validate_history(records)
    if history.milestone not in {
        "COLD_MASTER_RECONCILED", "SAVED_USER_LOAD_REPLY_REJECTED"
    }:
        raise NativeStateRecoveryError(
            "canonical restart is not at its derived-master boundary"
        )
    milestones = [
        record.get("milestone")
        for record in records
        if not t2_mutation_journal.is_repair_milestone(record.get("milestone"))
    ]
    if (
        "COLD_MASTER_RECONCILED" not in milestones
        or "RETAINED_MASTER_LOAD_ACCEPTED" not in milestones
    ):
        raise NativeStateRecoveryError(
            "canonical restart requires the recorded derived-master path"
        )
    try:
        source_boot = str(uuid.UUID(linux_boot_uuid))
        master = t2_catacomb_codec.decode_master_catacomb(master_archive)
    except (AttributeError, TypeError, ValueError) as error:
        raise NativeStateRecoveryError("Linux boot UUID is invalid") from error
    except t2_catacomb_codec.CatacombCodecError as error:
        raise NativeStateRecoveryError("canonical master is invalid") from error
    if (
        source_boot != linux_boot_uuid
        or not user.identities
        or _sha256(master_archive)
        != history.component_sha256.get("master.cat")
    ):
        raise NativeStateRecoveryError(
            "canonical restart authority differs from the recovery journal"
        )
    surface = t2_compatibility_user_rebind.read_stable_surface(
        lease, apple_user_id
    )
    if surface != {
        "per_user_identity_count": 0,
        "global_identity_count": 0,
        "user_states": (("master", 0xFFFFFFFF, 3),),
        "group_state_count": 0,
    }:
        raise NativeStateRecoveryError(
            "canonical restart requires the exact derived-master surface"
        )
    return _append(
        journal_path,
        history.operation_id,
        "CANONICAL_RESTART_PREPARED",
        {
            "source_linux_boot_uuid": source_boot,
            "master_sha256": _sha256(master_archive),
            "master_secure_data_sha256": _sha256(master.secure_data),
            "user_secure_data_sha256": _sha256(user.secure_data),
            "identity_count": len(user.identities),
        },
    )


def reconcile_canonical_cold_surface(
    lease,
    *,
    apple_user_id: int,
    linux_boot_uuid: str,
    journal_path: Path,
) -> NativeStateRecoveryHistory:
    """Require a new Linux boot and an exact cold canonical-load surface."""
    history = validate_history(t2_mutation_journal.read(journal_path))
    if history.milestone != "CANONICAL_RESTART_PREPARED":
        raise NativeStateRecoveryError(
            "canonical cold-surface readback is not at its prepared boundary"
        )
    prepared = next(
        record["evidence"]
        for record in t2_mutation_journal.read(journal_path)
        if record.get("milestone") == "CANONICAL_RESTART_PREPARED"
    )
    try:
        current_boot = str(uuid.UUID(linux_boot_uuid))
    except (AttributeError, TypeError, ValueError) as error:
        raise NativeStateRecoveryError("Linux boot UUID is invalid") from error
    if (
        current_boot != linux_boot_uuid
        or current_boot == prepared["source_linux_boot_uuid"]
    ):
        raise NativeStateRecoveryError(
            "canonical recovery requires a different Linux boot"
        )
    surface = t2_compatibility_user_rebind.read_stable_surface(
        lease, apple_user_id
    )
    cold_states = {
        (("master", 0xFFFFFFFF, 1),),
        (("master", 0xFFFFFFFF, 1), ("user", apple_user_id, 1)),
    }
    if (
        any(
            surface[key] != 0
            for key in (
                "per_user_identity_count",
                "global_identity_count",
                "group_state_count",
            )
        )
        or surface["user_states"] not in cold_states
    ):
        raise NativeStateRecoveryError(
            "canonical recovery requires an exact cold loadable surface"
        )
    return _append(
        journal_path,
        history.operation_id,
        "CANONICAL_COLD_SURFACE_RECONCILED",
        {
            "different_linux_boot": True,
            "master_state": 1,
            "user_state": 1 if len(surface["user_states"]) == 2 else None,
            "identity_count": 0,
            "group_state_count": 0,
        },
    )


def load_canonical_master(
    lease,
    *,
    apple_user_id: int,
    master_archive: bytes,
    user: t2_catacomb_codec.UserCatacomb,
    journal_path: Path,
) -> NativeStateRecoveryHistory:
    """Load the canonical master once from either admitted cold boundary."""
    history = validate_history(t2_mutation_journal.read(journal_path))
    if history.milestone not in {
        "COLD_SURFACE_RECONCILED", "CANONICAL_COLD_SURFACE_RECONCILED"
    }:
        raise NativeStateRecoveryError(
            "canonical master load is not at its cold boundary"
        )
    try:
        master = t2_catacomb_codec.decode_master_catacomb(master_archive)
    except t2_catacomb_codec.CatacombCodecError as error:
        raise NativeStateRecoveryError("canonical master is invalid") from error
    if (
        not user.identities
        or _sha256(master_archive)
        != history.component_sha256.get("master.cat")
    ):
        raise NativeStateRecoveryError(
            "canonical master differs from the recovery journal"
        )
    restart = next(
        (
            record["evidence"]
            for record in t2_mutation_journal.read(journal_path)
            if record.get("milestone") == "CANONICAL_RESTART_PREPARED"
        ),
        None,
    )
    if restart is not None and (
        restart["master_sha256"] != _sha256(master_archive)
        or restart["master_secure_data_sha256"] != _sha256(master.secure_data)
        or restart["user_secure_data_sha256"] != _sha256(user.secure_data)
    ):
        raise NativeStateRecoveryError(
            "canonical authority changed across the cold restart"
        )
    history = _append(
        journal_path,
        history.operation_id,
        "CANONICAL_MASTER_LOAD_INTENT",
        {
            "command": 0x40,
            "component": "master",
            "secure_data_sha256": _sha256(master.secure_data),
            "identity_count": len(user.identities),
            "retry_permitted": False,
        },
    )
    try:
        reply, events = lease.biometric_command(
            0x40,
            version=1,
            value=0,
            data=master.secure_data,
            output_capacity=0,
        )
    except BaseException as error:
        _append(
            journal_path,
            history.operation_id,
            "CANONICAL_MASTER_LOAD_OUTCOME_UNKNOWN",
            {"dispatch_attempted": True, "retry_permitted": False},
        )
        raise NativeStateRecoveryError(
            "canonical master load outcome is unknown; do not retry"
        ) from error
    try:
        _reply_output(reply, events, "canonical master load", apple_user_id)
    except NativeStateRecoveryError as error:
        _record_reply_failure(journal_path, history.operation_id,
                              "CANONICAL_MASTER_LOAD", error)
        raise
    return _append(
        journal_path,
        history.operation_id,
        "CANONICAL_MASTER_LOAD_ACCEPTED",
        {"reply_received": True, "retry_permitted": False},
    )


def reconcile_canonical_master(
    lease,
    *,
    apple_user_id: int,
    journal_path: Path,
) -> NativeStateRecoveryHistory:
    """Prove the canonical master load without replaying it."""
    history = validate_history(t2_mutation_journal.read(journal_path))
    if history.milestone != "CANONICAL_MASTER_LOAD_ACCEPTED":
        raise NativeStateRecoveryError(
            "canonical master readback is not at its accepted boundary"
        )
    surface = t2_compatibility_user_rebind.read_stable_surface(
        lease, apple_user_id
    )
    loaded_states = {
        (("master", 0xFFFFFFFF, 3),),
        (("master", 0xFFFFFFFF, 3), ("user", apple_user_id, 1)),
    }
    if (
        any(
            surface[key] != 0
            for key in (
                "per_user_identity_count",
                "global_identity_count",
                "group_state_count",
            )
        )
        or surface["user_states"] not in loaded_states
    ):
        _append(
            journal_path,
            history.operation_id,
            "CANONICAL_MASTER_POST_STATE_REJECTED",
            {"master_load_accepted": True, "retry_permitted": False},
        )
        raise NativeStateRecoveryError(
            "canonical master load produced an unexpected state"
        )
    return _append(
        journal_path,
        history.operation_id,
        "CANONICAL_MASTER_RECONCILED",
        {
            "master_state": 3,
            "user_state": 1 if len(surface["user_states"]) == 2 else None,
            "identity_count": 0,
            "group_state_count": 0,
        },
    )


def reconcile_canonical_master_reply(
    lease,
    *,
    apple_user_id: int,
    journal_path: Path,
) -> NativeStateRecoveryHistory:
    """Refuse the legacy readback override of a rejected master load."""
    validate_history(t2_mutation_journal.read(journal_path))
    raise NativeStateRecoveryError(
        "canonical master load was rejected; an empty state-3 master does not "
        "prove the saved archive loaded; preserving state for diagnosis"
    )


def load_canonical_user(
    lease,
    *,
    apple_user_id: int,
    user: t2_catacomb_codec.UserCatacomb,
    journal_path: Path,
) -> NativeStateRecoveryHistory:
    """Load the saved user once after its matching canonical master."""
    history = validate_history(t2_mutation_journal.read(journal_path))
    if history.milestone != "CANONICAL_MASTER_RECONCILED":
        raise NativeStateRecoveryError(
            "canonical user load is not at its master boundary"
        )
    surface = t2_compatibility_user_rebind.read_stable_surface(
        lease, apple_user_id
    )
    prepared_states = {
        (("master", 0xFFFFFFFF, 3),),
        (("master", 0xFFFFFFFF, 3), ("user", apple_user_id, 1)),
        (("master", 0xFFFFFFFF, 3), ("user", apple_user_id, 5)),
    }
    if (
        not user.identities
        or surface["user_states"] not in prepared_states
        or any(
            surface[key] != 0
            for key in (
                "per_user_identity_count",
                "global_identity_count",
                "group_state_count",
            )
        )
    ):
        raise NativeStateRecoveryError(
            "canonical recovery surface changed before user load"
        )
    history = _append(
        journal_path,
        history.operation_id,
        "CANONICAL_USER_LOAD_INTENT",
        {
            "command": 0x40,
            "component": "selected-user",
            "secure_data_sha256": _sha256(user.secure_data),
            "identity_count": len(user.identities),
            "retry_permitted": False,
        },
    )
    try:
        reply, events = lease.biometric_command(
            0x40,
            version=1,
            value=0,
            data=user.secure_data,
            output_capacity=0,
        )
    except BaseException as error:
        _append(
            journal_path,
            history.operation_id,
            "CANONICAL_USER_LOAD_OUTCOME_UNKNOWN",
            {"dispatch_attempted": True, "retry_permitted": False},
        )
        raise NativeStateRecoveryError(
            "canonical user load outcome is unknown; do not retry"
        ) from error
    try:
        _reply_output(reply, events, "canonical user load", apple_user_id)
    except NativeStateRecoveryError as error:
        _record_reply_failure(journal_path, history.operation_id,
                              "CANONICAL_USER_LOAD", error)
        raise
    return _append(
        journal_path,
        history.operation_id,
        "CANONICAL_USER_LOAD_ACCEPTED",
        {"reply_received": True, "retry_permitted": False},
    )


def load_retained_master(
    lease,
    *,
    apple_user_id: int,
    candidate_path: Path,
    journal_path: Path,
) -> NativeStateRecoveryHistory:
    """Load the journal-bound retained master once on the cold surface."""
    history = validate_history(t2_mutation_journal.read(journal_path))
    if history.milestone != "COLD_SURFACE_RECONCILED":
        raise NativeStateRecoveryError(
            "retained-master load is not at its cold boundary"
        )
    candidate_bytes = _read_private_regular(candidate_path)
    prepared = next(
        record["evidence"]
        for record in t2_mutation_journal.read(journal_path)
        if record.get("milestone") == "COLD_RESTART_PREPARED"
    )
    if _sha256(candidate_bytes) != prepared["candidate_master_sha256"]:
        raise NativeStateRecoveryError(
            "retained-master candidate changed after preparation"
        )
    try:
        candidate = t2_catacomb_codec.decode_master_catacomb(candidate_bytes)
    except t2_catacomb_codec.CatacombCodecError as error:
        raise NativeStateRecoveryError(
            "retained-master candidate is invalid"
        ) from error
    history = _append(
        journal_path,
        history.operation_id,
        "RETAINED_MASTER_LOAD_INTENT",
        {
            "command": 0x40,
            "component": "master",
            "secure_data_sha256": _sha256(candidate.secure_data),
            "identity_count": candidate.enrollment_count,
            "retry_permitted": False,
        },
    )
    try:
        reply, events = lease.biometric_command(
            0x40,
            version=1,
            value=0,
            data=candidate.secure_data,
            output_capacity=0,
        )
    except BaseException as error:
        _append(
            journal_path,
            history.operation_id,
            "RETAINED_MASTER_LOAD_OUTCOME_UNKNOWN",
            {"dispatch_attempted": True, "retry_permitted": False},
        )
        raise NativeStateRecoveryError(
            "retained-master load outcome is unknown; do not retry"
        ) from error
    try:
        _reply_output(reply, events, "retained-master load", apple_user_id)
    except NativeStateRecoveryError as error:
        _record_reply_failure(journal_path, history.operation_id,
                              "RETAINED_MASTER_LOAD", error)
        raise
    history = _append(
        journal_path,
        history.operation_id,
        "RETAINED_MASTER_LOAD_ACCEPTED",
        {"reply_received": True, "retry_permitted": False},
    )
    return reconcile_cold_master(
        lease, apple_user_id=apple_user_id, journal_path=journal_path
    )


def reconcile_cold_master(
    lease,
    *,
    apple_user_id: int,
    journal_path: Path,
) -> NativeStateRecoveryHistory:
    """Prove the accepted retained-master load without replaying it."""
    history = validate_history(t2_mutation_journal.read(journal_path))
    if history.milestone != "RETAINED_MASTER_LOAD_ACCEPTED":
        raise NativeStateRecoveryError(
            "retained-master readback is not at its accepted boundary"
        )
    surface = t2_compatibility_user_rebind.read_stable_surface(
        lease, apple_user_id
    )
    loaded_states = {
        (("master", 0xFFFFFFFF, 3),),
        (("master", 0xFFFFFFFF, 3), ("user", apple_user_id, 1)),
    }
    if (
        any(
            surface[key] != 0
            for key in (
                "per_user_identity_count",
                "global_identity_count",
                "group_state_count",
            )
        )
        or surface["user_states"] not in loaded_states
    ):
        _append(
            journal_path,
            history.operation_id,
            "RETAINED_MASTER_POST_STATE_REJECTED",
            {"master_load_accepted": True, "retry_permitted": False},
        )
        raise NativeStateRecoveryError(
            "retained-master load produced an unexpected state"
        )
    user_state = 1 if len(surface["user_states"]) == 2 else None
    return _append(
        journal_path,
        history.operation_id,
        "COLD_MASTER_RECONCILED",
        {
            "master_state": 3,
            "user_state": user_state,
            "identity_count": 0,
            "group_state_count": 0,
        },
    )


def restore_saved_user(
    lease,
    *,
    apple_user_id: int,
    user: t2_catacomb_codec.UserCatacomb,
    journal_path: Path,
) -> NativeStateRecoveryHistory:
    history = validate_history(t2_mutation_journal.read(journal_path))
    if history.milestone not in {
        "MISSING_COMPONENTS_RECONCILED", "COLD_MASTER_RECONCILED"
    }:
        raise NativeStateRecoveryError("saved-user restore is not at its prepared boundary")
    surface = t2_compatibility_user_rebind.read_stable_surface(lease, apple_user_id)
    prepared_states = {
        (("master", 0xFFFFFFFF, 3), ("user", apple_user_id, 1)),
        (("master", 0xFFFFFFFF, 3), ("user", apple_user_id, 5)),
        (("master", 0xFFFFFFFF, 7), ("user", apple_user_id, 1)),
        (("master", 0xFFFFFFFF, 7), ("user", apple_user_id, 5)),
    }
    if history.milestone == "COLD_MASTER_RECONCILED":
        prepared_states.add((("master", 0xFFFFFFFF, 3),))
    prepared = surface["user_states"] in prepared_states
    if not prepared or any(
        surface[key] != 0
        for key in ("per_user_identity_count", "global_identity_count", "group_state_count")
    ):
        raise NativeStateRecoveryError("prepared recovery surface changed before user load")
    history = _append(
        journal_path,
        history.operation_id,
        "SAVED_USER_LOAD_INTENT",
        {
            "command": 0x40,
            "component": "selected-user",
            "secure_data_sha256": _sha256(user.secure_data),
            "identity_count": len(user.identities),
            "retry_permitted": False,
        },
    )
    try:
        reply, events = lease.biometric_command(
            0x40, version=1, value=0, data=user.secure_data, output_capacity=0
        )
    except BaseException as error:
        _append(
            journal_path,
            history.operation_id,
            "SAVED_USER_LOAD_OUTCOME_UNKNOWN",
            {"dispatch_attempted": True, "retry_permitted": False},
        )
        raise NativeStateRecoveryError(
            "saved-user load outcome is unknown; do not retry"
        ) from error
    try:
        _reply_output(reply, events, "saved-user load", apple_user_id)
    except NativeStateRecoveryError as error:
        _record_reply_failure(journal_path, history.operation_id,
                              "SAVED_USER_LOAD", error)
        raise
    history = _append(
        journal_path,
        history.operation_id,
        "SAVED_USER_LOAD_ACCEPTED",
        {"reply_received": True, "retry_permitted": False},
    )
    return reconcile_saved_user(
        lease,
        apple_user_id=apple_user_id,
        user=user,
        journal_path=journal_path,
    )


def reconcile_incompatible_user_surface(
    lease,
    *,
    apple_user_id: int,
    journal_path: Path,
) -> NativeStateRecoveryHistory:
    """Bind the rejected canonical user to an exact empty master-only surface."""
    history = validate_history(t2_mutation_journal.read(journal_path))
    if history.milestone != "CANONICAL_USER_LOAD_REPLY_REJECTED":
        raise NativeStateRecoveryError(
            "empty reprovision is not at its rejected-user boundary"
        )
    surface = t2_compatibility_user_rebind.read_stable_surface(
        lease, apple_user_id
    )
    expected = {
        "per_user_identity_count": 0,
        "global_identity_count": 0,
        "user_states": (("master", 0xFFFFFFFF, 3),),
        "group_state_count": 0,
    }
    if surface != expected:
        raise NativeStateRecoveryError(
            "rejected canonical user did not leave an exact empty master surface"
        )
    return _append(
        journal_path,
        history.operation_id,
        "EMPTY_REPROVISION_SURFACE_RECONCILED",
        {"master_state": 3, "identity_count": 0, "group_state_count": 0},
    )


def prepare_empty_reprovision(
    lease,
    *,
    apple_user_id: int,
    journal_path: Path,
) -> NativeStateRecoveryHistory:
    """Create one fresh empty user component without replaying rejected loads."""
    history = validate_history(t2_mutation_journal.read(journal_path))
    if (
        history.milestone
        not in {
            "EMPTY_REPROVISION_SURFACE_RECONCILED",
            "EMPTY_REPROVISION_MASTER_ACCEPTED",
        }
        or getattr(lease, "client_version", None) != 0
    ):
        raise NativeStateRecoveryError(
            "empty reprovision preparation is not at its pre-client boundary"
        )
    try:
        t2_bridge_inventory.attest_preclient_protocol(lease, apple_user_id)
    except t2_bridge_inventory.BridgeInventoryError as error:
        raise NativeStateRecoveryError(
            "empty reprovision pre-client protocol attestation failed"
        ) from error
    commands = (
        (
            0xFFFFFFFF,
            "master",
            "EMPTY_REPROVISION_MASTER_INTENT",
            "EMPTY_REPROVISION_MASTER_ACCEPTED",
        ),
        (
            apple_user_id,
            "selected-user",
            "EMPTY_REPROVISION_USER_INTENT",
            "EMPTY_REPROVISION_USER_ACCEPTED",
        ),
    )
    if history.milestone == "EMPTY_REPROVISION_MASTER_ACCEPTED":
        commands = commands[1:]
    for component, name, intent, accepted in commands:
        history = _append(
            journal_path,
            history.operation_id,
            intent,
            {"command": 0x31, "component": name, "retry_permitted": False},
        )
        try:
            reply, events = lease.biometric_command(
                0x31,
                version=1,
                value=0,
                data=struct.pack("<I", component),
                output_capacity=0,
            )
        except BaseException as error:
            _append(
                journal_path,
                history.operation_id,
                f"{intent.removesuffix('_INTENT')}_OUTCOME_UNKNOWN",
                {"dispatch_attempted": True, "retry_permitted": False},
            )
            raise NativeStateRecoveryError(
                f"empty reprovision {name} outcome is unknown; do not retry"
            ) from error
        try:
            _reply_output(
                reply, events, f"empty reprovision {name}", apple_user_id
            )
        except NativeStateRecoveryError as error:
            _record_reply_failure(journal_path, history.operation_id,
                                  intent.removesuffix('_INTENT'), error)
            raise
        history = _append(
            journal_path,
            history.operation_id,
            accepted,
            {"reply_received": True, "retry_permitted": False},
        )
    try:
        version = lease.select_client_version()
    except BaseException as error:
        _append(
            journal_path,
            history.operation_id,
            "EMPTY_REPROVISION_CLIENT_SELECTION_FAILED",
            {"commands_accepted": True, "retry_permitted": False},
        )
        raise NativeStateRecoveryError(
            "empty reprovision client selection failed"
        ) from error
    history = _append(
        journal_path,
        history.operation_id,
        "EMPTY_REPROVISION_CLIENT_SELECTED",
        {"client_version": version},
    )
    return reconcile_empty_reprovision(
        lease, apple_user_id=apple_user_id, journal_path=journal_path
    )


def reconcile_empty_reprovision(
    lease,
    *,
    apple_user_id: int,
    journal_path: Path,
) -> NativeStateRecoveryHistory:
    """Prove that admission created only one dirty empty selected user."""
    history = validate_history(t2_mutation_journal.read(journal_path))
    if history.milestone not in {
        "EMPTY_REPROVISION_USER_ACCEPTED",
        "EMPTY_REPROVISION_CLIENT_SELECTED",
    }:
        raise NativeStateRecoveryError(
            "empty reprovision readback is not at its accepted boundary"
        )
    if history.milestone == "EMPTY_REPROVISION_USER_ACCEPTED":
        version = getattr(lease, "client_version", None)
        if version not in (1, 2):
            raise NativeStateRecoveryError(
                "empty reprovision readback requires a selected client"
            )
        history = _append(
            journal_path,
            history.operation_id,
            "EMPTY_REPROVISION_CLIENT_SELECTED",
            {"client_version": version},
        )
    surface = t2_compatibility_user_rebind.read_stable_surface(
        lease, apple_user_id
    )
    states = surface["user_states"]
    if (
        any(
            surface[key] != 0
            for key in (
                "per_user_identity_count",
                "global_identity_count",
                "group_state_count",
            )
        )
        or states
        not in {
            (("master", 0xFFFFFFFF, 3), ("user", apple_user_id, 7)),
            (("master", 0xFFFFFFFF, 7), ("user", apple_user_id, 7)),
        }
    ):
        _append(
            journal_path,
            history.operation_id,
            "EMPTY_REPROVISION_POST_STATE_REJECTED",
            {"stable_surface_rejected": True, "retry_permitted": False},
        )
        raise NativeStateRecoveryError(
            "empty reprovision produced an unexpected component state"
        )
    return _append(
        journal_path,
        history.operation_id,
        "EMPTY_REPROVISION_READY",
        {
            "master_state": states[0][2],
            "user_state": states[1][2],
            "identity_count": 0,
            "group_state_count": 0,
        },
    )


def reconcile_empty_catacombs(
    lease,
    *,
    apple_user_id: int,
    components: dict[str, bytes],
    journal_path: Path,
) -> NativeStateRecoveryHistory:
    """Bind the empty live generation to its atomically committed host pair."""
    history = validate_history(t2_mutation_journal.read(journal_path))
    if history.milestone != "EMPTY_REPROVISION_READY":
        raise NativeStateRecoveryError(
            "empty Catacomb readback is not at its persistence boundary"
        )
    user_name = f"user_{apple_user_id:08x}.cat"
    expected_names = {"master.cat", "biolockout.cat", user_name}
    if set(components) != expected_names:
        raise NativeStateRecoveryError(
            "empty reprovision component set changed"
        )
    user = t2_catacomb_codec.decode_user_catacomb(
        components[user_name], apple_user_id
    )
    master = t2_catacomb_codec.decode_master_catacomb(components["master.cat"])
    live = t2_bridge_inventory.collect_stable_private_inventory(
        lease, apple_user_id
    )
    summary = t2_identity_inventory.summarize(user, live)
    if user.identities or master.enrollment_count != 0 or summary["identity_count"] != 0:
        raise NativeStateRecoveryError(
            "empty reprovision Catacombs did not reconcile"
        )
    return _append(
        journal_path,
        history.operation_id,
        "EMPTY_REPROVISION_CATACOMBS_RECONCILED",
        {
            "identity_count": 0,
            "master_enrollment_count": 0,
            "component_sha256": {
                name: _sha256(data) for name, data in sorted(components.items())
            },
        },
    )


def restore_empty_reprovision_biolockout(
    lease,
    *,
    apple_user_id: int,
    store: t2_biolockout_store.BioLockoutStore,
    journal_path: Path,
) -> NativeStateRecoveryHistory:
    history = validate_history(t2_mutation_journal.read(journal_path))
    if history.milestone != "EMPTY_REPROVISION_CATACOMBS_RECONCILED":
        raise NativeStateRecoveryError(
            "empty reprovision BioLockout restore is out of order"
        )
    current = store.current()
    if current is None:
        raise NativeStateRecoveryError("rolling BioLockout authority is absent")
    history = _append(
        journal_path,
        history.operation_id,
        "EMPTY_REPROVISION_BIOLOCKOUT_INTENT",
        {"payload_sha256": _sha256(current.payload), "retry_permitted": False},
    )
    try:
        t2_native_state_restore._load_biolockout(
            lease, store, current, apple_user_id
        )
    except BaseException as error:
        _append(
            journal_path,
            history.operation_id,
            "EMPTY_REPROVISION_BIOLOCKOUT_OUTCOME_UNKNOWN",
            {"dispatch_attempted": True, "retry_permitted": False},
        )
        raise NativeStateRecoveryError(
            "empty reprovision BioLockout outcome is unknown; do not retry"
        ) from error
    history = _append(
        journal_path,
        history.operation_id,
        "EMPTY_REPROVISION_BIOLOCKOUT_RECONCILED",
        {"payload_sha256": _sha256(store.current().payload)},
    )
    return _append(
        journal_path,
        history.operation_id,
        "EMPTY_REPROVISION_COMPLETE",
        {
            "identity_count": 0,
            "fingerprint_reenrollment_required": True,
            "identifiers_redacted": True,
        },
    )


def reconcile_saved_user(
    lease,
    *,
    apple_user_id: int,
    user: t2_catacomb_codec.UserCatacomb,
    journal_path: Path,
) -> NativeStateRecoveryHistory:
    """Prove an accepted saved-user load without dispatching it again."""
    history = validate_history(t2_mutation_journal.read(journal_path))
    if history.milestone not in {
        "SAVED_USER_LOAD_ACCEPTED", "CANONICAL_USER_LOAD_ACCEPTED"
    }:
        raise NativeStateRecoveryError(
            "saved-user readback is not at its accepted boundary"
        )
    committed = {(item.user_id, item.uuid) for item in user.identities}
    surface = t2_compatibility_user_rebind.read_stable_surface(lease, apple_user_id)
    states = surface["user_states"]
    try:
        live = t2_native_state_restore._identities(lease, apple_user_id)
    except t2_native_state_restore.NativeStateRestoreError as error:
        raise NativeStateRecoveryError("saved-user post-state is unavailable") from error
    if (
        live != committed
        or surface["per_user_identity_count"] != len(committed)
        or surface["global_identity_count"] != len(committed)
        or surface["group_state_count"] != 0
        or frozenset(states)
        not in {
            frozenset(
                {
                ("master", 0xFFFFFFFF, master),
                ("user", apple_user_id, user_state),
                }
            )
            for master in (3, 7)
            for user_state in (3, 7)
        }
    ):
        _append(
            journal_path,
            history.operation_id,
            "SAVED_USER_POST_STATE_REJECTED",
            {"saved_user_load_accepted": True, "retry_permitted": False},
        )
        raise NativeStateRecoveryError(
            "saved-user load did not reproduce the committed identity set"
        )
    return _append(
        journal_path,
        history.operation_id,
        "SAVED_USER_RECONCILED",
        {"identity_count": len(committed), "group_state_count": 0},
    )


def restore_biolockout(
    lease,
    *,
    apple_user_id: int,
    store: t2_biolockout_store.BioLockoutStore,
    journal_path: Path,
) -> NativeStateRecoveryHistory:
    history = validate_history(t2_mutation_journal.read(journal_path))
    if history.milestone != "CATACOMB_PERSISTENCE_RECONCILED":
        raise NativeStateRecoveryError("BioLockout restore is not at its reconciled boundary")
    current = store.current()
    if current is None:
        raise NativeStateRecoveryError("rolling BioLockout authority is absent")
    history = _append(
        journal_path,
        history.operation_id,
        "BIOLOCKOUT_LOAD_INTENT",
        {"payload_sha256": _sha256(current.payload), "retry_permitted": False},
    )
    try:
        t2_native_state_restore._load_biolockout(
            lease, store, current, apple_user_id
        )
    except BaseException as error:
        _append(
            journal_path,
            history.operation_id,
            "BIOLOCKOUT_LOAD_OUTCOME_UNKNOWN",
            {"dispatch_attempted": True, "retry_permitted": False},
        )
        raise NativeStateRecoveryError(
            "BioLockout load outcome is unknown; do not retry"
        ) from error
    history = _append(
        journal_path,
        history.operation_id,
        "BIOLOCKOUT_RECONCILED",
        {"payload_sha256": _sha256(store.current().payload)},
    )
    return _append(
        journal_path,
        history.operation_id,
        "RECOVERY_COMPLETE",
        {"identity_count": history.baseline["identity_count"], "identifiers_redacted": True},
    )


def begin_catacomb_persistence(
    journal_path: Path, *, required: bool
) -> NativeStateRecoveryHistory:
    history = validate_history(t2_mutation_journal.read(journal_path))
    if history.milestone != "SAVED_USER_RECONCILED" or type(required) is not bool:
        raise NativeStateRecoveryError(
            "Catacomb persistence is not at its saved-user boundary"
        )
    return _append(
        journal_path,
        history.operation_id,
        "CATACOMB_PERSISTENCE_INTENT",
        {"persistence_required": required, "retry_permitted": False},
    )


def reconcile_catacomb_persistence(
    journal_path: Path,
    *,
    persisted: bool,
    components: dict[str, bytes],
    user: t2_catacomb_codec.UserCatacomb,
) -> NativeStateRecoveryHistory:
    history = validate_history(t2_mutation_journal.read(journal_path))
    if (
        history.milestone != "CATACOMB_PERSISTENCE_INTENT"
        or type(persisted) is not bool
    ):
        raise NativeStateRecoveryError(
            "Catacomb persistence is not at its readback boundary"
        )
    identity_records = sorted(
        (identity.user_id, identity.uuid, identity.entity)
        for identity in user.identities
    )
    component_sha256 = {
        name: _sha256(data) for name, data in sorted(components.items())
    }
    if set(component_sha256) != set(history.component_sha256):
        raise NativeStateRecoveryError(
            "persisted Catacomb component set changed"
        )
    return _append(
        journal_path,
        history.operation_id,
        "CATACOMB_PERSISTENCE_RECONCILED",
        {
            "persisted": persisted,
            "catacomb_clean": True,
            "component_sha256": component_sha256,
            "identity_snapshot_sha256": _sha256(
                t2_mutation_journal.canonical(identity_records)
            ),
        },
    )


def complete_reconciled(journal_path: Path) -> NativeStateRecoveryHistory:
    """Close a transaction whose BioLockout readback was already journaled."""
    history = validate_history(t2_mutation_journal.read(journal_path))
    if history.milestone != "BIOLOCKOUT_RECONCILED":
        raise NativeStateRecoveryError(
            "native-state recovery is not at its completion boundary"
        )
    return _append(
        journal_path,
        history.operation_id,
        "RECOVERY_COMPLETE",
        {
            "identity_count": history.baseline["identity_count"],
            "identifiers_redacted": True,
        },
    )


def find_journal(root: Path) -> Path | None:
    """Return the sole unfinished native-state recovery journal, if any."""
    matches = []
    for path in sorted(root.glob("*.jsonl")):
        records = t2_mutation_journal.read(path)
        evidence = records[0].get("evidence") if records else None
        if isinstance(evidence, dict) and evidence.get("operation_kind") == KIND:
            history = validate_history(records)
            if not history.complete:
                matches.append(path)
    if len(matches) > 1:
        raise NativeStateRecoveryError("native-state recovery journals are ambiguous")
    return matches[0] if matches else None
