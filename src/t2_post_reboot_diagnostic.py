# SPDX-License-Identifier: GPL-2.0-only
"""Bounded, identifier-free diagnostics for the post-reboot service gate."""

from __future__ import annotations

import errno as errno_module
from typing import Any


STAGES = frozenset(
    {
        "service-dispatch",
        "candidate-selection",
        "configuration-mapping-validation",
        "native-activation",
        "inventory-collection",
        "journal-append",
        "authority-publication",
        "final-authority-readback",
        "native-owner",
        "terminal-proof-validation",
        "external-deletion-reconciliation",
    }
)


def _class_name(value: BaseException | None) -> str | None:
    if value is None:
        return None
    name = type(value).__name__
    if not name.isidentifier() or not name.isascii() or len(name) > 80:
        return "Exception"
    return name


def _numeric_errno(error: BaseException) -> int | None:
    current: BaseException | None = error
    seen: set[int] = set()
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        value = getattr(current, "errno", None)
        if (
            type(value) is int
            and value in errno_module.errorcode
        ):
            return value
        current = current.__cause__ or current.__context__
    return None


class PostRebootStageError(RuntimeError):
    """Carry only allowlisted stage metadata across the service boundary."""

    def __init__(
        self,
        stage: str,
        error: BaseException,
        *,
        child_exit_status: int | None = None,
    ) -> None:
        if stage not in STAGES:
            raise ValueError("post-reboot diagnostic stage is not allowlisted")
        if child_exit_status is not None and (
            type(child_exit_status) is not int
            or not -(1 << 31) <= child_exit_status < (1 << 31)
        ):
            raise ValueError("child exit status is not bounded")
        super().__init__("post-reboot stage stopped")
        self.stage = stage
        self.exception_class = _class_name(error)
        self.cause_class = _class_name(error.__cause__ or error.__context__)
        self.errno = _numeric_errno(error)
        self.child_exit_status = child_exit_status

    def redacted(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "event": "post-reboot-reconciliation-stopped",
            "stage": self.stage,
            "exception_class": self.exception_class,
            "cause_class": self.cause_class,
            "errno": self.errno,
            "child_exit_status": self.child_exit_status,
            "identifiers_redacted": True,
        }


def staged(
    stage: str,
    error: BaseException,
    *,
    child_exit_status: int | None = None,
) -> PostRebootStageError:
    if isinstance(error, PostRebootStageError):
        return error
    return PostRebootStageError(
        stage, error, child_exit_status=child_exit_status
    )


def redacted_failure(error: BaseException) -> dict[str, Any]:
    if isinstance(error, PostRebootStageError):
        return error.redacted()
    return PostRebootStageError("service-dispatch", error).redacted()
