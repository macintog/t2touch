# SPDX-License-Identifier: GPL-2.0-only
"""Preserve the exact system-bus sender across dbus-next service dispatch."""

from __future__ import annotations

import contextvars
import re

from dbus_next import DBusError
from dbus_next.aio import MessageBus


class DBusSenderError(RuntimeError):
    pass


_CURRENT_SENDER: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "t2_touchid_dbus_sender", default=None
)
_UNIQUE_NAME = re.compile(r":[0-9]+(?:\.[0-9]+)+")


def validate_sender(value: object) -> str:
    if (
        type(value) is not str
        or len(value) > 255
        or _UNIQUE_NAME.fullmatch(value) is None
    ):
        raise DBusSenderError("D-Bus caller has no canonical unique name")
    return value


def current_sender() -> str:
    return validate_sender(_CURRENT_SENDER.get())


class SenderAwareMessageBus(MessageBus):
    """Pin each method task to the sender of its immutable D-Bus message."""

    def _make_method_handler(self, interface, method):
        delegated = super()._make_method_handler(interface, method)

        def handler(message, send_reply):
            class TypedErrorReply:
                def __call__(self, reply):
                    return send_reply(reply)

                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc_value, traceback):
                    if isinstance(exc_value, DBusError):
                        # dbus-next 0.2.3 sends the typed error, but its reply
                        # context fails to suppress it in async callbacks.
                        # Expected protocol replies must not look like crashes.
                        send_reply.send_error(exc_value)
                        return True
                    return send_reply.__exit__(exc_type, exc_value, traceback)

                def send_error(self, error):
                    return send_reply.send_error(error)

            token = _CURRENT_SENDER.set(message.sender)
            try:
                return delegated(message, TypedErrorReply())
            finally:
                _CURRENT_SENDER.reset(token)

        return handler
