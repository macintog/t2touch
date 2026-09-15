# SPDX-License-Identifier: GPL-2.0-only
from __future__ import annotations

import sys
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


SOURCE = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE))
import t2_ipc_session as ipc_session
import t2_linux_account as linux_account
import t2_native_caller_authorization as caller_authorization
import t2_user_mapping as mapping
import t2_user_policy as policy


def identifier(number: int) -> str:
    return str(uuid.UUID(int=number))


class NativeCallerAuthorizationTests(unittest.TestCase):
    def test_migrated_account_is_bound_to_preserved_authority_generation(self):
        selected = mapping.UserMapping(
            1000,
            "a" * 64,
            501,
            identifier(1),
            identifier(2),
            "/var/lib/t2-touchid/users/1000/user.kb",
            "b" * 64,
            "password-on-demand",
            frozenset({"verify", "enroll", "identity-management"}),
            True,
        )
        mapping_set = mapping.UserMappingSet("c" * 64, (selected,), 2)
        authority = SimpleNamespace(selected=selected, mapping_set=mapping_set)
        session = mock.create_autospec(
            ipc_session.AuthorizationSession, instance=True
        )
        session.account = linux_account.AccountEvidence(
            1000,
            "d" * 64,
            compatible_generations=frozenset({"a" * 64}),
        )
        session.caller = policy.CallerEvidence(1000, "d" * 64, True, True)

        def bind(generation):
            session.account = linux_account.AccountEvidence(1000, generation)
            session.caller = policy.CallerEvidence(1000, generation, True, True)

        session.bind_account_generation.side_effect = bind

        def collect(**arguments):
            grant = policy.PolicyGrant(
                identifier(10 if "activate" not in arguments["action"] else 11),
                arguments["action"],
                1000,
                session.account.generation,
                arguments["target_linux_uid"],
                arguments["mapping_generation"],
                arguments["operation_id"],
                arguments["linux_boot_uuid"],
                arguments["runtime_generation"],
                1,
                (1 << 63) - 1,
                True,
            )
            return SimpleNamespace(policy=SimpleNamespace(grant=grant))

        session.collect.side_effect = collect
        with mock.patch.object(
            caller_authorization.t2_user_authority,
            "load",
            return_value=authority,
        ):
            result = caller_authorization.collect(
                session,
                authority,
                operation="enroll",
                operation_id=identifier(3),
                linux_boot_uuid=identifier(4),
                runtime_generation=identifier(5),
            )

        session.bind_account_generation.assert_called_once_with("a" * 64)
        self.assertEqual(result.operation_grant.linux_account_generation, "a" * 64)


if __name__ == "__main__":
    unittest.main()
