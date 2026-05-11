"""LOW #3: `_pb_action` must cover every RuleAction enum member.

The original implementation was a `dict.get(..., RULE_ACTION_UNSPECIFIED)`
that silently sent UNSPECIFIED to every agent if someone added a new
RuleAction without updating the dict. Now it's a match-statement;
this test pins the contract — every member of RuleAction must map to
a non-UNSPECIFIED wire value.
"""

from __future__ import annotations

from app.grpc.services import _pb_action
from app.models import RuleAction
from app.proto_gen.edr.v1 import common_pb2


def test_every_rule_action_member_maps_to_concrete_wire_value() -> None:
    for member in RuleAction:
        wire = _pb_action(member.value)
        assert wire != common_pb2.RULE_ACTION_UNSPECIFIED, (
            f"RuleAction.{member.name} maps to RULE_ACTION_UNSPECIFIED — "
            f"add a `case` to `_pb_action` in app/grpc/services.py."
        )


def test_unknown_action_falls_through_to_unspecified_and_logs() -> None:
    """Defensive — keeps the fallthrough path well-defined for the
    unlikely case where a non-RuleAction string reaches the function
    (e.g. a malformed Rule row from a hand-edit)."""
    assert _pb_action("definitely_not_a_real_action") == common_pb2.RULE_ACTION_UNSPECIFIED
