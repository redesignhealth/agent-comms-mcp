"""Pure workflow-state ordering rule for Linear-backed auto-approve judge
lanes.

Deliberately separate from ``state_machine.py``: that module is
conversation-negotiation state (DESIGN.md §6/§4, the comms board's own
``active``/``completed``/``canceled``/``expired`` lifecycle) and has
nothing to do with a Linear issue's workflow state. This module's
``is_forward_transition`` is the one universal safety rule every future
Linear auto-approve lane (``start_ticket``, ``review_ticket``, etc.) will
depend on: no ``service.py``/judge call sites exist yet -- that wiring is
follow-up work (this PR only adds the rule).

Side-effect-free and dependency-free (no I/O, no imports beyond the
standard library) so it is trivially unit-testable on its own.
"""

from __future__ import annotations

_STATE_TYPE_RANK: dict[str, int] = {
    "backlog": 0,
    "unstarted": 1,
    "started": 2,
    "completed": 3,
}

# Linear's own WorkflowState.type is coarse: BOTH "In Progress" and
# "In Review" are type="started". This tiebreaks within that type only,
# keyed on lowercased display name, since type alone can't distinguish
# them -- which matters because start_ticket (-> In Progress) and
# review_ticket (-> In Review) are different lanes with different rules.
_STARTED_SUBRANK: dict[str, int] = {
    "in progress": 0,
    "in review": 1,
}


def is_forward_transition(
    *, current_type: str, current_name: str, target_type: str, target_name: str
) -> bool:
    """Returns True only if the target state is strictly forward of the
    current state along the workflow.

    Fails CLOSED (returns False) on: an unknown type on either side, a
    name inside 'started' not present in ``_STARTED_SUBRANK`` on either
    side, 'canceled' appearing on either side, or an equal-rank (no-op)
    transition. This is the one universal safety rule every new
    auto-approve lane depends on: forward only, backward (or unknown)
    always held for a human."""
    if current_type == "canceled" or target_type == "canceled":
        return False
    if current_type not in _STATE_TYPE_RANK or target_type not in _STATE_TYPE_RANK:
        return False

    current_rank = (_STATE_TYPE_RANK[current_type], 0)
    if current_type == "started":
        subrank = _STARTED_SUBRANK.get(current_name.lower())
        if subrank is None:
            return False
        current_rank = (current_rank[0], subrank)

    target_rank = (_STATE_TYPE_RANK[target_type], 0)
    if target_type == "started":
        subrank = _STARTED_SUBRANK.get(target_name.lower())
        if subrank is None:
            return False
        target_rank = (target_rank[0], subrank)

    return target_rank > current_rank


__all__ = ["is_forward_transition"]
