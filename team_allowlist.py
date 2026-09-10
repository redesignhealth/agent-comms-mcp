"""Server-side allowlist of Linear team keys ``open_ticket`` may auto-approve
issue creation into (``service._rule_open_ticket``, TECH-5877 follow-up).

Closes a scope gap: ``action["team"]`` is entirely bot-asserted -- there is
no pre-existing Linear issue for ``open_ticket`` to fetch and cross-check a
team against (unlike ``start_ticket``/``review_ticket``/``label_ticket``,
which mutate an existing ``target_id`` whose real team already bounds the
blast radius; see ``docs/DESIGN.md``'s deferred-scope note for those three).
Without this allowlist, a bot could get a brand-new issue auto-created on
ANY Linear team just by naming it in ``action["team"]``. This module gives
``_rule_open_ticket`` a SERVER-SIDE set of team keys it is allowed to
auto-approve into; a team not on the list is held for a human, never
auto-approved, no matter what else about the proposal checks out.

Built from the ``PROPOSAL_OPEN_TICKET_TEAM_ALLOWLIST`` env var (a JSON
array of strings, e.g. ``["TECH"]``) -- same "Terraform injects the env
var, application code never calls SSM directly" convention, and the same
JSON-array-of-strings shape as this module's sibling ``identity_map.py``
(which uses a JSON object instead, since it maps keys to values rather
than enumerating a set) -- parsed ONCE at module import time into an
immutable ``frozenset``, rather than a mutable module-level container: a
plain ``set``/``list`` literal is a server-side trust anchor any importer
could mutate at runtime, and hardcoding this directly in source permanently
embeds it in git history with no rotation path.

Matching is CASE-SENSITIVE, exact-string equality -- consistent with
``linear_client.resolve_team_id``'s own exact-match team-key filter (Linear
team keys are matched as literal strings there too, never case-folded).

FAIL CLOSED, NOT FAIL-THE-WHOLE-SERVICE: if the env var is absent, empty, or
fails to parse as a JSON array of non-empty strings, this module logs a
warning and falls back to a genuinely empty immutable ``frozenset`` -- same
"inert by construction until populated" posture as ``identity_map.py``'s
own mapping. An empty allowlist means ``open_ticket`` NEVER auto-approves
(every proposal is held for a human instead), which is always the safe
default -- this one optional env var being malformed or unset must never
crash the whole service at import time, and must never fail OPEN into
allowing auto-approval for every team.
"""

from __future__ import annotations

import json
import logging
import os

logger = logging.getLogger(__name__)

_ENV_VAR = "PROPOSAL_OPEN_TICKET_TEAM_ALLOWLIST"


def _parse_team_allowlist(raw: str | None) -> frozenset[str]:
    """Parse ``raw`` (the ``_ENV_VAR`` env var's value) into an immutable
    set of allowed Linear team keys. Returns an empty ``frozenset`` --
    logging a warning, never raising -- if ``raw`` is absent/empty, is not
    valid JSON, is not a JSON array, or contains any non-string or
    empty-string element."""
    if not raw:
        return frozenset()
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("%s is not valid JSON; defaulting to an empty team allowlist", _ENV_VAR)
        return frozenset()
    if not isinstance(parsed, list) or not all(isinstance(item, str) and item for item in parsed):
        logger.warning(
            "%s must be a JSON array of non-empty strings; defaulting to an empty team allowlist",
            _ENV_VAR,
        )
        return frozenset()
    return frozenset(parsed)


OPEN_TICKET_TEAM_ALLOWLIST: frozenset[str] = _parse_team_allowlist(os.environ.get(_ENV_VAR))

__all__ = ["OPEN_TICKET_TEAM_ALLOWLIST"]
