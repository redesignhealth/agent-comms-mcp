"""GitHub-login -> Linear-user-ID identity mapping for the
``assign_ticket`` auto-approve lane (``service._rule_assign_ticket``,
TECH-5877 follow-up).

Closes a self-approval hole: a proposing bot could otherwise claim "the PR
author is also the proposed assignee" simply by asserting a GitHub login
of its own choosing inside the ``action`` payload it submits. Instead, the
rule fetches the PR from GitHub directly (an artifact, not a bot's own
claim) and looks up its ACTUAL ``user.login`` in this SERVER-SIDE mapping
to get the one Linear user id that login is trusted to correspond to -- an
unmapped login can never auto-approve, no matter what ``assignee_id`` the
bot proposes.

Built from the ``GITHUB_LOGIN_TO_LINEAR_USER_ID_JSON`` env var (a JSON
object, e.g. ``{"octocat": "user-uuid-1"}``), parsed ONCE at module import
time into an immutable mapping (``types.MappingProxyType``) -- same
"Terraform injects the env var, application code never calls SSM
directly" convention this repo already uses for ``GITHUB_TOKEN``/
``LINEAR_API_TOKEN`` (see ``.env.example``), rather than a mutable
module-level dict literal: hardcoding internal team-membership data
directly in source permanently embeds it in git history with no rotation
path, and a plain ``dict`` is a server-side trust anchor any importer
could mutate at runtime.

FAIL SAFE, NOT FAIL-THE-WHOLE-SERVICE: if the env var is absent, empty, or
fails to parse as a JSON object of string keys to string values, this
module logs a warning and falls back to a genuinely empty immutable
mapping -- same "inert by construction until populated" behavior this
mapping has always had (an unmapped login can never auto-approve, so an
empty map is always safe). This one optional env var being malformed must
never crash the whole service at import time.
"""

from __future__ import annotations

import json
import logging
import os
from types import MappingProxyType

logger = logging.getLogger(__name__)

_ENV_VAR = "GITHUB_LOGIN_TO_LINEAR_USER_ID_JSON"


def _parse_identity_map(raw: str | None) -> MappingProxyType[str, str]:
    """Parse ``raw`` (the ``_ENV_VAR`` env var's value) into an immutable
    ``{github_login: linear_user_id}`` mapping. Returns an empty mapping
    -- logging a warning, never raising -- if ``raw`` is absent/empty, is
    not valid JSON, is not a JSON object, or any key/value isn't a
    string."""
    if not raw:
        return MappingProxyType({})
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        logger.warning("%s is not valid JSON; defaulting to an empty identity map", _ENV_VAR)
        return MappingProxyType({})
    if not isinstance(parsed, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in parsed.items()
    ):
        logger.warning(
            "%s must be a JSON object of string keys to string values; defaulting to an "
            "empty identity map",
            _ENV_VAR,
        )
        return MappingProxyType({})
    return MappingProxyType(dict(parsed))


GITHUB_LOGIN_TO_LINEAR_USER_ID: MappingProxyType[str, str] = _parse_identity_map(
    os.environ.get(_ENV_VAR)
)

__all__ = ["GITHUB_LOGIN_TO_LINEAR_USER_ID"]
