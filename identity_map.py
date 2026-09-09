"""Placeholder GitHub-login -> Linear-user-ID identity mapping for the
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

PLACEHOLDER / INTENTIONALLY EMPTY: this repo does not have access to the
real team's GitHub-login-to-Linear-user-ID roster, so this dict starts
empty rather than fabricated. An empty mapping means every lookup misses,
so ``assign_ticket`` fails safe/inert by construction until a human
populates it with real ``{github_login: linear_user_id}`` entries (the
Linear user id is the internal id from Linear's ``User.id``, an opaque
string -- same convention as every other Linear internal id this repo
already handles, e.g. ``resolve_team_id``'s return value). Populate this
before deploying the ``assign_ticket`` lane in any environment where it
should actually be able to auto-approve anything.
"""

from __future__ import annotations

GITHUB_LOGIN_TO_LINEAR_USER_ID: dict[str, str] = {}

__all__ = ["GITHUB_LOGIN_TO_LINEAR_USER_ID"]
