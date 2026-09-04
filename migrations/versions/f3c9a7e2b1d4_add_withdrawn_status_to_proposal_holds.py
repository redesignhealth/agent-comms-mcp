"""add withdrawn status and bot decision_source to proposal_holds

Revision ID: f3c9a7e2b1d4
Revises: e2f7a91c5b34
Create Date: 2026-09-04 00:00:00.000000

TECH-6018: lets the SUBMITTING bot retire its own still-``pending``
proposal via a new ``POST /proposals/{id}/withdraw`` route -- most useful
when the bot has since determined the proposal is stale or simply wrong
and wants it retracted before a human can decide it. NOT for freeing up
the create-time dedup key: a resubmission for the SAME ``(kind,
proposed_by_bot_id, target_id, action_type)`` key already updates the
existing pending row in place at create time, and a DIFFERENT key was
never blocked to begin with. Not the TTL-based lazy expiry
``approval_holds`` uses for its own, differently-named ``expired``
status -- ``proposal_holds`` has no ``expires_at`` column or sweep
mechanism; this is a caller-initiated retraction, always immediate.

Widens ``ck_proposal_holds_status`` (new terminal value ``'withdrawn'``)
and ``ck_proposal_holds_decision_source`` (new value ``'bot'``, marking a
decision made by the submitting bot itself rather than the TECH-5877
auto-judge (``'auto'``) or a human reviewer (``'human'``) -- a bot can
never reach ``decide_proposal`` at all, so ``'bot'`` can only appear on a
``'withdrawn'`` row today). ``'withdrawn'`` already satisfies
``ck_proposal_holds_decision_consistency`` (the ``status != 'pending'``
branch requires ``decided_at``/``decided_by_actor_id``/``decision_source``
all set, which the withdraw call stamps together) and
``ck_proposal_holds_applied_at_consistency`` (``applied_at`` stays NULL
for every status other than ``'applied'``) without any further change.

No index change: the create-time dedup partial index
(``idx_proposal_holds_pending_dedup``, predicate
``status IN ('pending', 'applying')``) already excludes any terminal
status, including this new one -- a withdrawn proposal's
``(kind, proposed_by_bot_id, target_id, action_type)`` key becomes
available for a fresh submission immediately, with no further widening
needed.

DEPLOYMENT: purely additive (widening two CHECK constraints' allowed
value sets, not narrowing either) -- safe for a normal rolling deploy. An
old container's code never writes ``'withdrawn'``/``'bot'`` (it doesn't
know either value exists) and treats any row it doesn't recognize as an
opaque non-``pending``, non-``applied`` status, same as it already does
for every other terminal status it doesn't specifically branch on.

``downgrade()`` first reaps any row sitting at ``'withdrawn'`` (mirroring
``e2f7a91c5b34``'s own reap-before-narrow pattern for ``'applying'``) --
PostgreSQL validates every existing row against a newly-narrowed CHECK
constraint, so a single withdrawn row would otherwise make
``downgrade()`` fail non-idempotently. Resolving it to ``'rejected'`` is
the closest existing terminal status with the same practical effect
(never applied, safely retryable via a fresh proposal resubmission) --
its ``decision_source`` is reset to ``'human'`` in the same statement
since ``'bot'`` would no longer satisfy the narrowed
``ck_proposal_holds_decision_source`` either.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "f3c9a7e2b1d4"
down_revision: str | None = "e2f7a91c5b34"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_OLD_STATUSES = "'pending', 'approved', 'applying', 'rejected', 'applied', 'apply_failed', 'stale'"
_NEW_STATUSES = (
    "'pending', 'approved', 'applying', 'rejected', 'applied', 'apply_failed', 'stale', 'withdrawn'"
)
_OLD_DECISION_SOURCES = "'human', 'auto'"
_NEW_DECISION_SOURCES = "'human', 'auto', 'bot'"


def upgrade() -> None:
    op.drop_constraint("ck_proposal_holds_status", "proposal_holds", type_="check")
    op.create_check_constraint(
        "ck_proposal_holds_status",
        "proposal_holds",
        f"status IN ({_NEW_STATUSES})",
    )
    op.drop_constraint("ck_proposal_holds_decision_source", "proposal_holds", type_="check")
    op.create_check_constraint(
        "ck_proposal_holds_decision_source",
        "proposal_holds",
        f"decision_source IS NULL OR decision_source IN ({_NEW_DECISION_SOURCES})",
    )


def downgrade() -> None:
    op.execute(
        "UPDATE proposal_holds SET status = 'rejected', decision_source = 'human' "
        "WHERE status = 'withdrawn'"
    )
    op.drop_constraint("ck_proposal_holds_decision_source", "proposal_holds", type_="check")
    op.create_check_constraint(
        "ck_proposal_holds_decision_source",
        "proposal_holds",
        f"decision_source IS NULL OR decision_source IN ({_OLD_DECISION_SOURCES})",
    )
    op.drop_constraint("ck_proposal_holds_status", "proposal_holds", type_="check")
    op.create_check_constraint(
        "ck_proposal_holds_status",
        "proposal_holds",
        f"status IN ({_OLD_STATUSES})",
    )
