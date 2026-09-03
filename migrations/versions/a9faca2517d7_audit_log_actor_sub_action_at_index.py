"""audit_log actor_sub/action/at concurrent index

Revision ID: a9faca2517d7
Revises: 9a1c2d3e4f5b
Create Date: 2026-09-03 00:00:00.000002

TECH-5872/5875 (Argus review, B1 round 3): ``idx_audit_log_actor_sub_action_at``
backs the per-bot rate-limit COUNT query moved to ``audit_log`` in
``service._deny_rate_limited_proposals`` -- ``audit_log`` had no index on
``actor_sub`` at all before this revision (only ``conversation_id`` and
``at``), so that query would otherwise full-scan a table every mutation and
denial in the service ever writes to.

This index is purely additive (no column/table changes) but is built with
``postgresql_concurrently=True`` specifically because ``audit_log`` is
written on every tool call/mutation/denial in this service -- a plain,
lock-taking ``CREATE INDEX`` would hold ``ACCESS EXCLUSIVE`` for the full
build and stall all of those writes for the deploy window. Concurrent index
builds cannot run inside a transaction, so ``upgrade()`` drops out of the
ambient migration transaction via ``op.get_context().autocommit_block()``
for that one statement, mirroring the only non-transactional pattern this
repo's migration history has needed so far.

Building a concurrent index while holding ``migrations/env.py``'s
``pg_advisory_xact_lock`` is inherently awkward: the autocommit block's
implicit COMMIT releases that lock for its duration, so a second
``alembic upgrade head`` invocation started at exactly the wrong moment is
not fully serialized against this one for this specific statement. This
migration was split out from ``9a1c2d3e4f5b`` (Argus review B1, round 3)
specifically so that split isolates the exposure to just this one
already-additive, already-idempotent (``if_not_exists=True``) step, rather
than letting it also race the ``proposal_holds`` unique-index build in the
prior revision.

DEPLOYMENT: this migration's ``CREATE INDEX CONCURRENTLY`` step is NOT
covered by ``migrations/env.py``'s advisory lock for its full duration (see
above) -- correctness under a rolling/multi-container deploy therefore
relies on deploy discipline, not the DB: run migrations from a single
migration-runner invocation (this repo has no additional migration-gating
mechanism beyond that advisory lock and CI's single migration step: do not
add a second concurrent entry point that also calls ``alembic upgrade head``
against the same database).

If ``CREATE INDEX CONCURRENTLY`` fails or is interrupted, it can leave
``idx_audit_log_actor_sub_action_at`` in Postgres's ``INVALID`` state
(present in ``pg_indexes``/``pg_index`` but unusable and silently skipped by
the planner). Remediation: query
``SELECT indexrelid::regclass, indisvalid FROM pg_index WHERE indexrelid = 'idx_audit_log_actor_sub_action_at'::regclass;``
(or ``\\d audit_log`` / ``pg_indexes`` to spot ``INVALID`` in the index
list), then ``DROP INDEX CONCURRENTLY idx_audit_log_actor_sub_action_at;``
before re-running ``alembic upgrade head`` to rebuild it cleanly.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "a9faca2517d7"
down_revision: str | None = "9a1c2d3e4f5b"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # CONCURRENTLY cannot run inside a transaction; drop out of the ambient
    # migration transaction for this one statement (see DEPLOYMENT note
    # above) and let Alembic re-open a transaction afterward.
    with op.get_context().autocommit_block():
        op.create_index(
            "idx_audit_log_actor_sub_action_at",
            "audit_log",
            ["actor_sub", "action", "at"],
            unique=False,
            if_not_exists=True,
            postgresql_concurrently=True,
        )


def downgrade() -> None:
    with op.get_context().autocommit_block():
        op.drop_index(
            "idx_audit_log_actor_sub_action_at",
            table_name="audit_log",
            if_exists=True,
            postgresql_concurrently=True,
        )
