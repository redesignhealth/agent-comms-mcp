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
above). ``entrypoint.sh`` runs ``alembic upgrade head`` on every ECS
container start, so two containers CAN race this build against the same
database during a rolling deploy. The actual safety net is NOT deploy
discipline -- it's ``if_not_exists=True``, which reduces the race window but
does not fully eliminate it: it checks whether the index name exists BEFORE
inserting the catalog row, so two containers that both pass that check
before either one commits can still race into a duplicate-name conflict.
That conflict is a loud container startup failure -- recoverable, since the
container simply fails to start and gets restarted/replaced by ECS, rather
than corrupting data or silently degrading -- not the guaranteed single-
winner outcome the naive reading of ``if_not_exists`` suggests.

That guard has a gap, though: ``if_not_exists`` only checks whether the
name exists, not whether the existing index is *valid*. If a build is
interrupted (e.g. the container that started it is killed mid-build), the
name exists but the index is left in Postgres's ``INVALID`` state (present
in ``pg_indexes``/``pg_index`` but unusable and silently skipped by the
planner). A later container's migration run then sees the name already
exists, skips rebuilding it, and Alembic stamps this revision as applied
-- even though the index is still unusable. Nothing surfaces this: the
rate-limit COUNT query in ``service._deny_rate_limited_proposals`` just
keeps full-scanning ``audit_log`` indefinitely as a silent perf
regression, not a deploy failure.

POST-DEPLOY HEALTH CHECK -- Operator runbook: this repo's deploy pipeline
(``.github/workflows/deploy.yml``) has no DB access -- migrations run
inside containers via ``entrypoint.sh``, and the workflow only builds and
pushes ECR images -- so this is NOT wired into CI/CD today. After deploying
a change that touches this migration, run the query below by hand against
the production DB to confirm the index is valid before considering the
deploy complete. (Wiring this into an automated check -- e.g. a
``/health?check_indexes`` variant, since the ``Dockerfile`` already defines
a plain ``/health`` check -- would be a reasonable follow-up, but does not
exist yet; don't assume it runs automatically.)

The query is written so it ALWAYS returns exactly one row, to avoid an
ambiguous NULL-vs-zero-rows read: naively querying
``SELECT NOT indisvalid FROM pg_index WHERE indexrelid = to_regclass(...)``
returns ZERO ROWS (not a row containing NULL) when the index doesn't exist,
because ``WHERE indexrelid = NULL`` is never true under SQL's three-valued
logic -- a caller checking ``result[0] is None`` would actually be checking
"no row came back" and would silently pass on a genuinely missing index.
The ``CASE`` wrapper below sidesteps that:

.. code-block:: sql

    SELECT CASE WHEN to_regclass('idx_audit_log_actor_sub_action_at') IS NULL
                THEN NULL
                ELSE (SELECT NOT indisvalid FROM pg_index
                      WHERE indexrelid = 'idx_audit_log_actor_sub_action_at'::regclass)
           END;

``true`` means INVALID (rebuild needed), ``false`` means healthy, and
``NULL`` means the index was never created.

PRE-CHECK before any remediation: the health-check query above reports the
same "needs attention" result (``true``) whether the index build is
genuinely stuck/failed OR is simply still actively running -- a concurrent
build's row is present-but-INVALID for the entire duration of the build,
not just after a failure. Jumping straight to remediation against a
still-building index would ``DROP INDEX CONCURRENTLY`` out from under a
healthy, in-progress build. Before concluding the index is genuinely stuck,
first check for an active builder:

.. code-block:: sql

    SELECT pid, query, state FROM pg_stat_activity
    WHERE query ILIKE '%idx_audit_log_actor_sub_action_at%' AND state != 'idle';

If this returns a row, an index build is still in flight -- wait for it to
finish (and confirm the ECS task running ``entrypoint.sh`` that started it
has since exited cleanly) and re-run the health-check query rather than
remediating. Only proceed to remediation below once this query returns zero
rows AND the health check still reports INVALID.

REMEDIATION if the health check reports INVALID (or you're diagnosing by
hand): query
``SELECT indexrelid::regclass, indisvalid FROM pg_index WHERE indexrelid = to_regclass('idx_audit_log_actor_sub_action_at');``
(using ``to_regclass`` rather than a plain ``::regclass`` cast so this
returns zero rows instead of raising ``ERROR: relation does not exist``
when the index was never built at all -- letting an operator distinguish
"never built" from "built but INVALID" without a hard error) -- or ``\\d
audit_log`` / ``pg_indexes`` to spot ``INVALID`` in the index list --
then ``DROP INDEX CONCURRENTLY idx_audit_log_actor_sub_action_at;`` before
re-running ``alembic upgrade head`` to rebuild it cleanly.
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
