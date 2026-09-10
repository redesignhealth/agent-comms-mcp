"""validate apply_result consistency check without exclusive lock

Revision ID: 572b2b9a96d6
Revises: cf72736e07f5
Create Date: 2026-09-09 17:39:33.774951

Argus review round on cf72736e07f5: ``migrations/env.py::do_run_migrations``
wraps an entire ``alembic upgrade head`` run in ONE transaction (no
``transaction_per_migration``), so a plain ``VALIDATE CONSTRAINT`` here
would still run under the ``ACCESS EXCLUSIVE`` lock ``cf72736e07f5``'s own
``ADD CONSTRAINT ... NOT VALID`` took in that same ambient transaction --
fully negating the point of splitting the two steps into separate
migrations. This migration validates the constraint ``cf72736e07f5`` added
``NOT VALID``, using ``op.get_context().autocommit_block()`` (same pattern
as ``a9faca2517d7``) to drop out of that ambient transaction for the
``VALIDATE CONSTRAINT`` statement, so it genuinely runs in its own
transaction and takes only ``SHARE UPDATE EXCLUSIVE`` -- which does not
block concurrent SELECTs/INSERTs/UPDATEs -- instead of ``ACCESS
EXCLUSIVE``.

DEPLOYMENT: the autocommit block's implicit COMMIT releases
``migrations/env.py``'s advisory lock for the duration of this one
statement, same gap ``a9faca2517d7`` documents for its own concurrent
index build. The exposure here is much milder, though: unlike a
concurrent index build (which can be left ``INVALID`` if interrupted),
``VALIDATE CONSTRAINT`` is idempotent and PostgreSQL itself serializes
concurrent validations of the *same* constraint (the second waits on the
first's lock, then finds the constraint already valid and returns
immediately) -- so two racing deploy containers cannot corrupt anything or
leave the constraint in a broken state here. No operator runbook/manual-
intervention section is needed for this one.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "572b2b9a96d6"
down_revision: str | None = "cf72736e07f5"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # VALIDATE CONSTRAINT only takes SHARE UPDATE EXCLUSIVE -- but only if
    # it runs in its OWN transaction, separate from cf72736e07f5's
    # ADD CONSTRAINT ... NOT VALID. env.py wraps the whole `upgrade head`
    # run in one transaction, so drop out of it for this one statement
    # (same pattern as a9faca2517d7).
    with op.get_context().autocommit_block():
        op.execute(
            "ALTER TABLE proposal_holds VALIDATE CONSTRAINT "
            "ck_proposal_holds_apply_result_consistency"
        )


def downgrade() -> None:
    # PostgreSQL has no "un-validate a constraint" DDL, and it doesn't
    # matter: a NOT VALID CHECK is already enforced against every new
    # INSERT/UPDATE, so a validated constraint is a strictly stronger
    # state, never a broken one. cf72736e07f5's own downgrade() drops the
    # constraint outright, so `alembic downgrade base` still ends up in
    # the right place. Deliberately no DROP-and-re-add-NOT-VALID here --
    # that would re-take ACCESS EXCLUSIVE to reach a strictly weaker state.
    pass
