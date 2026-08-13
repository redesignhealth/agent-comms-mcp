"""backfill accepted_types for existing agents

Revision ID: e1db7c2e6b70
Revises: da3e1646c44d
Create Date: 2026-08-13 10:07:06.090851

Followup: this PR turns ``accepted_types`` from a purely
informational, unenforced declaration (DESIGN.md's own prior wording) into
a real per-message capability gate (``service._enforce_message_type_accepted``)
that denies a send when a recipient hasn't declared the message's type.

Any agent already registered before this PR merges declared its
``accepted_types`` at a time when that value had zero behavioral effect --
narrowing it cost nothing and communicated nothing except intent. Deploying
the new gate without backfilling would silently break every one of those
agents' *incoming* traffic for any type outside whatever narrow list they
happened to register with, the moment this ships -- not a bug in the new
code, but a real production incident caused by enforcing a field
retroactively against declarations made under a different contract.

This is a one-time grandfather clause, not a permanent behavior: it widens
every EXISTING agent row's ``accepted_types`` to the full registered
message-type set as of this revision, so nothing that worked yesterday
breaks today. Any agent registered AFTER this migration runs is unaffected
by it -- `register_agent`'s own validation/defaults apply to those as
normal, and a caller's own future re-registration (idempotent upsert on
`agents.sub`) can narrow its own declared set going forward, now that doing
so has a real, understood effect.

The literal list below is intentionally not imported from `schemas.py`:
migrations are frozen historical artifacts (see other revisions' own notes
on this), and `schemas.MESSAGE_TYPES` reflects the CURRENT registry, not
"whatever existed at this migration's authoring time" -- importing it would
make this file's behavior depend on future changes to that module.

DEPLOYMENT: taken in isolation, this revision's own DDL/DML needs no
stop-then-start -- it only widens an existing `agents.accepted_types`
column's VALUES, touching no column that any currently-running container
(old or new) reads or writes differently because of it. But
`entrypoint.sh` runs `alembic upgrade head` atomically, so a deploy that
carries this revision alongside its still-pending parent (`da3e1646c44d`,
which DROPs `audit_log.task_id`) is governed by that parent's
stop-then-start requirement for the combined run -- this note does not
override that.

Even under stop-then-start, there is a real window this migration cannot
close on its own: any container still draining writes to
`agents.accepted_types` via `service.register_agent`'s unconditional
upsert right up until it stops. A re-registration that lands after this
migration's UPDATE commits, from an old container still operating under
the pre-enforcement "informational" contract, can re-narrow that row --
which the new gate then enforces. This is precisely why stop-then-start
matters here too, not merely for the parent revision's column drop.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "e1db7c2e6b70"
down_revision: str | None = "da3e1646c44d"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Literal snapshot of schemas.MESSAGE_TYPES at authoring time, written
    # directly rather than assembled from a Python constant -- see the
    # module docstring for why this isn't imported from schemas.py, and
    # matching this migration chain's convention (e.g. 15ef34885e30) of
    # frozen migrations containing plain SQL literals, not code that could
    # silently change what a "frozen" file emits.
    op.execute(
        "UPDATE public.agents SET accepted_types = ARRAY["
        "'availability_request', 'availability_response', 'confirm', "
        "'counter_proposal', 'decline', 'needs_clarification', 'note', "
        "'task_assign', 'task_cancel', 'task_complete', 'task_decline', "
        "'task_report']::text[], updated_at = now()"
    )


def downgrade() -> None:
    # Not reversed: there is no way to recover each agent's actual
    # pre-migration accepted_types (this UPDATE overwrites them
    # unconditionally, same lossy-downgrade posture as other revisions in
    # this migration chain). Downgrading this revision leaves every
    # agent's accepted_types at the widened set rather than restoring
    # narrower pre-migration declarations.
    pass
