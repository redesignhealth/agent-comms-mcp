"""add suppressed status to wake_events

Revision ID: b5d2e8f41a96
Revises: a7c3e91d5b08
Create Date: 2026-11-24 00:00:00.000000

TECH-9883: the wake loop guard records an event it holds back as a
``wake_events`` row with status ``suppressed`` (never delivered), so an operator
can see it in ``comms_admin_wake_events_list`` and an agent can see why it stopped
being woken. Widens ``ck_wake_events_status`` by one value.

DEPLOYMENT: purely additive. An old container never writes the new value and the
delivery task only claims open statuses, so it ignores any ``suppressed`` row.

``downgrade()`` deletes the ``suppressed`` rows first: they carry no delivery
state, and the narrowed constraint would otherwise fail on them.
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "b5d2e8f41a96"
down_revision: str | None = "a7c3e91d5b08"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_OLD = "'pending', 'delivered', 'retry', 'retry_later', 'failed', 'dead'"
_NEW = "'pending', 'delivered', 'retry', 'retry_later', 'failed', 'dead', 'suppressed'"


def upgrade() -> None:
    op.drop_constraint("ck_wake_events_status", "wake_events", type_="check")
    op.create_check_constraint("ck_wake_events_status", "wake_events", f"status IN ({_NEW})")


def downgrade() -> None:
    op.execute("DELETE FROM wake_events WHERE status = 'suppressed'")
    op.drop_constraint("ck_wake_events_status", "wake_events", type_="check")
    op.create_check_constraint("ck_wake_events_status", "wake_events", f"status IN ({_OLD})")
