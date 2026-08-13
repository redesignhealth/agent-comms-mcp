"""Migration entry point for the agent-comms-mcp console script.

Runs ``alembic upgrade head`` against the migrations bundled with this
package, using the alembic Python API so no ``alembic.ini`` file is
required in the working directory.
"""

from __future__ import annotations

import importlib.resources
import os

from alembic import command
from alembic.config import Config


def _cli() -> None:
    """Entry point for the ``agent-comms-mcp-migrate`` console script."""
    cfg = Config()
    cfg.set_main_option(
        "script_location",
        str(importlib.resources.files("migrations")),
    )
    cfg.set_main_option("sqlalchemy.url", os.environ["DATABASE_URL"])
    command.upgrade(cfg, "head")
