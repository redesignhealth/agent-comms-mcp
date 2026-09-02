"""Provider sub-servers mounted on the root FastMCP server.

One module per provider; each exposes a ``FastMCP`` sub-server that main.py
mounts under a namespace. Tool names become ``<namespace>_<tool>`` and must
be enrolled in ``scopes.TOOL_SCOPES`` in the same PR that adds them.

WARNING (Argus round 3, TECH-5822): this ``__init__`` MUST remain
import-free. ``plugins.py`` calls ``importlib.resources.files("providers")``
at module load time (see ``INSTRUCTION_REGISTRY_PATH``), which imports this
package; meanwhile ``providers/comms.py`` imports ``plugins`` (and
``service``, which also imports ``plugins``). That's only safe today because
this file has no executable imports of its own -- adding one (e.g.
re-exporting ``comms`` here) creates a circular import via
``providers/comms.py -> plugins -> providers`` that surfaces as an
unrelated-looking ``ImportError`` at boot.
"""
