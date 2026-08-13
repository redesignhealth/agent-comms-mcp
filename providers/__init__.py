"""Provider sub-servers mounted on the root FastMCP server.

One module per provider; each exposes a ``FastMCP`` sub-server that main.py
mounts under a namespace. Tool names become ``<namespace>_<tool>`` and must
be enrolled in ``scopes.TOOL_SCOPES`` in the same PR that adds them.
"""
