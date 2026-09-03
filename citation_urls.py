"""Shared citation-URL allowlist/validation (Argus review round-2 S2).

Extracted out of ``service.py`` so both ``service.py`` (the
``linear_progress_update`` auto-approval judge) and ``linear_client.py``
(re-validating a URL at apply time, before writing it into a Linear
comment -- see ``linear_client._progress_comment_body``) can import a
single neutral module instead of ``linear_client.py`` lazy-importing
``service`` to reach a private helper there. ``service.py`` already
imports ``linear_client`` at module level, so that lazy import was a real
circular-dependency workaround, not just a style choice -- this module
removes the cycle instead of routing around it.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

# A citation URL (``source_message_url``/``resolving_pr_url`` on a
# ``linear_progress_update`` proposal action) must now be an http(s) URL
# whose host is one of these two families: Slack message permalinks
# (``*.slack.com``) and GitHub PR/commit links (``github.com``) -- the two
# citation shapes the judge is documented to accept.
ALLOWED_CITATION_HOST_EXACT = frozenset({"github.com"})
ALLOWED_CITATION_HOST_SUFFIXES = (".slack.com",)


def is_allowed_citation_host(host: str) -> bool:
    host = host.lower()
    if host in ALLOWED_CITATION_HOST_EXACT:
        return True
    return any(host.endswith(suffix) for suffix in ALLOWED_CITATION_HOST_SUFFIXES)


def is_valid_citation_url(value: Any) -> bool:
    """A citation must be an http(s) URL on an allowlisted host (see
    ``ALLOWED_CITATION_HOST_EXACT``/``ALLOWED_CITATION_HOST_SUFFIXES``
    above), not merely a non-empty string."""
    if not isinstance(value, str) or not value.strip():
        return False
    parsed = urlsplit(value)
    if parsed.scheme not in ("http", "https"):
        return False
    return parsed.hostname is not None and is_allowed_citation_host(parsed.hostname)
