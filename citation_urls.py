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

Also holds ``CLOSE_TICKET_ACTION_TYPES`` (Argus review round-4
suggestion): both ``service.py``'s judge (OR-of-two-citation-fields
auto-approval rule) and ``linear_client.py``'s applier (which mirrors
that same OR semantics by omitting rather than raising on an invalid
field, but ONLY for these action types -- see
``linear_client._progress_comment_body``) must agree on exactly which
action types this applies to, or the two would silently desync the same
way the OR-vs-AND semantics themselves once did (Argus review round-2
B3/round-3 S4).
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

CLOSE_TICKET_ACTION_TYPES = frozenset({"close_ticket"})


def is_allowed_citation_host(host: str) -> bool:
    host = host.lower()
    if host in ALLOWED_CITATION_HOST_EXACT:
        return True
    return any(host.endswith(suffix) for suffix in ALLOWED_CITATION_HOST_SUFFIXES)


def is_valid_citation_url(value: Any) -> bool:
    """A citation must be an http(s) URL on an allowlisted host (see
    ``ALLOWED_CITATION_HOST_EXACT``/``ALLOWED_CITATION_HOST_SUFFIXES``
    above), not merely a non-empty string.

    Rejects embedded userinfo (``https://user@host/...``, Argus review
    round-4 suggestion) even when the host itself is allowlisted: the
    hostname check alone validates WHERE the link points, but the full
    URL -- userinfo included -- is what gets posted verbatim into the
    Linear comment (``linear_client._progress_comment_body``). A
    proposing bot could otherwise craft a citation like
    ``https://click-here-for-a-refund@redesignhealth.slack.com/...`` that
    passes host validation while presenting arbitrary attacker-controlled
    text ahead of the real, allowlisted host -- a social-engineering
    vector for whoever reads the resulting Linear comment.
    """
    if not isinstance(value, str) or not value.strip():
        return False
    parsed = urlsplit(value)
    if parsed.scheme not in ("http", "https"):
        return False
    if "@" in parsed.netloc:
        return False
    return parsed.hostname is not None and is_allowed_citation_host(parsed.hostname)
