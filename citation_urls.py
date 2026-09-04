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
from urllib.parse import SplitResult, urlsplit


# Argus review round-10 BLOCKING fix: `urlsplit()` ITSELF can raise
# `ValueError` for a malformed IPv6 literal (e.g. an unclosed bracket
# `https://[::1/x`, or extra `::` groups `https://[::1::2]/path`) --
# eagerly, at parse time, not lazily on a later `.port`/`.hostname`
# access. Both call sites in this module (`is_valid_citation_url`,
# `redact_url_for_logging`) run on arbitrary caller-supplied strings that
# have not yet been validated as well-formed URLs, so BOTH need this same
# guard -- round-9's fix only wrapped `.port` in `redact_url_for_logging`,
# which is a strict subset of the actual failure surface: a bare
# `urlsplit()` call in `is_valid_citation_url` (which runs FIRST, before a
# rejected value ever reaches `redact_url_for_logging`) could already
# raise, propagating straight out of `_apply_or_finalize_proposal_hold`'s
# exception handling (neither `LinearAPIError` nor `CancelledError`
# matches a bare `ValueError`) and permanently stranding the hold at
# `"applying"`.
def _safe_urlsplit(value: str) -> SplitResult | None:
    try:
        return urlsplit(value)
    except ValueError:
        return None


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
    parsed = _safe_urlsplit(value)
    if parsed is None:
        return False
    if parsed.scheme not in ("http", "https"):
        return False
    if "@" in parsed.netloc:
        return False
    return parsed.hostname is not None and is_allowed_citation_host(parsed.hostname)


def redact_url_for_logging(value: str) -> str:
    """Scheme + host + path only, for logging/error text about a URL that
    FAILED ``is_valid_citation_url`` (Argus review round-7 suggestion): a
    rejected URL is by definition from an untrusted or unexpected source,
    and its query string or fragment may carry a token or other secret a
    caller embedded for its own (non-Linear) purpose -- neither belongs in
    a log line or an exception message, both of which can end up in
    less-trusted sinks (log aggregators, error-tracking services) than the
    Linear comment this validation exists to protect in the first place.
    Falls back to a fixed placeholder if the value doesn't even parse as a
    URL with a netloc, rather than logging the raw string in that case.

    Reconstructs the authority from ``parsed.hostname``/``parsed.port``,
    NOT ``parsed.netloc`` (Argus review round-8 BLOCKING fix): `netloc`
    includes embedded userinfo verbatim
    (``urlsplit("https://token:secret@evil.example/x").netloc ==
    "token:secret@evil.example"``) -- exactly the shape
    ``is_valid_citation_url`` rejects a URL FOR (round-4's userinfo
    check), which means every userinfo-bearing URL is guaranteed to reach
    this "redaction" path, and using `netloc` would have logged the
    credential verbatim instead of stripping it. `hostname` is userinfo-
    free by contract (``urllib.parse`` strips it before exposing that
    property).

    Every value read off ``parsed`` here is called on a URL that is, BY
    DEFINITION, one that already failed validation -- ``.port`` is a
    property that PARSES the authority on access and raises ``ValueError``
    for a malformed one (Argus review round-9 BLOCKING fix: a bare
    ``.port`` access previously let that propagate straight out of this
    function, uncaught anywhere in `_apply_or_finalize_proposal_hold`'s
    exception handling since neither `LinearAPIError` nor
    `CancelledError` matches a bare `ValueError`, permanently stranding
    the hold at `"applying"` -- exactly the failure mode this whole
    cooperative-cancellation/sanitization effort exists to prevent).
    Falls back to the same placeholder as an unparseable scheme/host.

    IPv6 literal hosts need their brackets restored on reconstruction
    (Argus review round-9 suggestion): ``parsed.hostname`` strips them
    (``"::1"``, not ``"[::1]"``), so a bare f-string join would produce an
    address that no longer parses as a URL at all -- misleading in a log
    line about what the actual offending value looked like.

    Uses ``_safe_urlsplit`` (Argus review round-10 BLOCKING fix): the bare
    ``urlsplit()`` call itself, not just the later ``.port`` access, can
    raise ``ValueError`` for a malformed URL (see the module-level
    comment on ``_safe_urlsplit``)."""
    parsed = _safe_urlsplit(value)
    if parsed is None or not parsed.scheme or not parsed.hostname:
        return "<unparseable-url>"
    try:
        port = parsed.port
    except ValueError:
        return "<unparseable-url>"
    host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
    authority = f"{host}:{port}" if port else host
    return f"{parsed.scheme}://{authority}{parsed.path}"
