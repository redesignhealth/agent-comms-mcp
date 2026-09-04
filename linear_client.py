"""Thin Linear API client for synchronously applying decided
``proposal_holds`` of ``kind="linear_progress_update"`` (TECH-5873).

Deliberately narrow -- two functions, ``fetch_current_fingerprint`` and
``apply_progress_update`` -- so ``service.decide_proposal`` can mock this
module wholesale in tests (this repo has no CI, let alone a Linear sandbox,
so nothing here is ever exercised against the real API in automated tests).

Called directly from agent-comms-mcp, not proxied back through whatever
Prefect flow originally submitted the proposal -- that flow run is long
gone by decide time (TECH-5873 ticket).

Credential: ``LINEAR_API_TOKEN`` env var, provisioned via SSM at
``/reclaw-comms/{env}/linear-api-token`` (TECH-5874) and injected by
Terraform -- same "application code reads an env var, never calls SSM
directly" convention this repo already uses for
``OKTA_CLIENT_SECRET``/``MCP_JWT_SECRET``/``AGENT_JWT_SECRET`` (see
``auth.py``'s ``require_env`` and ``.env.example``).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from typing import Any

import httpx

import citation_urls

logger = logging.getLogger(__name__)

_LINEAR_API_URL = "https://api.linear.app/graphql"
_LINEAR_API_TOKEN_ENV_VAR = "LINEAR_API_TOKEN"
_LINEAR_REQUEST_TIMEOUT_SECONDS = 10.0

_ISSUE_QUERY = """
query Issue($id: String!) {
  issue(id: $id) {
    id
    state { id name }
    priority
    assignee { id }
    updatedAt
  }
}
"""

_COMMENT_MUTATION = """
mutation CreateComment($issueId: String!, $body: String!) {
  commentCreate(input: { issueId: $issueId, body: $body }) {
    success
  }
}
"""

# Design decision (TECH-5873, not fully specified by the ticket): the
# actual Linear "write" for kind="linear_progress_update" is a comment
# posted to the target issue, not an issue-state mutation -- this is a
# progress-reporting bot (the name says so), and the two action_types the
# judge understands (open_ticket/close_ticket -- see
# citation_urls.CLOSE_TICKET_ACTION_TYPES for the close-ticket set, shared
# with service.py to avoid semantic drift since Argus review round-4 S1)
# read as "report that a ticket was opened/closed", not "mutate this
# issue's workflow state" -- mutating state would additionally require
# resolving a team-specific workflow state id, which the action payload
# doesn't carry. A future kind that genuinely needs a state transition
# gets its own applier function.


class LinearAPIError(Exception):
    """Raised on any non-2xx response, GraphQL error payload, missing
    issue, or transport failure. Caught by ``service.decide_proposal``'s
    approve path and mapped to ``status="apply_failed"`` with
    ``apply_error=str(exc)`` -- never propagated as an unhandled 500."""


class LinearTokenMissingError(LinearAPIError):
    """``LINEAR_API_TOKEN`` is unset. A typed subclass (Argus review
    round-6 suggestion), not string-matched by
    ``service._sanitize_apply_error``: a bare substring check
    (``"is not configured" in str(exc)``) would also match this text if it
    ever appeared verbatim inside a message Linear's own GraphQL API
    returned, misclassifying a real Linear-side error as a local
    configuration problem."""


class LinearTransportError(LinearAPIError):
    """The HTTP request to Linear itself failed (connection error, timeout,
    non-JSON body) -- as opposed to a well-formed response Linear returned
    with an error payload. A typed subclass (Argus review round-6
    suggestion) for the same reason as ``LinearTokenMissingError``."""


def _require_api_token() -> str:
    token = os.environ.get(_LINEAR_API_TOKEN_ENV_VAR)
    if not token:
        raise LinearTokenMissingError(f"{_LINEAR_API_TOKEN_ENV_VAR} is not configured")
    return token


async def _post_graphql(query: str, variables: dict[str, Any]) -> dict[str, Any]:
    token = _require_api_token()
    try:
        async with httpx.AsyncClient(
            timeout=_LINEAR_REQUEST_TIMEOUT_SECONDS, follow_redirects=False
        ) as client:
            response = await client.post(
                _LINEAR_API_URL,
                json={"query": query, "variables": variables},
                headers={"Authorization": token, "Content-Type": "application/json"},
            )
            response.raise_for_status()
            payload = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise LinearTransportError(f"Linear API request failed: {exc}") from exc
    if payload.get("errors"):
        messages = "; ".join(
            error.get("message", str(error)) if isinstance(error, dict) else str(error)
            for error in payload["errors"]
        )
        raise LinearAPIError(f"Linear API returned errors: {messages}")
    data = payload.get("data")
    if not isinstance(data, dict):
        raise LinearAPIError("Linear API response missing 'data'")
    return data


def compute_target_fingerprint(issue: dict[str, Any]) -> str:
    """Deterministic sha256 hex digest of the issue fields that matter for
    a ``linear_progress_update`` proposal's staleness check.

    CROSS-REPO CONTRACT: whatever submits the original proposal (a Prefect
    flow, per the ticket) must compute ``target_fingerprint`` the SAME way,
    over the SAME field set, or every decide will spuriously come back
    ``stale``. This function is the single source of truth for that scheme
    on the agent-comms-mcp side; see ``docs/DESIGN.md``'s proposal
    decide/apply section for the contract note.

    Exact serialization pinned here (Argus review round-5 S6 -- a
    same-inputs-different-bytes bug in either implementation would be
    silent and only surface as spurious ``stale`` results, so this is
    intentionally explicit rather than "whatever ``json.dumps`` happens to
    do"): ``json.dumps(..., sort_keys=True)`` with the library DEFAULT
    ``separators`` (``", "``/``": "``, i.e. a space after both `,` and `:`)
    and DEFAULT ``ensure_ascii=True``; ``updated_at`` is the raw
    ``updatedAt`` string as Linear's GraphQL API returns it (an ISO-8601
    timestamp), not re-parsed or re-formatted. A cross-repo implementation
    must match all of the above, not just the field set -- see
    ``test_pinned_digest_for_fixed_input`` in ``tests/test_linear_client.py``
    for the exact digest this scheme produces for a fixed input, which
    would need updating (with the other side of the contract) if any of
    these serialization choices ever changed.
    """
    state = issue.get("state") or {}
    assignee = issue.get("assignee") or {}
    canonical = json.dumps(
        {
            "state_id": state.get("id"),
            "state_name": state.get("name"),
            "priority": issue.get("priority"),
            "assignee_id": assignee.get("id"),
            "updated_at": issue.get("updatedAt"),
        },
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


async def fetch_current_fingerprint(target_id: str) -> str:
    """Fetch the current Linear issue state for ``target_id`` and return
    its fingerprint (``compute_target_fingerprint``) -- used by
    ``service.decide_proposal`` to detect drift since submission, before
    applying anything."""
    data = await _post_graphql(_ISSUE_QUERY, {"id": target_id})
    issue = data.get("issue")
    if not isinstance(issue, dict):
        raise LinearAPIError(f"Linear API returned no issue for id={target_id!r}")
    return compute_target_fingerprint(issue)


def _omit_invalid_url_instead_of_raising(action_type: str, key: str) -> bool:
    """Whether an invalid ``key`` URL field should be silently OMITTED
    from the Linear comment rather than raising -- per FIELD, not
    (only) per ``action_type`` (Argus review round-5 B3 -- an earlier
    version of this decision was made per-``action_type`` alone, which
    desynced from the judge for exactly one combination it didn't
    consider: ``open_ticket`` + a present-but-invalid ``resolving_pr_url``).

    The judge (``service.evaluate_linear_progress_update_judge``) never
    inspects ``resolving_pr_url`` for ``open_ticket`` at all -- it is not
    part of that action_type's approval criteria one way or the other, so
    its validity is irrelevant to why this proposal got approved. Raising
    on it anyway (the old per-``action_type`` logic did, since
    ``open_ticket`` isn't a close-ticket action type) meant a proposal
    the judge legitimately auto-approved on a valid ``source_message_url``
    alone could still deterministically hit ``apply_failed`` if it also
    happened to carry an unrelated, invalid ``resolving_pr_url`` -- with
    no retry path, since the terminal row blocks a dedup'd resubmission
    (see ``docs/DESIGN.md``'s stuck-``applying``/dedup section).
    ``resolving_pr_url`` is therefore ALWAYS omit-on-invalid, for every
    action_type: for close-ticket it already has an OR-partner (see
    below), and for every other action_type the judge doesn't gate on it
    at all -- there is no action_type today where an invalid
    ``resolving_pr_url`` should block the apply.

    ``source_message_url`` is different: for ``open_ticket`` it is the
    SOLE required field with no OR-partner, so an invalid one there means
    a human manually approved a proposal the judge itself never would
    have -- that must still raise. For close-ticket action types, it has
    an OR-partner (``resolving_pr_url``) per the judge's rule, so the
    same reasoning as always applies: omit rather than raise."""
    if key == "resolving_pr_url":
        return True
    return action_type in citation_urls.CLOSE_TICKET_ACTION_TYPES


def _progress_comment_body(action: dict[str, Any], rationale: str) -> str:
    # Argus review S3: re-validate URL fields with the same allowlist
    # `citation_urls.is_valid_citation_url` uses at judging time (extracted
    # to a neutral shared module in Argus review round-2 S2, so this no
    # longer needs a lazy `import service` to reach it). A proposal can
    # reach here via manual human approval (not just the auto-approve
    # judge path), so a non-allowlisted URL must not silently reach Linear.
    # See `_omit_invalid_url_instead_of_raising`'s own docstring for the
    # per-field/per-action_type omit-vs-raise reasoning (Argus review
    # round-2 B3, round-3 S4, round-5 B3).
    action_type = action.get("action_type", "update")
    lines = [f"Progress update: {action_type}"]
    if rationale:
        lines.append(rationale)
    for label, key in (("Source", "source_message_url"), ("Resolved by", "resolving_pr_url")):
        value = action.get(key)
        if isinstance(value, str) and value:
            if not citation_urls.is_valid_citation_url(value):
                if _omit_invalid_url_instead_of_raising(action_type, key):
                    # Argus review round-6 suggestion: include the rejected
                    # URL value itself, not just the field name -- the
                    # raise path a few lines below already includes it
                    # (`value!r`), and with multiple proposals in flight
                    # against the same target_id, the value is what lets an
                    # operator actually identify which proposal's omission
                    # this log line is about.
                    logger.warning(
                        "Omitting %s=%r from Linear comment for target_id=%r: "
                        "failed citation-URL validation",
                        key,
                        value,
                        action.get("target_id"),
                    )
                    continue
                raise LinearAPIError(f"{key} failed citation-URL validation: {value!r}")
            lines.append(f"{label}: {value}")
    return "\n\n".join(lines)


async def apply_progress_update(action: dict[str, Any], rationale: str) -> None:
    """Execute the real Linear write for a decided ``linear_progress_update``
    proposal -- posts a comment on ``action["target_id"]`` summarizing the
    action (see ``_progress_comment_body``). Called ONLY after staleness
    has already been checked by the caller. Raises ``LinearAPIError`` on
    any failure; the caller maps that to ``status="apply_failed"``.

    ``rationale`` is a top-level ``ProposalHold`` column, NOT part of
    ``action`` (Argus review round-5 B2): a proposal's human-authored
    justification for the write is threaded through as its own
    parameter, not read off ``action`` -- ``action`` is exactly the
    caller-submitted JSONB blob (``ProposalHold.action``), which never
    contains it. An earlier version of this function read
    ``action.get("rationale")``, which was always ``None`` in production
    (the field simply isn't there) and only appeared to work in tests
    because the test fixtures incorrectly baked ``rationale`` into the
    action dict they constructed.
    """
    target_id = action["target_id"]
    body = _progress_comment_body(action, rationale)
    result = await _post_graphql(_COMMENT_MUTATION, {"issueId": target_id, "body": body})
    if not result.get("commentCreate", {}).get("success"):
        raise LinearAPIError("commentCreate returned success=false")


__all__ = [
    "LinearAPIError",
    "LinearTokenMissingError",
    "LinearTransportError",
    "apply_progress_update",
    "compute_target_fingerprint",
    "fetch_current_fingerprint",
]
