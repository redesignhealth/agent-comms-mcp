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
# judge understands (open_ticket/close_ticket, service._LINEAR_OPEN_TICKET_
# ACTION_TYPES/_LINEAR_CLOSE_TICKET_ACTION_TYPES) read as "report that a
# ticket was opened/closed", not "mutate this issue's workflow state" --
# mutating state would additionally require resolving a team-specific
# workflow state id, which the action payload doesn't carry. A future kind
# that genuinely needs a state transition gets its own applier function.


class LinearAPIError(Exception):
    """Raised on any non-2xx response, GraphQL error payload, missing
    issue, or transport failure. Caught by ``service.decide_proposal``'s
    approve path and mapped to ``status="apply_failed"`` with
    ``apply_error=str(exc)`` -- never propagated as an unhandled 500."""


def _require_api_token() -> str:
    token = os.environ.get(_LINEAR_API_TOKEN_ENV_VAR)
    if not token:
        raise LinearAPIError(f"{_LINEAR_API_TOKEN_ENV_VAR} is not configured")
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
        raise LinearAPIError(f"Linear API request failed: {exc}") from exc
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


def _progress_comment_body(action: dict[str, Any]) -> str:
    # Argus review S3: re-validate URL fields with the same allowlist
    # `citation_urls.is_valid_citation_url` uses at judging time (extracted
    # to a neutral shared module in Argus review round-2 S2, so this no
    # longer needs a lazy `import service` to reach it). A proposal can
    # reach here via manual human approval (not just the auto-approve
    # judge path), so a non-allowlisted URL must not silently reach Linear.
    #
    # Argus review round-2 B3: SKIP a non-allowlisted URL rather than
    # raising. The judge's close-ticket rule auto-approves when EITHER
    # `source_message_url` OR `resolving_pr_url` is valid (OR semantics --
    # the other field can be present-but-invalid, or simply absent, and
    # the judge doesn't care). Raising here on ANY present-but-invalid
    # field enforced AND semantics instead, so a judge-approved proposal
    # with exactly one valid + one invalid URL would deterministically
    # fail apply with no retry path through decide. Omitting the invalid
    # field (rather than writing it verbatim, which the pre-round-2 S3 fix
    # already ruled out) keeps the security property -- no
    # non-allowlisted URL ever reaches the Linear comment -- while
    # matching what actually got this proposal approved.
    action_type = action.get("action_type", "update")
    lines = [f"Progress update: {action_type}"]
    rationale = action.get("rationale")
    if isinstance(rationale, str) and rationale:
        lines.append(rationale)
    for label, key in (("Source", "source_message_url"), ("Resolved by", "resolving_pr_url")):
        value = action.get(key)
        if isinstance(value, str) and value:
            if not citation_urls.is_valid_citation_url(value):
                logger.warning(
                    "Omitting %s from Linear comment: failed citation-URL validation", key
                )
                continue
            lines.append(f"{label}: {value}")
    return "\n\n".join(lines)


async def apply_progress_update(action: dict[str, Any]) -> None:
    """Execute the real Linear write for a decided ``linear_progress_update``
    proposal -- posts a comment on ``action["target_id"]`` summarizing the
    action (see ``_progress_comment_body``). Called ONLY after staleness
    has already been checked by the caller. Raises ``LinearAPIError`` on
    any failure; the caller maps that to ``status="apply_failed"``.
    """
    target_id = action["target_id"]
    body = _progress_comment_body(action)
    result = await _post_graphql(_COMMENT_MUTATION, {"issueId": target_id, "body": body})
    if not result.get("commentCreate", {}).get("success"):
        raise LinearAPIError("commentCreate returned success=false")


__all__ = [
    "LinearAPIError",
    "apply_progress_update",
    "compute_target_fingerprint",
    "fetch_current_fingerprint",
]
