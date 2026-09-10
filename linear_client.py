"""Thin Linear API client for synchronously applying decided
``proposal_holds`` of ``kind="linear_progress_update"`` (TECH-5873).

Originally narrow -- two functions, ``fetch_current_fingerprint`` and
``apply_progress_update`` -- so ``service.decide_proposal`` can mock this
module wholesale in tests (this repo has no CI, let alone a Linear sandbox,
so nothing here is ever exercised against the real API in automated tests).
Since grown ``fetch_issue`` (the raw fetch ``fetch_current_fingerprint`` now
wraps) and three read-only ``resolve_*`` lookups (team/workflow-state/label),
all three of which are now exercised: ``resolve_team_id``/
``resolve_workflow_state_id`` by ``apply_open_ticket`` below (TECH-5873
follow-up: ``open_ticket`` creates a brand-new Linear issue rather than
commenting on a pre-existing one, so its applier needs to resolve a team
KEY and, optionally, a workflow state NAME to Linear's internal IDs before
it can create anything) and now also by ``apply_start_ticket``/
``apply_review_ticket``/``apply_label_ticket`` (TECH-5877 follow-up auto-
approve lanes) below; ``resolve_label_id`` by ``apply_label_ticket``.

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
    state { id name type }
    priority
    assignee { id }
    updatedAt
  }
}
"""

_TEAM_BY_KEY_QUERY = """
query TeamByKey($key: String!) {
  teams(filter: { key: { eq: $key } }) {
    nodes { id }
  }
}
"""

_TEAM_WORKFLOW_STATES_QUERY = """
query TeamWorkflowStates($teamId: String!, $name: String!) {
  team(id: $teamId) {
    states(filter: { name: { eq: $name } }) {
      nodes { id }
    }
  }
}
"""

_LABEL_QUERY = """
query LabelByName($teamId: String!, $name: String!) {
  issueLabels(filter: { name: { eq: $name }, team: { id: { eq: $teamId } } }) {
    nodes { id }
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

_ISSUE_CREATE_MUTATION = """
mutation IssueCreate($input: IssueCreateInput!) {
  issueCreate(input: $input) {
    success
    issue { id identifier url }
  }
}
"""

# Verified against Linear's real public GraphQL schema
# (raw.githubusercontent.com/linear/linear/master/packages/sdk/src/schema.graphql,
# same source used to verify every other mutation/query in this file) --
# not guessed. ``issueUpdate(id, input: IssueUpdateInput!)`` covers both
# the state-transition (``stateId``) and reassignment (``assigneeId``)
# writes below; each call site scopes its own ``input`` to just the one
# field it's changing, leaving every other field on the issue untouched.
_ISSUE_UPDATE_MUTATION = """
mutation IssueUpdate($id: String!, $input: IssueUpdateInput!) {
  issueUpdate(id: $id, input: $input) {
    success
  }
}
"""

# TECH-5877 auto-approve lanes: adding a single label to an issue.
# Deliberately NOT ``issueUpdate(input: { labelIds })`` -- per
# ``IssueUpdateInput``'s own schema comment, ``labelIds`` REPLACES the
# issue's full label set rather than adding to it (``addedLabelIds``/
# ``removedLabelIds`` are the incremental alternative on that same input,
# but this dedicated mutation is simpler and needs no separate fetch of
# the issue's current labels first). Verified against the real schema:
# ``issueAddLabel(id, labelId): IssuePayload!`` exists as a first-class
# mutation for exactly this one-label-at-a-time case.
_ISSUE_ADD_LABEL_MUTATION = """
mutation IssueAddLabel($id: String!, $labelId: String!) {
  issueAddLabel(id: $id, labelId: $labelId) {
    success
  }
}
"""

# Design decision (TECH-5873, not fully specified by the ticket): the
# actual Linear "write" for kind="linear_progress_update"'s close_ticket
# action_type is a comment posted to the target issue, not an issue-state
# mutation -- this is a progress-reporting bot (the name says so), and
# close_ticket (see citation_urls.CLOSE_TICKET_ACTION_TYPES for the
# close-ticket set, shared with service.py to avoid semantic drift since
# Argus review round-4 S1) reads as "report that a ticket was closed", not
# "mutate this issue's workflow state" -- mutating state would
# additionally require resolving a team-specific workflow state id, which
# the action payload doesn't carry.
#
# open_ticket is the deliberate exception (redefined in place -- see
# apply_open_ticket below): there is no pre-existing issue to comment on,
# so its "write" genuinely IS an issue-creation mutation. A future kind
# that needs a state transition on an EXISTING issue still gets its own
# applier function, same as this reasoning always intended.


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


class LinearNotFoundError(LinearAPIError):
    """A ``resolve_*`` lookup (team key, workflow state name, label name)
    found zero matching Linear records. A typed subclass, same convention
    as ``LinearTokenMissingError``/``LinearTransportError`` above, so
    future callers (a judge rule resolving a team/state/label at
    auto-approve time) can distinguish "this name doesn't exist" from a
    generic API failure."""


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

    Whatever a caller submits as ``target_fingerprint`` (an HTTP/MCP
    request body field of the same name) is IGNORED: ``service.
    create_proposal`` always computes the stored value itself, server-side,
    by calling this function (via ``fetch_current_fingerprint``) against
    the target's CURRENT Linear state at submission time -- never trusting
    a caller-supplied value. ``_apply_or_finalize_proposal_hold`` later
    re-fetches the SAME way at apply/decide time and compares the two, so
    the stored value and the value it's compared against always come from
    this one function.

    Historical context for why this function's field-set/serialization
    contract is still pinned as precisely as it is, even though nothing
    external feeds it anymore: earlier designs expected whatever SUBMITS
    the original proposal (a Prefect flow, per the ticket) to compute
    ``target_fingerprint`` itself and send it along, which would have made
    this a genuine CROSS-REPO CONTRACT -- both sides would need to hash
    the SAME field set the SAME way, or every decide would spuriously come
    back ``stale``. That external-compute path was removed (a bot-supplied
    hash can never independently equal what this function computes, so
    every proposal was landing in ``"stale"`` deterministically, not from
    an actual race -- see ``create_proposal``'s own docstring), but this
    function's contract stayed exact rather than loosening, since it's
    still the ONLY thing anything on either side of an apply/decide
    fingerprint comparison ever calls.

    Field set: ``state_id``/``state_name``/``priority``/``assignee_id``
    only -- ``updatedAt`` is deliberately EXCLUDED (bug fix: it used to be
    part of this digest, but Linear bumps ``updatedAt`` on ANY touch,
    including this same bot's own prior comment on the issue, so including
    it made staleness fire on unrelated activity, not just on a
    meaningful change to the ticket). Staleness now means "someone else
    already moved this ticket's state/priority/assignee since the
    proposal was submitted," not "any touch happened."

    Exact serialization pinned here (Argus review round-5 S6 -- a
    same-inputs-different-bytes bug in either implementation would be
    silent and only surface as spurious ``stale`` results, so this is
    intentionally explicit rather than "whatever ``json.dumps`` happens to
    do"): ``json.dumps(..., sort_keys=True)`` with the library DEFAULT
    ``separators`` (``", "``/``": "``, i.e. a space after both `,` and `:`)
    and DEFAULT ``ensure_ascii=True``. A cross-repo implementation must
    match all of the above, not just the field set -- see
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
        },
        sort_keys=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


async def fetch_issue(target_id: str) -> dict[str, Any]:
    """Fetch the current state of a Linear issue for ``target_id``. Returns
    the raw parsed GraphQL response fields (``state`` id/name/type,
    ``priority``, ``assignee`` id, ``updatedAt``).

    Used both by ``fetch_current_fingerprint`` below (staleness
    fingerprinting -- see ``compute_target_fingerprint``'s docstring for
    exactly which of these fields feed the hash) and by future judge
    rules that need to reason about the issue's current workflow state
    (``state.type``, via ``workflow_order.is_forward_transition``) --
    that field is fetched here but is NOT part of the fingerprint (see
    ``compute_target_fingerprint``'s docstring's field set)."""
    data = await _post_graphql(_ISSUE_QUERY, {"id": target_id})
    issue = data.get("issue")
    if not isinstance(issue, dict):
        raise LinearAPIError(f"Linear API returned no issue for id={target_id!r}")
    return issue


async def fetch_current_fingerprint(target_id: str) -> str:
    """Fetch the current Linear issue state for ``target_id`` and return
    its fingerprint (``compute_target_fingerprint``) -- called both by
    ``service.create_proposal`` (to compute the fingerprint stored at
    submission time, ignoring any caller-supplied ``target_fingerprint``)
    and by ``service._apply_or_finalize_proposal_hold`` (``decide_proposal``/
    the auto-judge's own apply) to detect drift since submission, before
    applying anything."""
    return compute_target_fingerprint(await fetch_issue(target_id))


async def resolve_team_id(team_key: str) -> str:
    """Resolve a Linear team key (e.g. ``"TECH"``) to its internal team ID.

    Raises ``LinearNotFoundError`` if no team matches ``team_key``, and
    (defensively -- team keys should be unique workspace-wide, but this
    is precision-critical for an auto-approve context, same reasoning as
    ``resolve_workflow_state_id`` below) if MORE than one matches, rather
    than silently picking one (Argus review: this guard existed on
    ``resolve_workflow_state_id`` but was missing here)."""
    data = await _post_graphql(_TEAM_BY_KEY_QUERY, {"key": team_key})
    teams = data.get("teams")
    nodes = teams.get("nodes", []) if isinstance(teams, dict) else []
    if not nodes:
        raise LinearNotFoundError(f"Linear API returned no team for key={team_key!r}")
    if len(nodes) > 1:
        raise LinearAPIError(
            f"Linear API returned {len(nodes)} teams for key={team_key!r}, expected exactly one"
        )
    team_id = nodes[0].get("id")
    if not isinstance(team_id, str):
        raise LinearAPIError(f"Linear API returned a team with no id for key={team_key!r}")
    return team_id


async def resolve_workflow_state_id(team_id: str, state_name: str) -> str:
    """Resolve a workflow state NAME (e.g. ``"In Progress"``) to its
    internal state ID, scoped to ``team_id`` (Linear workflow states are
    per-team).

    Matches ``state_name`` case-sensitively against Linear's exact display
    name -- deliberately not case-folded, since that could produce a false
    match. Raises ``LinearNotFoundError`` if no state on this team matches,
    and (defensively -- state names should be unique per team, but this is
    precision-critical for a future auto-approve context) if MORE than one
    matches, rather than silently picking one."""
    data = await _post_graphql(_TEAM_WORKFLOW_STATES_QUERY, {"teamId": team_id, "name": state_name})
    team = data.get("team")
    nodes = team.get("states", {}).get("nodes", []) if isinstance(team, dict) else []
    if not nodes:
        raise LinearNotFoundError(
            f"Linear API returned no workflow state named {state_name!r} for team_id={team_id!r}"
        )
    if len(nodes) > 1:
        raise LinearAPIError(
            f"Linear API returned {len(nodes)} workflow states named {state_name!r} for "
            f"team_id={team_id!r}, expected exactly one"
        )
    state_id = nodes[0].get("id")
    if not isinstance(state_id, str):
        raise LinearAPIError(
            f"Linear API returned a workflow state with no id for name={state_name!r}"
        )
    return state_id


async def resolve_label_id(team_id: str, name: str) -> str:
    """Resolve a label NAME (e.g. ``"target:agent-comms-mcp"``) to its
    internal label ID, scoped to ``team_id`` (labels can be team-specific
    in Linear).

    Raises ``LinearNotFoundError`` if no label on this team matches
    ``name``, and (defensively -- label names should be unique per team,
    but this is precision-critical for an auto-approve context, same
    reasoning as ``resolve_workflow_state_id`` above) if MORE than one
    matches, rather than silently picking one (Argus review: this guard
    existed on ``resolve_workflow_state_id`` but was missing here)."""
    data = await _post_graphql(_LABEL_QUERY, {"teamId": team_id, "name": name})
    issue_labels = data.get("issueLabels")
    nodes = issue_labels.get("nodes", []) if isinstance(issue_labels, dict) else []
    if not nodes:
        raise LinearNotFoundError(
            f"Linear API returned no label named {name!r} for team_id={team_id!r}"
        )
    if len(nodes) > 1:
        raise LinearAPIError(
            f"Linear API returned {len(nodes)} labels named {name!r} for team_id={team_id!r}, "
            "expected exactly one"
        )
    label_id = nodes[0].get("id")
    if not isinstance(label_id, str):
        raise LinearAPIError(f"Linear API returned a label with no id for name={name!r}")
    return label_id


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
                # Argus review round-7 suggestion: log/raise only a
                # redacted form of a REJECTED URL (scheme+host+path), never
                # the raw value -- a URL that already failed the citation
                # allowlist check is, by definition, from an untrusted or
                # unexpected source, and its query string/fragment may
                # carry a token or other secret a legitimate caller
                # embedded for its own (non-Linear) purposes. This applies
                # uniformly to BOTH the omit-and-continue path and the
                # raise path below -- round-6's fix added the value to the
                # omit path's log line unredacted, matching the raise
                # path's pre-existing `value!r`, which had the same
                # exposure and needed the same fix.
                redacted_value = citation_urls.redact_url_for_logging(value)
                if _omit_invalid_url_instead_of_raising(action_type, key):
                    logger.warning(
                        "Omitting %s=%s from Linear comment for target_id=%r: "
                        "failed citation-URL validation",
                        key,
                        redacted_value,
                        action.get("target_id"),
                    )
                    continue
                raise LinearAPIError(f"{key} failed citation-URL validation: {redacted_value}")
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


async def create_ticket(
    *,
    title: str,
    description: str,
    team_id: str,
    project_id: str | None = None,
    state_id: str | None = None,
) -> dict[str, str]:
    """Create a Linear issue in ONE mutation, optionally landing it
    directly in a target workflow state (so a create-then-close proposal
    collapses into a single Linear write instead of two).

    ``team_id``/``project_id``/``state_id`` are all Linear's internal IDs
    (UUIDs), NOT human-readable names/keys -- resolve a team KEY or a
    workflow state NAME via ``resolve_team_id``/``resolve_workflow_state_id``
    before calling this. ``project_id`` is accepted as-is with no
    resolution step here (see ``apply_open_ticket``'s docstring for why).

    Returns ``{"id": ..., "identifier": ..., "url": ...}`` for the created
    issue (``identifier`` is the human-readable ``TECH-####`` form).
    Raises ``LinearAPIError`` if the mutation reports ``success=false`` or
    omits any of those three fields on the returned issue -- same
    fail-fast posture as every other function in this module; never
    returns a partial result."""
    issue_input: dict[str, Any] = {"teamId": team_id, "title": title, "description": description}
    if project_id is not None:
        issue_input["projectId"] = project_id
    if state_id is not None:
        issue_input["stateId"] = state_id
    data = await _post_graphql(_ISSUE_CREATE_MUTATION, {"input": issue_input})
    payload = data.get("issueCreate")
    if not isinstance(payload, dict) or not payload.get("success"):
        raise LinearAPIError("issueCreate returned success=false")
    issue = payload.get("issue")
    if not isinstance(issue, dict):
        raise LinearAPIError("Linear API returned no issue from issueCreate")
    issue_id, identifier, url = issue.get("id"), issue.get("identifier"), issue.get("url")
    if not isinstance(issue_id, str) or not isinstance(identifier, str) or not isinstance(url, str):
        raise LinearAPIError("Linear API returned an incomplete issue from issueCreate")
    return {"id": issue_id, "identifier": identifier, "url": url}


async def apply_open_ticket(action: dict[str, Any], rationale: str) -> dict[str, Any]:
    """Applier for ``kind="linear_progress_update"``, ``action_type=
    "open_ticket"`` (TECH-5873 redefinition): creates the Linear issue
    described by ``action`` and returns metadata about what was created.
    Called ONLY after staleness has already been checked by the caller --
    though ``open_ticket`` is exempt from that check entirely (there is no
    pre-existing target to have gone stale; see
    ``service._PROPOSAL_FINGERPRINT_EXEMPT``), so in practice this is
    always called unconditionally once the proposal is approved.

    Expected ``action`` shape (beyond ``target_id``/``action_type``, which
    ``service._extract_proposal_target`` already requires -- ``target_id``
    is the PR URL that originated this proposal, per that function's own
    docstring, and is NOT read by this applier at all):

    - ``"title"`` (str, required): the new issue's title.
    - ``"description"`` (str, optional, default ``""``): the new issue's
      description, in markdown.
    - ``"team"`` (str, required): the target team's KEY (e.g. ``"TECH"``),
      NOT its internal UUID -- resolved via ``resolve_team_id``.
    - ``"project"`` (str, optional): a raw Linear PROJECT ID to file the
      issue under. Accepted as-is, no name resolution -- unlike
      ``team``/``target_state``, a project has no per-team-scoped lookup
      analogous to ``resolve_team_id``/``resolve_workflow_state_id`` in
      this module today, so the caller is expected to already have the
      ID (e.g. from whatever created the underlying proposal).
    - ``"target_state"`` (str, optional): a workflow state NAME (e.g.
      ``"Done"``) to create the issue directly into, resolved via
      ``resolve_workflow_state_id`` scoped to the resolved team. Passing
      this lets a create-then-close proposal collapse into the ONE
      ``create_ticket`` mutation instead of a create followed by a
      separate close.

    ``rationale`` (the top-level ``ProposalHold`` column, same convention
    as ``apply_progress_update``) is accepted for signature parity with
    the shared applier-dispatch call site (``service.
    _apply_or_finalize_proposal_hold`` always calls ``applier(action,
    rationale)``) but is not itself written anywhere on the created issue
    today -- there is no comment-posting step here to put it in.

    Returns the created issue's ``{"id", "identifier", "url"}`` (see
    ``create_ticket``) -- this dict flows back through
    ``_apply_or_finalize_proposal_hold`` into ``hold.apply_result`` (see
    ``models.ProposalHold``), the only way a caller learns the new
    issue's ``TECH-####`` identifier.

    Raises ``LinearAPIError`` on a missing/invalid ``title``/``team``, or
    on any failure from ``resolve_team_id``/``resolve_workflow_state_id``/
    ``create_ticket`` -- never a raw ``KeyError``/``TypeError``, matching
    this module's "every function here only ever raises ``LinearAPIError``
    (or a subclass)" contract, which ``_apply_or_finalize_proposal_hold``'s
    exception handling depends on."""
    title = action.get("title")
    if not isinstance(title, str) or not title:
        raise LinearAPIError("action.title is required and must be a non-empty string")
    team = action.get("team")
    if not isinstance(team, str) or not team:
        raise LinearAPIError("action.team is required and must be a non-empty string")
    description = action.get("description", "")
    if not isinstance(description, str):
        raise LinearAPIError("action.description must be a string")
    project_id = action.get("project")
    if project_id is not None and not isinstance(project_id, str):
        raise LinearAPIError("action.project must be a string")
    target_state = action.get("target_state")
    if target_state is not None and not isinstance(target_state, str):
        raise LinearAPIError("action.target_state must be a string")

    team_id = await resolve_team_id(team)
    state_id = (
        await resolve_workflow_state_id(team_id, target_state) if target_state is not None else None
    )
    return await create_ticket(
        title=title,
        description=description,
        team_id=team_id,
        project_id=project_id,
        state_id=state_id,
    )


async def update_issue_state(issue_id: str, state_id: str) -> None:
    """Move an EXISTING Linear issue to a new workflow state via
    ``issueUpdate(input: { stateId })`` (see ``_ISSUE_UPDATE_MUTATION``'s
    comment for the schema-verification note).

    ``issue_id``/``state_id`` are both Linear's internal IDs -- resolve a
    workflow state NAME to its ID via ``resolve_workflow_state_id`` (scoped
    to the issue's team, resolved via ``resolve_team_id``) before calling
    this. Used by ``apply_start_ticket``/``apply_review_ticket`` below (the
    ``start_ticket``/``review_ticket`` action_types move an existing issue
    to "In Progress"/"In Review" respectively).

    Raises ``LinearAPIError`` if the mutation reports ``success=false``."""
    result = await _post_graphql(
        _ISSUE_UPDATE_MUTATION, {"id": issue_id, "input": {"stateId": state_id}}
    )
    issue_update = result.get("issueUpdate")
    if not isinstance(issue_update, dict) or not issue_update.get("success"):
        raise LinearAPIError("issueUpdate returned success=false")


async def update_issue_assignee(issue_id: str, assignee_id: str) -> None:
    """Reassign an EXISTING Linear issue via
    ``issueUpdate(input: { assigneeId })`` -- the same mutation as
    ``update_issue_state`` above, scoped to just the ``assigneeId`` field.

    ``assignee_id`` is already a Linear internal user ID -- there is no
    name to resolve here (unlike ``team``/workflow-state-name/label-name
    elsewhere in this module). Per TECH-6153, the auto-approve rule that
    feeds this (``service._rule_assign_ticket``) verifies that a real,
    existing PR was cited and actually references the target ticket
    (via ``_pull_request_references_ticket``), but deliberately enforces
    neither attribution nor authorization: (a) the assignee's identity
    is not verified against the PR author (this service tracks outstanding
    work, not credit/attribution), and (b) there is no authorization anchor
    at all on who can be assigned -- no team-membership check and no bound
    on which Linear user UUID the bot proposes. A bot can cite any real PR
    referencing the target ticket and assign it to any Linear user it names,
    a confirmed, deliberate, doubly-considered tradeoff per TECH-6153.
    Used by ``apply_assign_ticket`` below.

    Raises ``LinearAPIError`` if the mutation reports ``success=false``."""
    result = await _post_graphql(
        _ISSUE_UPDATE_MUTATION, {"id": issue_id, "input": {"assigneeId": assignee_id}}
    )
    issue_update = result.get("issueUpdate")
    if not isinstance(issue_update, dict) or not issue_update.get("success"):
        raise LinearAPIError("issueUpdate returned success=false")


async def add_issue_label(issue_id: str, label_id: str) -> None:
    """Add a single label to an EXISTING Linear issue via the DEDICATED
    ``issueAddLabel(id, labelId)`` mutation -- see
    ``_ISSUE_ADD_LABEL_MUTATION``'s comment for why this does NOT use
    ``issueUpdate``'s replace-all-labels ``labelIds`` field. Used by
    ``apply_label_ticket`` below.

    Raises ``LinearAPIError`` if the mutation reports ``success=false``."""
    result = await _post_graphql(_ISSUE_ADD_LABEL_MUTATION, {"id": issue_id, "labelId": label_id})
    issue_add_label = result.get("issueAddLabel")
    if not isinstance(issue_add_label, dict) or not issue_add_label.get("success"):
        raise LinearAPIError("issueAddLabel returned success=false")


async def apply_start_ticket(action: dict[str, Any], rationale: str) -> None:
    """Applier for ``kind="linear_progress_update"``, ``action_type=
    "start_ticket"`` (TECH-5877): moves an EXISTING issue to "In Progress".
    Called ONLY after staleness has already been checked by the caller --
    unlike ``open_ticket``, ``start_ticket`` is NOT in
    ``service._PROPOSAL_FINGERPRINT_EXEMPT``: its ``target_id`` IS a
    pre-existing Linear issue id, so the normal re-fetch/staleness
    comparison applies before this is ever called.

    Expected ``action`` fields (beyond ``target_id``, already required by
    ``service._extract_proposal_target``):

    - ``"team"`` (str, required): the issue's team KEY (e.g. ``"TECH"``),
      resolved via ``resolve_team_id`` -- workflow states are per-team in
      Linear, so this is needed to resolve "In Progress" scoped to the
      right team.

    ``rationale`` is accepted for signature parity with the shared
    applier-dispatch call site (same as ``apply_open_ticket``) but is not
    itself written anywhere -- there is no comment-posting step here.

    CASE-SENSITIVITY (Argus review: document, don't make bot-controllable):
    the literal string ``"In Progress"`` below is matched against the
    target team's real workflow state names via ``resolve_workflow_state_id``,
    which is deliberately case-sensitive (see its own docstring). The
    target Linear team's workflow state must be named EXACTLY
    ``"In Progress"`` -- not ``"in progress"``, ``"In progress"``, or any
    other casing/naming variant -- for this applier to succeed. This is
    NOT bot-controllable via the action payload (that would let a bot
    influence its own approval target, reintroducing a control gap this
    design deliberately closes); a mismatch on a given team raises
    ``LinearNotFoundError`` here, which resolves the hold to a clean
    ``"apply_failed"``, never a silent no-op.

    Raises ``LinearAPIError`` on a missing/invalid ``target_id``/``team``,
    or on any failure from ``resolve_team_id``/``resolve_workflow_state_id``/
    ``update_issue_state`` -- never a raw ``KeyError``/``TypeError``,
    matching this module's established contract (see
    ``apply_open_ticket``'s own docstring)."""
    target_id = action.get("target_id")
    if not isinstance(target_id, str) or not target_id:
        raise LinearAPIError("action.target_id is required and must be a non-empty string")
    team = action.get("team")
    if not isinstance(team, str) or not team:
        raise LinearAPIError("action.team is required and must be a non-empty string")

    team_id = await resolve_team_id(team)
    state_id = await resolve_workflow_state_id(team_id, "In Progress")
    await update_issue_state(target_id, state_id)


async def apply_review_ticket(action: dict[str, Any], rationale: str) -> None:
    """Applier for ``action_type="review_ticket"`` (TECH-5877) -- same
    shape as ``apply_start_ticket`` above, but moves the issue to
    "In Review" instead of "In Progress". See that function's docstring
    for the shared field/staleness/error-handling contract."""
    target_id = action.get("target_id")
    if not isinstance(target_id, str) or not target_id:
        raise LinearAPIError("action.target_id is required and must be a non-empty string")
    team = action.get("team")
    if not isinstance(team, str) or not team:
        raise LinearAPIError("action.team is required and must be a non-empty string")

    team_id = await resolve_team_id(team)
    state_id = await resolve_workflow_state_id(team_id, "In Review")
    await update_issue_state(target_id, state_id)


async def apply_assign_ticket(action: dict[str, Any], rationale: str) -> None:
    """Applier for ``action_type="assign_ticket"`` (TECH-5877) -- reassigns
    an existing issue to ``action["assignee_id"]``, already a Linear
    internal user ID (no resolution step needed here, unlike
    ``team``/workflow-state/label names elsewhere in this module).

    Per TECH-6153, the judge rule that approved this
    (``service._rule_assign_ticket``) verified that a real, existing PR was
    cited and actually references the target ticket via
    ``_pull_request_references_ticket``, but deliberately enforces neither
    attribution nor authorization: (a) the assignee's identity is not
    verified against the PR author (this service tracks outstanding work,
    not a credit/attribution system), and (b) there is no authorization
    anchor at all on who can be assigned -- no team-membership check and
    no bound on which Linear user UUID the bot proposes. A bot can cite any
    real PR referencing the target ticket and assign it to any Linear user
    it names, a confirmed, deliberate, doubly-considered tradeoff per
    TECH-6153.

    Raises ``LinearAPIError`` on a missing/invalid ``target_id``/
    ``assignee_id``, or on any failure from ``update_issue_assignee``."""
    target_id = action.get("target_id")
    if not isinstance(target_id, str) or not target_id:
        raise LinearAPIError("action.target_id is required and must be a non-empty string")
    assignee_id = action.get("assignee_id")
    if not isinstance(assignee_id, str) or not assignee_id:
        raise LinearAPIError("action.assignee_id is required and must be a non-empty string")

    await update_issue_assignee(target_id, assignee_id)


async def apply_label_ticket(action: dict[str, Any], rationale: str) -> None:
    """Applier for ``action_type="label_ticket"`` (TECH-5877) -- adds
    ``action["label_name"]`` to an existing issue via ``add_issue_label``
    (the dedicated add-only mutation -- see that function's docstring for
    why this does NOT use ``issueUpdate``'s replace-all-labels
    ``labelIds`` field).

    Expected ``action`` fields (beyond ``target_id``/``label_name``):

    - ``"team"`` (str, required): the label's team KEY, resolved via
      ``resolve_team_id`` -- labels can be team-scoped in Linear, so this
      is needed to resolve ``label_name`` scoped to the right team via
      ``resolve_label_id``.

    Raises ``LinearAPIError`` on a missing/invalid ``target_id``/``team``/
    ``label_name``, or on any failure from ``resolve_team_id``/
    ``resolve_label_id``/``add_issue_label``."""
    target_id = action.get("target_id")
    if not isinstance(target_id, str) or not target_id:
        raise LinearAPIError("action.target_id is required and must be a non-empty string")
    team = action.get("team")
    if not isinstance(team, str) or not team:
        raise LinearAPIError("action.team is required and must be a non-empty string")
    label_name = action.get("label_name")
    if not isinstance(label_name, str) or not label_name:
        raise LinearAPIError("action.label_name is required and must be a non-empty string")

    team_id = await resolve_team_id(team)
    label_id = await resolve_label_id(team_id, label_name)
    await add_issue_label(target_id, label_id)


__all__ = [
    "LinearAPIError",
    "LinearNotFoundError",
    "LinearTokenMissingError",
    "LinearTransportError",
    "add_issue_label",
    "apply_assign_ticket",
    "apply_label_ticket",
    "apply_open_ticket",
    "apply_progress_update",
    "apply_review_ticket",
    "apply_start_ticket",
    "compute_target_fingerprint",
    "create_ticket",
    "fetch_current_fingerprint",
    "fetch_issue",
    "resolve_label_id",
    "resolve_team_id",
    "resolve_workflow_state_id",
    "update_issue_assignee",
    "update_issue_state",
]
