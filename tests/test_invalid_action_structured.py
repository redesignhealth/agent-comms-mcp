"""TECH-9214: a refused proposal ``action`` reaches the agent as
``{code, message, errors: [{path, rule, message}]}`` without any submitted value."""

from __future__ import annotations

import json

import pytest
from fastmcp.exceptions import ToolError

import providers.proposals as proposals
from exceptions import (
    INVALID_PROPOSAL_ACTION_CODE,
    PROPOSAL_ACTION_RULE_MESSAGES,
    InvalidProposalActionError,
)
from plugins import PROPOSAL_ACTION_ERROR_CODES


def test_every_rule_has_a_fixed_sentence() -> None:
    assert set(PROPOSAL_ACTION_RULE_MESSAGES) == set(PROPOSAL_ACTION_ERROR_CODES)


def test_structured_shape() -> None:
    exc = InvalidProposalActionError(
        "invalid catalog_candidate action: payload.slug: not_canonical (+2 more)",
        field_errors=(("payload.slug", "not_canonical"), ("fact_check", "missing")),
        omitted=2,
    )
    out = exc.structured()
    assert out["code"] == INVALID_PROPOSAL_ACTION_CODE
    assert out["message"] == str(exc)
    assert out["omitted"] == 2
    assert [(e["path"], e["rule"]) for e in out["errors"]] == [
        ("payload.slug", "not_canonical"),
        ("fact_check", "missing"),
    ]
    assert all(set(e) == {"path", "rule", "message"} for e in out["errors"])
    assert out["errors"][1]["message"] == "fact_check: this required field is missing"


def test_unknown_rule_gets_a_generic_sentence() -> None:
    out = InvalidProposalActionError("x", field_errors=(("a", "weird"),)).structured()
    assert out["errors"][0]["message"] == "a: the value is not valid"


def test_no_errors_still_has_the_shape() -> None:
    out = InvalidProposalActionError("invalid proposal action").structured()
    assert out["errors"] == [] and out["code"] == INVALID_PROPOSAL_ACTION_CODE


async def test_mcp_error_is_the_structured_json() -> None:
    exc = InvalidProposalActionError(
        "invalid x action: a: missing", field_errors=(("a", "missing"),)
    )
    with pytest.raises(ToolError) as caught:
        async with proposals._map_proposal_errors():
            raise exc
    body = json.loads(str(caught.value))
    assert body == exc.structured()
    assert body["errors"] == [
        {"path": "a", "rule": "missing", "message": "a: this required field is missing"}
    ]


async def test_other_value_errors_stay_plain_text() -> None:
    with pytest.raises(ToolError, match="unsupported proposal kind"):
        async with proposals._map_proposal_errors():
            raise ValueError("unsupported proposal kind: 'x'")
