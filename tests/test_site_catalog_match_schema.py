"""BLU-18: ``proposals_schema("site_catalog_match")`` and the vendored payload schema.

The board checks structure only (Arcadia checks the site, the agent and every citation),
so these tests pin the schema's own rules: no quote field, Arcadia-only line types
refused, citations required except for a declared absence, and the length limits.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
from fastmcp import Client
from jsonschema import Draft202012Validator

from providers import proposal_schemas
from tests.test_proposal_schema_tool import _ENV_PATCH, _OIDC_PATCH, _import_main, _token

_ROOT = Path(__file__).resolve().parents[1]
_KIND = "site_catalog_match"


@pytest.fixture
def main() -> Any:
    return _import_main()


def _built() -> dict[str, Any]:
    out = proposal_schemas.schema_for_kind(_KIND)
    assert out is not None
    return out


def _validator() -> Draft202012Validator:
    schema = _built()["schema"]
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def _payload() -> dict[str, Any]:
    return copy.deepcopy(_built()["examples"]["rank"]["payload"])


def _errors(payload: dict[str, Any]) -> list[str]:
    return [e.message for e in _validator().iter_errors(payload)]


def _cite(**kw: Any) -> dict[str, Any]:
    return {"kind": "interview_answer", "review_id": "r1", "start": 0, "length": 5, **kw}


class TestTool:
    async def test_returns_the_schema_guide_and_example(self, main: Any) -> None:
        with (
            _OIDC_PATCH,
            _ENV_PATCH,
            patch("main.get_access_token", return_value=_token()),
            patch("providers.proposals.get_access_token", return_value=_token()),
        ):
            async with Client(main.mcp) as client:
                out = (await client.call_tool("proposals_schema", {"kind": _KIND})).data
        assert set(out) == {
            "kind",
            "schema_version",
            "schema_sha256",
            "schema_source",
            "schema",
            "guide",
            "examples",
        }
        assert out["kind"] == _KIND
        assert out["schema_version"] == 1 == out["schema"]["x-schema-version"]
        assert out["schema_sha256"] == proposal_schemas.canonical_sha256(out["schema"])
        assert set(out["examples"]) == {"rank"}
        for text in ("site-match:<site-slug>:<concept-slug>:<MARKET>:r<seq>", "rank", "64 KiB"):
            assert text in out["guide"]

    def test_both_kinds_are_listed(self) -> None:
        assert set(proposal_schemas.SCHEMAS) == {"catalog_candidate", _KIND}


class TestExample:
    def test_example_is_valid(self) -> None:
        assert _errors(_payload()) == []

    def test_example_action_shape(self) -> None:
        action = _built()["examples"]["rank"]
        assert action["action_type"] == "rank"
        assert action["target_id"].startswith("site-match:")
        assert action["target_id"].rsplit(":", 1)[1].startswith("r")
        assert action["payload"]["schema_version"] == 1

    def test_example_carries_no_quote_or_name_field(self) -> None:
        text = json.dumps(_built()["examples"])
        assert "quote" not in text


class TestRules:
    def test_a_quote_field_is_refused(self) -> None:
        payload = _payload()
        payload["need"][0]["citations"][0]["quote"] = "words"
        assert _errors(payload)

    @pytest.mark.parametrize("field", ["extra", "quote"])
    def test_unknown_top_level_fields_are_refused(self, field: str) -> None:
        payload = _payload()
        payload[field] = "x"
        assert _errors(payload)

    @pytest.mark.parametrize("line_type", ["capability_gap", "market_fit", "nope"])
    def test_arcadia_only_need_types_are_refused(self, line_type: str) -> None:
        payload = _payload()
        payload["need"][0]["type"] = line_type
        assert _errors(payload)

    @pytest.mark.parametrize(
        "line_type",
        [
            "geography_not_viable",
            "prerequisite_missing",
            "weak_catalog_evidence",
            "prior_dismissal",
            "geography_not_assessed",
        ],
    )
    def test_arcadia_only_risk_types_are_refused(self, line_type: str) -> None:
        payload = _payload()
        payload["risk"][0]["type"] = line_type
        assert _errors(payload)

    def test_a_line_without_citations_is_refused(self) -> None:
        payload = _payload()
        payload["need"][0]["citations"] = []
        assert _errors(payload)
        payload = _payload()
        payload["risk"][0]["citations"] = []
        assert _errors(payload)

    def test_an_absence_line_may_have_no_citations_only_for_no_sponsor_and_other(self) -> None:
        for line_type in ("no_sponsor", "other"):
            payload = _payload()
            payload["risk"] = [
                {
                    "type": line_type,
                    "severity": "low",
                    "statement": "Nothing found.",
                    "absence": {"searched": "all answers"},
                    "citations": [],
                }
            ]
            assert _errors(payload) == []
        payload = _payload()
        payload["risk"] = [
            {
                "type": "existing_solution",
                "severity": "low",
                "statement": "Nothing found.",
                "absence": {"searched": "all answers"},
                "citations": [],
            }
        ]
        assert _errors(payload)

    def test_no_sponsor_without_absence_or_citations_is_refused(self) -> None:
        payload = _payload()
        payload["risk"] = [
            {"type": "no_sponsor", "severity": "low", "statement": "None.", "citations": []}
        ]
        assert _errors(payload)

    def test_absence_cannot_be_on_a_need_line(self) -> None:
        payload = _payload()
        payload["need"][0]["absence"] = {"searched": "x"}
        assert _errors(payload)

    @pytest.mark.parametrize(
        "citation",
        [
            _cite(),
            {"kind": "site_document", "document_id": "d1", "start": 3, "length": 9},
            {"kind": "assessment_score", "run_seq": 2, "capability": "a", "sub_capability": "b"},
            {"kind": "catalog_row", "target_key": "pair:x-y:US", "version": 2, "field": "summary"},
        ],
    )
    def test_each_citation_kind_is_accepted(self, citation: dict[str, Any]) -> None:
        payload = _payload()
        payload["need"][0]["citations"] = [citation]
        assert _errors(payload) == []

    @pytest.mark.parametrize(
        "citation",
        [
            {"kind": "interview_answer", "review_id": "r1", "start": 0},
            {"kind": "interview_answer", "review_id": "r1", "start": -1, "length": 4},
            {"kind": "interview_answer", "review_id": "r1", "start": 0, "length": 0},
            {"kind": "site_document", "review_id": "r1", "start": 0, "length": 4},
            {"kind": "web_page", "url": "https://example.org"},
            {"kind": "assessment_score", "run_seq": 0, "capability": "a", "sub_capability": "b"},
            {"kind": "catalog_row", "target_key": "concept:x", "version": 1, "field": "f"},
        ],
    )
    def test_bad_citations_are_refused(self, citation: dict[str, Any]) -> None:
        payload = _payload()
        payload["need"][0]["citations"] = [citation]
        assert _errors(payload)

    def test_length_limits(self) -> None:
        for mutate in (
            lambda p: p.__setitem__("rationale", "x" * 601),
            lambda p: p["need"][0].__setitem__("statement", "x" * 401),
            lambda p: p["risk"][0].__setitem__("statement", "x" * 401),
            lambda p: p.__setitem__("client_summary_draft", "x" * 301),
            lambda p: p.__setitem__("follow_up_questions", ["q"] * 4),
            lambda p: p.__setitem__("need", [copy.deepcopy(p["need"][0]) for _ in range(7)]),
            lambda p: p.__setitem__("risk", [copy.deepcopy(p["risk"][0]) for _ in range(7)]),
        ):
            payload = _payload()
            mutate(payload)
            assert _errors(payload), mutate

    def test_limits_are_inclusive(self) -> None:
        payload = _payload()
        payload["rationale"] = "x" * 600
        payload["need"][0]["statement"] = "x" * 400
        payload["client_summary_draft"] = "x" * 300
        payload["follow_up_questions"] = ["q"] * 3
        payload["need"] = [copy.deepcopy(payload["need"][0]) for _ in range(6)]
        payload["risk"] = [copy.deepcopy(payload["risk"][0]) for _ in range(6)]
        assert _errors(payload) == []

    @pytest.mark.parametrize(
        ("field", "value"),
        [
            ("schema_version", 2),
            ("agent_score", 101),
            ("agent_score", -1),
            ("agent_score", 50.5),
            ("proposed_call", "low"),
            ("row_version", 0),
            ("target_key", "concept:discharge-coordination"),
            ("target_key", "pair:Discharge:DE"),
            ("site_slug", "Example Site"),
        ],
    )
    def test_bad_scalar_values_are_refused(self, field: str, value: Any) -> None:
        payload = _payload()
        payload[field] = value
        assert _errors(payload)

    @pytest.mark.parametrize(
        "field", ["ranking_request_id", "site_slug", "target_key", "need", "risk"]
    )
    def test_required_fields(self, field: str) -> None:
        payload = _payload()
        del payload[field]
        assert _errors(payload)

    def test_strength_and_severity_vocabulary(self) -> None:
        payload = _payload()
        payload["need"][0]["strength"] = "huge"
        assert _errors(payload)
        payload = _payload()
        payload["risk"][0]["severity"] = "critical"
        assert _errors(payload)

    def test_optional_fields_may_be_left_out(self) -> None:
        payload = _payload()
        del payload["follow_up_questions"]
        del payload["client_summary_draft"]
        payload["need"] = []
        assert _errors(payload) == []


class TestSchemaCopy:
    def test_file_matches_its_pin(self) -> None:
        pin = json.loads(
            (_ROOT / "providers" / proposal_schemas.SITE_MATCH_PIN_RESOURCE).read_text()
        )
        data = proposal_schemas.schema_bytes(proposal_schemas.SITE_MATCH_SCHEMA_RESOURCE)
        assert hashlib.sha256(data).hexdigest() == pin["sha256"]
        blob = hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()
        assert blob == pin["blob_sha"]
        assert json.loads(data)["x-schema-version"] == pin["schema_version"] == 1

    def test_every_object_refuses_unknown_fields(self) -> None:
        def walk(node: Any, path: str) -> None:
            if isinstance(node, dict):
                if node.get("type") == "object":
                    assert node.get("additionalProperties") is False, path
                for key, child in node.items():
                    walk(child, f"{path}/{key}")
            elif isinstance(node, list):
                for i, child in enumerate(node):
                    walk(child, f"{path}/{i}")

        walk(_built()["schema"], "#")

    def test_has_no_quote_property_anywhere(self) -> None:
        def names(node: Any) -> set[str]:
            found: set[str] = set()
            if isinstance(node, dict):
                found |= set(node.get("properties", {}))
                for child in node.values():
                    found |= names(child)
            elif isinstance(node, list):
                for child in node:
                    found |= names(child)
            return found

        assert "quote" not in names(_built()["schema"])

    def test_is_declared_as_package_data(self) -> None:
        import tomllib

        config = tomllib.loads((_ROOT / "pyproject.toml").read_text())
        patterns = config["tool"]["setuptools"]["package-data"]["providers"]
        assert "site_catalog_match_payload.schema*.json" in patterns
