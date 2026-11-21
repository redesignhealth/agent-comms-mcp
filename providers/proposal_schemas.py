"""What an agent must follow to submit a proposal of a given kind (TECH-9214).

``proposals_schema(kind)`` returns this. Today only ``catalog_candidate`` has a
schema: the vendored copy of Arcadia's payload JSON Schema (version 2) plus a
short guide. The schema file is byte-identical to the copy the approvals service
validates against and forwards with; ``catalog_candidate_payload.schema.pin.json``
beside it records Arcadia's commit and the file's sha256, and the tests pin both,
so the two repos can only drift on purpose (the approvals service also refuses to
forward while its sha256 differs from Arcadia's).
"""

from __future__ import annotations

import copy
import hashlib
import json
from importlib import resources
from typing import Any

SCHEMA_RESOURCE = "catalog_candidate_payload.schema.json"
PIN_RESOURCE = "catalog_candidate_payload.schema.pin.json"

_FACT_CHECK = [{"round": 1, "agreement_score": 85, "issues_low": 2}]

CATALOG_CANDIDATE_GUIDE = """\
A catalog_candidate proposes one change to Arcadia's opportunity catalog. A submission that breaks
any rule below is refused at submit with 422 and a list of {path, rule} errors; nothing is stored.
Arcadia checks it again against the live catalog and may still refuse it; then the proposal is
closed as rejected and proposals_get shows Arcadia's code and field errors in decision_note.

Before you write a create or upsert, call catalog_get(target_key) with the same target_key
("concept:<slug>" or "pair:<concept-slug>:<MARKET>"). It returns {target_key, target_type, exists,
status, version, payload}:
- exists false -> propose a create.
- exists true -> propose an upsert, never a create. Start from "payload" (the row in the payload
  shape below). For a pair, send "version" as base_version; a concept has no version, so send none.
- status "deleted" (exists is still true): the target was soft-deleted; an upsert restores it.
If catalog_get fails or says it is not configured you cannot see the catalog: say so rather than
guess, and do not propose a create.

action fields (proposals_submit(kind="catalog_candidate", action=...)):
- action_type: "create" | "upsert" | "delete".
- target_id: "concept:<slug>" for a concept, "pair:<concept-slug>:<MARKET>" for one concept in one
  market. <slug> is lowercase words joined by single hyphens ([a-z0-9]+(-[a-z0-9]+)*); <MARKET> is
  exactly two capital letters, such as US. No other form is accepted.
- create / upsert: "payload" (required) is the schema's ConceptPayload for a concept target or
  ConceptMarketPayload for a pair target, and must name the same slug (and market) as target_id.
  Also required: "fact_check", a non-empty list of rounds {round >= 1, agreement_score 0-100,
  issues_high/medium/low >= 0, open_issue_count >= 0}; no minimum score, at most 20 rounds.
  Optional: "citations" (at most 10, each resolving to YOUR OWN stored sources; same shape as Arcana
  brain proposals), "reason" (text, at most 2000 characters).
- upsert only: "base_version" (integer >= 1), the catalog version you edited. Arcadia
  requires it when it already holds that pair; omit it only if the pair is new. Never on create.
- delete: only target_id, action_type and "reason" (required, non-empty, at most 2000 characters);
  "fact_check" and "citations" are optional. No payload: the schema's DeletePayload definition is
  built by the approvals service from target_id and reason; never send a payload on a delete.
- Payload rules the schema alone cannot say: a related company's source_url is lowercase http:// or
  https:// with a host and no spaces; a "works" version has exactly one assessment per kind (impact,
  technical, uptake) plus research_depth and sources_as_of; value_low is not above value_high;
  no repeated assessment kind, assessment flag or fact-check round; citation "supports" entries
  name a real assessment kind or an in-range index into related_companies/replaces.
- No unknown fields anywhere. Do not include health-system material; it is refused.
- schema_version in a payload must be the schema's version (it defaults to it when omitted).
"""


def _concept_example() -> dict[str, Any]:
    return {
        "target_id": "concept:remote-patient-monitoring",
        "action_type": "create",
        "payload": {
            "schema_version": 2,
            "slug": "remote-patient-monitoring",
            "name": "Remote patient monitoring",
            "summary": "Devices and workflows that track patients at home.",
            "domain_code": "chronic-care",
            "value_types": ["cost"],
        },
        "fact_check": copy.deepcopy(_FACT_CHECK),
    }


def _assessment(kind: str, rating: str, **extra: Any) -> dict[str, Any]:
    return {
        "kind": kind,
        "rating": rating,
        "confidence": "medium",
        "rationale": f"Why {kind} is {rating}.",
        **extra,
    }


def _pair_example() -> dict[str, Any]:
    return {
        "target_id": "pair:remote-patient-monitoring:US",
        "action_type": "upsert",
        "base_version": 3,
        "payload": {
            "schema_version": 2,
            "concept_slug": "remote-patient-monitoring",
            "market_code": "US",
            "version": {
                "viability": "works",
                "works_score": 70,
                "confidence_score": 60,
                "build_scope": "core",
                "deciding_feature": "Finance owns the budget",
                "research_depth": "web_checked",
                "sources_as_of": "2026-06-30",
                "assessments": [
                    _assessment(
                        "impact",
                        "green",
                        value_low=1000000,
                        value_high=2000000,
                        value_unit="USD per year",
                        value_basis="range",
                    ),
                    _assessment("technical", "amber"),
                    _assessment("uptake", "amber", flags=["vendor_sourced"]),
                ],
                "citations": [
                    {
                        "title": "Hospital finance survey",
                        "year": 2025,
                        "url": "https://example.org/survey",
                        "source_type": "survey",
                        "supports": [
                            {"target_type": "assessment", "assessment_kind": "impact"},
                            {"target_type": "related_company", "index": 0},
                        ],
                    }
                ],
                "related_companies": [
                    {
                        "company": "Incumbent Co",
                        "source_url": "https://example.org/incumbent",
                        "role_in_space": "Incumbent",
                        "description": "Sells the report today.",
                    }
                ],
                "fact_check_rounds": [{"round": 1, "agreement_score": 85}],
            },
        },
        "fact_check": copy.deepcopy(_FACT_CHECK),
    }


def _delete_example() -> dict[str, Any]:
    return {
        "target_id": "pair:remote-patient-monitoring:CA",
        "action_type": "delete",
        "reason": "The market row duplicates another concept.",
    }


def _read_json(name: str) -> dict[str, Any]:
    loaded = json.loads((resources.files("providers") / name).read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def schema_bytes() -> bytes:
    return (resources.files("providers") / SCHEMA_RESOURCE).read_bytes()


def canonical_sha256(schema: dict[str, Any]) -> str:
    """SHA-256 of the schema as Arcadia's ``GET /catalog/v1/schema`` hashes it:
    canonical JSON (``sort_keys``, no spaces, ``ensure_ascii`` off, UTF-8). This
    is the hash the approvals forwarder compares; the pin file's ``sha256`` is
    the raw file's."""
    canonical = json.dumps(schema, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def catalog_candidate_schema() -> dict[str, Any]:
    pin = _read_json(PIN_RESOURCE)
    schema = _read_json(SCHEMA_RESOURCE)
    return {
        "kind": "catalog_candidate",
        "schema_version": pin["schema_version"],
        "schema_sha256": canonical_sha256(schema),
        "schema_source": {"repo": pin["repo"], "path": pin["path"], "commit": pin["commit"]},
        "schema": schema,
        "guide": CATALOG_CANDIDATE_GUIDE,
        "examples": {
            "create": _concept_example(),
            "upsert": _pair_example(),
            "delete": _delete_example(),
        },
    }


SCHEMAS = {"catalog_candidate": catalog_candidate_schema}


def schema_for_kind(kind: str) -> dict[str, Any] | None:
    builder = SCHEMAS.get(kind) if isinstance(kind, str) else None
    return builder() if builder is not None else None
