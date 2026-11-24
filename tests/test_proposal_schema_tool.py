"""TECH-9214: ``proposals_schema`` -- what an agent must follow to submit a
``catalog_candidate``, and the schema copy staying in step with approvals'."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from providers import proposal_schemas
from scopes import PROPOSAL_SUBMIT_SCOPE, TOOL_SCOPES
from tests.test_proposal_tools import _ENV_PATCH, _OIDC_PATCH, _import_main

_BOT = "catalog-agent"
# Same vector as agent-comms-approvals' tests: the canonical-JSON hash Arcadia's
# schema endpoint reports for this schema (not the raw file hash).
CANONICAL_VECTOR = "265a8c93240d97024bcc2483ecf5557e45962b136eb227af93aee06fbaea5c93"
CANONICAL_V3 = "23f4eca43c9ae555b490787bf2d84511788f3e2595bb0623cc17a2d28169af81"
CANONICAL_V2 = "5029b9f3e1ca690dee61a36d9a0063564326aeaaeb82bc7aa7f33d46b61e028d"
_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def main() -> Any:
    return _import_main()


def _token(sub: str = _BOT, scopes: list[str] | None = None) -> MagicMock:
    token = MagicMock()
    token.claims = {
        "iss": "agent-jwt",
        "sub": sub,
        "scopes": [PROPOSAL_SUBMIT_SCOPE] if scopes is None else scopes,
        "owner_sub": "owner@example.com",
    }
    token.scopes = []
    token.client_id = sub
    return token


async def _call(main: Any, kind: Any, token: MagicMock | None = None) -> Any:
    with (
        _OIDC_PATCH,
        _ENV_PATCH,
        patch("main.get_access_token", return_value=token or _token()),
        patch("providers.proposals.get_access_token", return_value=token or _token()),
    ):
        async with Client(main.mcp) as client:
            return (await client.call_tool("proposals_schema", {"kind": kind})).data


class TestTool:
    async def test_is_mounted_read_only_and_gated_like_other_bot_tools(self, main: Any) -> None:
        tools = {t.name: t for t in await main.mcp.list_tools()}
        assert "proposals_schema" in tools
        assert TOOL_SCOPES["proposals_schema"] == PROPOSAL_SUBMIT_SCOPE

    async def test_catalog_candidate_shape(self, main: Any) -> None:
        out = await _call(main, "catalog_candidate")
        assert set(out) == {
            "kind",
            "schema_version",
            "schema_sha256",
            "schema_source",
            "schema",
            "guide",
            "examples",
        }
        assert out["kind"] == "catalog_candidate"
        assert out["schema_version"] == 4 == out["schema"]["x-schema-version"]
        assert out["schema_sha256"] == CANONICAL_VECTOR
        assert out["schema_sha256"] == proposal_schemas.canonical_sha256(out["schema"])
        assert {
            "ConceptPayload",
            "ConceptMarketPayload",
            "DeletePayload",
            "CapabilityMapPayload",
        } <= set(out["schema"]["$defs"])
        assert set(out["examples"]) == {
            "create",
            "upsert",
            "create_pair_with_concept",
            "delete",
            "upsert_capability_map",
        }
        for text in ("concept:<slug>", "pair:<concept-slug>:<MARKET>", "base_version", "reason"):
            assert text in out["guide"]

    async def test_examples_are_shaped_like_the_schema(self, main: Any) -> None:
        out = await _call(main, "catalog_candidate")
        create, upsert, delete = (out["examples"][k] for k in ("create", "upsert", "delete"))
        assert (create["action_type"], upsert["action_type"], delete["action_type"]) == (
            "create",
            "upsert",
            "delete",
        )
        assert create["target_id"].startswith("concept:")
        assert upsert["target_id"].startswith("pair:")
        assert isinstance(upsert["base_version"], int)
        assert "payload" not in delete and delete["reason"]
        concept = out["schema"]["$defs"]["ConceptPayload"]
        assert set(create["payload"]) <= set(concept["properties"])
        assert set(concept["required"]) <= set(create["payload"])
        pair = out["schema"]["$defs"]["ConceptMarketPayload"]
        assert set(pair["required"]) <= set(upsert["payload"])
        new = out["examples"]["create_pair_with_concept"]
        assert new["action_type"] == "create" and "base_version" not in new
        assert set(new["payload"]) <= set(pair["properties"])
        concept_def = out["schema"]["$defs"]["ConceptIn"]
        assert set(new["payload"]["concept"]) <= set(concept_def["properties"])
        assert new["payload"]["concept"]["slug"] == new["payload"]["concept_slug"]
        assert new["payload"]["schema_version"] == 3
        for text in ("payload.concept", "CONCEPT_CREATION_PENDING", "first row"):
            assert text in out["guide"]
        version = out["schema"]["$defs"]["VersionIn"]
        assert set(upsert["payload"]["version"]) <= set(version["properties"])
        assert set(version["required"]) <= set(upsert["payload"]["version"])

    async def test_capability_map_example_is_shaped_like_the_schema(self, main: Any) -> None:
        out = await _call(main, "catalog_candidate")
        example = out["examples"]["upsert_capability_map"]
        assert example["action_type"] == "upsert"
        assert example["target_id"] == "capability_map:" + example["payload"]["concept_slug"]
        cap_map = out["schema"]["$defs"]["CapabilityMapPayload"]
        assert set(cap_map["required"]) <= set(example["payload"])
        assert set(example["payload"]) <= set(cap_map["properties"])
        assert (
            example["payload"]["schema_version"] == cap_map["properties"]["schema_version"]["const"]
        )
        item = out["schema"]["$defs"]["CapabilityMapItemIn"]
        for entry in example["payload"]["items"]:
            assert set(entry) <= set(item["properties"])
            assert set(item["required"]) <= set(entry)
        for text in ("capability_map:<concept-slug>", "catalog_capabilities", "UNKNOWN_CAPABILITY"):
            assert text in out["guide"]

    @pytest.mark.parametrize("kind", ["gmail_send", "nope", "Catalog_Candidate"])
    async def test_unknown_kind_lists_the_kinds_with_a_schema(self, main: Any, kind: str) -> None:
        with pytest.raises(ToolError, match=r"invalid_request.*catalog_candidate"):
            await _call(main, kind)

    async def test_empty_kind_is_invalid(self, main: Any) -> None:
        with pytest.raises(ToolError, match="invalid_request"):
            await _call(main, "")

    async def test_interactive_callers_are_refused(self, main: Any) -> None:
        token = _token()
        token.claims = {"iss": "okta", "sub": "human@example.com"}
        with pytest.raises(ToolError):
            await _call(main, "catalog_candidate", token)

    async def test_submit_description_points_at_it(self, main: Any) -> None:
        tools = {t.name: t for t in await main.mcp.list_tools()}
        assert "proposals_schema" in (tools["proposals_submit"].description or "")


class TestSchemaCopy:
    def test_file_matches_its_pin(self) -> None:
        pin = json.loads((_ROOT / "providers" / proposal_schemas.PIN_RESOURCE).read_text())
        data = proposal_schemas.schema_bytes()
        assert hashlib.sha256(data).hexdigest() == pin["sha256"]
        blob = hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()
        assert blob == pin["blob_sha"]
        assert json.loads(data)["x-schema-version"] == pin["schema_version"]

    def test_canonical_hash_is_not_the_raw_file_hash(self) -> None:
        pin = json.loads((Path("providers") / proposal_schemas.PIN_RESOURCE).read_text())
        assert pin["sha256"] != CANONICAL_VECTOR
        assert (
            proposal_schemas.canonical_sha256(json.loads(proposal_schemas.schema_bytes()))
            == CANONICAL_VECTOR
        )

    def test_is_declared_as_package_data(self) -> None:
        import tomllib

        config = tomllib.loads((_ROOT / "pyproject.toml").read_text())
        patterns = config["tool"]["setuptools"]["package-data"]["providers"]
        assert "catalog_candidate_payload.schema*.json" in patterns

    @pytest.mark.skipif(
        not os.environ.get("AGENT_COMMS_APPROVALS_DIR"),
        reason="set AGENT_COMMS_APPROVALS_DIR to a checkout of agent-comms-approvals",
    )
    def test_equals_the_approvals_copy(self) -> None:
        root = Path(os.environ["AGENT_COMMS_APPROVALS_DIR"]) / "rh_comms_plugins"
        theirs = (root / "catalog_candidate_payload.schema.json").read_bytes()
        assert theirs == proposal_schemas.schema_bytes()
        pin = json.loads((root / "catalog_candidate_payload.schema.pin.json").read_text())
        ours = json.loads((_ROOT / "providers" / proposal_schemas.PIN_RESOURCE).read_text())
        assert pin == ours

    def test_pin_is_v4_and_keeps_v2_and_v3_compatible(self) -> None:
        pin = json.loads((_ROOT / "providers" / proposal_schemas.PIN_RESOURCE).read_text())
        assert (pin["schema_version"], pin["vocabulary_version"]) == (4, 3)
        assert pin["compatible_arcadia_sha256"] == {"2": CANONICAL_V2, "3": CANONICAL_V3}
