"""Unit tests for ``identity_map.py`` (Argus review: mutable dict literal ->
env-var-driven immutable mapping).

Most cases are covered against ``_parse_identity_map`` directly -- a pure
function, no env var/reimport needed. One test reloads the module to prove
the module-level ``GITHUB_LOGIN_TO_LINEAR_USER_ID`` constant is actually
wired from the real env var at import time, following the same
``monkeypatch.setenv`` + ``importlib.reload`` idiom other env-var-driven
modules in this codebase would use (see ``github_client.py``'s
``GITHUB_TOKEN``, though that one is read lazily per-call rather than once
at import, so its own tests only need ``monkeypatch.setenv`` with no
reload).
"""

from __future__ import annotations

import importlib
from types import MappingProxyType

import pytest

import identity_map


class TestParseIdentityMap:
    def test_none_returns_empty_mapping(self) -> None:
        assert dict(identity_map._parse_identity_map(None)) == {}

    def test_empty_string_returns_empty_mapping(self) -> None:
        assert dict(identity_map._parse_identity_map("")) == {}

    def test_valid_json_object_parses(self) -> None:
        result = identity_map._parse_identity_map('{"octocat": "user-uuid-1"}')
        assert dict(result) == {"octocat": "user-uuid-1"}

    def test_result_is_immutable(self) -> None:
        result = identity_map._parse_identity_map('{"octocat": "user-uuid-1"}')
        assert isinstance(result, MappingProxyType)
        with pytest.raises(TypeError):
            result["octocat"] = "someone-else"  # type: ignore[index]

    def test_malformed_json_defaults_to_empty_and_logs_warning(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level("WARNING", logger="identity_map"):
            result = identity_map._parse_identity_map("not json")
        assert dict(result) == {}
        assert "not valid JSON" in caplog.text

    def test_non_object_json_defaults_to_empty_and_logs_warning(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level("WARNING", logger="identity_map"):
            result = identity_map._parse_identity_map("[1, 2, 3]")
        assert dict(result) == {}
        assert "must be a JSON object" in caplog.text

    def test_non_string_values_default_to_empty_and_logs_warning(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level("WARNING", logger="identity_map"):
            result = identity_map._parse_identity_map('{"octocat": 12345}')
        assert dict(result) == {}
        assert "must be a JSON object" in caplog.text

    def test_non_string_keys_default_to_empty_and_logs_warning(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        # JSON object keys are always strings once parsed, but a non-str
        # value at any key is exactly what the previous test covers --
        # this one instead exercises a key colliding with a non-string
        # VALUE for a different, still-valid-looking key, to make sure a
        # single bad entry poisons the whole mapping rather than being
        # silently dropped.
        with caplog.at_level("WARNING", logger="identity_map"):
            result = identity_map._parse_identity_map('{"octocat": "user-uuid-1", "other": null}')
        assert dict(result) == {}
        assert "must be a JSON object" in caplog.text


class TestModuleLevelConstant:
    def test_reads_from_env_var_at_import_time(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(identity_map._ENV_VAR, '{"octocat": "user-uuid-1"}')
        try:
            reloaded = importlib.reload(identity_map)
            assert dict(reloaded.GITHUB_LOGIN_TO_LINEAR_USER_ID) == {"octocat": "user-uuid-1"}
        finally:
            monkeypatch.delenv(identity_map._ENV_VAR, raising=False)
            importlib.reload(identity_map)

    def test_defaults_to_empty_mapping_when_env_var_unset(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(identity_map._ENV_VAR, raising=False)
        reloaded = importlib.reload(identity_map)
        assert dict(reloaded.GITHUB_LOGIN_TO_LINEAR_USER_ID) == {}
