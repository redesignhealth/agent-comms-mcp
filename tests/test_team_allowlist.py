"""Unit tests for ``team_allowlist.py`` (Problem 2 fix: `open_ticket`'s
bot-asserted `action.team` was previously unverified against anything).

Most cases are covered against ``_parse_team_allowlist`` directly -- a pure
function, no env var/reimport needed. One test reloads the module to prove
the module-level ``OPEN_TICKET_TEAM_ALLOWLIST`` constant is actually wired
from the real env var at import time -- same ``monkeypatch.setenv`` +
``importlib.reload`` idiom as ``tests/test_identity_map.py``.
"""

from __future__ import annotations

import importlib

import pytest

import team_allowlist


class TestParseTeamAllowlist:
    def test_none_returns_empty_frozenset(self) -> None:
        assert team_allowlist._parse_team_allowlist(None) == frozenset()

    def test_empty_string_returns_empty_frozenset(self) -> None:
        assert team_allowlist._parse_team_allowlist("") == frozenset()

    def test_valid_json_array_parses(self) -> None:
        result = team_allowlist._parse_team_allowlist('["TECH"]')
        assert result == frozenset({"TECH"})

    def test_result_is_genuinely_a_frozenset(self) -> None:
        result = team_allowlist._parse_team_allowlist('["TECH"]')
        assert isinstance(result, frozenset)

    def test_malformed_json_defaults_to_empty_and_logs_warning(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level("WARNING", logger="team_allowlist"):
            result = team_allowlist._parse_team_allowlist("not json")
        assert result == frozenset()
        assert "not valid JSON" in caplog.text

    def test_non_list_json_defaults_to_empty_and_logs_warning(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level("WARNING", logger="team_allowlist"):
            result = team_allowlist._parse_team_allowlist('{"TECH": true}')
        assert result == frozenset()
        assert "must be a JSON array" in caplog.text

    def test_non_string_element_defaults_to_empty_and_logs_warning(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level("WARNING", logger="team_allowlist"):
            result = team_allowlist._parse_team_allowlist('["TECH", 123]')
        assert result == frozenset()
        assert "must be a JSON array" in caplog.text

    def test_empty_string_element_defaults_to_empty_and_logs_warning(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level("WARNING", logger="team_allowlist"):
            result = team_allowlist._parse_team_allowlist('["TECH", ""]')
        assert result == frozenset()
        assert "must be a JSON array" in caplog.text


class TestModuleLevelConstant:
    def test_reads_from_env_var_at_import_time(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(team_allowlist._ENV_VAR, '["TECH"]')
        try:
            reloaded = importlib.reload(team_allowlist)
            assert frozenset({"TECH"}) == reloaded.OPEN_TICKET_TEAM_ALLOWLIST
        finally:
            monkeypatch.delenv(team_allowlist._ENV_VAR, raising=False)
            importlib.reload(team_allowlist)

    def test_defaults_to_empty_frozenset_when_env_var_unset(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(team_allowlist._ENV_VAR, raising=False)
        reloaded = importlib.reload(team_allowlist)
        assert frozenset() == reloaded.OPEN_TICKET_TEAM_ALLOWLIST
