"""Tests for the pluggable risk-scorer seam's registry/resolution
mechanism (plugins.py) -- TECH-5389 PR1."""

from __future__ import annotations

import pytest

import plugins
from plugins import (
    BoundaryCrossingScorer,
    RiskScorer,
    resolve_plugin,
)


class _FakeScorer:
    async def score(self, ctx: object) -> None:  # pragma: no cover -- never called
        raise NotImplementedError


_REGISTRY: dict[str, type] = {"boundary_v1": BoundaryCrossingScorer}


class TestResolvePluginRegistryLookup:
    def test_default_name_resolves_to_default_factory(self) -> None:
        scorer = resolve_plugin("SOME_ENV_VAR", _REGISTRY, "boundary_v1")
        assert isinstance(scorer, BoundaryCrossingScorer)

    def test_env_var_overrides_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SOME_ENV_VAR", "fake")
        scorer = resolve_plugin(
            "SOME_ENV_VAR",
            {**_REGISTRY, "fake": _FakeScorer},
            "boundary_v1",
        )
        assert isinstance(scorer, _FakeScorer)

    def test_unknown_registry_name_raises_runtime_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SOME_ENV_VAR", "not_a_registered_name")
        with pytest.raises(RuntimeError, match="unknown plugin"):
            resolve_plugin("SOME_ENV_VAR", _REGISTRY, "boundary_v1")


class TestResolvePluginImportPath:
    def test_valid_import_path_resolves(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SOME_ENV_VAR", "tests.test_plugins:_FakeScorer")
        scorer = resolve_plugin("SOME_ENV_VAR", _REGISTRY, "boundary_v1")
        assert isinstance(scorer, _FakeScorer)

    def test_unimportable_module_raises_runtime_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SOME_ENV_VAR", "not_a_real_module:Whatever")
        with pytest.raises(RuntimeError, match="failed to import plugin"):
            resolve_plugin("SOME_ENV_VAR", _REGISTRY, "boundary_v1")

    def test_missing_attribute_raises_runtime_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SOME_ENV_VAR", "tests.test_plugins:NotDefinedAnywhere")
        with pytest.raises(RuntimeError, match="failed to import plugin"):
            resolve_plugin("SOME_ENV_VAR", _REGISTRY, "boundary_v1")


class TestRiskScorerRegistry:
    def test_default_registry_contains_boundary_v1(self) -> None:
        assert plugins.RISK_SCORERS[plugins.DEFAULT_RISK_SCORER] is BoundaryCrossingScorer

    def test_boundary_crossing_scorer_satisfies_protocol(self) -> None:
        scorer: RiskScorer = BoundaryCrossingScorer()
        assert hasattr(scorer, "score")


class TestGetRiskScorerAndValidateConfiguration:
    def setup_method(self) -> None:
        # get_risk_scorer caches a process-wide singleton -- reset it so
        # each test starts from a clean slate regardless of run order.
        plugins._risk_scorer = None

    def teardown_method(self) -> None:
        plugins._risk_scorer = None

    def test_get_risk_scorer_defaults_to_boundary_v1(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(plugins.RISK_SCORER_ENV_VAR, raising=False)
        assert isinstance(plugins.get_risk_scorer(), BoundaryCrossingScorer)

    def test_get_risk_scorer_caches_the_instance(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(plugins.RISK_SCORER_ENV_VAR, raising=False)
        first = plugins.get_risk_scorer()
        second = plugins.get_risk_scorer()
        assert first is second

    def test_validate_configuration_passes_for_the_default(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(plugins.RISK_SCORER_ENV_VAR, raising=False)
        plugins.validate_configuration()  # must not raise

    def test_validate_configuration_fails_fast_on_unknown_scorer(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(plugins.RISK_SCORER_ENV_VAR, "not_a_real_scorer")
        with pytest.raises(RuntimeError, match="unknown plugin"):
            plugins.validate_configuration()

    def test_validate_configuration_fails_fast_on_bad_import_path(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(plugins.RISK_SCORER_ENV_VAR, "not_a_real_module:Whatever")
        with pytest.raises(RuntimeError, match="failed to import plugin"):
            plugins.validate_configuration()
