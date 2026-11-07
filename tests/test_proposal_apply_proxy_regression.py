"""Regression tests for TECH-8246 targeted review findings.

Covers:
Finding (1): Transport/client construction failures raising non-ValueError
(e.g. FileNotFoundError, OSError) must be caught safely by apply_proposal
without violating its never-raise contract, and redundant transport
construction during apply_proposal pre-validation is eliminated.

Finding (2): _resolve_tailnet_proxy_mounts only falls back when rh_comms_plugins
or rh_comms_plugins.tls (or the tailnet_proxy_mounts symbol) is genuinely absent;
internal import errors raised from within rh_comms_plugins.tls must propagate.
"""

from __future__ import annotations

import importlib
import sys
import types
from typing import Any
from unittest.mock import MagicMock

import httpx
import pytest

import proposal_apply_http_client
from proposal_apply_http_client import (
    PROPOSAL_APPLY_TOKEN_ENV_VAR,
    PROPOSAL_APPLY_URL_ENV_VAR,
    TAILNET_HTTP_PROXY_ENV_VAR,
    _resolve_tailnet_proxy_mounts,
    _tailnet_proxy_mounts_fallback,
    apply_proposal,
    validate_proposal_apply_configuration,
)
from tests.test_proposal_apply_http_client import _ctx


def _set_required_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(
        PROPOSAL_APPLY_URL_ENV_VAR,
        "https://comms-approvals.drum-mackarel.ts.net/actions",
    )
    monkeypatch.setenv(PROPOSAL_APPLY_TOKEN_ENV_VAR, "test-token")
    monkeypatch.setenv(TAILNET_HTTP_PROXY_ENV_VAR, "http://127.0.0.1:1055")


class TestTransportConstructionNonValueErrorNeverRaises:
    """Finding (1): non-ValueError exceptions during transport/client construction
    must not leak out of apply_proposal.
    """

    async def test_apply_proposal_never_raises_on_file_not_found_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_required_env(monkeypatch)

        def exploding_mounts() -> dict[str, httpx.AsyncBaseTransport]:
            raise FileNotFoundError("No such file or directory: '/nonexistent/ca-bundle.crt'")

        monkeypatch.setattr(proposal_apply_http_client, "tailnet_proxy_mounts", exploding_mounts)

        # Must not raise FileNotFoundError
        outcome = await apply_proposal(_ctx())
        assert outcome.applied is False
        assert outcome.indeterminate is False
        assert outcome.caller_error == "server configuration error"
        assert "ca-bundle.crt" in (outcome.log_detail or "")
        assert "failed to build HTTP client" in (outcome.log_detail or "")

    async def test_apply_proposal_never_raises_on_os_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_required_env(monkeypatch)

        def exploding_mounts() -> dict[str, httpx.AsyncBaseTransport]:
            raise OSError("Custom OS-level transport failure")

        monkeypatch.setattr(proposal_apply_http_client, "tailnet_proxy_mounts", exploding_mounts)

        outcome = await apply_proposal(_ctx())
        assert outcome.applied is False
        assert outcome.indeterminate is False
        assert outcome.caller_error == "server configuration error"
        assert "Custom OS-level transport failure" in (outcome.log_detail or "")

    def test_validate_configuration_hard_fails_on_non_value_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _set_required_env(monkeypatch)

        def exploding_mounts() -> dict[str, httpx.AsyncBaseTransport]:
            raise FileNotFoundError("Missing SSL bundle")

        monkeypatch.setattr(proposal_apply_http_client, "tailnet_proxy_mounts", exploding_mounts)

        with pytest.raises(RuntimeError, match="failed to initialize HTTP client transport"):
            validate_proposal_apply_configuration()

    async def test_apply_proposal_constructs_mounts_only_once(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Finding (1) & Low finding: redundant runtime construction of AsyncHTTPTransport
        at apply_proposal pre-validation is eliminated; mounts are created exactly once
        inside _build_apply_client.
        """
        _set_required_env(monkeypatch)

        call_count = 0
        real_mounts_fn = proposal_apply_http_client.tailnet_proxy_mounts

        def counting_mounts() -> dict[str, httpx.AsyncBaseTransport]:
            nonlocal call_count
            call_count += 1
            return real_mounts_fn()

        monkeypatch.setattr(proposal_apply_http_client, "tailnet_proxy_mounts", counting_mounts)

        def fake_handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"applied": True, "result": {"status": "ok"}})

        def fake_build_apply_client(
            timeout_seconds: float, tls_sni_host: str | None
        ) -> httpx.AsyncClient:
            # Invokes counting_mounts once to construct mounts for the client
            counting_mounts()
            return httpx.AsyncClient(
                timeout=httpx.Timeout(timeout_seconds),
                transport=httpx.MockTransport(fake_handler),
            )

        monkeypatch.setattr(
            proposal_apply_http_client, "_build_apply_client", fake_build_apply_client
        )

        outcome = await apply_proposal(_ctx())
        assert outcome.applied is True
        # Must be called exactly once inside _build_apply_client, not twice
        assert call_count == 1


class TestTlsPluginImportFallbackScoping:
    """Finding (2): _resolve_tailnet_proxy_mounts must fall back ONLY when
    genuinely absent, and must propagate internal errors inside rh_comms_plugins.tls.
    """

    def test_fallback_when_rh_comms_plugins_package_genuinely_absent(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delitem(sys.modules, "rh_comms_plugins", raising=False)
        monkeypatch.delitem(sys.modules, "rh_comms_plugins.tls", raising=False)

        resolved = _resolve_tailnet_proxy_mounts()
        assert resolved is _tailnet_proxy_mounts_fallback

    def test_fallback_when_module_absent_in_present_package(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pkg = types.ModuleType("rh_comms_plugins")
        pkg.__path__ = []  # marks it as package with no submodules
        monkeypatch.setitem(sys.modules, "rh_comms_plugins", pkg)
        monkeypatch.delitem(sys.modules, "rh_comms_plugins.tls", raising=False)

        resolved = _resolve_tailnet_proxy_mounts()
        assert resolved is _tailnet_proxy_mounts_fallback

    def test_fallback_when_symbol_absent_in_present_module(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        pkg = types.ModuleType("rh_comms_plugins")
        pkg.__path__ = []
        mod = types.ModuleType("rh_comms_plugins.tls")
        # mod does not have tailnet_proxy_mounts
        monkeypatch.setitem(sys.modules, "rh_comms_plugins", pkg)
        monkeypatch.setitem(sys.modules, "rh_comms_plugins.tls", mod)

        resolved = _resolve_tailnet_proxy_mounts()
        assert resolved is _tailnet_proxy_mounts_fallback

    def test_returns_symbol_when_present(self, monkeypatch: pytest.MonkeyPatch) -> None:
        pkg = types.ModuleType("rh_comms_plugins")
        pkg.__path__ = []
        mod = types.ModuleType("rh_comms_plugins.tls")
        dummy_mounts = MagicMock()
        mod.tailnet_proxy_mounts = dummy_mounts  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "rh_comms_plugins", pkg)
        monkeypatch.setitem(sys.modules, "rh_comms_plugins.tls", mod)

        resolved = _resolve_tailnet_proxy_mounts()
        assert resolved is dummy_mounts

    def test_propagates_internal_module_not_found_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """If rh_comms_plugins.tls fails importing an internal dependency,
        ModuleNotFoundError must NOT be swallowed by the fallback.
        """
        pkg = types.ModuleType("rh_comms_plugins")
        pkg.__path__ = []
        monkeypatch.setitem(sys.modules, "rh_comms_plugins", pkg)
        monkeypatch.delitem(sys.modules, "rh_comms_plugins.tls", raising=False)

        class BrokenInnerLoader:
            def create_module(self, spec: Any) -> None:
                return None

            def exec_module(self, module: Any) -> None:
                raise ModuleNotFoundError("No module named 'internal_dep'", name="internal_dep")

        spec = importlib.machinery.ModuleSpec("rh_comms_plugins.tls", BrokenInnerLoader())

        class BrokenInnerFinder:
            def find_spec(self, fullname: str, path: Any = None, target: Any = None) -> Any:
                if fullname == "rh_comms_plugins.tls":
                    return spec
                return None

        monkeypatch.setattr(sys, "meta_path", [BrokenInnerFinder(), *sys.meta_path])

        with pytest.raises(ModuleNotFoundError) as exc_info:
            _resolve_tailnet_proxy_mounts()
        assert exc_info.value.name == "internal_dep"

    def test_propagates_internal_import_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """If rh_comms_plugins.tls fails with an internal ImportError
        (e.g. symbol missing from an inner dependency), it must propagate.
        """
        pkg = types.ModuleType("rh_comms_plugins")
        pkg.__path__ = []
        monkeypatch.setitem(sys.modules, "rh_comms_plugins", pkg)
        monkeypatch.delitem(sys.modules, "rh_comms_plugins.tls", raising=False)

        class BrokenImportLoader:
            def create_module(self, spec: Any) -> None:
                return None

            def exec_module(self, module: Any) -> None:
                raise ImportError("cannot import name 'internal_symbol' from 'some_dep'")

        spec = importlib.machinery.ModuleSpec("rh_comms_plugins.tls", BrokenImportLoader())

        class BrokenImportFinder:
            def find_spec(self, fullname: str, path: Any = None, target: Any = None) -> Any:
                if fullname == "rh_comms_plugins.tls":
                    return spec
                return None

        monkeypatch.setattr(sys, "meta_path", [BrokenImportFinder(), *sys.meta_path])

        with pytest.raises(ImportError, match="cannot import name 'internal_symbol'"):
            _resolve_tailnet_proxy_mounts()
