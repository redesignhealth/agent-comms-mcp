"""Pytest configuration — flat-layout imports + auth env defaults.

The service is a flat-layout app (main.py, providers/, etc.), so the service
root goes on sys.path, and the env vars required by
``auth.build_auth_provider()`` get dummy values so module-level FastMCP
construction doesn't raise when tests import ``main``.
"""

import os
import sys
from pathlib import Path

import pytest

SERVICE_ROOT = Path(__file__).parent
sys.path.insert(0, str(SERVICE_ROOT))


@pytest.fixture(autouse=True)
def _auth_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Point token storage at a temp dir and default the required auth env.

    The FileTree sanitization strategies call os.pathconf on the storage
    directory at construction time, so the path must exist.

    Uses ``monkeypatch.setenv`` (function-scoped, same as this fixture's
    own default scope — no widening/narrowing tension) instead of mutating
    ``os.environ`` directly, so pytest automatically restores the prior
    environment after each test rather than these vars accumulating across
    the session. ``setdefault``-style "only if unset" semantics are
    preserved via an explicit ``name not in os.environ`` check before each
    ``setenv`` call (``monkeypatch`` has no built-in ``setdefault``).
    """
    monkeypatch.setenv("MCP_TOKEN_STORAGE_PATH", str(tmp_path))
    _setdefault(monkeypatch, "OKTA_ISSUER_URL", "https://example.okta.com/oauth2/default")
    _setdefault(monkeypatch, "OKTA_CLIENT_ID", "test-client-id")
    _setdefault(monkeypatch, "OKTA_CLIENT_SECRET", "test-client-secret")
    _setdefault(monkeypatch, "BASE_URL", "http://localhost:8080")
    _setdefault(monkeypatch, "MCP_JWT_SECRET", "test-jwt-secret-for-unit-tests-only")
    _setdefault(monkeypatch, "AGENT_JWT_SECRET", "test-agent-jwt-secret-long-enough-for-hs256")


def _setdefault(monkeypatch: pytest.MonkeyPatch, name: str, value: str) -> None:
    """``monkeypatch.setenv`` equivalent of ``os.environ.setdefault``."""
    if name not in os.environ:
        monkeypatch.setenv(name, value)
