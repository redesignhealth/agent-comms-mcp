"""Unit tests for the comms_whoami placeholder tool (raw function path)."""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock, patch

import pytest
from fastmcp.exceptions import ToolError

# ``@comms_server.tool`` registers the coroutine and returns it unchanged
# in fastmcp 3.4.2, so the tool body can be invoked directly.
from providers.comms import whoami as _whoami


class TestWhoami:
    def test_okta_caller_reports_interactive_identity(self) -> None:
        token = MagicMock()
        token.claims = {
            "iss": "https://example.okta.com/oauth2/default",
            "email": "alice@example.com",
        }

        with patch("providers.comms.get_access_token", return_value=token):
            result = asyncio.run(_whoami())

        assert result == {
            "identity": "alice@example.com",
            "issuer": "https://example.okta.com/oauth2/default",
            "caller_type": "interactive",
            "scopes": [],
        }

    def test_agent_jwt_caller_reports_service_identity_and_scopes(self) -> None:
        token = MagicMock()
        token.claims = {
            "iss": "agent-jwt",
            "sub": "ea-agent-svc",
            "scopes": ["comms:read"],
        }

        with patch("providers.comms.get_access_token", return_value=token):
            result = asyncio.run(_whoami())

        assert result == {
            "identity": "ea-agent-svc",
            "issuer": "agent-jwt",
            "caller_type": "service",
            "scopes": ["comms:read"],
        }

    def test_agent_jwt_caller_with_forged_email_claim_is_not_impersonated(self) -> None:
        """agent-jwt identity comes from ``sub`` only — a forged ``email``
        claim must not surface as the caller identity."""
        token = MagicMock()
        token.claims = {
            "iss": "agent-jwt",
            "sub": "ea-agent-svc",
            "email": "victim@example.com",
            "scopes": ["comms:read"],
        }

        with patch("providers.comms.get_access_token", return_value=token):
            result = asyncio.run(_whoami())

        assert result["identity"] == "ea-agent-svc"

    def test_missing_token_raises_tool_error(self) -> None:
        with patch("providers.comms.get_access_token", return_value=None):
            with pytest.raises(ToolError, match="no access token"):
                asyncio.run(_whoami())
