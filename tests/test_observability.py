"""Tests for observability.py's structured logging helpers.

``hash_user`` is tested under its current (deliberately-not-yet-renamed)
name per a deferred follow-up ticket — see observability.py's own
docstring for why it returns the email local-part.
"""

from __future__ import annotations

import logging
from unittest.mock import patch

import structlog

import observability
from observability import (
    _resolve_log_level,
    configure_logging,
    hash_user,
    log_auth_flow,
    log_auth_rejected,
    log_scope_denial,
    log_tool_call,
    log_user_active,
)


class TestHashUser:
    def test_email_shaped_input_returns_local_part(self) -> None:
        assert hash_user("user@example.com") == "user"

    def test_non_email_slug_shaped_input_passes_through_unchanged(self) -> None:
        assert hash_user("ea-agent-svc") == "ea-agent-svc"

    def test_strips_surrounding_whitespace(self) -> None:
        assert hash_user("  person@example.com  ") == "person"


class TestConfigureLoggingIdempotent:
    def test_calling_twice_does_not_raise(self) -> None:
        configure_logging()
        configure_logging()  # must not error or otherwise blow up


class TestResolveLogLevel:
    def test_default_is_info(self) -> None:
        with patch.dict("os.environ", {}, clear=False):
            import os as _os

            _os.environ.pop("LOG_LEVEL", None)
            assert _resolve_log_level() == logging.INFO

    def test_debug_is_honored(self) -> None:
        with patch.dict("os.environ", {"LOG_LEVEL": "DEBUG"}):
            assert _resolve_log_level() == logging.DEBUG

    def test_lowercase_value_is_normalized(self) -> None:
        with patch.dict("os.environ", {"LOG_LEVEL": "warning"}):
            assert _resolve_log_level() == logging.WARNING

    def test_invalid_value_falls_back_to_info(self) -> None:
        with patch.dict("os.environ", {"LOG_LEVEL": "NOT_A_REAL_LEVEL"}):
            assert _resolve_log_level() == logging.INFO

    def test_invalid_value_logs_a_warning(self) -> None:
        with patch.dict("os.environ", {"LOG_LEVEL": "DBG"}):
            with patch.object(observability._fallback_logger, "warning") as mock_warning:
                _resolve_log_level()
        mock_warning.assert_called_once_with("Invalid LOG_LEVEL=%r; falling back to INFO", "DBG")

    def test_notset_falls_back_to_info(self) -> None:
        """LOG_LEVEL=NOTSET resolves via getattr to 0, which passes a naive
        isinstance(level, int) check but is structlog's "log everything"
        sentinel, not a real filtering threshold -- must fall back to INFO
        rather than disabling filtering entirely."""
        with patch.dict("os.environ", {"LOG_LEVEL": "NOTSET"}):
            assert _resolve_log_level() == logging.INFO

    def test_notset_logs_a_warning(self) -> None:
        with patch.dict("os.environ", {"LOG_LEVEL": "NOTSET"}):
            with patch.object(observability._fallback_logger, "warning") as mock_warning:
                _resolve_log_level()
        mock_warning.assert_called_once_with("Invalid LOG_LEVEL=%r; falling back to INFO", "NOTSET")

    def test_invalid_value_does_not_pollute_root_logger_handlers(self) -> None:
        """Regression test for the bug this round fixed: the bare
        ``logging.warning()`` convenience function implicitly calls
        ``logging.basicConfig()`` (installing a root handler) the first
        time it's invoked if the root logger has no handlers yet -- which
        would make the later, real ``logging.basicConfig(level=level)`` in
        ``configure_logging`` a no-op. Routing the fallback warning through
        the module-scoped ``_fallback_logger`` instead must not trigger that
        side effect, even with no patch around the warning call itself."""
        root = logging.getLogger()
        handlers_before = list(root.handlers)
        try:
            # Force the clean "no handlers" precondition this test actually
            # needs: under normal pytest ordering an earlier test may have
            # already installed a root handler (e.g. via configure_logging()
            # elsewhere in the session), which would make the bug this test
            # guards against invisible even if it regressed.
            root.handlers[:] = []
            with patch.dict("os.environ", {"LOG_LEVEL": "NOT_A_REAL_LEVEL"}):
                _resolve_log_level()
            assert root.handlers == []
        finally:
            root.handlers[:] = handlers_before

    def test_configure_logging_applies_debug_level_to_structlog(self) -> None:
        """LOG_LEVEL=DEBUG must reach structlog's filtering wrapper, not just
        stdlib logging.basicConfig (the bug this round fixed)."""
        try:
            with patch.dict("os.environ", {"LOG_LEVEL": "DEBUG"}):
                configure_logging()
            # ``structlog.get_logger()`` returns a lazy proxy; ``.bind()``
            # resolves it against the just-applied configuration so
            # ``is_enabled_for`` reflects the real filtering level.
            bound_logger = structlog.get_logger().bind()
            assert bound_logger.is_enabled_for(logging.DEBUG)
        finally:
            # Restore INFO so later tests (and the module-level default) are
            # not left running at DEBUG even if the assertion above fails --
            # structlog's configuration is process-global, not per-test.
            configure_logging()


class TestFallbackLoggerPaths:
    """Every ``log_*`` helper swallows its own failures — force the primary
    ``obs_log.info`` call to raise and assert the fallback path executes
    without the exception propagating to the caller."""

    def test_log_tool_call_fallback_does_not_raise(self) -> None:
        with patch.object(observability.obs_log, "info", side_effect=RuntimeError("boom")):
            with patch.object(observability._fallback_logger, "warning") as mock_warning:
                log_tool_call("some_tool", 12.3, True)
        mock_warning.assert_called_once()
        assert mock_warning.call_args.kwargs.get("exc_info") is True

    def test_log_user_active_fallback_does_not_raise(self) -> None:
        with patch.object(observability.obs_log, "info", side_effect=RuntimeError("boom")):
            with patch.object(observability._fallback_logger, "warning") as mock_warning:
                log_user_active("person@example.com")
        mock_warning.assert_called_once()
        assert mock_warning.call_args.kwargs.get("exc_info") is True

    def test_log_auth_flow_fallback_does_not_raise_and_uses_exc_info_true(self) -> None:
        """Regression test for this round's fix: ``log_auth_flow``'s fallback
        previously passed ``exc_info=False``, inconsistent with every other
        helper's fallback in this module."""
        with patch.object(observability.obs_log, "info", side_effect=RuntimeError("boom")):
            with patch.object(observability._fallback_logger, "warning") as mock_warning:
                log_auth_flow("new_auth")
        mock_warning.assert_called_once()
        assert mock_warning.call_args.kwargs.get("exc_info") is True

    def test_log_auth_rejected_fallback_does_not_raise(self) -> None:
        with patch.object(observability.obs_log, "info", side_effect=RuntimeError("boom")):
            with patch.object(observability._fallback_logger, "warning") as mock_warning:
                log_auth_rejected("sub_missing")
        mock_warning.assert_called_once()
        assert mock_warning.call_args.kwargs.get("exc_info") is True

    def test_log_scope_denial_fallback_does_not_raise(self) -> None:
        with patch.object(observability.obs_log, "info", side_effect=RuntimeError("boom")):
            with patch.object(observability._fallback_logger, "warning") as mock_warning:
                log_scope_denial(tool="comms_whoami", reason="missing_token", client_id="unknown")
        mock_warning.assert_called_once()
        assert mock_warning.call_args.kwargs.get("exc_info") is True


class TestLogAuthFlowEventTypes:
    """``Literal`` isn't enforced at runtime, and mypy alone doesn't confirm
    the actual emitted JSON field -- these pin every ``auth_type`` value
    (both the original two and the three added for the refresh-token
    rotation-grace port, auth.py) actually reaching ``obs_log.info`` with
    the exact literal, not a typo'd string."""

    def test_new_auth_reaches_obs_log(self) -> None:
        with patch.object(observability.obs_log, "info") as mock_info:
            log_auth_flow("new_auth")
        mock_info.assert_called_once_with("auth_flow", auth_type="new_auth")

    def test_token_refresh_reaches_obs_log(self) -> None:
        with patch.object(observability.obs_log, "info") as mock_info:
            log_auth_flow("token_refresh")
        mock_info.assert_called_once_with("auth_flow", auth_type="token_refresh")

    def test_refresh_token_grace_redirect_reaches_obs_log(self) -> None:
        with patch.object(observability.obs_log, "info") as mock_info:
            log_auth_flow("refresh_token_grace_redirect")
        mock_info.assert_called_once_with("auth_flow", auth_type="refresh_token_grace_redirect")

    def test_refresh_token_miss_reaches_obs_log(self) -> None:
        with patch.object(observability.obs_log, "info") as mock_info:
            log_auth_flow("refresh_token_miss")
        mock_info.assert_called_once_with("auth_flow", auth_type="refresh_token_miss")

    def test_refresh_token_hop_cap_exceeded_reaches_obs_log(self) -> None:
        """This value is deliberately distinct from refresh_token_miss --
        a rotation chain exceeding _ROTATION_MAX_HOPS is a different
        operational condition from a genuine miss and must not collapse
        into the same auth_type at the observability layer."""
        with patch.object(observability.obs_log, "info") as mock_info:
            log_auth_flow("refresh_token_hop_cap_exceeded")
        mock_info.assert_called_once_with("auth_flow", auth_type="refresh_token_hop_cap_exceeded")
