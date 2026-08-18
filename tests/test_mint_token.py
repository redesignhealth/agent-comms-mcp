"""Tests for mint_token.py's agent-jwt minting CLI.

Runs ``_cli()`` in-process against ``sys.argv`` (patched) and stdout/stderr
captures, mirroring how ``main.py``/``migrate.py``'s own ``_cli()`` entry
points are invoked in practice — no subprocess needed since there's no
long-running server to isolate. ``conftest.py``'s autouse ``_auth_env``
fixture already sets ``AGENT_JWT_SECRET`` to a test value, so the
"unset" case explicitly deletes it.
"""

from __future__ import annotations

import time

import jwt
import pytest

import mint_token
from identity import AGENT_JWT_ISSUER


def _run_cli(monkeypatch: pytest.MonkeyPatch, args: list[str]) -> None:
    monkeypatch.setattr("sys.argv", ["agent-comms-mcp-mint-token", *args])
    mint_token._cli()


class TestOwnerEmail:
    def test_happy_path_sets_owner_sub_claim(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _run_cli(
            monkeypatch,
            [
                "--sub",
                "ea-agent-svc",
                "--scopes",
                "comms:read,comms:write",
                "--owner-email",
                "alice@example.com",
            ],
        )
        out = capsys.readouterr()
        token = out.out.strip()
        assert "\n" not in token

        claims = jwt.decode(
            token,
            "test-agent-jwt-secret-long-enough-for-hs256",
            algorithms=["HS256"],
            issuer=AGENT_JWT_ISSUER,
        )
        assert claims["sub"] == "ea-agent-svc"
        assert claims["iss"] == AGENT_JWT_ISSUER
        assert sorted(claims["scopes"]) == ["comms:read", "comms:write"]
        assert claims["owner_sub"] == "alice@example.com"
        assert claims["exp"] > claims["iat"]


class TestSelfOwned:
    def test_happy_path_omits_owner_sub_claim(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _run_cli(
            monkeypatch,
            ["--sub", "notifier-bot", "--scopes", "comms:write", "--self-owned"],
        )
        token = capsys.readouterr().out.strip()

        claims = jwt.decode(
            token,
            "test-agent-jwt-secret-long-enough-for-hs256",
            algorithms=["HS256"],
            issuer=AGENT_JWT_ISSUER,
        )
        assert claims["sub"] == "notifier-bot"
        assert claims["scopes"] == ["comms:write"]
        assert "owner_sub" not in claims


class TestOwnerChoiceRequired:
    def test_missing_both_flags_fails(self, monkeypatch: pytest.MonkeyPatch) -> None:
        with pytest.raises(SystemExit):
            _run_cli(monkeypatch, ["--sub", "agent-x", "--scopes", "comms:read"])

    def test_both_flags_given_fails(self, monkeypatch: pytest.MonkeyPatch) -> None:
        with pytest.raises(SystemExit):
            _run_cli(
                monkeypatch,
                [
                    "--sub",
                    "agent-x",
                    "--scopes",
                    "comms:read",
                    "--owner-email",
                    "alice@example.com",
                    "--self-owned",
                ],
            )


class TestMalformedInput:
    def test_email_shaped_sub_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        with pytest.raises(SystemExit):
            _run_cli(
                monkeypatch,
                [
                    "--sub",
                    "alice@example.com",
                    "--scopes",
                    "comms:read",
                    "--self-owned",
                ],
            )

    def test_malformed_owner_email_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        with pytest.raises(SystemExit):
            _run_cli(
                monkeypatch,
                [
                    "--sub",
                    "agent-x",
                    "--scopes",
                    "comms:read",
                    "--owner-email",
                    "not-an-email",
                ],
            )

    def test_unknown_scope_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        with pytest.raises(SystemExit):
            _run_cli(
                monkeypatch,
                ["--sub", "agent-x", "--scopes", "not:a:real:scope", "--self-owned"],
            )

    @pytest.mark.parametrize(
        "expires", [0, -1, mint_token._MAX_EXPIRES_SECONDS + 1]
    )
    def test_out_of_bounds_expires_rejected(
        self, monkeypatch: pytest.MonkeyPatch, expires: int
    ) -> None:
        with pytest.raises(SystemExit):
            _run_cli(
                monkeypatch,
                [
                    "--sub",
                    "agent-x",
                    "--scopes",
                    "comms:read",
                    "--self-owned",
                    "--expires",
                    str(expires),
                ],
            )

    def test_max_expires_is_accepted(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        before = int(time.time())
        _run_cli(
            monkeypatch,
            [
                "--sub",
                "agent-x",
                "--scopes",
                "comms:read",
                "--self-owned",
                "--expires",
                str(mint_token._MAX_EXPIRES_SECONDS),
            ],
        )
        token = capsys.readouterr().out.strip()
        claims = jwt.decode(
            token,
            "test-agent-jwt-secret-long-enough-for-hs256",
            algorithms=["HS256"],
            issuer=AGENT_JWT_ISSUER,
        )
        assert claims["exp"] - before == pytest.approx(mint_token._MAX_EXPIRES_SECONDS, abs=5)


class TestMissingSecret:
    def test_agent_jwt_secret_unset_fails_fast(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("AGENT_JWT_SECRET", raising=False)
        with pytest.raises(RuntimeError, match="AGENT_JWT_SECRET"):
            _run_cli(
                monkeypatch,
                ["--sub", "agent-x", "--scopes", "comms:read", "--self-owned"],
            )


def test_default_expiry_is_ninety_days(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    before = int(time.time())
    _run_cli(monkeypatch, ["--sub", "agent-x", "--scopes", "comms:read", "--self-owned"])
    token = capsys.readouterr().out.strip()
    claims = jwt.decode(
        token,
        "test-agent-jwt-secret-long-enough-for-hs256",
        algorithms=["HS256"],
        issuer=AGENT_JWT_ISSUER,
    )
    assert claims["exp"] - before == pytest.approx(90 * 24 * 60 * 60, abs=5)
