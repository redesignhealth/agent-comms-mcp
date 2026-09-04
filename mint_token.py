"""CLI to mint agent-jwt Bearer tokens for agent-comms-mcp.

Mints exactly the claim shape ``auth.py``/``identity.py``/``scopes.py`` read
today: ``sub``, ``iss``, ``iat``, ``exp``, ``scopes``, and (optionally)
``owner_sub``. No arbitrary extra claims — this is a minting tool for THIS
service's own token format, not a generic JWT-crafting utility.

The owner-identity choice (``--owner-email`` vs ``--self-owned``) is
mandatory and mutually exclusive: skipping it is exactly how an agent that's
supposed to be human-owned silently becomes self-owned instead (see
``providers.comms.register``'s ``owner_sub`` fallback), which later makes
anything requiring that human's approval unsatisfiable until re-minted with
the correct owner. Forcing an explicit choice here catches the mistake at
mint time instead.

Prints ONLY the token to stdout (so this composes in shell pipelines); a
human-readable confirmation goes to stderr.
"""

from __future__ import annotations

import argparse
import sys
import time
from typing import NoReturn

import jwt

from auth import require_env
from identity import AGENT_JWT_ISSUER, validate_sub_shape
from scopes import PROPOSAL_SUBMIT_SCOPE, TOOL_SCOPES

# Matches DESIGN.md's MAX_CONVERSATION_TTL ceiling (ninety days) — no other
# token-lifetime precedent exists in this repo, and reusing that number
# keeps this service's two "how long is too long" defaults aligned.
_DEFAULT_EXPIRES_SECONDS = 90 * 24 * 60 * 60

# Same ceiling as the default: a longer-lived token than the default is a
# deliberate choice a caller can still make, but there is no legitimate use
# case for a token that outlives this service's own longest-lived state.
_MAX_EXPIRES_SECONDS = 90 * 24 * 60 * 60

# comms:admin gates providers.comms.set_agent_shared/deregister_agent/
# admin_register directly (see scopes.py) but never appears as a
# TOOL_SCOPES value since it isn't itself a per-tool requirement — union it
# in explicitly so it remains mintable.
# PROPOSAL_SUBMIT_SCOPE (comms:proposals:write) is the same story for the
# non-MCP `POST /proposals` route (TECH-5872): it self-checks this scope
# directly rather than going through TOOL_SCOPES/ScopeEnforcementMiddleware
# (see scopes.py's own docstring), so it likewise never appears as a
# TOOL_SCOPES value. Without unioning it in here too (Argus review B3), no
# token minted by this CLI could ever legitimately carry it --
# `_validate_scopes` would reject every `--scopes comms:proposals:write`
# request, making the route permanently unreachable by any agent.
_VALID_SCOPES = set(TOOL_SCOPES.values()) | {"comms:admin", PROPOSAL_SUBMIT_SCOPE}


def _parse_scopes(raw: str) -> list[str]:
    """Split on commas or whitespace — either reads naturally on a CLI."""
    return [s for s in raw.replace(",", " ").split() if s]


def _validate_scopes(scopes: list[str]) -> list[str]:
    unknown = [s for s in scopes if s not in _VALID_SCOPES]
    if unknown:
        raise ValueError(
            f"unknown scope(s) {unknown!r}: valid scopes are {sorted(_VALID_SCOPES)!r}"
        )
    return scopes


def _validate_sub(sub: str) -> str:
    """Reject a ``--sub`` that ``identity.validate_sub_shape`` would reject.

    Reuses that function directly (rather than replicating the check) so
    the two stay in sync by construction.
    """
    validate_sub_shape({"sub": sub})
    return sub


def _validate_owner_email(email: str) -> str:
    """Simple email shape check: exactly one ``@`` with non-empty sides.

    Deliberately not an RFC 5322 validator — this only needs to catch the
    "forgot the @" mistake, not police every edge case of email syntax.
    """
    local, sep, domain = email.partition("@")
    if not sep or not local or not domain:
        raise ValueError(f"--owner-email must be email-shaped (got {email!r})")
    return email


def _die(parser: argparse.ArgumentParser, message: str) -> NoReturn:
    parser.error(message)
    raise SystemExit(2)  # pragma: no cover - argparse.error already exits


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="agent-comms-mcp-mint-token",
        description="Mint an agent-jwt Bearer token for agent-comms-mcp.",
    )
    parser.add_argument("--sub", required=True, help="The agent's own identity string.")
    parser.add_argument(
        "--scopes",
        required=True,
        help="Space- or comma-separated agent-jwt scopes (see scopes.py's TOOL_SCOPES).",
    )
    parser.add_argument(
        "--expires",
        type=int,
        default=_DEFAULT_EXPIRES_SECONDS,
        help=(
            f"Token lifetime in seconds (default: {_DEFAULT_EXPIRES_SECONDS}, i.e. 90 "
            f"days; must be > 0 and <= {_MAX_EXPIRES_SECONDS})."
        ),
    )
    parser.add_argument(
        "--owner-email",
        help="The human owner's email — sets the token's owner_sub claim.",
    )
    parser.add_argument(
        "--self-owned",
        action="store_true",
        help="Explicitly acknowledge this agent has no human owner (self-owned fallback).",
    )
    return parser


def _cli() -> None:
    """Entry point for the ``agent-comms-mcp-mint-token`` console script."""
    parser = _build_parser()
    args = parser.parse_args()

    if bool(args.owner_email) == bool(args.self_owned):
        _die(
            parser,
            "exactly one of --owner-email or --self-owned is required: "
            "an agent-jwt token's human-owner identity must be a conscious "
            "choice, not a silent default.",
        )

    try:
        sub = _validate_sub(args.sub)
    except Exception as exc:
        _die(parser, f"invalid --sub: {exc}")

    if not (0 < args.expires <= _MAX_EXPIRES_SECONDS):
        _die(
            parser,
            f"invalid --expires {args.expires!r}: must be > 0 and <= "
            f"{_MAX_EXPIRES_SECONDS} seconds",
        )

    owner_email = None
    if args.owner_email:
        try:
            owner_email = _validate_owner_email(args.owner_email)
        except ValueError as exc:
            _die(parser, str(exc))

    try:
        scopes = _validate_scopes(_parse_scopes(args.scopes))
    except ValueError as exc:
        _die(parser, f"invalid --scopes: {exc}")
    secret = require_env("AGENT_JWT_SECRET")

    now = int(time.time())
    claims: dict[str, object] = {
        "sub": sub,
        "iss": AGENT_JWT_ISSUER,
        "iat": now,
        "exp": now + args.expires,
        "scopes": scopes,
    }
    if owner_email is not None:
        claims["owner_sub"] = owner_email

    token = jwt.encode(claims, secret, algorithm="HS256")
    print(token)

    print(
        f"minted agent-jwt token: sub={sub!r} scopes={scopes} "
        f"owner={'self' if args.self_owned else owner_email} "
        f"expires_in={args.expires}s",
        file=sys.stderr,
    )


if __name__ == "__main__":
    _cli()
