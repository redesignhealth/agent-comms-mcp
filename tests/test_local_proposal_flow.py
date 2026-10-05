"""TECH-7163 minimum local proof: one focused end-to-end board+approvals flow.

What is REAL here (no module-import hacks, no production code changes):

- The board's PERSISTED ``proposal_holds`` pipeline (``service.create_proposal``
  / ``service.decide_proposal`` / dedup / rate limit / the claim-apply state
  machine) on a runner-created uniquely-named ephemeral Postgres container on a
  dynamically assigned loopback port, driven through the real HTTP routes
  (``main.py``'s ``POST /proposals``, ``GET /proposals/{id}``,
  ``GET /proposals/pending``, ``POST /proposals/{hold_id}/decide``).
- The REAL ``RHProposalJudge`` from the local ``agent-comms-approvals``
  checkout (editable-installed into this venv, matching
  ``Dockerfile.board-derived``'s install of that dist into the board image),
  resolved through the board's own ``PROPOSAL_JUDGE`` seam machinery using the
  exact import-path env var the derived board image is configured with, and
  automatically wrapped in the real ``HttpApplyProposalJudge``.
- The real board-side HTTP clients: ``arcana_read_http_client`` (judgment
  reads) and ``proposal_apply_http_client`` (the apply write), each wired to
  the REAL approvals action API (``proposal_action_api.app`` FastAPI app,
  including its rh-auth scope gates and its ``proposal_apply_attempts``
  SQLite idempotency table) over a controlled ``httpx.ASGITransport`` --
  the same no-network stand-in ``agent-comms-approvals``' own local flow
  tests use for this exact app.
- Synthetic LOCAL test JWTs only: bot callers are real HS256 agent-jwt tokens
  (the exact ``mint_token`` claim shape) verified by the REAL verifier chain
  built at ``main`` import; the trusted-service scopes (``proposals:arcana_read``
  / ``proposals:apply``) are real ``rh_auth.issue_token`` service tokens
  verified by the approvals app's real ``require_scope`` gate.

What is FAKE here (deliberately, and only on the approvals side of the seam):

- ``FakeBrainResolver`` / ``FakeArcanaClient`` -- injected ONLY into this
  test-owned approvals app instance (the same in-memory doubles
  ``agent-comms-approvals`` ships for exactly this purpose). No live Arcana,
  no live Linear, no network beyond the in-process ASGI transport, and no
  credentials beyond the synthetic local secrets above.
- The Okta leg of the board's auth (``main._okta_provider``) uses the
  established fake-interactive-provider pattern from
  ``tests/test_proposal_endpoint.py`` -- the REAL interactive-only gate code
  in ``main._authenticate_approval_caller`` runs against it; only the external
  Okta round-trip is stood in for, since no local Okta exists.

Environment prerequisites (isolated; nothing here touches an ambient
``DATABASE_URL`` or any hosted DB): runner creates and tears down its own
ephemeral Postgres container on a dynamic loopback port with unique DB and
credentials; and the editable installs described in this worktree's branch
description -- ``uv pip install -e <approvals checkout> --no-deps`` plus
``-e <rh-auth checkout> --no-deps`` on top of the board's own locked env.

Run this module in its own pytest invocation, separate from
``tests/test_proposal_apply_http_client.py``'s zero-Linear-reachability test:
this module deliberately hosts the APPROVALS SERVICE side in-process
(``proposal_action_api.app`` imports the credential-bearing
``rh_comms_plugins.linear_client``/``proposal_apply_service``), so that
board-process-only ``sys.modules`` absence assertion cannot coexist with this
module in one shared pytest session. The board side of this flow still imports
none of those modules.
"""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import os
import subprocess
import sys
import time
import uuid
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import asyncpg
import httpx
import jwt as pyjwt
import pytest

# Explicit opt-in gate BEFORE ANY optional/private imports:
# Normal CI does not have the private agent-comms-approvals package installed
# and has ambient DATABASE_URL set; skipping here prevents collection failures
# and avoids running ephemeral container / refusal logic in normal CI.
if os.environ.get("RUN_LOCAL_ARCANA_PROPOSAL_FLOW") != "1":
    pytest.skip(
        "Local Arcana proposal flow tests require RUN_LOCAL_ARCANA_PROPOSAL_FLOW=1",
        allow_module_level=True,
    )

import pytest_asyncio
import rh_auth
import sqlalchemy as sa
from ownership_api.db import Base, get_db
from proposal_action_api.app import app as approvals_app
from proposal_action_api.models import ProposalApplyAttempt
from rh_comms_plugins import arcana_client, arcana_read_http_client
from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
)
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from starlette.applications import Starlette
from starlette.routing import Route

import plugins
import proposal_apply_http_client
from identity import AGENT_JWT_ISSUER
from models import ProposalHold

# Real-Postgres fixtures (engine/session) are shared via tests/conftest.py;
# this module opts in to the migrated schema explicitly and TRUNCATEs between
# tests, mirroring tests/test_proposal_endpoint.py's conventions.
pytestmark = pytest.mark.usefixtures("_migrated_schema")

# Synthetic local secrets (never a real credential).
TEST_RH_AUTH_SECRET = "local-flow-test-secret-that-is-at-least-32-bytes-long"
AGENT_JWT_SECRET_VALUE = "local-flow-test-agent-jwt-secret-0123456789abcdef"


@dataclasses.dataclass(frozen=True)
class EphemeralPostgres:
    container_id: str
    container_name: str
    host_port: int
    db_name: str
    user: str
    password: str
    url: str

    @property
    def async_url(self) -> str:
        return self.url.replace("postgresql://", "postgresql+asyncpg://", 1)


def _refuse_externally_supplied_database_target(candidate: str | None = None) -> None:
    """Test setup refuses externally supplied target before connections."""
    target = candidate if candidate is not None else os.environ.get("DATABASE_URL")
    if target:
        raise RuntimeError(
            "Harness safety: externally supplied database target is refused; "
            "test runner must own its ephemeral container."
        )


def _start_ephemeral_postgres() -> EphemeralPostgres:
    _refuse_externally_supplied_database_target()

    uid = uuid.uuid4().hex[:12]
    container_name = f"flow-test-pg-{uid}"
    db_name = f"flow_db_{uid}"
    user = f"u_{uid[:8]}"
    password = f"p_{uid}_{uuid.uuid4().hex[:8]}"

    cmd = [
        "docker",
        "run",
        "-d",
        "--name",
        container_name,
        "-e",
        f"POSTGRES_USER={user}",
        "-e",
        f"POSTGRES_PASSWORD={password}",
        "-e",
        f"POSTGRES_DB={db_name}",
        "-p",
        "127.0.0.1::5432",
        "postgres:16.6",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
    container_id = proc.stdout.strip()

    try:
        port_proc = subprocess.run(
            ["docker", "port", container_id, "5432/tcp"],
            capture_output=True,
            text=True,
            check=True,
        )
        host_port = int(port_proc.stdout.strip().split(":")[-1])
        raw_url = f"postgresql://{user}:{password}@127.0.0.1:{host_port}/{db_name}"

        async def _wait_ready() -> bool:
            for _ in range(100):
                try:
                    conn = await asyncpg.connect(
                        host="127.0.0.1",
                        port=host_port,
                        user=user,
                        password=password,
                        database=db_name,
                        timeout=1,
                    )
                    await conn.execute("SELECT 1")
                    await conn.close()
                    return True
                except Exception:
                    await asyncio.sleep(0.1)
            return False

        if not asyncio.run(_wait_ready()):
            raise RuntimeError(
                f"Ephemeral Postgres container {container_id} failed to become ready"
            )

        return EphemeralPostgres(
            container_id=container_id,
            container_name=container_name,
            host_port=host_port,
            db_name=db_name,
            user=user,
            password=password,
            url=raw_url,
        )
    except Exception:
        subprocess.run(["docker", "rm", "-f", container_id], capture_output=True, check=False)
        raise


def _stop_ephemeral_postgres(pg: EphemeralPostgres) -> None:
    subprocess.run(["docker", "rm", "-f", pg.container_id], capture_output=True, check=False)


# The exact Terraform env-var wiring the derived board image uses for the
# PROPOSAL_JUDGE seam (see agent-comms-approvals' proposal_judge.py header).
_PROPOSAL_JUDGE_WIRING = "rh_comms_plugins.proposal_judge:build_rh_proposal_judge"

# The approvals action API's base URL, as the board-side HTTP clients see it
# in production (the deployment mounts the app under a path prefix; over the
# controlled ASGI transport the app is served at its own root, exactly as
# agent-comms-approvals' own local flow tests wire it).
_APPROVALS_BASE_URL = "https://approvals.test"

# Two synthetic bots with isolated brains and pre-seeded evidence documents.
EVIDENCE_A = "Alpha ☕ beta gamma"  # '☕' is one character, three UTF-8 bytes
EVIDENCE_B = "Beta evidence text"
_BOT_A = "bot-a"
_BOT_B = "bot-b"
_BRAIN_A = "brain-a"
_BRAIN_B = "brain-b"
_OWNER_A = "owner-a@example.com"
_OWNER_B = "owner-b@example.com"


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@pytest.fixture(scope="module")
def database_url() -> Iterator[str]:
    """Runner-created uniquely named ephemeral Postgres container on dynamic loopback port.

    Captures container ID and port, refuses ambient DATABASE_URL or externally supplied DB,
    and on teardown destroys ONLY this container.
    """
    _refuse_externally_supplied_database_target()
    pg = _start_ephemeral_postgres()
    old_env = os.environ.get("DATABASE_URL")
    os.environ["DATABASE_URL"] = pg.url
    try:
        yield pg.async_url
    finally:
        if old_env is None:
            os.environ.pop("DATABASE_URL", None)
        else:
            os.environ["DATABASE_URL"] = old_env
        _stop_ephemeral_postgres(pg)


@pytest_asyncio.fixture(autouse=True)
async def _clean_tables(engine: AsyncEngine) -> AsyncIterator[None]:
    async with engine.begin() as conn:
        await conn.execute(
            sa.text("TRUNCATE TABLE proposal_holds, audit_log, agents RESTART IDENTITY CASCADE")
        )
    yield


@pytest.fixture
def test_session_factory(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


# --- approvals side: real action API + its own SQLite attempt table ---------


@pytest.fixture
def approvals_sqlite() -> Iterator[sa.Engine]:
    """The approvals action API's OWN database for this module: an in-memory
    SQLite engine holding the real ``proposal_apply_attempts`` idempotency
    table (the same shape agent-comms-approvals' own action-API tests use --
    production uses that service's own Postgres, which no board test may
    touch)."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)

    def _override() -> Iterator[Session]:
        session = sessionmaker(bind=engine, autoflush=False, autocommit=False)()
        try:
            yield session
        finally:
            session.close()

    approvals_app.dependency_overrides[get_db] = _override
    try:
        yield engine
    finally:
        approvals_app.dependency_overrides.clear()
        engine.dispose()


# --- the real judge + the real HTTP clients, wired to the real action API ---


def _asgi_read_client_builder(timeout: float, sni: str | None) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=approvals_app), timeout=timeout)


def _asgi_apply_client_builder(timeout_seconds: float, tls_sni: str | None) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=approvals_app),
        timeout=httpx.Timeout(timeout_seconds),
    )


@pytest.fixture(autouse=True)
def _rh_auth_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RH_AUTH_SECRET", TEST_RH_AUTH_SECRET)


@pytest.fixture(autouse=True)
def _real_judge_wiring(_rh_auth_secret: None, monkeypatch: pytest.MonkeyPatch) -> None:
    """Resolve the REAL judge through the board's own seam machinery.

    ``PROPOSAL_JUDGE`` is set to the exact import-path wiring the derived
    board image's Terraform uses, so ``plugins.get_proposal_judge()`` resolves
    the real ``RHProposalJudge`` from the editable-installed local approvals
    checkout and wraps it in the real ``HttpApplyProposalJudge`` -- the apply
    write never touches the deprecated in-process shim. Both HTTP clients dial
    the real approvals action API over a controlled ASGI transport (the
    documented test seam of each client's ``_build_*_client`` builder), with
    real rh-auth service tokens carrying the trusted-service scopes."""
    monkeypatch.setenv(plugins.PROPOSAL_JUDGE_ENV_VAR, _PROPOSAL_JUDGE_WIRING)
    # Force fresh resolution per test through the real registry/import path.
    monkeypatch.setattr(plugins, "_proposal_judge", None, raising=False)
    monkeypatch.setenv(arcana_read_http_client.PROPOSAL_READ_URL_ENV_VAR, _APPROVALS_BASE_URL)
    monkeypatch.setenv(
        arcana_read_http_client.PROPOSAL_READ_TOKEN_ENV_VAR,
        rh_auth.issue_token("board-local-flow", ["proposals:arcana_read"]),
    )
    monkeypatch.delenv(arcana_read_http_client.PROPOSAL_READ_TLS_SNI_HOST_ENV_VAR, raising=False)
    monkeypatch.delenv(arcana_read_http_client.PROPOSAL_READ_TIMEOUT_SECONDS_ENV_VAR, raising=False)
    monkeypatch.setattr(arcana_read_http_client, "_build_read_client", _asgi_read_client_builder)
    monkeypatch.setenv(proposal_apply_http_client.PROPOSAL_APPLY_URL_ENV_VAR, _APPROVALS_BASE_URL)
    monkeypatch.setenv(
        proposal_apply_http_client.PROPOSAL_APPLY_TOKEN_ENV_VAR,
        rh_auth.issue_token("board-local-flow", ["proposals:apply"]),
    )
    monkeypatch.setenv(
        proposal_apply_http_client.PROPOSAL_APPLY_RETRY_BACKOFF_SECONDS_ENV_VAR, "0.01"
    )
    monkeypatch.delenv(
        proposal_apply_http_client.PROPOSAL_APPLY_TLS_SNI_HOST_ENV_VAR, raising=False
    )
    monkeypatch.setattr(
        proposal_apply_http_client, "_build_apply_client", _asgi_apply_client_builder
    )


@dataclasses.dataclass
class World:
    """Everything the approvals side of this flow owns for one test."""

    resolver: arcana_client.FakeBrainResolver
    backend: arcana_client.FakeArcanaClient
    approvals_engine: sa.Engine
    readback: httpx.AsyncClient
    read_token: str


@pytest_asyncio.fixture
async def world(
    approvals_sqlite: sa.Engine,
    _real_judge_wiring: None,
) -> AsyncIterator[World]:
    """Two synthetic bots, isolated brains, pre-seeded evidence; FakeBrainResolver/
    FakeArcanaClient injected ONLY into this test-owned approvals app instance."""
    arcana_client.reset_arcana_for_tests()
    resolver = arcana_client.FakeBrainResolver()
    resolver.register_principal(_BOT_A, _BRAIN_A, company_id="co-a")
    resolver.register_principal(_BOT_B, _BRAIN_B, company_id="co-b")
    backend = arcana_client.FakeArcanaClient()
    backend.brain_owners.update({_BRAIN_A: _BOT_A, _BRAIN_B: _BOT_B})
    backend.add_source(
        _BRAIN_A, "evidence-a", content=EVIDENCE_A, revision_id="rev-ev-a", owner_bot_id=_BOT_A
    )
    backend.add_source(
        _BRAIN_B, "evidence-b", content=EVIDENCE_B, revision_id="rev-ev-b", owner_bot_id=_BOT_B
    )
    arcana_client.set_brain_resolver(resolver)
    arcana_client.set_arcana_client(backend)
    read_token = rh_auth.issue_token("board-local-flow", ["proposals:arcana_read"])
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=approvals_app), base_url=_APPROVALS_BASE_URL
    ) as readback:
        yield World(
            resolver=resolver,
            backend=backend,
            approvals_engine=approvals_sqlite,
            readback=readback,
            read_token=read_token,
        )
    arcana_client.reset_arcana_for_tests()


# --- board side: real routes, real gates, synthetic local tokens -------------

_MOCK_OIDC_CONFIG = MagicMock()
_OIDC_PATCH = patch(
    "fastmcp.server.auth.oidc_proxy.OIDCProxy.get_oidc_configuration",
    return_value=_MOCK_OIDC_CONFIG,
)
_ENV_PATCH = patch.dict(
    os.environ,
    {
        "OKTA_ISSUER_URL": "https://example.okta.com/oauth2/default",
        "OKTA_CLIENT_ID": "test-id",
        "OKTA_CLIENT_SECRET": "test-secret",
        "BASE_URL": "http://localhost:8080",
        "MCP_JWT_SECRET": "test-jwt-secret",
        "AGENT_JWT_SECRET": AGENT_JWT_SECRET_VALUE,
    },
)


def _import_main() -> Any:
    sys.modules.pop("main", None)
    with _OIDC_PATCH, _ENV_PATCH:
        import main

        return main


class _FakeAccessToken:
    def __init__(self, claims: dict[str, Any]) -> None:
        self.claims = claims


class _FakeInteractiveOnlyProvider:
    """The established human-actor stand-in from tests/test_proposal_endpoint.py:
    the REAL interactive-only gate code in ``main._authenticate_approval_caller``
    runs against this; only the external Okta round-trip is faked."""

    def __init__(self, outer: _FakeAuthProvider) -> None:
        self._outer = outer

    async def verify_token(self, token: str) -> _FakeAccessToken | None:
        found = self._outer.tokens.get(token)
        if found is None or found.claims.get("iss") == AGENT_JWT_ISSUER:
            return None
        return found


class _FakeAuthProvider:
    """The endpoint-test fake-provider pattern, inverted: only the Okta leg is
    faked. The agent-verifier chain is the REAL one built at ``main`` import
    (``agent_jwt_hs256`` keyed to the synthetic AGENT_JWT_SECRET), so bot
    callers are real HS256 agent-jwt tokens verified by the real verifier --
    synthetic local JWTs, no live token anywhere."""

    def __init__(self, agent_verifiers: list[Any]) -> None:
        self.tokens: dict[str, _FakeAccessToken] = {}
        self._agent_verifiers = list(agent_verifiers)
        self.server = _FakeInteractiveOnlyProvider(self)

    @property
    def verifiers(self) -> list[Any]:
        return self._agent_verifiers

    async def verify_token(self, token: str) -> _FakeAccessToken | None:
        for verifier in self._agent_verifiers:
            try:
                result = await verifier.verify_token(token)
            except Exception:
                continue
            if result is not None:
                return result
        return self.tokens.get(token)


def _mint_agent_jwt(sub: str, owner_sub: str) -> str:
    """A synthetic local agent-jwt with mint_token.py's exact claim shape."""
    now = int(time.time())
    return pyjwt.encode(
        {
            "sub": sub,
            "iss": AGENT_JWT_ISSUER,
            "iat": now,
            "exp": now + 3600,
            "scopes": ["comms:proposals:write"],
            "owner_sub": owner_sub,
        },
        AGENT_JWT_SECRET_VALUE,
        algorithm="HS256",
    )


@pytest.fixture
def main() -> Any:
    return _import_main()


@pytest_asyncio.fixture
async def client(
    main: Any,
    test_session_factory: async_sessionmaker[AsyncSession],
    world: World,
) -> AsyncIterator[tuple[httpx.AsyncClient, _FakeAuthProvider]]:
    real_agent_verifiers = list(main._auth_provider.verifiers)
    fake_provider = _FakeAuthProvider(real_agent_verifiers)
    fake_provider.tokens["human-a"] = _FakeAccessToken(
        {"iss": "https://agent-comms.example/mcp", "email": _OWNER_A}
    )
    fake_provider.tokens["human-b"] = _FakeAccessToken(
        {"iss": "https://agent-comms.example/mcp", "email": _OWNER_B}
    )
    app = Starlette(
        routes=[
            Route("/proposals", main.submit_proposal, methods=["POST"]),
            Route("/proposals/pending", main.list_pending_proposals, methods=["GET"]),
            Route("/proposals/history", main.list_proposal_history, methods=["GET"]),
            Route("/proposals/{proposal_id}", main.get_proposal, methods=["GET"]),
            Route(
                "/proposals/{proposal_id}/withdraw",
                main.withdraw_proposal_route,
                methods=["POST"],
            ),
            Route("/proposals/{hold_id}/decide", main.decide_proposal_route, methods=["POST"]),
        ]
    )
    with (
        _OIDC_PATCH,
        _ENV_PATCH,
        patch.object(main, "_auth_provider", fake_provider),
        patch.object(main, "_okta_provider", fake_provider.server),
        patch("main.get_session_factory", return_value=test_session_factory),
    ):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://board.test"
        ) as http_client:
            yield http_client, fake_provider


# --- arcana action payload builders (strict TECH-7163 shapes) ---------------


def _citation(revision_id: str, offset: int, length: int, quote: str) -> dict[str, Any]:
    return {
        "revision_id": revision_id,
        "offset": offset,
        "length": length,
        "quote": quote,
    }


def _add_action(
    logical_id: str,
    *,
    content: str = "Fact: the sky is blue on clear days.",
    audience: str = "private",
    citations: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "action_type": "source_add",
        "logical_id": logical_id,
        "filename": "doc.md",
        "content": content,
        "sha256": _sha(content),
        "target_id": f"arcana-source:{logical_id}",
        "audience": audience,
        "citations": [] if citations is None else citations,
    }


def _revise_action(
    logical_id: str,
    supersedes: str,
    *,
    content: str = "Revised: the sky is blue.",
    audience: str = "private",
    citations: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    action = _add_action(logical_id, content=content, audience=audience, citations=citations)
    action["action_type"] = "source_revise"
    action["supersedes_revision"] = supersedes
    return action


def _proposal_body(action: dict[str, Any]) -> dict[str, Any]:
    kind = (
        "arcana_source_revise" if action["action_type"] == "source_revise" else "arcana_source_add"
    )
    return {
        "kind": kind,
        "action": action,
        "rationale": "local flow proof",
        "confidence": "medium",
        "importance": "medium",
        "impact": "medium",
    }


# --- flow helpers -------------------------------------------------------------


async def _submit(
    http_client: httpx.AsyncClient, bot_jwt: str, action: dict[str, Any]
) -> httpx.Response:
    return await http_client.post(
        "/proposals",
        json=_proposal_body(action),
        headers={"Authorization": f"Bearer {bot_jwt}"},
    )


async def _decide(
    http_client: httpx.AsyncClient,
    human_token: str,
    proposal_id: str,
    decision: str = "approve",
    decision_note: str | None = "human reviewed",
) -> httpx.Response:
    return await http_client.post(
        f"/proposals/{proposal_id}/decide",
        json={"decision": decision, "decision_note": decision_note},
        headers={"Authorization": f"Bearer {human_token}"},
    )


async def _arcana_readback(world: World, bot_id: str, logical_id: str) -> dict[str, Any]:
    """Read back the authoritative source state through the board-safe
    by-bot read endpoint of the real approvals action API."""
    resp = await world.readback.post(
        f"{_APPROVALS_BASE_URL}/proposals/arcana/source-metadata-by-bot",
        json={"bot_id": bot_id, "logical_id": logical_id},
        headers={"Authorization": f"Bearer {world.read_token}"},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


async def _hold_row(
    test_session_factory: async_sessionmaker[AsyncSession], proposal_id: str
) -> ProposalHold:
    """Read one hold row through a FRESH session so the assertion always
    observes the latest committed state (a long-lived session's ORM identity
    map would keep serving the first version it ever loaded)."""
    async with test_session_factory() as sess:
        row = await sess.get(ProposalHold, uuid.UUID(proposal_id))
    assert row is not None
    return row


async def _hold_count(test_session_factory: async_sessionmaker[AsyncSession]) -> int:
    async with test_session_factory() as sess:
        result = await sess.execute(sa.text("SELECT count(*) FROM proposal_holds"))
        return result.scalar_one()


def _attempt_rows(world: World) -> list[Any]:
    with world.approvals_engine.connect() as conn:
        return list(
            conn.execute(
                sa.text(
                    "SELECT hold_id, request_digest, outcome, applied FROM proposal_apply_attempts"
                )
            )
        )


def _attempt_outcome(world: World, proposal_id: str) -> dict[str, Any] | None:
    """The recorded apply outcome for one hold, via the approvals action API's
    own ORM model (raw sqlite SQL would hand back the JSON column as text)."""
    with sessionmaker(bind=world.approvals_engine)() as sess:
        row = sess.get(ProposalApplyAttempt, uuid.UUID(proposal_id))
        return row.outcome if row is not None else None


def _revisions(world: World, brain_id: str, logical_id: str) -> int:
    return len(world.backend._sources.get((brain_id, logical_id), []))


class TestLocalProposalFlow:
    async def test_eligible_private_add_auto_judged_applied_persisted_and_read_back(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        world: World,
        test_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        http_client, _provider = client
        bot_a = _mint_agent_jwt(_BOT_A, _OWNER_A)
        action = _add_action(
            "doc-a",
            citations=[_citation("rev-ev-a", 6, 1, "☕")],
        )

        resp = await _submit(http_client, bot_a, action)
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["status"] == "applied"
        assert body["decision_source"] == "auto"
        assert body["priority"] == "medium"
        revision_id = body["apply_result"]["revision_id"]

        # Persisted "applied" in the real board Postgres, not just the response.
        row = await _hold_row(test_session_factory, body["proposal_id"])
        assert row.status == "applied"
        assert row.proposed_by_bot_id == _BOT_A
        assert row.owner_sub == _OWNER_A

        # The write landed exactly once in the bot's own authoritative brain...
        assert _revisions(world, _BRAIN_A, "doc-a") == 1
        # ...and the board-safe read seam confirms it for the submitting bot.
        meta = await _arcana_readback(world, _BOT_A, "doc-a")
        assert meta["exists"] is True
        assert meta["owner_bot_id"] == _BOT_A
        assert meta["sha256"] == _sha(action["content"])
        assert meta["revision_id"] == revision_id

        # Bot readback through the board's own API.
        poll = await http_client.get(
            f"/proposals/{body['proposal_id']}",
            headers={"Authorization": f"Bearer {bot_a}"},
        )
        assert poll.status_code == 200
        assert poll.json()["status"] == "applied"

    @pytest.mark.parametrize(
        ("disqualifier", "mutate"),
        [
            ("first-document-empty-citations", {"citations": []}),
            ("shared-audience", {"audience": "shared"}),
        ],
    )
    async def test_non_auto_qualifiable_proposal_pends_then_human_decide_applies(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        world: World,
        test_session_factory: async_sessionmaker[AsyncSession],
        disqualifier: str,
        mutate: dict[str, Any],
    ) -> None:
        http_client, _provider = client
        bot_a = _mint_agent_jwt(_BOT_A, _OWNER_A)
        action = _add_action("doc-held", citations=[_citation("rev-ev-a", 6, 1, "☕")])
        action.update(mutate)

        resp = await _submit(http_client, bot_a, action)
        assert resp.status_code == 200, resp.text
        proposal_id = resp.json()["proposal_id"]
        assert resp.json()["status"] == "pending"
        # Nothing was written pre-approval.
        assert _revisions(world, _BRAIN_A, "doc-held") == 0

        # Persisted "pending" for the owner, visible on the real pending list.
        row = await _hold_row(test_session_factory, proposal_id)
        assert row.status == "pending"
        pending = await http_client.get(
            "/proposals/pending", headers={"Authorization": "Bearer human-a"}
        )
        assert pending.status_code == 200
        assert [p["proposal_id"] for p in pending.json()["proposals"]] == [proposal_id]

        # A bot can never reach the decide route at all (structural 403).
        bot_decide = await _decide(http_client, bot_a, proposal_id)
        assert bot_decide.status_code == 403

        # The authorized human approves via the actual board decide API.
        decide = await _decide(http_client, "human-a", proposal_id)
        assert decide.status_code == 200, decide.text
        assert decide.json()["status"] == "applied"
        assert decide.json()["decision_source"] == "human"

        row = await _hold_row(test_session_factory, proposal_id)
        assert row.status == "applied"
        assert _revisions(world, _BRAIN_A, "doc-held") == 1
        meta = await _arcana_readback(world, _BOT_A, "doc-held")
        assert meta["revision_id"] == decide.json()["apply_result"]["revision_id"]

        # Bot-facing readback stays applied and redacts the human's identity.
        poll = await http_client.get(
            f"/proposals/{proposal_id}", headers={"Authorization": f"Bearer {bot_a}"}
        )
        assert poll.status_code == 200
        poll_body = poll.json()
        assert poll_body["status"] == "applied"
        assert "decided_by_actor_id" not in poll_body

    async def test_same_bot_pending_dedup_resubmission_and_idempotent_redecide(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        world: World,
        test_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        http_client, _provider = client
        bot_b = _mint_agent_jwt(_BOT_B, _OWNER_B)

        # First submission: valid first document, no citations -> pending.
        first = await _submit(http_client, bot_b, _add_action("doc-b", citations=[]))
        assert first.status_code == 200, first.text
        proposal_id = first.json()["proposal_id"]
        assert first.json()["status"] == "pending"

        # Same bot resubmits the SAME (kind, target_id, action_type) with an
        # updated payload (now grounded in its own brain's evidence): the
        # pending row is deduped/updated IN PLACE -- same proposal_id -- and
        # the real judge auto-approves and applies it on this pass.
        second = await _submit(
            http_client,
            bot_b,
            _add_action("doc-b", citations=[_citation("rev-ev-b", 0, 4, "Beta")]),
        )
        assert second.status_code == 200, second.text
        assert second.json()["proposal_id"] == proposal_id
        assert second.json()["status"] == "applied"
        assert _revisions(world, _BRAIN_B, "doc-b") == 1

        # A repeated human decide on the already-applied hold is idempotent:
        # 200 with the applied state, no re-run of the write.
        redecide = await _decide(http_client, "human-b", proposal_id)
        assert redecide.status_code == 200
        assert redecide.json()["status"] == "applied"
        assert _revisions(world, _BRAIN_B, "doc-b") == 1
        # One apply attempt row for the whole flow: the auto-apply, once.
        assert len(_attempt_rows(world)) == 1

        row = await _hold_row(test_session_factory, proposal_id)
        assert row.status == "applied"

    async def test_bot_a_cannot_cite_or_revise_bot_bs_sources_even_human_approved(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        world: World,
        test_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        http_client, _provider = client
        bot_a = _mint_agent_jwt(_BOT_A, _OWNER_A)
        # A source that lives in bot-a's authoritative brain but is OWNED by
        # bot-b -- the ownership boundary a human approval must not cross.
        seeded = world.backend.add_source(
            _BRAIN_A,
            "bot-b-owned-source",
            content="bot-b fact",
            revision_id="rev-b-owned-head",
            owner_bot_id=_BOT_B,
        )

        # bot-a citing bot-b's evidence revision: the by-bot read resolves
        # bot-a's OWN brain, where that revision does not exist -> held.
        cite = await _submit(
            http_client,
            bot_a,
            _add_action(
                "doc-cite-cross",
                citations=[_citation("rev-ev-b", 0, 4, "Beta")],
            ),
        )
        assert cite.status_code == 200
        assert cite.json()["status"] == "pending"

        # bot-a revising a source owned by bot-b: held, never auto-approved.
        revise = await _submit(
            http_client,
            bot_a,
            _revise_action(
                "bot-b-owned-source",
                seeded.revision_id,
                citations=[_citation("rev-ev-a", 6, 1, "☕")],
            ),
        )
        assert revise.status_code == 200, revise.text
        revise_id = revise.json()["proposal_id"]
        assert revise.json()["status"] == "pending"

        # Even the authorized human's approval cannot override the boundary:
        # the decide API runs the real apply, which refuses the foreign source.
        decide = await _decide(http_client, "human-a", revise_id)
        assert decide.status_code == 200, decide.text
        assert decide.json()["status"] == "apply_failed"
        assert decide.json()["apply_error"] == "source not owned by bot principal"

        row = await _hold_row(test_session_factory, revise_id)
        assert row.status == "apply_failed"
        # Still exactly the one seeded revision -- nothing new was written.
        assert _revisions(world, _BRAIN_A, "bot-b-owned-source") == 1

        # M3: Even the authorized human's approval cannot override foreign citation:
        # approving the foreign citation proposal also runs the real apply and fails.
        cite_id = cite.json()["proposal_id"]
        cite_decide = await _decide(http_client, "human-a", cite_id)
        assert cite_decide.status_code == 200, cite_decide.text
        assert cite_decide.json()["status"] == "apply_failed"
        assert cite_decide.json()["apply_error"] is not None

        cite_row = await _hold_row(test_session_factory, cite_id)
        assert cite_row.status == "apply_failed"
        assert cite_row.apply_error is not None

        # No new backend logical source or revision was created in bot-a's brain.
        assert _revisions(world, _BRAIN_A, "doc-cite-cross") == 0

        # Bot-facing readback confirms failure and redacts human identity.
        poll_cite = await http_client.get(
            f"/proposals/{cite_id}", headers={"Authorization": f"Bearer {bot_a}"}
        )
        assert poll_cite.status_code == 200
        poll_body = poll_cite.json()
        assert poll_body["status"] == "apply_failed"
        assert "decided_by_actor_id" not in poll_body
        assert poll_body["apply_error"] == cite_row.apply_error

    async def test_unauthorized_principal_typed_403_aborts_before_hold_and_rate_limit(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        world: World,
        test_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        http_client, _provider = client
        bot_a = _mint_agent_jwt(_BOT_A, _OWNER_A)
        # Strip the propose scope: admission fails closed at the fingerprint
        # seam, BEFORE the board creates a hold or burns a rate-limit slot.
        world.resolver.principals[_BOT_A] = dataclasses.replace(
            world.resolver.principals[_BOT_A], allowed_scopes=frozenset()
        )

        denied = await _submit(http_client, bot_a, _add_action("doc-unauth"))

        # The abort mechanics hold regardless of the response shape below:
        # no hold row was created at all...
        assert await _hold_count(test_session_factory) == 0
        pending = await http_client.get(
            "/proposals/pending", headers={"Authorization": "Bearer human-a"}
        )
        assert pending.json()["proposals"] == []
        # ...and the failed attempt consumed no rate-limit budget: restoring
        # the scope lets the very next submission through immediately.
        world.resolver.principals[_BOT_A] = dataclasses.replace(
            world.resolver.principals[_BOT_A],
            allowed_scopes=frozenset({arcana_client.PROPOSE_SCOPE}),
        )
        ok = await _submit(
            http_client,
            bot_a,
            _add_action("doc-auth", citations=[_citation("rev-ev-a", 6, 1, "☕")]),
        )
        assert ok.status_code == 200, ok.text
        assert ok.json()["status"] == "applied"

        # Cross-repo contract resolution (TECH-7163): the approvals side
        # (agent-comms-approvals TECH-7163, `_fingerprint_arcana`'s admission
        # lane) returns a TYPED 403 ProposalTargetError
        # ("forbidden" / "bot principal is not authorized to propose").
        # The board allowlist (`_ALLOWED_PROPOSAL_TARGET_ERROR_STATUS_CODES`)
        # includes 403, passing the typed caller-actionable "not authorized"
        # signal end-to-end.
        assert denied.status_code == 403, denied.text
        assert denied.json() == {
            "error": "forbidden",
            "detail": "bot principal is not authorized to propose",
        }

    async def test_write_then_timeout_retry_reuses_hold_one_backend_revision(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        world: World,
        test_session_factory: async_sessionmaker[AsyncSession],
    ) -> None:
        http_client, _provider = client
        bot_a = _mint_agent_jwt(_BOT_A, _OWNER_A)
        # The backend writes the revision, THEN times out: the board's first
        # apply attempt gets an in-band indeterminate outcome, which the
        # board's HTTP client (TECH-7170) treats as ambiguous and retries.
        world.backend.simulate_write_then_timeout = True

        resp = await _submit(
            http_client,
            bot_a,
            _add_action("doc-tmo", citations=[_citation("rev-ev-a", 6, 1, "☕")]),
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        # The real retry loop recovered: the hold resolved to "applied" on the
        # SAME hold (no fresh hold was ever minted for the retry).
        assert body["status"] == "applied"
        proposal_id = body["proposal_id"]
        revision_id = body["apply_result"]["revision_id"]

        row = await _hold_row(test_session_factory, proposal_id)
        assert row.status == "applied"
        # Exactly one backend revision despite two HTTP apply attempts.
        assert _revisions(world, _BRAIN_A, "doc-tmo") == 1
        # Exactly one approvals attempt row: both attempts shared the hold_id
        # idempotency key (reclaimed in place, never re-inserted).
        assert len(_attempt_rows(world)) == 1
        meta = await _arcana_readback(world, _BOT_A, "doc-tmo")
        assert meta["revision_id"] == revision_id

    async def test_write_then_timeout_exhaustion_stays_applying_and_blocks_redecide(
        self,
        client: tuple[httpx.AsyncClient, _FakeAuthProvider],
        world: World,
        test_session_factory: async_sessionmaker[AsyncSession],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        http_client, _provider = client
        bot_a = _mint_agent_jwt(_BOT_A, _OWNER_A)
        # One attempt only: the in-band indeterminate outcome is the last
        # attempt, so the board resolves the apply as indeterminate and the
        # hold must STAY at "applying" -- the real contract, asserted as-is.
        monkeypatch.setenv(proposal_apply_http_client.PROPOSAL_APPLY_MAX_ATTEMPTS_ENV_VAR, "1")
        world.backend.simulate_write_then_timeout = True

        resp = await _submit(
            http_client,
            bot_a,
            _add_action("doc-tmo2", citations=[_citation("rev-ev-a", 6, 1, "☕")]),
        )
        assert resp.status_code == 200, resp.text
        proposal_id = resp.json()["proposal_id"]
        assert resp.json()["status"] == "applying"
        assert (
            resp.json()["apply_error"]
            == "apply outcome could not be confirmed; awaiting manual reconciliation"
        )

        row = await _hold_row(test_session_factory, proposal_id)
        assert row.status == "applying"
        # The backend DID write one revision before the timeout: that is the
        # ambiguity "applying" exists to hold open, not a contradiction.
        assert _revisions(world, _BRAIN_A, "doc-tmo2") == 1
        outcome = _attempt_outcome(world, proposal_id)
        assert outcome is not None
        assert outcome.get("indeterminate") is True

        # A second human decide on the "applying" hold is NOT allowed -- the
        # real contract raises HoldAlreadyDecidedError (HTTP 409). No test
        # here fakes a successful second decide.
        redecide = await _decide(http_client, "human-a", proposal_id)
        assert redecide.status_code == 409
        assert redecide.json() == {"error": "already_decided", "status": "applying"}

        # Resubmitting the same (kind, target_id, action_type) from the same
        # bot dedups onto the SAME hold (the applying row blocks a fresh
        # hold_id), rather than minting a second one.
        resubmit = await _submit(
            http_client,
            bot_a,
            _add_action("doc-tmo2", citations=[_citation("rev-ev-a", 6, 1, "☕")]),
        )
        assert resubmit.status_code == 200, resubmit.text
        assert resubmit.json()["proposal_id"] == proposal_id
        assert resubmit.json()["status"] == "applying"
        assert _revisions(world, _BRAIN_A, "doc-tmo2") == 1

    def test_refuse_externally_supplied_database_target_is_static_and_secret_free(
        self,
    ) -> None:
        """M1: Refusal of an external target must raise a static error that never
        interpolates the raw DSN, credentials, host, or query parameters."""
        dummy_secret_dsn = (
            "postgresql://secret_user:super_secret_password@db.internal:5432/proddb?sslmode=require"
        )
        with pytest.raises(RuntimeError) as exc_info:
            _refuse_externally_supplied_database_target(dummy_secret_dsn)

        err_msg = str(exc_info.value)
        assert err_msg == (
            "Harness safety: externally supplied database target is refused; "
            "test runner must own its ephemeral container."
        )
        for secret_part in (
            "secret_user",
            "super_secret_password",
            "db.internal",
            "proddb",
            "sslmode",
            "postgresql://",
        ):
            assert secret_part not in err_msg

    def test_default_collection_without_opt_in_skips_cleanly(self) -> None:
        """M2: Normal CI collection regression -- without RUN_LOCAL_ARCANA_PROPOSAL_FLOW=1
        and with ambient DATABASE_URL set, pytest skips cleanly at module level
        without importing private approvals packages or starting Docker."""
        env = {k: v for k, v in os.environ.items() if k != "RUN_LOCAL_ARCANA_PROPOSAL_FLOW"}
        env["DATABASE_URL"] = "postgresql://ci_user:ci_pass@localhost:5432/ambient_ci_db"
        repo_root = str(Path(__file__).resolve().parents[1])
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "tests/test_local_proposal_flow.py", "-v"],
            cwd=repo_root,
            env=env,
            capture_output=True,
            text=True,
        )
        # Pytest returns exit code 5 (NO_TESTS_COLLECTED) when every item in a targeted file skips.
        assert proc.returncode in (0, 5), f"Unexpected returncode {proc.returncode}: {proc.stderr}"
        assert "1 skipped" in proc.stdout
        assert "RuntimeError" not in proc.stdout
        assert "RuntimeError" not in proc.stderr
