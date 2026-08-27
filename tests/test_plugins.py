"""Tests for the pluggable risk-scorer/auto-approver/notifier seams'
registry/resolution mechanism (plugins.py) -- TECH-5389 PR1 (risk scorer)
and PR2 (auto-approver, notifier)."""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid

import httpx
import pytest

import plugins
import service
from plugins import (
    ApprovalNotification,
    BoundaryCrossingScorer,
    EscalateAllAutoApprover,
    HoldContext,
    LogOnlyNotifier,
    RiskScorer,
    WebhookNotifier,
    resolve_plugin,
)


class _FakeScorer:
    async def score(self, ctx: object) -> None:  # pragma: no cover -- never called
        raise NotImplementedError


class _FakeApprover:
    async def review(self, ctx: object) -> None:  # pragma: no cover -- never called
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
        # get_risk_scorer/get_auto_approver/get_approval_notifier/
        # get_active_checker each cache a process-wide singleton -- reset
        # all four so each test starts from a clean slate regardless of run
        # order (validate_configuration now resolves all four).
        plugins._risk_scorer = None
        plugins._auto_approver = None
        plugins._approval_notifier = None
        plugins._active_checker = None

    def teardown_method(self) -> None:
        plugins._risk_scorer = None
        plugins._auto_approver = None
        plugins._approval_notifier = None
        plugins._active_checker = None

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

    def test_validate_configuration_fails_fast_on_missing_webhook_env(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(plugins.RISK_SCORER_ENV_VAR, raising=False)
        monkeypatch.delenv(plugins.AUTO_APPROVER_ENV_VAR, raising=False)
        monkeypatch.setenv(plugins.APPROVAL_NOTIFIER_ENV_VAR, "webhook")
        monkeypatch.delenv(plugins.APPROVAL_WEBHOOK_URL_ENV_VAR, raising=False)
        monkeypatch.delenv(plugins.APPROVAL_WEBHOOK_SECRET_ENV_VAR, raising=False)
        with pytest.raises(RuntimeError, match="requires both"):
            plugins.validate_configuration()


# --- Seam 2: the auto-approver (TECH-5389 PR2) -------------------------------


class TestAutoApproverRegistry:
    def test_default_registry_contains_escalate_all(self) -> None:
        assert plugins.AUTO_APPROVERS[plugins.DEFAULT_AUTO_APPROVER] is EscalateAllAutoApprover

    async def test_escalate_all_never_clears(self) -> None:
        approver = EscalateAllAutoApprover()
        ctx = HoldContext(
            hold_id=uuid.uuid4(),
            conversation_id=uuid.uuid4(),
            conversation_type="open",
            sender_agent_id=uuid.uuid4(),
            owner_sub="owner-a",
            message_type="note",
            schema_version=1,
            payload={"type": "note", "text": "hello"},
            risk_reason="boundary_crossing",
        )
        decision = await approver.review(ctx)
        assert decision.cleared is False


class TestGetAutoApprover:
    def setup_method(self) -> None:
        plugins._auto_approver = None

    def teardown_method(self) -> None:
        plugins._auto_approver = None

    def test_defaults_to_escalate_all(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(plugins.AUTO_APPROVER_ENV_VAR, raising=False)
        assert isinstance(plugins.get_auto_approver(), EscalateAllAutoApprover)

    def test_env_var_overrides_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(plugins.AUTO_APPROVER_ENV_VAR, "tests.test_plugins:_FakeApprover")
        approver = plugins.get_auto_approver()
        assert isinstance(approver, _FakeApprover)


# --- Seam 3: the approval-request notifier (TECH-5389 PR2) ------------------


class TestNotifierRegistry:
    def test_default_registry_contains_log_only(self) -> None:
        assert plugins.APPROVAL_NOTIFIERS[plugins.DEFAULT_APPROVAL_NOTIFIER] is LogOnlyNotifier

    def test_registry_contains_webhook(self) -> None:
        assert plugins.APPROVAL_NOTIFIERS["webhook"] is WebhookNotifier


def _notification(**overrides: object) -> ApprovalNotification:
    fields: dict[str, object] = {
        "hold_id": "hold-1",
        "conversation_id": "conv-1",
        "conversation_type": "open",
        "sender_agent_id": "agent-1",
        "sender_display_name": "Agent One",
        "owner_sub": "owner-1",
        "owner_email": "owner1@example.com",
        "message_type": "note",
        "risk_reason": "boundary_crossing",
        "expires_at": "2026-08-25T00:00:00+00:00",
        "created_at": "2026-08-18T00:00:00+00:00",
    }
    fields.update(overrides)
    return ApprovalNotification(**fields)  # type: ignore[arg-type]


class TestLogOnlyNotifier:
    async def test_notify_escalated_does_not_raise(self) -> None:
        notifier = LogOnlyNotifier()
        await notifier.notify_escalated(_notification())  # must not raise


class TestWebhookNotifier:
    def test_construction_requires_url_and_secret(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(plugins.APPROVAL_WEBHOOK_URL_ENV_VAR, raising=False)
        monkeypatch.delenv(plugins.APPROVAL_WEBHOOK_SECRET_ENV_VAR, raising=False)
        with pytest.raises(RuntimeError, match="requires both"):
            WebhookNotifier()

    async def test_notify_escalated_posts_signed_payload(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(plugins.APPROVAL_WEBHOOK_URL_ENV_VAR, "https://example.test/hook")
        monkeypatch.setenv(plugins.APPROVAL_WEBHOOK_SECRET_ENV_VAR, "s3cr3t")
        notifier = WebhookNotifier()
        notification = _notification()

        captured: dict[str, object] = {}

        async def _fake_post(
            self: httpx.AsyncClient, url: str, *, content: bytes, headers: dict[str, str]
        ) -> httpx.Response:
            captured["url"] = url
            captured["content"] = content
            captured["headers"] = headers
            return httpx.Response(200, request=httpx.Request("POST", url))

        monkeypatch.setattr(httpx.AsyncClient, "post", _fake_post)
        await notifier.notify_escalated(notification)

        assert captured["url"] == "https://example.test/hook"
        body = captured["content"]
        assert isinstance(body, bytes)
        payload = json.loads(body)
        # Pointer-not-content: no held text/payload field anywhere in the
        # wire body -- only routing/rendering metadata.
        assert set(payload) == {
            "hold_id",
            "conversation_id",
            "conversation_type",
            "sender_agent_id",
            "sender_display_name",
            "owner_sub",
            "owner_email",
            "message_type",
            "risk_reason",
            "expires_at",
            "created_at",
        }
        expected_sig = hmac.new(b"s3cr3t", body, hashlib.sha256).hexdigest()
        headers = captured["headers"]
        assert isinstance(headers, dict)
        assert headers[plugins.APPROVAL_WEBHOOK_SIGNATURE_HEADER] == expected_sig

    async def test_notify_escalated_raises_on_non_2xx(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(plugins.APPROVAL_WEBHOOK_URL_ENV_VAR, "https://example.test/hook")
        monkeypatch.setenv(plugins.APPROVAL_WEBHOOK_SECRET_ENV_VAR, "s3cr3t")
        notifier = WebhookNotifier()

        async def _fake_post(
            self: httpx.AsyncClient, url: str, *, content: bytes, headers: dict[str, str]
        ) -> httpx.Response:
            return httpx.Response(500, request=httpx.Request("POST", url))

        monkeypatch.setattr(httpx.AsyncClient, "post", _fake_post)
        with pytest.raises(httpx.HTTPStatusError):
            await notifier.notify_escalated(_notification())


class TestGetApprovalNotifier:
    def setup_method(self) -> None:
        plugins._approval_notifier = None

    def teardown_method(self) -> None:
        plugins._approval_notifier = None

    def test_defaults_to_log_only(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(plugins.APPROVAL_NOTIFIER_ENV_VAR, raising=False)
        assert isinstance(plugins.get_approval_notifier(), LogOnlyNotifier)


# --- Seam 4: the active checker (TECH-5703) -----------------------------------


class TestActiveCheckerRegistry:
    def test_default_registry_contains_always_active(self) -> None:
        assert (
            plugins.ACTIVE_CHECKERS[plugins.DEFAULT_ACTIVE_CHECKER] is plugins.AlwaysActiveChecker
        )

    def test_always_active_checker_satisfies_protocol(self) -> None:
        checker: plugins.ActiveChecker = plugins.AlwaysActiveChecker()
        assert hasattr(checker, "is_active")

    @pytest.mark.asyncio
    async def test_always_active_checker_reports_every_sub_active(self) -> None:
        checker = plugins.AlwaysActiveChecker()
        assert await checker.is_active("literally-anything") is True


class TestGetActiveCheckerAndValidateConfiguration:
    def setup_method(self) -> None:
        plugins._risk_scorer = None
        plugins._auto_approver = None
        plugins._approval_notifier = None
        plugins._active_checker = None

    def teardown_method(self) -> None:
        plugins._risk_scorer = None
        plugins._auto_approver = None
        plugins._approval_notifier = None
        plugins._active_checker = None

    def test_get_active_checker_defaults_to_always_active(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(plugins.ACTIVE_CHECKER_ENV_VAR, raising=False)
        assert isinstance(plugins.get_active_checker(), plugins.AlwaysActiveChecker)

    def test_get_active_checker_caches_the_instance(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(plugins.ACTIVE_CHECKER_ENV_VAR, raising=False)
        first = plugins.get_active_checker()
        second = plugins.get_active_checker()
        assert first is second

    def test_validate_configuration_passes_for_the_default(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(plugins.ACTIVE_CHECKER_ENV_VAR, raising=False)
        plugins.validate_configuration()  # must not raise

    def test_validate_configuration_fails_fast_on_unknown_checker(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(plugins.ACTIVE_CHECKER_ENV_VAR, "not_a_real_checker")
        with pytest.raises(RuntimeError, match="unknown plugin"):
            plugins.validate_configuration()

    def test_non_default_registry_name_resolves(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class _AllInactiveChecker:
            async def is_active(self, sub: str) -> bool:
                return False

        monkeypatch.setitem(plugins.ACTIVE_CHECKERS, "sentinel", _AllInactiveChecker)
        monkeypatch.setenv(plugins.ACTIVE_CHECKER_ENV_VAR, "sentinel")
        assert isinstance(plugins.get_active_checker(), _AllInactiveChecker)

    def test_validate_configuration_fails_fast_on_bad_import_path(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Isolate the earlier seams: an invalid RISK_SCORER/AUTO_APPROVER/
        # APPROVAL_NOTIFIER env var would make validate_configuration() raise
        # at that earlier seam instead, and this test's pytest.raises would
        # pass for the wrong reason (message wouldn't be "failed to import
        # plugin").
        monkeypatch.delenv(plugins.RISK_SCORER_ENV_VAR, raising=False)
        monkeypatch.delenv(plugins.AUTO_APPROVER_ENV_VAR, raising=False)
        monkeypatch.delenv(plugins.APPROVAL_NOTIFIER_ENV_VAR, raising=False)
        monkeypatch.setenv(plugins.ACTIVE_CHECKER_ENV_VAR, "not_a_real_module:Whatever")
        with pytest.raises(RuntimeError, match="failed to import plugin"):
            plugins.validate_configuration()


# --- Plugin name resolution (audit-readable names) ---------------------------


class TestPluginDisplayNames:
    def test_risk_scorer_name_for_registry_instance(self) -> None:
        assert plugins.risk_scorer_name(BoundaryCrossingScorer()) == "boundary_v1"

    def test_auto_approver_name_for_registry_instance(self) -> None:
        assert plugins.auto_approver_name(EscalateAllAutoApprover()) == "escalate_all"

    def test_notifier_name_for_registry_instance(self) -> None:
        assert plugins.notifier_name(LogOnlyNotifier()) == "log_only"

    def test_falls_back_to_module_qualname_for_unregistered_instance(self) -> None:
        class _AdHocScorer:
            async def score(self, ctx: object) -> None:  # pragma: no cover
                raise NotImplementedError

        name = plugins.risk_scorer_name(_AdHocScorer())  # type: ignore[arg-type]
        assert name.startswith("tests.test_plugins:")
        assert name.endswith("_AdHocScorer")


# --- OwnershipClient pluggable seam (TECH-5396 open question 1) -------------------
#
# Lives here rather than in test_service.py: this seam's registry/resolution
# is pure Python with no DB dependency, and test_service.py's module-scoped
# autouse fixture skips everything when Postgres is unreachable. The one
# genuinely DB-dependent test (a resolved import-path factory actually
# constructing a working client against a real session) lives in
# test_service.py's TestOwnershipClientSeamDbBacked instead.


class TestOwnershipClientRegistry:
    def test_default_registry_contains_agent_table(self) -> None:
        assert (
            service.OWNERSHIP_CLIENTS[service.DEFAULT_OWNERSHIP_CLIENT]
            is service._agent_table_ownership_client_factory
        )


def _not_a_factory_ownership_client_factory() -> object:
    """Import-path-resolvable factory returning something NOT callable as
    Callable[[AsyncSession], OwnershipClient] -- pins the boot-validation
    callable() check (an operator misconfiguring OWNERSHIP_CLIENT to point at
    a plain implementation class/instance rather than a factory-of-factories)."""
    return object()


class TestGetOwnershipClientFactoryAndValidateConfiguration:
    def setup_method(self) -> None:
        service._ownership_client_factory = None

    def teardown_method(self) -> None:
        service._ownership_client_factory = None

    def test_defaults_to_agent_table_ownership_client(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(service.OWNERSHIP_CLIENT_ENV_VAR, raising=False)
        factory = service.get_ownership_client_factory()
        assert factory is service.AgentTableOwnershipClient

    def test_caches_the_resolved_factory(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv(service.OWNERSHIP_CLIENT_ENV_VAR, raising=False)
        first = service.get_ownership_client_factory()
        second = service.get_ownership_client_factory()
        assert first is second

    def test_resolution_failure_is_not_cached(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv(service.OWNERSHIP_CLIENT_ENV_VAR, "not_a_real_client")
        with pytest.raises(RuntimeError, match="unknown plugin"):
            service.get_ownership_client_factory()
        # A second call against the SAME (still-broken) config must retry,
        # not return a stale/cached value from the failed attempt.
        with pytest.raises(RuntimeError, match="unknown plugin"):
            service.get_ownership_client_factory()

    def test_non_default_registry_name_resolves(self, monkeypatch: pytest.MonkeyPatch) -> None:
        sentinel_factory = object()
        monkeypatch.setitem(service.OWNERSHIP_CLIENTS, "sentinel", lambda: sentinel_factory)
        monkeypatch.setenv(service.OWNERSHIP_CLIENT_ENV_VAR, "sentinel")
        assert service.get_ownership_client_factory() is sentinel_factory

    def test_validate_configuration_passes_for_the_default(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(service.OWNERSHIP_CLIENT_ENV_VAR, raising=False)
        service.validate_ownership_client_configuration()  # must not raise

    def test_validate_configuration_fails_fast_on_unknown_name(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(service.OWNERSHIP_CLIENT_ENV_VAR, "not_a_real_client")
        with pytest.raises(RuntimeError, match="unknown plugin"):
            service.validate_ownership_client_configuration()

    def test_validate_configuration_fails_fast_on_bad_import_path(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(service.OWNERSHIP_CLIENT_ENV_VAR, "not_a_real_module:Whatever")
        with pytest.raises(RuntimeError, match="failed to import plugin"):
            service.validate_ownership_client_configuration()

    def test_validate_configuration_fails_fast_on_non_callable_result(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(
            service.OWNERSHIP_CLIENT_ENV_VAR,
            "tests.test_plugins:_not_a_factory_ownership_client_factory",
        )
        with pytest.raises(RuntimeError, match="is not callable"):
            service.validate_ownership_client_configuration()
