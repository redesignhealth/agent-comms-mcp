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
        # get_risk_scorer/get_auto_approver/get_approval_notifier each cache
        # a process-wide singleton -- reset all three so each test starts
        # from a clean slate regardless of run order (validate_configuration
        # now resolves all three).
        plugins._risk_scorer = None
        plugins._auto_approver = None
        plugins._approval_notifier = None

    def teardown_method(self) -> None:
        plugins._risk_scorer = None
        plugins._auto_approver = None
        plugins._approval_notifier = None

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
        assert (
            plugins.AUTO_APPROVERS[plugins.DEFAULT_AUTO_APPROVER] is EscalateAllAutoApprover
        )

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
