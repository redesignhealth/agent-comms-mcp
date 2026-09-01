"""Tests for the v1 risk scorer (``plugins.BoundaryCrossingScorer``).

Absorbs the ownership-boundary matrix formerly exercised against
``state_machine.is_boundary_crossing_safe`` directly (moved here per
TECH-5389 PR1 -- the predicate now lives inside the scorer and is driven
through ``MessageRiskContext``/an injected ``OwnershipClient`` fake rather
than plain ``boundary_safe``/owner-set arguments)."""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from plugins import (
    BoundaryCrossingScorer,
    MessageRiskContext,
    RiskScoringInfraError,
)

# "note" is the one barrier-sensitive type (plugins.BARRIER_SENSITIVE_TYPES);
# any other registered type is a stand-in for "not sensitive".
_SENSITIVE_TYPE = "note"
_SAFE_TYPE = "confirm"


class _FakeOwnershipClient:
    """Test double for ``service.OwnershipClient`` — an in-memory owners
    map, keyed by agent id, same shape as ``tests/test_service.py``'s own
    fake."""

    def __init__(self, owners_by_agent_id: dict[uuid.UUID, dict[str, Any]]) -> None:
        self._owners_by_agent_id = owners_by_agent_id
        self.calls: list[uuid.UUID] = []

    async def get_agent_owners(self, agent_id: uuid.UUID) -> dict[str, Any]:
        self.calls.append(agent_id)
        if agent_id not in self._owners_by_agent_id:
            raise LookupError(f"unknown agent {agent_id}")
        return self._owners_by_agent_id[agent_id]


class _FailingOwnershipClient:
    async def get_agent_owners(self, agent_id: uuid.UUID) -> dict[str, Any]:
        raise RuntimeError("platform unreachable")


def _ctx(
    *,
    conversation_type: str,
    message_type: str,
    sender_agent_id: uuid.UUID,
    other_agent_ids: list[uuid.UUID] | None = None,
    ownership_client: Any = None,
) -> MessageRiskContext:
    return MessageRiskContext(
        conversation_type=conversation_type,
        conversation_id=uuid.uuid4(),
        sender_agent_id=sender_agent_id,
        other_agent_ids=other_agent_ids or [],
        message_type=message_type,
        schema_version=1,
        ownership_client=ownership_client or _FailingOwnershipClient(),
    )


class TestNonSensitiveTypesNeverScored:
    """A message type outside ``BARRIER_SENSITIVE_TYPES`` is never high
    risk and never touches the ownership client, for every recognized
    conversation type."""

    @pytest.mark.parametrize("conversation_type", ["open", "internal", "asymmetric"])
    async def test_non_sensitive_type_is_low_risk_without_lookup(
        self, conversation_type: str
    ) -> None:
        sender = uuid.uuid4()
        other = uuid.uuid4()
        ctx = _ctx(
            conversation_type=conversation_type,
            message_type=_SAFE_TYPE,
            sender_agent_id=sender,
            other_agent_ids=[other],
            # A raising client: if the scorer touched it at all, this test
            # would fail with the wrong exception type instead of asserting
            # a RiskVerdict.
            ownership_client=_FailingOwnershipClient(),
        )
        verdict = await BoundaryCrossingScorer().score(ctx)
        assert verdict.high_risk is False
        assert verdict.reason is None


class TestOpenConversationType:
    async def test_sensitive_type_is_high_risk(self) -> None:
        ctx = _ctx(
            conversation_type="open",
            message_type=_SENSITIVE_TYPE,
            sender_agent_id=uuid.uuid4(),
        )
        verdict = await BoundaryCrossingScorer().score(ctx)
        assert verdict.high_risk is True
        assert verdict.reason == "boundary_crossing"

    async def test_ignores_owner_sets(self) -> None:
        # open has no ownership concept -- never touches the client at all.
        ctx = _ctx(
            conversation_type="open",
            message_type=_SENSITIVE_TYPE,
            sender_agent_id=uuid.uuid4(),
            other_agent_ids=[uuid.uuid4()],
            ownership_client=_FailingOwnershipClient(),
        )
        verdict = await BoundaryCrossingScorer().score(ctx)
        assert verdict.high_risk is True


class TestInternalConversationType:
    """TECH-5735: `internal` stays "never high risk" -- but now that
    invariant is guaranteed BY CONSTRUCTION (no `is_shared` agent can ever
    be admitted to `internal` -- see test_service.py), not merely assumed,
    so no ownership lookup is needed here at all."""

    async def test_sensitive_type_never_high_risk(self) -> None:
        ctx = _ctx(
            conversation_type="internal",
            message_type=_SENSITIVE_TYPE,
            sender_agent_id=uuid.uuid4(),
            other_agent_ids=[uuid.uuid4()],
            ownership_client=_FailingOwnershipClient(),
        )
        verdict = await BoundaryCrossingScorer().score(ctx)
        assert verdict.high_risk is False


class TestAsymmetricConversationType:
    async def test_single_owner_to_shared_crosses(self) -> None:
        # sender owns only {dan}; other side (shared) has an owner {priya}
        # outside the sender's set -- crosses, high risk.
        sender = uuid.uuid4()
        other = uuid.uuid4()
        client = _FakeOwnershipClient(
            {
                sender: {"is_shared": False, "owners": ["dan"]},
                other: {"is_shared": True, "owners": ["dan", "priya"]},
            }
        )
        ctx = _ctx(
            conversation_type="asymmetric",
            message_type=_SENSITIVE_TYPE,
            sender_agent_id=sender,
            other_agent_ids=[other],
            ownership_client=client,
        )
        verdict = await BoundaryCrossingScorer().score(ctx)
        assert verdict.high_risk is True
        assert verdict.reason == "boundary_crossing"

    async def test_shared_to_single_owner_does_not_cross(self) -> None:
        # sender is shared {dan, priya}; other side's owner {priya} is
        # already in the sender's own set -- does not cross.
        sender = uuid.uuid4()
        other = uuid.uuid4()
        client = _FakeOwnershipClient(
            {
                sender: {"is_shared": True, "owners": ["dan", "priya"]},
                other: {"is_shared": False, "owners": ["priya"]},
            }
        )
        ctx = _ctx(
            conversation_type="asymmetric",
            message_type=_SENSITIVE_TYPE,
            sender_agent_id=sender,
            other_agent_ids=[other],
            ownership_client=client,
        )
        verdict = await BoundaryCrossingScorer().score(ctx)
        assert verdict.high_risk is False

    async def test_same_single_owner_does_not_cross(self) -> None:
        sender = uuid.uuid4()
        other = uuid.uuid4()
        client = _FakeOwnershipClient(
            {
                sender: {"is_shared": False, "owners": ["dan"]},
                other: {"is_shared": False, "owners": ["dan"]},
            }
        )
        ctx = _ctx(
            conversation_type="asymmetric",
            message_type=_SENSITIVE_TYPE,
            sender_agent_id=sender,
            other_agent_ids=[other],
            ownership_client=client,
        )
        verdict = await BoundaryCrossingScorer().score(ctx)
        assert verdict.high_risk is False

    async def test_disjoint_owners_crosses(self) -> None:
        sender = uuid.uuid4()
        other = uuid.uuid4()
        client = _FakeOwnershipClient(
            {
                sender: {"is_shared": False, "owners": ["dan"]},
                other: {"is_shared": False, "owners": ["priya"]},
            }
        )
        ctx = _ctx(
            conversation_type="asymmetric",
            message_type=_SENSITIVE_TYPE,
            sender_agent_id=sender,
            other_agent_ids=[other],
            ownership_client=client,
        )
        verdict = await BoundaryCrossingScorer().score(ctx)
        assert verdict.high_risk is True

    async def test_shared_sender_bypasses_when_other_not_shared(self) -> None:
        sender = uuid.uuid4()
        other = uuid.uuid4()
        client = _FakeOwnershipClient(
            {
                sender: {"is_shared": True, "owners": ["dan"]},
                other: {"is_shared": False, "owners": ["priya"]},
            },
        )
        ctx = _ctx(
            conversation_type="asymmetric",
            message_type=_SENSITIVE_TYPE,
            sender_agent_id=sender,
            other_agent_ids=[other],
            ownership_client=client,
        )
        verdict = await BoundaryCrossingScorer().score(ctx)
        assert verdict.high_risk is False
        assert verdict.detail == {"bypass": "shared_sender"}
        # The shared-recipient check now always resolves every other
        # participant's info before the shared-sender bypass is even
        # considered (it needs their `is_shared` flag) -- it just doesn't
        # need their OWNER SETS once none of them turn out to be shared.
        assert other in client.calls

    async def test_shared_recipient_forces_review_even_when_sender_not_shared(self) -> None:
        """A non-shared sender messaging a shared recipient must always be
        flagged for review -- the recipient-side gap this scorer change
        closes. Owner sets happen to overlap here (both include "dan"), so
        the OLD subset-comparison logic alone would have returned
        ``high_risk=False``; the shared-recipient check must win regardless
        of what the owner-set comparison would have said."""
        sender = uuid.uuid4()
        other = uuid.uuid4()
        client = _FakeOwnershipClient(
            {
                sender: {"is_shared": False, "owners": ["dan"]},
                other: {"is_shared": True, "owners": ["dan"]},
            }
        )
        ctx = _ctx(
            conversation_type="asymmetric",
            message_type=_SENSITIVE_TYPE,
            sender_agent_id=sender,
            other_agent_ids=[other],
            ownership_client=client,
        )
        verdict = await BoundaryCrossingScorer().score(ctx)
        assert verdict.high_risk is True
        assert verdict.reason == "boundary_crossing"
        assert verdict.detail == {"reason": "shared_recipient"}

    async def test_shared_recipient_forces_review_even_when_sender_also_shared(self) -> None:
        """Precedence: when BOTH the sender and a recipient are shared, the
        shared-RECIPIENT check wins -- a message TO a shared agent must
        never silently bypass review just because the sender also happens
        to be shared. This is the key precedence call in the recipient-side
        fix: without it, a shared sender could launder any message past a
        shared recipient's review requirement."""
        sender = uuid.uuid4()
        other = uuid.uuid4()
        client = _FakeOwnershipClient(
            {
                sender: {"is_shared": True, "owners": ["dan"]},
                other: {"is_shared": True, "owners": ["priya"]},
            }
        )
        ctx = _ctx(
            conversation_type="asymmetric",
            message_type=_SENSITIVE_TYPE,
            sender_agent_id=sender,
            other_agent_ids=[other],
            ownership_client=client,
        )
        verdict = await BoundaryCrossingScorer().score(ctx)
        assert verdict.high_risk is True
        assert verdict.reason == "boundary_crossing"
        assert verdict.detail == {"reason": "shared_recipient"}

    async def test_shared_recipient_among_multiple_others_forces_review(self) -> None:
        """Any OTHER participant being shared forces review, not just a
        lone recipient -- checked across the full ``other_agent_ids`` set."""
        sender = uuid.uuid4()
        other_plain = uuid.uuid4()
        other_shared = uuid.uuid4()
        client = _FakeOwnershipClient(
            {
                sender: {"is_shared": False, "owners": ["dan"]},
                other_plain: {"is_shared": False, "owners": ["dan"]},
                other_shared: {"is_shared": True, "owners": ["priya"]},
            }
        )
        ctx = _ctx(
            conversation_type="asymmetric",
            message_type=_SENSITIVE_TYPE,
            sender_agent_id=sender,
            other_agent_ids=[other_plain, other_shared],
            ownership_client=client,
        )
        verdict = await BoundaryCrossingScorer().score(ctx)
        assert verdict.high_risk is True
        assert verdict.detail == {"reason": "shared_recipient"}

    async def test_shared_recipient_lookup_does_not_require_owner_set(self) -> None:
        """A shared recipient's (possibly empty) "owners" roster must never
        raise ``empty_owner_set`` -- the shared-recipient check only
        inspects ``is_shared`` and returns before any owner-set is ever
        consulted for that participant."""
        sender = uuid.uuid4()
        other = uuid.uuid4()
        client = _FakeOwnershipClient(
            {
                sender: {"is_shared": False, "owners": ["dan"]},
                other: {"is_shared": True, "owners": []},
            }
        )
        ctx = _ctx(
            conversation_type="asymmetric",
            message_type=_SENSITIVE_TYPE,
            sender_agent_id=sender,
            other_agent_ids=[other],
            ownership_client=client,
        )
        verdict = await BoundaryCrossingScorer().score(ctx)
        assert verdict.high_risk is True
        assert verdict.detail == {"reason": "shared_recipient"}

    async def test_non_sensitive_type_skips_lookup_even_in_asymmetric(self) -> None:
        ctx = _ctx(
            conversation_type="asymmetric",
            message_type=_SAFE_TYPE,
            sender_agent_id=uuid.uuid4(),
            other_agent_ids=[uuid.uuid4()],
            ownership_client=_FailingOwnershipClient(),
        )
        verdict = await BoundaryCrossingScorer().score(ctx)
        assert verdict.high_risk is False

    async def test_sender_lookup_failure_raises_ownership_unverified(self) -> None:
        ctx = _ctx(
            conversation_type="asymmetric",
            message_type=_SENSITIVE_TYPE,
            sender_agent_id=uuid.uuid4(),
            other_agent_ids=[uuid.uuid4()],
            ownership_client=_FailingOwnershipClient(),
        )
        with pytest.raises(RiskScoringInfraError) as exc_info:
            await BoundaryCrossingScorer().score(ctx)
        assert exc_info.value.cause == "ownership_unverified"

    async def test_other_lookup_failure_raises_ownership_unverified(self) -> None:
        sender = uuid.uuid4()
        other = uuid.uuid4()
        client = _FakeOwnershipClient({sender: {"is_shared": False, "owners": ["dan"]}})
        ctx = _ctx(
            conversation_type="asymmetric",
            message_type=_SENSITIVE_TYPE,
            sender_agent_id=sender,
            other_agent_ids=[other],
            ownership_client=client,
        )
        with pytest.raises(RiskScoringInfraError) as exc_info:
            await BoundaryCrossingScorer().score(ctx)
        assert exc_info.value.cause == "ownership_unverified"

    async def test_sender_empty_owner_set_raises_empty_owner_set(self) -> None:
        sender = uuid.uuid4()
        other = uuid.uuid4()
        client = _FakeOwnershipClient(
            {
                sender: {"is_shared": False, "owners": []},
                other: {"is_shared": False, "owners": []},
            }
        )
        ctx = _ctx(
            conversation_type="asymmetric",
            message_type=_SENSITIVE_TYPE,
            sender_agent_id=sender,
            other_agent_ids=[other],
            ownership_client=client,
        )
        with pytest.raises(RiskScoringInfraError) as exc_info:
            await BoundaryCrossingScorer().score(ctx)
        assert exc_info.value.cause == "empty_owner_set"

    async def test_other_empty_owner_set_raises_empty_owner_set(self) -> None:
        sender = uuid.uuid4()
        other = uuid.uuid4()
        client = _FakeOwnershipClient(
            {
                sender: {"is_shared": False, "owners": ["dan"]},
                other: {"is_shared": False, "owners": []},
            }
        )
        ctx = _ctx(
            conversation_type="asymmetric",
            message_type=_SENSITIVE_TYPE,
            sender_agent_id=sender,
            other_agent_ids=[other],
            ownership_client=client,
        )
        with pytest.raises(RiskScoringInfraError) as exc_info:
            await BoundaryCrossingScorer().score(ctx)
        assert exc_info.value.cause == "empty_owner_set"


class TestUnrecognizedConversationType:
    """A ``conversation_type`` this process doesn't recognize (e.g. a
    legacy pre-rename row) must raise for ANY message type -- even a
    non-sensitive one -- matching the pre-refactor
    ``is_boundary_crossing_safe`` default-deny posture that didn't
    special-case ``boundary_safe`` for unknown types."""

    @pytest.mark.parametrize("message_type", [_SAFE_TYPE, _SENSITIVE_TYPE])
    async def test_raises_unknown_conversation_type(self, message_type: str) -> None:
        ctx = _ctx(
            conversation_type="scheduling.availability",
            message_type=message_type,
            sender_agent_id=uuid.uuid4(),
            ownership_client=_FailingOwnershipClient(),
        )
        with pytest.raises(RiskScoringInfraError) as exc_info:
            await BoundaryCrossingScorer().score(ctx)
        assert exc_info.value.cause == "unknown_conversation_type"

    async def test_every_registered_conversation_type_is_explicitly_handled(self) -> None:
        # plugins.py already imports schemas.CONVERSATION_TYPES directly
        # (unlike state_machine.py's old is_boundary_crossing_safe, which
        # deliberately didn't), so this is a lighter cross-check than its
        # predecessor: just prove every registered type is actually
        # handled without raising for a non-sensitive message.
        from schemas import CONVERSATION_TYPES

        for conversation_type in CONVERSATION_TYPES:
            ctx = _ctx(
                conversation_type=conversation_type,
                message_type=_SAFE_TYPE,
                sender_agent_id=uuid.uuid4(),
                ownership_client=_FailingOwnershipClient(),
            )
            verdict = await BoundaryCrossingScorer().score(ctx)
            assert verdict.high_risk is False
