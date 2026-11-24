"""Background delivery of wake events: sign, POST, record the outcome, retry (TECH-9911).

The contract is ``docs/WAKE-EVENTS.md`` sections 3 to 5. A single task inside
the board process polls ``wake_events`` for due rows and sends each as a
Standard Webhooks-signed POST to the recipient's wake target. It runs as its
own asyncio task, started and stopped by the server lifespan
(``wake_delivery_lifespan``), so it is never part of the request that posted a
message.

Claim and lease. A claim is one short transaction that selects due events with
``FOR UPDATE SKIP LOCKED``, then writes a lease on each (``attempt_count`` + 1,
``next_attempt_at`` = now + ``LEASE_SECONDS``, ``session_ref_sent``) and
commits. No transaction or row lock is held across the HTTP call. The outcome
is written in a new transaction. If the process dies in between, the lease
expires, the event is due again and is re-sent: at-least-once delivery.

Ordering. Only the oldest unfinished event of a (recipient, conversation) pair
is eligible; ordering within a pair is ``seq`` (invites, which have no ``seq``,
come first). Different pairs are sent concurrently, up to
``MAX_CONCURRENT_SENDS``.

Retry later is per recipient. While a recipient has an event in ``retry_later``
that is not yet due (this includes the one currently leased as a probe), it is
sent nothing. When due, it is sent exactly one event, the probe. An accepted
probe turns the recipient's other ``retry_later`` events back into ``retry``,
due now, so normal delivery resumes.

Nothing here logs or stores a secret, a signature, a request body or a response
body. ``last_error`` is a short fixed phrase.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import hmac
import json
import logging
import os
import uuid
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from typing import Any, Final
from urllib.parse import urlsplit

import httpx
from sqlalchemy import and_, delete, exists, func, or_, select, tuple_, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import aliased

from db import get_session_factory
from models import WakeEvent, WakeSession, WakeTarget
from proposal_apply_http_client import tailnet_proxy_mounts
from service import _audit
from wake_events import WAKE_SESSION_WINDOW_SECONDS
from wake_pause import is_delivery_paused
from wake_secrets import decrypt_secret
from wake_targets import WAKE_TARGET_ALLOWED_HOSTS_ENV_VAR, host_is_allowed, parse_allowed_hosts

logger = logging.getLogger(__name__)

# --- Tunables (all of them, in one place) -----------------------------------

# Seconds between polls for due events.
LOOP_INTERVAL_SECONDS: Final = 2.0
# Total time allowed for one POST, response body included (contract section 4).
SEND_TIMEOUT_SECONDS: Final = 10.0
# How long a claimed event stays invisible to other claims. Must exceed
# SEND_TIMEOUT_SECONDS plus the time to write the outcome.
LEASE_SECONDS: Final = 60.0
# Delay before the next try after each transient failure; a failure after the
# last step dead-letters the event (6 attempts in all).
BACKOFF_SCHEDULE_SECONDS: Final = (5, 30, 120, 600, 1800)
# Delay before the next probe of a recipient that answered retry_later.
RETRY_LATER_SECONDS: Final = 300
# Delay before looking again when the operator host allowlist is empty or unusable.
ALLOWLIST_MISCONFIGURED_RETRY_SECONDS: Final = 60
# Cap on a Retry-After value.
MAX_RETRY_AFTER_SECONDS: Final = 3600
# An event still undelivered this long after it was recorded is dead-lettered.
EVENT_LIFETIME: Final = timedelta(hours=24)
# Most sends in flight at once.
MAX_CONCURRENT_SENDS: Final = 8
# Most due rows one claim looks at (before the one-probe-per-recipient filter).
CLAIM_SCAN_LIMIT: Final = 50
# Response bytes read; anything beyond is ignored.
MAX_RESPONSE_BYTES: Final = 65536
MAX_SESSION_REF_LENGTH: Final = 255

SYSTEM_ACTOR: Final = "system:wake-delivery"

_OPEN_STATUSES: Final = ("pending", "retry", "retry_later")
_SECRET_PREFIX: Final = "whsec_"


class _RedactUrlQuery(logging.Filter):
    """Drop URL query strings from httpx's own request log lines.

    A wake target URL may carry a token in its query string, and httpx logs the
    full URL of every request at INFO.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.args, tuple):
            record.args = tuple(
                a.copy_with(query=None) if isinstance(a, httpx.URL) and a.query else a
                for a in record.args
            )
        return True


logging.getLogger("httpx").addFilter(_RedactUrlQuery())


# --- Pure helpers ------------------------------------------------------------


def sign(secret: str, event_id: str, timestamp: str, body: bytes) -> str:
    """Return the ``webhook-signature`` header value for ``body``."""
    key = base64.b64decode(secret[len(_SECRET_PREFIX) :])
    digest = hmac.new(key, f"{event_id}.{timestamp}.".encode() + body, hashlib.sha256).digest()
    return "v1," + base64.b64encode(digest).decode()


def parse_retry_after(value: str | None, now: datetime) -> int | None:
    """Seconds from ``Retry-After`` (delta-seconds or HTTP date), capped; None if unusable."""
    if value is None:
        return None
    value = value.strip()
    if value.isascii() and value.isdigit():
        seconds = int(value)
    else:
        try:
            seconds = int((parsedate_to_datetime(value) - now).total_seconds())
        except (TypeError, ValueError, IndexError, OverflowError):
            return None
    return min(max(seconds, 0), MAX_RETRY_AFTER_SECONDS)


def _rfc3339(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True)
class _Claim:
    """Everything one send needs, read at claim time so the send touches no database."""

    event_id: uuid.UUID
    recipient_agent_id: uuid.UUID
    conversation_id: uuid.UUID
    kind: str
    seq: int | None
    message_type: str | None
    sender_agent_id: uuid.UUID
    reason: str
    created_at: datetime
    attempt: int  # attempt_count after the lease bump
    lease_until: datetime  # next_attempt_at as written by the claim
    session_ref: str | None
    url: str | None
    secret_ciphertext: bytes | None


@dataclass(frozen=True)
class _Outcome:
    status: str  # delivered | retry | retry_later | failed | dead
    label: str  # short, fixed phrase for the log line
    last_error: str | None = None
    delay_seconds: float | None = None  # for retry / retry_later
    status_code: int | None = None
    session_ref: str | None = None  # returned by the receiver, to store
    store_session_ref: bool = False  # the response carried a sessionRef key (null included)
    refund_attempt: bool = False  # retry_later does not consume the backoff sequence
    remove_target: bool = False


def _transient(
    claim: _Claim, error: str, *, delay: float | None = None, code: int | None = None
) -> _Outcome:
    index = claim.attempt - 1
    if index >= len(BACKOFF_SCHEDULE_SECONDS):
        return _Outcome(
            "dead", "retries_exhausted", f"{error}; retries exhausted", status_code=code
        )
    chosen = BACKOFF_SCHEDULE_SECONDS[index] if delay is None else delay
    return _Outcome("retry", "retry", error, delay_seconds=chosen, status_code=code)


def _read_json_object(raw: bytes) -> dict[str, Any] | None:
    try:
        parsed = json.loads(raw)
    except ValueError:
        return None
    return parsed if isinstance(parsed, dict) else None


def classify_response(
    claim: _Claim, status_code: int, headers: httpx.Headers, raw: bytes, now: datetime
) -> _Outcome:
    """Map the receiver's answer to an outcome per docs/WAKE-EVENTS.md section 4."""
    if status_code == 200:
        data = _read_json_object(raw)
        ref = data.get("sessionRef") if data is not None else None
        if (
            data is None
            or data.get("status") not in ("accepted", "duplicate")
            or not (ref is None or (isinstance(ref, str) and len(ref) <= MAX_SESSION_REF_LENGTH))
        ):
            return _transient(claim, "invalid 200 response", code=200)
        return _Outcome(
            "delivered",
            "delivered",
            status_code=200,
            session_ref=ref,
            store_session_ref="sessionRef" in data,
        )
    if status_code == 409:
        data = _read_json_object(raw)
        if data is not None and data.get("status") == "retry_later":
            return _Outcome(
                "retry_later",
                "retry_later",
                "receiver answered retry_later",
                delay_seconds=RETRY_LATER_SECONDS,
                status_code=409,
                refund_attempt=True,
            )
        return _Outcome("failed", "refused", "http 409", status_code=409)
    if status_code == 410:
        return _Outcome(
            "failed", "gone", "http 410, wake target removed", status_code=410, remove_target=True
        )
    if status_code == 401:
        return _Outcome("dead", "unauthorized", "http 401", status_code=401)
    if status_code == 429:
        retry_after = parse_retry_after(headers.get("retry-after"), now)
        return _transient(claim, "http 429", delay=retry_after, code=429)
    if 500 <= status_code < 600:
        return _transient(claim, f"http {status_code}", code=status_code)
    if 200 <= status_code < 300:
        return _transient(claim, f"unexpected http {status_code}", code=status_code)
    return _Outcome("failed", "refused", f"http {status_code}", status_code=status_code)


# --- The task ------------------------------------------------------------------


class WakeDelivery:
    """Polls for due wake events and delivers them. Use ``start`` / ``stop``."""

    def __init__(
        self,
        *,
        session_factory: Callable[[], async_sessionmaker[AsyncSession]] | None = None,
        client: httpx.AsyncClient | None = None,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        loop_interval: float = LOOP_INTERVAL_SECONDS,
        send_timeout: float = SEND_TIMEOUT_SECONDS,
        max_concurrent: int = MAX_CONCURRENT_SENDS,
    ) -> None:
        self._session_factory = session_factory or (lambda: get_session_factory())
        self._client = client
        self._owns_client = client is None
        self._clock = clock
        self._loop_interval = loop_interval
        self._send_timeout = send_timeout
        self._max_concurrent = max_concurrent
        self._loop_task: asyncio.Task[None] | None = None
        self._in_flight: set[asyncio.Task[None]] = set()

    # -- lifecycle --

    async def start(self) -> None:
        if self._loop_task is not None:
            return
        if self._client is None:
            self._client = httpx.AsyncClient(
                mounts=tailnet_proxy_mounts(),
                timeout=httpx.Timeout(self._send_timeout),
                follow_redirects=False,
            )
        self._loop_task = asyncio.create_task(self._run(), name="wake-delivery")

    async def stop(self) -> None:
        """Cancel the loop and any sends in flight, then close the client.

        A cancelled send leaves its event leased; the lease expires and the
        event is sent again (at least once).
        """
        tasks = [t for t in (self._loop_task, *self._in_flight) if t is not None]
        self._loop_task = None
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self._in_flight.clear()
        if self._client is not None and self._owns_client:
            await self._client.aclose()
            self._client = None

    async def _run(self) -> None:
        while True:
            try:
                await self.tick()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.error("wake delivery tick failed: %s", type(exc).__name__)
            await asyncio.sleep(self._loop_interval)

    # -- one pass --

    async def tick(self) -> int:
        """Dead-letter expired events, claim what is due and start sending it. Returns claims."""
        now = self._clock()
        await self._dead_letter_expired(now)
        # Paused (docs/WAKE-EVENTS.md section 11): claim and send nothing, leave
        # attempt counts alone. If the read fails the tick fails (logged by the
        # loop) and nothing is sent: the claim that follows needs the same database.
        async with self._session_factory()() as session:
            if await is_delivery_paused(session):
                return 0
        free = self._max_concurrent - len(self._in_flight)
        if free <= 0:
            return 0
        claims = await self._claim(free, now)
        for claim in claims:
            task = asyncio.create_task(self._deliver(claim), name=f"wake-send-{claim.event_id}")
            self._in_flight.add(task)
            task.add_done_callback(self._in_flight.discard)
        return len(claims)

    async def drain(self) -> None:
        """Wait for sends in flight (used by tests)."""
        while self._in_flight:
            await asyncio.gather(*list(self._in_flight), return_exceptions=True)

    async def _dead_letter_expired(self, now: datetime) -> None:
        async with self._session_factory()() as session:
            await session.execute(
                update(WakeEvent)
                .where(
                    WakeEvent.status.in_(_OPEN_STATUSES),
                    WakeEvent.created_at <= now - EVENT_LIFETIME,
                )
                .values(
                    status="dead", next_attempt_at=None, last_error="not delivered within 24 hours"
                )
            )
            await session.commit()

    async def _claim(self, limit: int, now: datetime) -> list[_Claim]:
        ev = WakeEvent
        older = aliased(WakeEvent)
        paused = aliased(WakeEvent)

        def order_key(t: Any) -> Any:
            return tuple_(func.coalesce(t.seq, -1), t.created_at, t.id)

        blocked_by_older = exists().where(
            older.recipient_agent_id == ev.recipient_agent_id,
            older.conversation_id == ev.conversation_id,
            older.status.in_(_OPEN_STATUSES),
            order_key(older) < order_key(ev),
        )
        recipient_paused_not_due = exists().where(
            paused.recipient_agent_id == ev.recipient_agent_id,
            paused.status == "retry_later",
            paused.next_attempt_at > now,
        )
        recipient_paused = exists().where(
            paused.recipient_agent_id == ev.recipient_agent_id, paused.status == "retry_later"
        )
        stmt = (
            select(
                ev,
                WakeTarget.url,
                WakeTarget.secret_ciphertext,
                WakeSession.session_ref,
                WakeSession.closed_at,
                WakeSession.last_activity_at,
            )
            .outerjoin(WakeTarget, WakeTarget.agent_id == ev.recipient_agent_id)
            .outerjoin(
                WakeSession,
                and_(
                    WakeSession.agent_id == ev.recipient_agent_id,
                    WakeSession.conversation_id == ev.conversation_id,
                ),
            )
            .where(
                ev.status.in_(_OPEN_STATUSES),
                or_(ev.next_attempt_at.is_(None), ev.next_attempt_at <= now),
                ev.created_at > now - EVENT_LIFETIME,
                ~blocked_by_older,
                ~recipient_paused_not_due,
                # A paused recipient is sent only a retry_later event (the probe).
                or_(ev.status == "retry_later", ~recipient_paused),
            )
            .order_by(ev.created_at, ev.id)
            .limit(CLAIM_SCAN_LIMIT)
            .with_for_update(of=ev, skip_locked=True)
        )
        claims: list[_Claim] = []
        async with self._session_factory()() as session:
            probed: set[uuid.UUID] = set()
            for event, url, ciphertext, session_ref, closed_at, last_activity_at in (
                await session.execute(stmt)
            ).all():
                if len(claims) >= limit:
                    break
                if event.status == "retry_later":
                    if event.recipient_agent_id in probed:
                        continue  # exactly one probe per recipient
                    probed.add(event.recipient_agent_id)
                # sessionRef only travels while the conversation is open (section 3.1).
                is_open = (
                    closed_at is None
                    and last_activity_at is not None
                    and last_activity_at >= now - timedelta(seconds=WAKE_SESSION_WINDOW_SECONDS)
                )
                ref = session_ref if is_open else None
                event.attempt_count += 1
                lease_until = now + timedelta(seconds=LEASE_SECONDS)
                event.next_attempt_at = lease_until
                event.session_ref_sent = ref
                claims.append(
                    _Claim(
                        event_id=event.id,
                        recipient_agent_id=event.recipient_agent_id,
                        conversation_id=event.conversation_id,
                        kind=event.kind,
                        seq=event.seq,
                        message_type=event.message_type,
                        sender_agent_id=event.sender_agent_id,
                        reason=event.reason,
                        created_at=event.created_at,
                        attempt=event.attempt_count,
                        lease_until=lease_until,
                        session_ref=ref,
                        url=url,
                        secret_ciphertext=ciphertext,
                    )
                )
            await session.commit()  # writes the leases and releases the row locks
        return claims

    # -- one delivery --

    async def _deliver(self, claim: _Claim) -> None:
        try:
            outcome = await self._attempt(claim)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # never let one event stop the others
            outcome = _transient(claim, f"internal error ({type(exc).__name__})")
        logger.info(
            "wake delivery event=%s recipient=%s attempt=%d outcome=%s status_code=%s",
            claim.event_id,
            claim.recipient_agent_id,
            claim.attempt,
            outcome.label,
            outcome.status_code,
        )
        try:
            await self._record(claim, outcome)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            # The lease expires and the event is sent again.
            logger.error(
                "wake delivery event=%s outcome not recorded: %s",
                claim.event_id,
                type(exc).__name__,
            )

    async def _attempt(self, claim: _Claim) -> _Outcome:
        if claim.url is None or claim.secret_ciphertext is None:
            return _Outcome("failed", "no_target", "no wake target registered")
        parts = urlsplit(claim.url)
        patterns = parse_allowed_hosts(os.environ.get(WAKE_TARGET_ALLOWED_HOSTS_ENV_VAR))
        if not patterns:
            # An empty or all-malformed allowlist is an operator mistake, possibly a
            # transient one (bad deploy). Send nothing, give the attempt back and look
            # again soon, so no event is lost to it; the 24-hour limit still applies.
            return _Outcome(
                "retry",
                "allowlist_misconfigured",
                "host allowlist is empty or invalid",
                delay_seconds=ALLOWLIST_MISCONFIGURED_RETRY_SECONDS,
                refund_attempt=True,
            )
        if (
            parts.scheme != "https"
            or not parts.hostname
            or not host_is_allowed(parts.hostname, patterns)
        ):
            return _Outcome(
                "failed", "host_not_allowed", "wake target host is not on the allowed host list"
            )
        try:
            secret = decrypt_secret(claim.secret_ciphertext)
            body_time = self._clock()
            timestamp = str(int(body_time.timestamp()))
            body = json.dumps(
                {
                    "eventId": str(claim.event_id),
                    "name": "comms.wake",
                    "timestamp": _rfc3339(claim.created_at),
                    "data": {
                        "kind": claim.kind,
                        "recipientAgentId": str(claim.recipient_agent_id),
                        "conversationId": str(claim.conversation_id),
                        "seq": claim.seq,
                        "messageType": claim.message_type,
                        "senderAgentId": str(claim.sender_agent_id),
                        "sessionRef": claim.session_ref,
                        "reason": claim.reason,
                    },
                    "cursor": None,
                },
                separators=(",", ":"),
            ).encode()
            signature = sign(secret, str(claim.event_id), timestamp, body)
        except Exception as exc:
            return _transient(claim, f"cannot sign ({type(exc).__name__})")
        headers = {
            "content-type": "application/json",
            "webhook-id": str(claim.event_id),
            "webhook-timestamp": timestamp,
            "webhook-signature": signature,
        }
        assert self._client is not None
        try:
            # httpx timeouts apply per operation; this bounds the whole exchange.
            async with asyncio.timeout(self._send_timeout):
                async with self._client.stream(
                    "POST", claim.url, content=body, headers=headers
                ) as response:
                    raw = b""
                    async for chunk in response.aiter_bytes():
                        raw += chunk
                        if len(raw) >= MAX_RESPONSE_BYTES:
                            break
                    status_code, response_headers = response.status_code, response.headers
        except TimeoutError:
            return _transient(claim, "timeout")
        except httpx.HTTPError as exc:
            return _transient(claim, f"network error ({type(exc).__name__})")
        return classify_response(
            claim, status_code, response_headers, raw[:MAX_RESPONSE_BYTES], self._clock()
        )

    async def _record(self, claim: _Claim, outcome: _Outcome) -> None:
        now = self._clock()
        values: dict[str, Any] = {"status": outcome.status, "next_attempt_at": None}
        if outcome.last_error is not None:
            values["last_error"] = outcome.last_error
        if outcome.delay_seconds is not None:
            values["next_attempt_at"] = now + timedelta(seconds=outcome.delay_seconds)
        if outcome.refund_attempt:
            values["attempt_count"] = claim.attempt - 1
        if outcome.status == "delivered":
            values["delivered_at"] = now
        async with self._session_factory()() as session:
            result = await session.execute(
                update(WakeEvent)
                .where(
                    WakeEvent.id == claim.event_id,
                    WakeEvent.attempt_count == claim.attempt,
                    # The lease identifies this claim even if a refund reused the count.
                    WakeEvent.next_attempt_at == claim.lease_until,
                    WakeEvent.status.in_(_OPEN_STATUSES),
                )
                .values(**values)
            )
            if result.rowcount == 0:  # type: ignore[attr-defined]
                logger.info(
                    "wake delivery event=%s outcome superseded, not recorded", claim.event_id
                )
                return
            if outcome.status == "delivered":
                # A sessionRef key in the answer (null included) replaces the stored ref;
                # an answer without the key leaves it. Only an open conversation holds one.
                if outcome.store_session_ref:
                    await session.execute(
                        update(WakeSession)
                        .where(
                            WakeSession.agent_id == claim.recipient_agent_id,
                            WakeSession.conversation_id == claim.conversation_id,
                            WakeSession.closed_at.is_(None),
                            WakeSession.last_activity_at
                            >= now - timedelta(seconds=WAKE_SESSION_WINDOW_SECONDS),
                        )
                        .values(session_ref=outcome.session_ref)
                    )
                # The recipient accepts again: its paused events flow, in order.
                await session.execute(
                    update(WakeEvent)
                    .where(
                        WakeEvent.recipient_agent_id == claim.recipient_agent_id,
                        WakeEvent.status == "retry_later",
                    )
                    .values(status="retry", next_attempt_at=now)
                )
            if outcome.remove_target:
                removed = (
                    await session.execute(
                        delete(WakeTarget)
                        .where(
                            WakeTarget.agent_id == claim.recipient_agent_id,
                            # Not a target an admin has replaced since the claim.
                            WakeTarget.url == claim.url,
                            WakeTarget.secret_ciphertext == claim.secret_ciphertext,
                        )
                        .returning(WakeTarget.system_label)
                    )
                ).scalar_one_or_none()
                if removed is not None:
                    _audit(
                        session,
                        actor_sub=SYSTEM_ACTOR,
                        action="wake_target.removed",
                        agent_id=claim.recipient_agent_id,
                        detail={
                            "reason": "receiver_answered_410",
                            "system": removed,
                            "host": urlsplit(claim.url or "").hostname,
                            "event_id": str(claim.event_id),
                        },
                    )
            await session.commit()


@contextlib.asynccontextmanager
async def wake_delivery_lifespan(server: Any) -> AsyncIterator[dict[str, Any]]:
    """FastMCP lifespan: run the delivery task for as long as the server runs."""
    delivery = WakeDelivery()
    await delivery.start()
    try:
        yield {}
    finally:
        await delivery.stop()


__all__ = [
    "ALLOWLIST_MISCONFIGURED_RETRY_SECONDS",
    "BACKOFF_SCHEDULE_SECONDS",
    "CLAIM_SCAN_LIMIT",
    "EVENT_LIFETIME",
    "LEASE_SECONDS",
    "LOOP_INTERVAL_SECONDS",
    "MAX_CONCURRENT_SENDS",
    "MAX_RETRY_AFTER_SECONDS",
    "RETRY_LATER_SECONDS",
    "SEND_TIMEOUT_SECONDS",
    "WakeDelivery",
    "parse_retry_after",
    "sign",
    "wake_delivery_lifespan",
]
