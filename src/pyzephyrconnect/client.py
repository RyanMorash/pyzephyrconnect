"""Facade tying auth, REST and MQTT into one lifecycle.

Read strategy is hybrid by design: discoverdevice supplies capabilities and
an initial state over plain HTTPS before MQTT exists, MQTT then carries live
push, and discoverdevice remains available as a fallback so consumers degrade
to slower updates instead of going unavailable.

Three behaviours here are deliberate and documented rather than changed:

- `token_updater` runs on the event loop. Persisting usually means a storage
  write, so the callback must be non-blocking; a consumer that needs I/O
  should schedule it rather than perform it inline.
- paho's own auto-reconnect races the supervisor. After credential expiry
  paho retries the presigned URL on a 1-120s backoff and fails every time
  until the supervisor rebuilds it. Noisy but self-correcting, and worth
  keeping: for an ordinary network drop the URL is still valid and paho's
  reconnect is the faster fix.
- A REST 403 raises rather than forcing a refresh and retrying once.
  `async_get_tokens()` already refreshes inside a 10-minute margin, so a 403
  means the token was genuinely rejected (revocation, or a vendor-side
  change), which retrying cannot fix.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Callable
from typing import Any

import aiohttp

from . import const
from .api import ZephyrApi
from .auth import AbstractAuth, Credentials, CredentialsAuth, ZephyrTokens
from .const import DEFAULT_ENDPOINTS, Endpoints
from .exceptions import ZephyrAuthError, ZephyrError, ZephyrPolicyError
from .hood import Hood
from .models import HoodCapabilities, HoodState
from .shadow import ShadowClient

_LOGGER = logging.getLogger(__name__)

# discoverdevice responses are a flat dict mixing shadow-state fields with
# device identifiers. These must never enter HoodState.raw (its default
# dataclass repr, and hence any careless log of a cached state, would carry
# them). Shadow messages over MQTT carry a clean state.reported block with
# none of these keys - see tests/fixtures/shadow_get_accepted.json versus
# tests/fixtures/discoverdevice.json - so only discoverdevice-derived state
# construction needs filtering; HoodCapabilities legitimately keeps them.
_PERSONAL_DATA_KEYS = ("thingName", "SN", "MAC", "location")


class ZephyrClient:
    """One authenticated account and the hoods under it."""

    def __init__(self, auth: AbstractAuth) -> None:
        self._auth = auth
        # Deliberately NOT a separate constructor argument. The auth object
        # already carries the endpoints and ZephyrApi reads them from there,
        # so a second source would let REST and MQTT point at different
        # clouds with nothing complaining.
        self._endpoints = auth.endpoints
        self._api = ZephyrApi(auth)
        self._hoods: dict[str, Hood] = {}
        # The setup sentinel. NOT _hoods, which breaks both ways: an
        # account with zero devices leaves it empty, so a second full setup
        # was permitted, and a failure partway through the discovery loop
        # left it partially filled, so the client looked initialized and
        # the failed setup could never be retried.
        self._setup_complete = False
        self._supervisor: asyncio.Task[None] | None = None
        self._supervisor_error: ZephyrError | None = None
        # Attribute, not the bare constant: tests drive the supervisor with
        # a zero interval instead of waiting a real minute.
        self._supervisor_interval: float = const.SUPERVISOR_INTERVAL_SECONDS
        # The IoT policy binding persists per identity. Keyed on WHICH
        # identity it was attached for, not a bare bool: a mid-session
        # identity refetch (AbstractAuth._identity_override) must trigger a
        # re-attach for the new identity, or every message on the next
        # reconnect is silently dropped - the exact failure the attach
        # exists to prevent.
        self._policy_attached_for: str | None = None
        # The latch above is read-modify-write across an await, so it needs
        # a lock: two hoods starting concurrently both pass the check and
        # both attach, and if an identity refetch lands between them the
        # interleaved writes can record the OLD identity as attached-for
        # while the NEW one never got the policy - the silent
        # message-drop failure the attach exists to prevent.
        self._policy_lock = asyncio.Lock()

    @classmethod
    def from_credentials(
        cls,
        username: str,
        password: str,
        session: aiohttp.ClientSession,
        *,
        tokens: ZephyrTokens | None = None,
        token_updater: Callable[[ZephyrTokens], None] | None = None,
        endpoints: Endpoints = DEFAULT_ENDPOINTS,
    ) -> ZephyrClient:
        """Convenience path: build a CredentialsAuth and a client from it.

        Supply `tokens` from a previous session and `token_updater` to
        persist new ones, and a restart will skip the SRP login entirely.

        `token_updater` is called on the event loop, so it must not block.
        Persisting usually means a storage write; a consumer that needs I/O
        should schedule it rather than perform it inline.
        """
        return cls(
            CredentialsAuth(
                username,
                password,
                session,
                tokens=tokens,
                token_updater=token_updater,
                endpoints=endpoints,
            )
        )

    @property
    def identity_id(self) -> str:
        """Cognito identity ID. Stable per account; a natural unique key.

        Reads the identity straight off the auth object. Do not reconstruct
        it by stripping the suffix off mqtt_client_id - that derives a source
        from its own derivative and returns a wrong value the day
        CLIENT_ID_SUFFIX changes.

        Raises ZephyrAuthError before the first credential exchange, which
        async_setup() performs.
        """
        return self._auth.identity_id

    @property
    def connected(self) -> bool:
        """True while at least one hood has a live push connection.

        Derived from the hoods rather than a single latched flag, which with
        more than one hood reported whichever shadow changed state last.
        """
        return any(hood.connected for hood in self._hoods.values())

    async def async_setup(self) -> list[Hood]:
        """Authenticate and discover every hood on the account."""
        if self._setup_complete:
            # Re-running setup would replace started Hood objects while
            # their sockets and the supervisor still reference the old ones.
            # One client = one setup; build a new client to re-discover.
            # Checked before the credential exchange below so a repeat call
            # fails fast instead of paying for a needless network round trip.
            raise ZephyrError("async_setup() has already run on this client")
        # Start every (re)attempt from empty: a previous attempt that raised
        # partway through the loop below left entries behind, and appending
        # to them would return duplicate and stale hoods. Discarding them is
        # safe precisely because nothing has started them - async_setup only
        # builds Hood objects, so there is no socket or paho thread to leak.
        self._hoods = {}
        # The full chain, not just tokens: this performs the identity
        # exchange, which is what makes auth.identity_id readable - the
        # config-flow ordering "async_setup(), then read identity_id for
        # the unique ID" depends on it. Also exactly what the pre-refactor
        # authenticate() verified at setup.
        await self._auth.async_get_credentials()
        devices = await self._api.get_own_devices()
        if not isinstance(devices, list):
            # get_own_devices is typed to return a list, but this is the
            # last line of defense against a vendor response shape change -
            # iterating a dict would silently walk its keys instead of
            # raising, and a scalar would blow up with a bare TypeError.
            _LOGGER.warning("getowndevices returned an unexpected shape; no devices")
            devices = []
        for device in devices:
            if not isinstance(device, dict):
                # Same defense, per-entry: a malformed list element must not
                # reach device.get() below and raise AttributeError.
                _LOGGER.warning("skipping a malformed device entry")
                continue
            if not (thing_name := device.get("thingName")):
                # A KeyError here would escape ZephyrError and reach the
                # consumer as an unknown crash rather than a setup retry.
                _LOGGER.warning("skipping a device with no thingName")
                continue
            payload = await self._api.discover_device(thing_name)
            caps = HoodCapabilities.from_discover(payload)
            hood = Hood(
                caps, self._make_shadow, self._poll_state, self._ensure_policy
            )
            hood.handle_state(self._state_from_discover(payload))
            self._hoods[thing_name] = hood
        # Only once the loop has run to completion. Setting it earlier would
        # latch a half-discovered account as done and make the failure
        # unretryable.
        self._setup_complete = True
        return list(self._hoods.values())

    async def async_stop(self) -> None:
        """Stop every hood and retire the supervisor.

        Stopping a hood directly via `hood.async_stop()` does NOT retire the
        supervisor - only THIS method does. The supervisor is scoped to the
        client, not to any one hood, and keeps ticking (renewing credentials,
        reconnecting whatever is still `_should_run`) until this cancels it.
        """
        if self._supervisor is not None:
            self._supervisor.cancel()
            # Await it. Cancelling without awaiting can leave a hood halfway
            # through async_reconnect() with no socket and no supervisor, and
            # lets the task be collected with an unretrieved CancelledError.
            # Suppress BaseException, not just CancelledError: a supervisor
            # that died with some other exception would otherwise re-raise
            # it here, which skips the hood-stopping loop below entirely -
            # leaking a paho network thread per hood on every consumer
            # reload - and leaves _supervisor set, so _ensure_supervisor's
            # `is None or .done()` check never restarts it and every retry
            # fails forever. The exception itself is not lost: _supervise's
            # own except clauses already logged it before the task exited.
            with contextlib.suppress(BaseException):
                await self._supervisor
            self._supervisor = None
        # A cancellation reaching this loop must not strand the hoods that
        # have not been torn down yet, and must not be swallowed either.
        # Note this is also where a CALLER's cancellation resurfaces: the
        # suppress(BaseException) above swallows it at the supervisor await,
        # and asyncio re-delivers a pending cancellation at the next await
        # point - which is this loop - so both cases funnel through here.
        cancelled = False
        for hood in self._hoods.values():
            try:
                await hood.async_stop()
            except asyncio.CancelledError:
                # Caught apart from Exception below, and the loop CONTINUES:
                # letting this propagate would leak a paho network thread
                # per remaining hood on every consumer reload.
                cancelled = True
            except Exception:  # noqa: BLE001
                # One hood's teardown failure must not strand the others -
                # each hood owns its own socket and paho thread.
                _LOGGER.exception("stopping a hood failed; continuing")
        if cancelled:
            # Every hood is down now, so the cancellation can be honoured
            # rather than silently dropped - a caller that cancelled this
            # shutdown must still see its CancelledError.
            raise asyncio.CancelledError

    # -- internals -----------------------------------------------------

    async def _ensure_policy(self) -> None:
        """Attach the IoT policy. Idempotent, and latched after the first run.

        Passed to each Hood as its `prepare` callable, so it always runs
        before the first connect and never on a reconnect.

        Serialised: hoods start concurrently, and the latch is a
        read-modify-write spanning an await. The identity is re-read INSIDE
        the lock, so a waiter that queued behind an attach for identity A
        latches whichever identity is current when its own attach runs -
        never A over a newer B.
        """
        async with self._policy_lock:
            # Re-read, not the value captured before the lock: an identity
            # refetch can land while this call is queued, and latching the
            # stale one would record the new identity as attached-for
            # without it ever having received the policy.
            identity = self._auth.identity_id
            if self._policy_attached_for == identity:
                return
            await self._auth.async_attach_policy()
            self._policy_attached_for = identity

    def _make_shadow(self, hood: Hood) -> ShadowClient:
        async def provider() -> Credentials:
            creds = await self._auth.async_get_credentials()
            # Record which credential generation this socket's URL is signed
            # under - the supervisor reconnects on mismatch, because expiry
            # alone lies when a REST call refreshed the cache first.
            hood.note_presigned_generation(self._auth.credentials_generation)
            return creds

        shadow = ShadowClient(
            hood.thing_name,
            # Per-CONNECTION client ID. AWS IoT treats two live connections
            # with the same ID as one session and evicts one for the other,
            # so N hoods sharing the bare mqtt_client_id would flap forever.
            # Identity-prefixed, so the policy's prefix-match still covers
            # it (PROTOCOL.md section 5).
            #
            # The FULL thing name, not a truncated 8-char prefix (deviation
            # from the original design, controller-authorized): two things
            # sharing an 8-char prefix got IDENTICAL client IDs under the
            # truncated form, which is the exact same-ID eviction this
            # suffix exists to prevent. identity (~50 chars) + "-" + a
            # 40-hex thing name stays comfortably under AWS IoT's 128-char
            # client-ID limit.
            f"{self._auth.mqtt_client_id}-{hood.thing_name}",
            lambda topic, payload: self._handle_message(hood, topic, payload),
            hood.handle_connection_change,
            # The per-hood wrapper, not async_get_credentials itself:
            # ShadowClient calls this on every connect, which is exactly
            # when the presigned URL is (re)built, so the generation it
            # records self-updates on reconnects.
            provider,
            # Without this the ShadowClient falls back to DEFAULT_ENDPOINTS,
            # so an endpoint override would reach REST but silently leave
            # MQTT pointed at production.
            endpoints=self._endpoints,
        )
        self._ensure_supervisor()
        return shadow

    def _ensure_supervisor(self) -> None:
        if self._supervisor is None or self._supervisor.done():
            # A fresh supervisor supersedes any stored terminal error -
            # otherwise the error outlives the condition that caused it and
            # every later poll raises.
            self._supervisor_error = None
            self._supervisor = asyncio.create_task(self._supervise())

    async def _poll_state(self, thing_name: str) -> HoodState:
        """Read one hood's state over HTTPS. Passed to Hood as its `poll`.

        Re-raises a stored terminal supervisor error before doing anything
        else, so an auth failure that stopped the supervisor becomes a
        reauth on the consumer's next tick rather than a hood that quietly
        stops updating.

        Deliberately lock-free: this is the degraded-mode read path and must
        not queue behind a reconnect that may itself be stuck.
        """
        if self._supervisor_error is not None:
            # A fresh instance, not the stored object: re-raising the SAME
            # exception appends frames to its __traceback__ on every poll
            # (this method, Hood.async_poll, the consumer's own frame) -
            # unbounded while a consumer keeps polling through a terminal
            # error that never clears. These exceptions carry only a
            # message, so type(err)(*err.args) reconstructs one losslessly.
            err = self._supervisor_error
            raise type(err)(*err.args) from err
        payload = await self._api.discover_device(thing_name)
        return self._state_from_discover(payload)

    def _state_from_discover(self, payload: dict[str, Any]) -> HoodState:
        """Build state from a discoverdevice payload, minus the identifiers.

        See _PERSONAL_DATA_KEYS: this response is a flat dict mixing shadow
        fields with identifiers, and those must never enter HoodState.raw.
        """
        return HoodState.from_reported(
            {k: v for k, v in payload.items() if k not in _PERSONAL_DATA_KEYS}
        )

    def _handle_message(
        self, hood: Hood, topic: str, payload: dict[str, Any]
    ) -> None:
        """Fold an incoming shadow message into one hood's state.

        get/accepted carries a full document; update/accepted carries only
        what changed, so it is merged rather than replacing the cache.
        update/delta is deliberately NOT merged - see the comment on that
        branch below.

        Runs on the asyncio loop: ShadowClient._dispatch schedules this via
        loop.call_soon_threadsafe. Nothing here may raise - an escaped
        exception hits asyncio's default exception handler, which logs the
        callback and its arguments (the topic, which embeds the thing name,
        and the raw payload) at ERROR. _on_message only catches JSON *parse*
        errors, so valid-but-wrong-shaped JSON (e.g. the literal `null`, or
        an array) still reaches here - hence the explicit shape guard below
        in addition to the try/except backstop. Diagnostics are limited to
        the topic's leaf segment (accepted/delta/rejected), which carries no
        identifiers.
        """
        if not isinstance(payload, dict):
            _LOGGER.warning(
                "shadow message on %s had an unexpected shape (not an "
                "object); ignoring",
                topic.rsplit("/", 1)[-1],
            )
            return

        try:
            if topic.endswith("/rejected"):
                # Do not log the payload: a rejection can echo back the
                # desired/reported fields it rejected, including identifiers.
                _LOGGER.warning(
                    "shadow operation rejected on %s", topic.rsplit("/", 1)[-1]
                )
                return

            state_block = payload.get("state") or {}
            if topic.endswith("/get/accepted"):
                reported = state_block.get("reported") or {}
                new_state = HoodState.from_reported(reported)
            elif topic.endswith("/update/accepted"):
                reported = state_block.get("reported") or {}
                current = hood.state
                new_state = (
                    current.merge(reported)
                    if current
                    else HoodState.from_reported(reported)
                )
            elif topic.endswith("/update/delta"):
                # A shadow delta is desired-vs-reported difference - a wish,
                # not confirmed device state. This vendor never writes
                # state.desired (see ShadowClient.publish_state), so any
                # delta observed here can only originate from a stale or
                # foreign desired write and never represents what the
                # hardware actually did. Folding it into the cache
                # previously made the probe report a "change" the device
                # had not - and might never - make, which is exactly what
                # disguised the state.desired/state.reported root-cause bug.
                # Deliberately a no-op: log at DEBUG and drop it.
                _LOGGER.debug(
                    "ignoring shadow delta on %s (never device-authored)",
                    topic.rsplit("/", 1)[-1],
                )
                return
            else:
                return

            # Hood.handle_state notifies listeners and swallows their
            # exceptions, so one bad consumer cannot stop the others.
            hood.handle_state(new_state)
        except Exception:  # noqa: BLE001
            # One malformed message must not escape onto the event loop.
            # Log leaf-only - never the thing name, full topic, or payload.
            _LOGGER.exception(
                "unhandled error processing shadow message on %s",
                topic.rsplit("/", 1)[-1],
            )

    # -- the refresh supervisor ----------------------------------------

    async def _supervise(self) -> None:
        """Keep credentials fresh and sockets alive.

        The presigned WebSocket URL embeds a SigV4 signature over
        credentials that expire in an hour. AWS IoT drops the session at
        expiry and paho reconnects to the same dead URL indefinitely, so
        push must be rebuilt from this side before that happens.

        It does NOT re-attach the IoT policy: per PROTOCOL.md section 3.3
        the binding persists on the identity. _ensure_policy owns that, and
        is keyed on the identity so a refetch still re-attaches.
        """
        while True:
            # The try is INSIDE the loop deliberately. A transient failure -
            # a DNS blip during one refresh cycle - must not end supervision,
            # because the consequence is not a logged error, it is push dying
            # silently an hour later.
            try:
                await asyncio.sleep(self._supervisor_interval)
                await self._refresh_once()
            except asyncio.CancelledError:
                raise
            except (ZephyrPolicyError, ZephyrAuthError) as err:
                # Neither of these fixes itself by retrying. A denied
                # subscribe closes the whole connection and needs the IoT
                # policy attached; a rejected credential needs the user.
                # Stop, and leave the error where async_poll() will surface
                # it - see _poll_state above.
                self._supervisor_error = err
                # Stop the hoods: the derived `connected` property flips to
                # False the moment their sockets close (a bare flag write
                # here would be dead code - the property never reads one),
                # and paho stops hammering presigned URLs that can no longer
                # be renewed. Consumer intent (_should_run) survives, so a
                # reauth that builds a new client is unaffected.
                for hood in self._hoods.values():
                    try:
                        await hood._stop_for_supervisor()
                    except Exception:  # noqa: BLE001
                        _LOGGER.exception("stopping hood after terminal error")
                # Log the TYPE, not the message - ZephyrPolicyError text may
                # name the policy, and identifiers do not belong at ERROR.
                _LOGGER.error(
                    "refresh supervisor stopping: %s", type(err).__name__
                )
                return
            except Exception:  # noqa: BLE001
                _LOGGER.exception("refresh cycle failed; retrying next tick")

    async def _refresh_once(self) -> bool:
        """Renew credentials if inside the margin; keep wanted hoods up.

        Asks `credentials_expired` rather than calling
        async_get_credentials() first: that method renews as a side effect,
        so testing its result would always report "not expired" and the
        socket would never be rebuilt.

        But expiry is only the trigger to RENEW, never the test for which
        sockets are stale - it answers "does the cache need replacing?", not
        "is this socket still signed under what the cache holds?". ZephyrApi
        calls async_get_tokens() on every REST request and CredentialsAuth
        replaces the cached credentials as a side effect, so an ordinary
        poll can refresh them minutes before this runs; the cache then looks
        fresh, this method skips the rebuild, and every live socket keeps a
        signature AWS IoT drops at the OLD expiry - paho then retries dead
        URLs for up to a full interval until the NEXT expiry. Each hood
        therefore records the credential generation its URL was presigned
        under and is rebuilt on mismatch (Hood.needs_represign).

        Per-hood try/except, terminal errors excepted: one hood's transient
        connect failure must neither abort the loop (stranding later hoods
        on expiring signatures) nor be swallowed as handled - the hood keeps
        its consumer intent and async_ensure_running retries it every tick,
        which is also how a hood whose rebuild failed LAST cycle recovers.
        """
        if self._auth.credentials_expired:
            _LOGGER.debug("credentials near expiry; refreshing")
            # Renews the Cognito tokens and re-exchanges for AWS credentials.
            await self._auth.async_get_credentials()
        current = self._auth.credentials_generation
        rebuilt = False
        for hood in self._hoods.values():
            try:
                if hood.needs_represign(current):
                    # The socket's presigned URL belongs to an older
                    # credential generation - rebuilt regardless of how
                    # fresh the credential cache looks (a REST-driven
                    # refresh replaces credentials without touching sockets).
                    await hood.async_reconnect()
                    rebuilt = True
                else:
                    # Recovery: reopens a wanted hood whose socket is gone.
                    await hood.async_ensure_running()
            except (ZephyrPolicyError, ZephyrAuthError):
                raise
            except Exception:  # noqa: BLE001
                _LOGGER.exception("hood rebuild failed; retrying next tick")
        return rebuilt
