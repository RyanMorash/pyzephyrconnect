"""One range hood: its capabilities, its state, and its controls.

The data-models guidance puts control methods on the model object rather
than on a generic client, so a consumer writes hood.async_set_fan(2) and
never learns the vendor's field spellings. That also makes the write
allowlist structural: only these methods exist.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Awaitable, Callable
from typing import Any

from . import const
from .exceptions import ZephyrNotConnectedError, ZephyrWriteError
from .models import HoodCapabilities, HoodState
from .shadow import ShadowClient

_LOGGER = logging.getLogger(__name__)

StateListener = Callable[[HoodState], None]


class _PendingWrite:
    """One command still waiting for its own echo.

    Confirmation is this command, not a later one that happens to publish
    the same level. ``baseline`` is the shadow version already applied when
    the command was sent. A document at that version, including the GET
    that was in flight before the command, is not its echo.
    """

    def __init__(self, baseline: int | None, fields: dict[str, int]) -> None:
        """Stores the version baseline and the fields this command set.

        Args:
            baseline: Shadow version already applied, or None when no
                versioned document has been applied yet.
            fields: Reported keys this command published.
        """
        self.baseline = baseline
        self.fields = fields


def _version_confirms(version: object, baseline: int | None) -> bool:
    """Reports whether a document is newer than a command's baseline.

    A missing version is not an echo: the rejection reread and an in-flight
    GET often arrive without moving the cursor, or at the same version the
    command was published against. A version equal to the baseline is that
    in-flight document, or a QoS 1 redelivery of an echo that already
    retired an earlier command. Greater-than is not by itself the
    acknowledgement. The caller still has to match one command's values,
    or a repeated level acks the wrong write.

    Args:
        version: The document's ``version`` field.
        baseline: The version applied when the command was published, or
            None when no versioned document had been applied yet.

    Returns:
        True when ``version`` is a newer shadow version than ``baseline``.
    """
    if isinstance(version, bool) or not isinstance(version, int):
        return False
    if baseline is None:
        return True
    return version > baseline


def _prepares_offline(shadow: object) -> bool:
    """Whether reconnect can presign before tearing this socket down.

    Read off the class, and only when the value is exactly True. A
    MagicMock's class does not define the flag; asking the instance would
    invent one and take the split path with methods the double does not
    implement.

    Args:
        shadow: The live session about to be replaced.
    """
    return getattr(type(shadow), "prepares_transport_before_disconnect", False) is True


class Hood:
    """A single hood on the account."""

    def __init__(
        self,
        capabilities: HoodCapabilities,
        shadow_factory: Callable[[Hood], ShadowClient],
        poll: Callable[[str], Awaitable[HoodState]],
        prepare: Callable[[], Awaitable[None]],
    ) -> None:
        """Binds the hood to the account-level callables ZephyrClient wires in.

        Args:
            capabilities: What this hood can do, from the discoverdevice
                endpoint.
            shadow_factory: Builds a new ShadowClient bound to this hood;
                invoked on every start and supervisor rebuild.
            poll: Reads current state over HTTPS for a given thing name.
            prepare: Attaches the IoT policy; awaited before each connect
                (see _start).
        """
        self._capabilities = capabilities
        self._shadow_factory = shadow_factory
        self._poll = poll
        # Runs before the first connect. Attaches the IoT policy; see _start.
        self._prepare = prepare
        self._shadow: ShadowClient | None = None
        self._state: HoodState | None = None
        self._listeners: list[StateListener] = []
        self._connected = False
        # Consumer intent: True between async_start() and async_stop().
        # Distinct from having a socket - a failed supervisor rebuild leaves
        # _shadow None while the hood SHOULD still be running, and keying
        # recovery on _shadow alone demotes it to "never started" forever.
        self._should_run = False
        # Which AWS credential generation this hood's live socket was
        # presigned under, recorded by the credentials provider ZephyrClient
        # wires in (so a reconnect updates it without anyone remembering
        # to). None until the first presign.
        self._presigned_generation: int | None = None
        # Newest shadow `version` applied from get/accepted or
        # update/accepted. An in-flight GET from before a write carries an
        # older version and must not replace the newer snapshot. None until
        # a versioned document arrives; a document with no version keeps
        # today's apply-anyway behaviour and does not move this cursor.
        self._shadow_version: int | None = None
        # Commands whose echo has not arrived, oldest first. The latest
        # value of a key is what the cache shows. One document retires at
        # most one command, the oldest whose values it actually carries,
        # and only when it is newer than that command's baseline. A partial
        # echo of a later command must not wait behind an older command it
        # does not mention, and it must not consume a redelivery of the
        # version that already retired something ahead of it. Matching the
        # value alone acks the wrong write when the same level is published
        # twice. The queue is dropped when the session that published it is
        # gone; a later GET must be able to show what the device or the
        # phone did during the outage. Dangerous fields are never entered
        # here.
        self._pending_writes: list[_PendingWrite] = []
        # Shadow version at which each reported key was last merged.
        # update/accepted is partial, so a newer document does not contain
        # the keys an older one changed. The global cursor cannot decide
        # that for a single key: version 12 reporting fan does not make
        # version 11's light stale, and version 11's light must not
        # overwrite a light already applied from version 14.
        self._field_versions: dict[str, int] = {}
        # One in-flight reread after update/rejected. A rejected optimistic
        # write would otherwise stick until something else refreshed state.
        self._reread_task: asyncio.Task[None] | None = None
        # Serialises start/stop/reconnect against writes.
        self._lock = asyncio.Lock()

    @property
    def thing_name(self) -> str:
        """The hood's AWS IoT thing name."""
        return self._capabilities.thing_name

    @property
    def capabilities(self) -> HoodCapabilities:
        """What this hood can do, from the discoverdevice endpoint."""
        return self._capabilities

    @property
    def state(self) -> HoodState | None:
        """Latest known state, or None before the first report."""
        return self._state

    # -- lifecycle -----------------------------------------------------

    @property
    def connected(self) -> bool:
        """Whether THIS hood's shadow connection is up.

        Per-hood, not per-account: with several hoods one dropping must not
        report the others as down.
        """
        return self._connected

    def handle_connection_change(self, connected: bool) -> None:
        """Records the new connection state for this hood.

        Called by ShadowClient from the event loop. paho's own
        auto-reconnect does not come through ``_stop``. The disconnect
        callback is the only point that knows the session which published
        the pending commands is gone. Leaving them pending paints the
        missed write over the resync GET, so a change made during the
        outage never shows. A write that lands after this callback belongs
        to the session that came back and stays pending. ``_stop`` already
        drops the queue before it awaits disconnect; this clear is the
        same drop for the path that never calls ``_stop``.

        Args:
            connected: Whether this hood's shadow connection is now up.
        """
        self._connected = connected
        if not connected:
            self.discard_unconfirmed_writes()

    async def async_start(self) -> None:
        """Opens this hood's shadow connection and requests current state."""
        async with self._lock:
            self._should_run = True
            try:
                await self._start()
            except BaseException:
                # A CONSUMER-facing start that raises must leave the hood
                # genuinely stopped. Home Assistant's ConfigEntryNotReady
                # pattern abandons the client whose setup failed and builds a
                # fresh one on the retry; intent surviving here would let the
                # supervisor bring the abandoned hood back up in the
                # background, and its per-connection MQTT client IDs are
                # IDENTICAL to the replacement client's - AWS IoT treats two
                # live connections sharing an ID as one session and evicts
                # the working one for the zombie.
                #
                # Only this path rolls back. The supervisor-internal paths
                # (async_reconnect, async_ensure_running, _stop_for_supervisor)
                # call _start/_stop directly and keep the intent-survival
                # semantics unchanged: nobody asked for those, so a transient
                # failure there must stay recoverable on the next tick.
                self._should_run = False
                raise

    async def async_stop(self) -> None:
        """Closes this hood's shadow connection and drops the intent to run.

        With _should_run cleared the supervisor will not bring the hood
        back up. This does not retire the account-level supervisor itself -
        that is ZephyrClient.async_stop's job.
        """
        async with self._lock:
            self._should_run = False
            await self._stop()

    async def async_reconnect(self) -> None:
        """Rebuilds the socket after a credential refresh.

        The presigned URL is derived from credentials that expire, so a
        refresh without a reconnect leaves a socket AWS IoT will drop.

        A write that arrives during the blackout waits and then publishes
        once, rather than failing with a spurious ZephyrNotConnectedError.
        The lock covers only the gap where there is no session that can
        publish: presign and the TLS context run first, while the old
        socket is still up, and SUBACKs plus the state GET run after the
        new session is past CONNACK. Two live sessions sharing a client ID
        evict each other, so the old socket is fully stopped before the
        new one is opened.
        """
        async with self._lock:
            if not self._should_run:
                # Never started, or deliberately stopped. The supervisor
                # calls this for every hood on the account; it must not
                # bring up MQTT for hoods the consumer chose not to start.
                return
            old = self._shadow
        if old is not None and _prepares_offline(old):
            await self._reconnect_prepared(old)
            return
        # Test doubles implement connect() as the whole handshake. That
        # call is the stand-in for "not yet past CONNACK", so it stays
        # inside the lock. The state GET does not.
        async with self._lock:
            if not self._should_run:
                return
            await self._stop()
            shadow = await self._open()
        if shadow is not None:
            await self._read_state_outside_lock(shadow)

    def note_presigned_generation(self, generation: int) -> None:
        """Records which credential generation signed the live socket's URL.

        Called when that socket is installed, from the generation the
        credentials provider stashed on the shadow while presigning. Noting
        it any earlier lets a presign that never connects, or that loses a
        race with another rebuild, describe the socket that is still up.
        ``needs_represign`` would then treat an expiring URL as current.

        Args:
            generation: The generation the installed socket was signed under.
        """
        self._presigned_generation = generation

    def _install_shadow(self, shadow: ShadowClient) -> None:
        """Records ``shadow`` as the live socket and commits its generation.

        Lock-free: callers hold ``self._lock``. The generation is copied
        only when the provider left an int on the shadow. A test double
        that never presigned leaves the hood's record alone.

        Args:
            shadow: The session that may now publish.
        """
        self._shadow = shadow
        generation = getattr(shadow, "presigned_generation", None)
        if isinstance(generation, bool) or not isinstance(generation, int):
            return
        self.note_presigned_generation(generation)

    async def _drop_failed_socket(self, shadow: ShadowClient) -> None:
        """Disconnects ``shadow`` before any other open can reuse its client ID.

        Lock-free: callers hold ``self._lock``. The live reference is
        cleared only when it still points here, so a newer session is left
        alone. The disconnect itself runs before the caller releases the
        lock either way. ``async_start`` and ``async_ensure_running`` treat
        ``_shadow is None`` as permission to connect, and a connect that
        overlaps this client's ``loop_stop`` is two sessions on one client
        ID.

        Args:
            shadow: The session whose handshake or state GET failed.
        """
        if self._shadow is shadow:
            self._shadow = None
            self._connected = False
            # The session that published these commands is gone, so their
            # echoes will not arrive. Keeping them would paint the old
            # values over the GET that follows the replacement session.
            self.discard_unconfirmed_writes()
        with contextlib.suppress(Exception):
            await shadow.disconnect()

    def needs_represign(self, current: int) -> bool:
        """Reports whether the live socket is signed under stale credentials.

        The supervisor's rebuild trigger. Keyed on the generation rather
        than on `credentials_expired`, because a REST call refreshing the
        credential cache leaves the cache looking fresh while this socket
        still holds a signature AWS IoT drops at the OLD expiry.

        Requires an actual socket: a generation mismatch must never bring up
        a hood that was never started or was deliberately stopped.

        Args:
            current: The credentials provider's current generation counter.

        Returns:
            True when this hood should run, has a live socket, and that
            socket was presigned under a different generation.
        """
        return (
            self._should_run
            and self._shadow is not None
            and self._presigned_generation != current
        )

    async def async_ensure_running(self) -> None:
        """Reopens the socket if the consumer wants this hood up and it is not.

        The recovery path for a transient failure during a supervisor
        rebuild: _start raised, _shadow stayed None, and without this the
        hood would be indistinguishable from one never started - push dead
        forever with no error surfaced. Called by the supervisor every tick.
        """
        async with self._lock:
            if self._should_run and self._shadow is None:
                await self._start()

    async def _stop_for_supervisor(self) -> None:
        """Closes the socket without clearing consumer intent.

        The supervisor's terminal branch calls this: paho must stop
        hammering presigned URLs that can no longer be renewed, and the
        derived `connected` property must flip to False - but the consumer
        never asked for this hood to stop, so _should_run survives and the
        recovery path (async_ensure_running) can still bring it back.
        """
        async with self._lock:
            await self._stop()

    # _open, _start and _stop are lock-free: their callers hold self._lock.
    # asyncio.Lock is not reentrant, so those bodies must not call the
    # public methods. _read_state_outside_lock and _reconnect_prepared take
    # the lock themselves around the sections that mutate the socket.

    async def _open(self) -> ShadowClient | None:
        """Attaches the policy, connects, and records the socket.

        Lock-free: callers hold self._lock. A no-op when a socket already
        exists, so a second start cannot orphan a live paho thread. Does
        not request state; the caller decides whether that GET is inside
        the lock (first start) or after it (a rebuild).

        Returns:
            The shadow just connected, or None when one was already up.
        """
        if self._shadow is not None:
            # Already connected. Rebuilding here would orphan the previous
            # paho client with its network thread still running.
            return None
        # MUST precede connect(). An already-open MQTT connection does not
        # pick up newly attached permissions, and the failure is silent:
        # connect, subscribe and publish all succeed and every message is
        # dropped (PROTOCOL.md section 3.3). Latched by the client, so a
        # reconnect does not re-attach - the binding persists on the identity.
        await self._prepare()
        shadow = self._shadow_factory(self)
        await shadow.connect()
        self._install_shadow(shadow)
        return shadow

    async def _start(self) -> None:
        """Connects the shadow and requests state, under the caller's lock.

        Lock-free: callers hold self._lock. If the initial state request
        fails, the hood is put back in the no-socket shape the supervisor
        knows how to recover from.
        """
        shadow = await self._open()
        if shadow is None:
            return
        try:
            await shadow.request_state()
        except BaseException:
            # Without this the hood LOOKS healthy - _shadow set, so
            # async_ensure_running declines to rebuild and async_start
            # returns early - while the initial state GET never happened,
            # so nothing ever populates state and no later tick retries.
            # Put it back in the no-socket shape the supervisor knows how
            # to recover from and let the next tick rebuild.
            #
            # Cleared before the await, and _connected joins the clear for
            # the same reasons as _stop: a cancellation landing on the
            # teardown below must not leave _shadow pointing at a dead
            # client, and reporting connected=True with no socket misleads
            # the derived client.connected. BaseException, not Exception,
            # so a cancellation here tears the client down too - mirrors
            # ShadowClient.connect's own cleanup.
            self._shadow = None
            self._connected = False
            # Best-effort: the caller needs the ORIGINAL failure, not
            # whatever the teardown of a half-built client raises on top
            # of it. The paho thread still has to go either way.
            with contextlib.suppress(Exception):
                await shadow.disconnect()
            raise

    async def _read_state_outside_lock(self, shadow: ShadowClient) -> None:
        """Requests the initial document without holding the hood lock.

        A command published while this GET is in flight must not wait for
        it. On failure the socket is dropped, and that disconnect finishes
        before the lock is released. ``async_start`` and
        ``async_ensure_running`` open a session as soon as ``_shadow`` is
        None; doing that while this client's network thread is still inside
        ``loop_stop`` puts two sessions on one client ID. AWS IoT evicts
        one, and the old disconnect callback then marks the survivor down.

        Args:
            shadow: The session the GET belongs to. Ignored if a newer
                session has already replaced it.

        Raises:
            Exception: Whatever ``request_state`` raised, after teardown.
        """
        try:
            await shadow.request_state()
        except BaseException:
            async with self._lock:
                await self._drop_failed_socket(shadow)
            raise

    async def _reconnect_prepared(self, old: ShadowClient) -> None:
        """Rebuilds a real shadow, presigning before the old socket stops.

        ``old`` must be a ShadowClient (it advertises
        ``prepares_transport_before_disconnect``). The replacement is a new
        object: opening it before ``old`` has disconnected would put two
        sessions on one client ID, and AWS IoT would evict one of them.

        Args:
            old: The live session being replaced. If it is no longer the
                hood's socket by the time the lock is taken, the rebuild
                is abandoned.
        """
        # Policy before any new socket. Latched, so this is a no-op after
        # the first successful attach for this identity.
        await self._prepare()
        replacement = self._shadow_factory(self)
        # Presign stamps its generation on ``replacement``, not on this
        # hood. Two rebuilds can be in prepare_transport at once; committing
        # either generation before that socket is the live one lets the
        # loser describe the winner, and needs_represign() then skips the
        # rebuild that would replace a URL signed under expiring credentials.
        await replacement.prepare_transport()
        async with self._lock:
            if not self._should_run or self._shadow is not old:
                return
            await self._stop()
            try:
                await replacement.open_until_connack()
            except BaseException:
                # Not installed, so _drop_failed_socket will not clear
                # _connected. A CONNACK callback may already have set it.
                # This attempt holds the lock, so nothing else is live.
                self._connected = False
                await self._drop_failed_socket(replacement)
                raise
            # Past CONNACK. publish_state is legal; release the lock before
            # the subscription wait and the state GET. The generation is
            # committed with the install, not when the URL was signed.
            self._install_shadow(replacement)
        try:
            await replacement.finish_subscriptions()
            await replacement.request_state()
        except BaseException:
            # Disconnect before releasing the lock. Clearing _shadow and
            # yielding first lets async_ensure_running open a second session
            # on this client ID while loop_stop is still joining the old
            # network thread.
            async with self._lock:
                await self._drop_failed_socket(replacement)
            raise

    async def _stop(self) -> None:
        """Tears down the shadow connection, if any.

        Lock-free: callers hold self._lock. Leaves consumer intent
        (_should_run) untouched - that distinction belongs to the callers.
        """
        if self._shadow is not None:
            # Swap before the await, and clear _connected right alongside
            # it: a cancellation OR a raise landing on the await would
            # otherwise leave _shadow pointing at a torn-down client with
            # _should_run still True - and async_ensure_running would then
            # decline to rebuild forever, a permanently dark hood. The flag
            # joins the swap on the clear-before-await side because a
            # failed teardown means the connection is gone regardless -
            # reporting connected=True with _shadow already None would
            # mislead the derived `client.connected` and availability logic.
            # Mirrors ShadowClient.disconnect's clear-before-await.
            shadow, self._shadow = self._shadow, None
            self._connected = False
            # Stop and the supervisor rebuild both come through here. The
            # commands published on this socket lose their echo when the
            # socket does. Writes on the replacement session are recorded
            # after this returns, and those stay pending.
            self.discard_unconfirmed_writes()
            await shadow.disconnect()

    async def async_poll(self) -> HoodState:
        """Reads state over HTTPS; used at setup and while push is down.

        This is also how a terminal supervisor failure reaches the consumer:
        the supervisor stops on an auth or policy error and flips `connected`
        to False, which drives the consumer to poll, and this call re-raises
        the stored error so it can become a reauth prompt rather than a hood
        that quietly stops updating.

        Returns:
            The freshly polled state, after recording it and notifying
            listeners.
        """
        state = await self._poll(self.thing_name)
        self.handle_state(state)
        return state

    # -- state ---------------------------------------------------------

    def handle_state(self, state: HoodState) -> None:
        """Records new state and notifies listeners.

        Called by ZephyrClient.

        Args:
            state: The newly received hood state.
        """
        self._state = state
        for callback in list(self._listeners):
            try:
                callback(state)
            except Exception:  # noqa: BLE001
                # One bad consumer must not stop the others from updating.
                _LOGGER.exception("state listener raised")

    def add_listener(self, callback: StateListener) -> Callable[[], None]:
        """Registers a state listener.

        Args:
            callback: Invoked with the new state on every update.

        Returns:
            A callable that removes the listener; safe to call more than
            once.
        """
        self._listeners.append(callback)

        def remove() -> None:
            """Unregisters the listener; safe to call more than once."""
            try:
                self._listeners.remove(callback)
            except ValueError:
                pass

        return remove

    # -- writes: ACTUATE HARDWARE --------------------------------------

    def _check_range(self, name: str, value: int, maximum: int | None) -> None:
        """Range-checks a value against 0..maximum for this hood.

        Negatives are always refused; the upper bound applies only when
        this hood advertises a positive maximum.

        Args:
            name: Field name used in the error message.
            value: The candidate value to check.
            maximum: The hood's advertised maximum, or None when it does
                not advertise one.

        Raises:
            ZephyrWriteError: If value is negative, or exceeds a positive
                advertised maximum.
        """
        if value < 0:
            raise ZephyrWriteError(f"{name} cannot be negative, got {value}")
        # A hood we have never seen may not advertise a maximum. Absent must
        # not become a blanket refusal to write.
        if isinstance(maximum, int) and maximum > 0 and value > maximum:
            raise ZephyrWriteError(
                f"{name} must be between 0 and {maximum} on this hood, got {value}"
            )

    async def async_set_fields(self, fields: dict[str, int]) -> None:
        """Publishes arbitrary allowlisted fields - actuates hardware.

        WRITE PATH and diagnostic surface. The typed async_set_* methods
        below are the normal way to write. This exists for the probe CLI,
        which writes arbitrary allowlisted fields in order to map
        semantics that are not yet established - something a fixed method
        surface cannot express.

        Publishes state.reported, not state.desired: that is what this
        device acts on. state.desired writes are accepted by AWS IoT and
        silently ignored by the hardware.

        Args:
            fields: Writable field names mapped to the integer values to
                publish.

        Raises:
            ZephyrNotConnectedError: If there is no live socket - never
                started, stopped, or a rebuild failed - or if the shadow
                destroyed its own connection while refusing the write.
            ZephyrWriteError: If fields is empty or names a field outside
                const.WRITABLE_FIELDS.
        """
        async with self._lock:
            await self._publish(fields)

    async def _publish(self, fields: dict[str, int]) -> None:
        """Validates fields and publishes them to the shadow.

        Actuates hardware. Lock-free: callers hold self._lock. Refuses
        empty payloads and anything outside const.WRITABLE_FIELDS;
        destructive fields go through with a warning. If the shadow tears
        its own connection down while refusing the write, the hood is
        reset to the no-socket shape the supervisor rebuilds from.

        Args:
            fields: Writable field names mapped to the integer values to
                publish.

        Raises:
            ZephyrNotConnectedError: If there is no socket, or if the
                shadow destroyed its own connection while refusing the
                write.
            ZephyrWriteError: If fields is empty or names a field outside
                const.WRITABLE_FIELDS.
        """
        if self._shadow is None:
            # No thing name in the message: it identifies a home, and
            # exception text ends up in logs users paste publicly.
            raise ZephyrNotConnectedError(
                "hood is not connected (never started, stopped, or a rebuild failed)"
            )
        if not fields:
            raise ZephyrWriteError("refusing to publish an empty reported state")
        if forbidden := set(fields) - const.WRITABLE_FIELDS:
            raise ZephyrWriteError(
                f"not writable: {', '.join(sorted(forbidden))}. Allowed: "
                f"{', '.join(sorted(const.WRITABLE_FIELDS))}"
            )
        if destructive := set(fields) & const.DANGEROUS_FIELDS:
            _LOGGER.warning(
                "destructive write to %s - this changes device configuration "
                "or zeroes a counter that cannot be reconstructed",
                ", ".join(sorted(destructive)),
            )
        try:
            await self._shadow.publish_state(dict(fields))
        except ZephyrNotConnectedError:
            # The shadow refused the write and destroyed its own connection
            # to do it (a message paho had already queued can only be
            # un-scheduled by discarding the client object it lives in). The
            # ShadowClient survives that with no paho client inside it, and
            # _shadow staying set is the shape nothing recovers from:
            # async_ensure_running declines to rebuild while _shadow is not
            # None, and needs_represign sees a generation that still matches,
            # so push would stay dark until the next credential rotation.
            # Put it back in the no-socket shape the supervisor knows how to
            # recover from - the same move _start makes when its own initial
            # request_state fails - and let the next tick rebuild.
            #
            # Cleared here rather than awaited away: the connection is
            # already gone, and reporting connected=True with no socket
            # misleads the derived client.connected.
            self._shadow = None
            self._connected = False
            self.discard_unconfirmed_writes()
            raise
        # Only after the publish was accepted into paho's queue. The
        # NO_CONN path above tears the client down so a qos>0 message
        # cannot actuate later; applying state there would report a
        # command that was refused. Listeners run inline, and this lock
        # is held, so a listener must not call back into the hood.
        self._note_optimistic_write(fields)

    def _note_optimistic_write(self, fields: dict[str, int]) -> None:
        """Merges a successful write into the cache before the echo arrives.

        The vendor app shows the tap immediately. Waiting for
        ``update/accepted`` makes every consumer one cloud round trip
        behind that. Device-derived keys (``power`` rising after a fan
        write, ``delaytimer`` counted down from ``setdelaytimer``) are
        left for the echo to merge. Destructive fields are skipped: showing
        a zeroed grease counter, or a recirculating change, before the
        device confirms it would lie about a change that cannot be undone.

        Args:
            fields: The fields just published to ``state.reported``.
        """
        if set(fields) & const.DANGEROUS_FIELDS:
            return
        # Kept until THIS command's echo, a rejection, or the loss of the
        # session. A GET at the current version was in flight before the
        # write and must not replace it. An earlier command's echo must
        # not either, including when it carries the same level a later
        # command published. ``<=`` on the version cursor would also drop
        # the rejection reread, which comes back at the same version.
        baseline = self._shadow_version
        self._pending_writes.append(
            _PendingWrite(
                baseline
                if isinstance(baseline, int) and not isinstance(baseline, bool)
                else None,
                dict(fields),
            )
        )
        if self._state is None:
            # No cache yet. from_reported on only these keys; the next full
            # document replaces it. Merging is impossible without a base,
            # and replacing a real cache with this partial payload is what
            # zeroes the usage counters.
            self.handle_state(HoodState.from_reported(dict(fields)))
            return
        self.handle_state(self._state.merge(dict(fields)))

    def is_shadow_version_current(self, version: object) -> bool:
        """Reports whether a document is new enough to apply, without recording it.

        A missing or non-integer version is current: those documents keep
        the apply-anyway behaviour and do not move the cursor. An integer
        older than the newest one already applied is not. Callers parse
        the reported block before ``accept_shadow_version``, so a document
        that fails to parse does not make a later valid one look stale.

        Args:
            version: The ``version`` field of a shadow document, or None
                when the document did not carry one.

        Returns:
            True when the caller should try to apply the document.
        """
        if isinstance(version, bool) or not isinstance(version, int):
            return True
        return self._shadow_version is None or version >= self._shadow_version

    def accept_shadow_version(self, version: object) -> bool:
        """Records a document version after its reported block parsed.

        Call only once the new state exists, and only for a document the
        caller has already judged current. A missing or non-integer
        version does not move the cursor. An older version is not
        recorded. A partial ``update/accepted`` older than the cursor is
        still applied field by field elsewhere; this method must not
        rewind the cursor to it. The check is repeated so a cursor that
        moved during parsing cannot be rewound either.

        Args:
            version: The ``version`` field of a shadow document, or None
                when the document did not carry one.

        Returns:
            True when the caller should apply the document.
        """
        if not self.is_shadow_version_current(version):
            return False
        if not isinstance(version, bool) and isinstance(version, int):
            self._shadow_version = version
        return True

    def discard_unconfirmed_writes(self) -> None:
        """Drops commands whose echo will not be the next document.

        A rejection means the device did not apply the write, and the
        follow-up GET reuses the current version so the cursor will not
        reject it. Leaving the commands pending would paint the refused
        values back over that document. Stop, rebuild, and a dead socket
        use the same drop: the session that published them is gone, and a
        fresh GET has to be able to show a change made while it was down.
        A write that lands after this drop belongs to the new session and
        stays pending over that GET.
        """
        self._pending_writes.clear()

    def reported_fields_to_apply(
        self, version: object, reported: dict[str, Any]
    ) -> dict[str, Any]:
        """Returns the reported keys this partial document may still change.

        ``update/accepted`` carries only the keys that changed. Dropping a
        whole older document because a newer partial arrived first loses
        the keys the newer one did not mention. A key already merged from
        a newer document must not be overwritten by the late one. A
        version that is not an integer does not participate: every key is
        applied, matching a document that never moves the cursor.

        Args:
            version: The document's ``version``, or None when it had none.
            reported: The reported object. Callers pass a dict; a list
                fails in parsing before this is consulted.

        Returns:
            The subset of ``reported`` safe to merge. Keys are omitted,
            not set to None: absent is not a value.
        """
        if isinstance(version, bool) or not isinstance(version, int):
            return dict(reported)
        return {
            key: value
            for key, value in reported.items()
            if key not in self._field_versions or version >= self._field_versions[key]
        }

    def note_applied_versions(self, version: object, reported: dict[str, Any]) -> None:
        """Records the version at which each applied key was last merged.

        Only moves a key forward. An older partial allowed to fill a key
        the newer document left out must not make a key that already
        moved look stale. A missing or non-integer version records
        nothing, so it cannot block a later numbered document.

        Args:
            version: The document version. Ignored unless it is an int.
            reported: The keys that were actually merged, not the keys the
                document carried and this version was too old to apply.
        """
        if isinstance(version, bool) or not isinstance(version, int):
            return
        for key in reported:
            seen = self._field_versions.get(key)
            if seen is None or version >= seen:
                self._field_versions[key] = version

    def reconcile_reported(
        self,
        state: HoodState,
        reported: object,
        *,
        version: object,
        echoed: bool,
    ) -> HoodState:
        """Keeps unconfirmed writes in place over a shadow document.

        A GET, including one at the current version, does not confirm a
        command. ``update/accepted`` retires the oldest command whose
        values the document actually carries, and only when the document
        is newer than that command's baseline. One document, one command:
        a fan echo that arrives before the light echo can retire the fan
        command without consuming the light one, and it must not be
        required to be the oldest entry. Commands published after the one
        retired have their baseline raised to this version, so a QoS 1
        redelivery of the same echo cannot retire the next write of the
        same value. Value equality alone will not do: after ``1`` then
        ``0``, an in-flight document that still says ``0`` matches the
        latest write, and after ``1 → 2 → 1`` the first echo matches the
        last write.

        Args:
            state: The state parsed from the document.
            reported: The reported object that document carried. Anything
                other than a dict is treated as carrying no keys.
            version: The document's ``version``, or None when it had none.
            echoed: True for ``update/accepted``. A GET is not an echo of
                a command this client published.

        Returns:
            ``state``, or a merge that puts the still-pending keys back.
        """
        if echoed:
            self._retire_echo(version, reported)
        overlay = self._pending_overlay()
        if not overlay:
            return state
        return state.merge(overlay)

    def _retire_echo(self, version: object, reported: object) -> None:
        """Retires the one command this document echoes.

        Oldest match wins, so a document that carries the oldest command
        still acks that one and not a later command with the same level.
        A partial that only carries a later command acks that later one.
        Commands ahead of it keep their baselines: the light echo can
        still be older than the fan echo that already arrived. Commands
        behind it move up to this version. A replay of this document is
        then equal to their baseline, and equal does not confirm.

        Args:
            version: The document's ``version``, or None.
            reported: The reported object. Not a dict means nothing matches.
        """
        if not self._pending_writes or not isinstance(reported, dict):
            return
        if isinstance(version, bool) or not isinstance(version, int):
            return
        for index, pending in enumerate(self._pending_writes):
            if not _version_confirms(version, pending.baseline):
                continue
            if any(
                key not in reported or reported[key] != value
                for key, value in pending.fields.items()
            ):
                continue
            del self._pending_writes[index]
            for later in self._pending_writes[index:]:
                if later.baseline is None or later.baseline < version:
                    later.baseline = version
            return

    def _pending_overlay(self) -> dict[str, int]:
        """Returns the latest unconfirmed value of each pending key.

        Later commands win. An older command is still in the queue so its
        echo can be told apart from the later one, but it no longer
        describes what the cache should show.

        Returns:
            Reported keys still waiting on a command, newest value first
            in the sense that the last command to set a key supplies it.
        """
        overlay: dict[str, int] = {}
        for pending in self._pending_writes:
            overlay.update(pending.fields)
        return overlay

    def schedule_state_reread(self) -> None:
        """Schedules a full shadow GET after a rejected update.

        Optimistic keys would otherwise stick: a rejection means the device
        did not apply the write, and nothing else will correct the cache
        until the next document. A ``get/rejected`` must not land here. That
        topic firing another GET retries forever when no shadow exists.

        One reread at a time. Runs on the event loop; failures are logged
        as the exception type only, because the message can name a topic.
        """
        in_flight = self._reread_task
        if in_flight is not None and not in_flight.done():
            return
        shadow = self._shadow
        if shadow is None:
            return
        task = asyncio.get_running_loop().create_task(
            self._reread_after_rejection(shadow)
        )
        self._reread_task = task
        task.add_done_callback(self._consume_reread)

    async def _reread_after_rejection(self, shadow: ShadowClient) -> None:
        """Asks for the full shadow so a rejected optimistic write can clear.

        Held under the hood lock for the whole publish. ``request_state``
        on a dead socket tears the paho client down and raises
        ``ZephyrNotConnectedError``. Leaving ``_shadow`` set after that is
        the shape nothing recovers from: ``async_ensure_running`` will not
        reopen while a client object remains, and ``needs_represign`` sees
        a generation that still matches, so push stays dark until the next
        credential rotation. A session that replaced this one before the
        lock was taken is left alone.

        Args:
            shadow: The session to read. The one that was current when the
                rejection was scheduled.

        Raises:
            ZephyrNotConnectedError: The GET was refused and, when
                ``shadow`` was still the live session, the hood was
                returned to the no-socket shape the supervisor rebuilds.
        """
        async with self._lock:
            if self._shadow is not shadow:
                return
            try:
                await shadow.request_state()
            except ZephyrNotConnectedError:
                # request_state already disconnected. Clear only the matching
                # reference, still inside this lock, so a supervisor tick
                # cannot observe a hollow client and also cannot open the
                # next session until that disconnect has finished.
                if self._shadow is shadow:
                    self._shadow = None
                    self._connected = False
                    self.discard_unconfirmed_writes()
                raise

    def _consume_reread(self, task: asyncio.Task[None]) -> None:
        """Logs a reread failure without the exception text.

        Args:
            task: The reread task that just finished.
        """
        if task.cancelled():
            return
        exc = task.exception()
        if exc is not None:
            # Type only. The message can embed a topic, and a topic embeds
            # the thing name.
            _LOGGER.debug(
                "state reread after a rejected write failed: %s", type(exc).__name__
            )

    async def async_set_power(self, on: bool) -> None:
        """Switches hood power on or off.

        Args:
            on: True to power the hood on; False to power it off.

        Raises:
            ZephyrNotConnectedError: If this hood is not connected - never
                started, stopped, or a rebuild failed.
        """
        await self.async_set_fields({"power": int(bool(on))})

    async def async_set_light(self, level: int) -> None:
        """Sets the light level, range-checked against this hood's maximum.

        Args:
            level: Target light level, from 0 up to the hood's advertised
                maximum.

        Raises:
            ZephyrNotConnectedError: If this hood is not connected - never
                started, stopped, or a rebuild failed.
            ZephyrWriteError: If level is negative or exceeds this hood's
                advertised maximum.
        """
        self._check_range("light", level, self._capabilities.max_light_level)
        await self.async_set_fields({"light": level})

    async def async_set_fan(self, speed: int) -> None:
        """Sets the fan speed, range-checked against this hood's maximum.

        Args:
            speed: Target fan speed, from 0 up to the hood's advertised
                maximum.

        Raises:
            ZephyrNotConnectedError: If this hood is not connected - never
                started, stopped, or a rebuild failed.
            ZephyrWriteError: If speed is negative or exceeds this hood's
                advertised maximum.
        """
        self._check_range("fan", speed, self._capabilities.max_fan_speed)
        await self.async_set_fields({"fan": speed})

    async def async_set_clean_air(self, on: bool) -> None:
        """Switches the clean-air function on or off.

        Args:
            on: True to enable the clean-air function; False to disable it.

        Raises:
            ZephyrNotConnectedError: If this hood is not connected - never
                started, stopped, or a rebuild failed.
        """
        await self.async_set_fields({"setcleanairfunction": int(bool(on))})

    async def async_set_delay_timer(self, value: int) -> None:
        """Arms the delay-off timer, in SECONDS.

        Seconds, not minutes - established by step 6 of the hardware runbook
        and recorded in PROTOCOL.md section 5. The vendor app exposing only
        two presets is a UI choice rather than a device constraint: values
        off the presets are accepted, proven up to 3600. Past that the
        device's own ceiling is unprobed, so a larger value may be clamped
        or rejected by the hardware rather than by this method.

        The device derives and decrements `delaytimer` from this itself, so
        only `setdelaytimer` is written.

        Args:
            value: Delay in seconds to write to `setdelaytimer`. Callers
                working in minutes must multiply by 60.

        Raises:
            ZephyrNotConnectedError: If this hood is not connected - never
                started, stopped, or a rebuild failed.
            ZephyrWriteError: If value is negative.
        """
        self._check_range("delay timer", value, None)
        await self.async_set_fields({"setdelaytimer": value})

    async def async_set_recirculating(self, on: bool) -> None:
        """Switches recirculating mode on or off - DESTRUCTIVE.

        Changes filter accounting for this hood.

        Args:
            on: True to enable recirculating mode; False to disable it.

        Raises:
            ZephyrNotConnectedError: If this hood is not connected - never
                started, stopped, or a rebuild failed.
        """
        await self.async_set_fields({"setrecirculating": int(bool(on))})

    async def async_reset_grease_filter(self) -> None:
        """Resets the grease filter usage counter - DESTRUCTIVE.

        Zeroes a usage counter that cannot be reconstructed.

        Raises:
            ZephyrNotConnectedError: If this hood is not connected - never
                started, stopped, or a rebuild failed.
        """
        await self.async_set_fields({"resetgreasefilter": 1})
