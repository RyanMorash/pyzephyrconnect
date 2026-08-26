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

from . import const
from .exceptions import ZephyrNotConnectedError, ZephyrWriteError
from .models import HoodCapabilities, HoodState
from .shadow import ShadowClient

_LOGGER = logging.getLogger(__name__)

StateListener = Callable[[HoodState], None]


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

        Called by ShadowClient from the event loop.

        Args:
            connected: Whether this hood's shadow connection is now up.
        """
        self._connected = connected

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

        Holds the lock across both halves so a write arriving mid-rebuild
        waits rather than failing with a spurious ZephyrNotConnectedError.
        """
        async with self._lock:
            if not self._should_run:
                # Never started, or deliberately stopped. The supervisor
                # calls this for every hood on the account; it must not
                # bring up MQTT for hoods the consumer chose not to start.
                return
            await self._stop()
            await self._start()

    def note_presigned_generation(self, generation: int) -> None:
        """Records which credential generation signed this socket's URL.

        Called by the provider ZephyrClient hands to ShadowClient, which
        invokes it on every connect attempt - so a reconnect re-records the
        current generation and no caller has to remember to.

        Args:
            generation: The credentials provider's current generation
                counter.
        """
        self._presigned_generation = generation

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

    # Lock-free bodies. Callers above hold self._lock; asyncio.Lock is not
    # reentrant, so async_reconnect cannot call the public methods.

    async def _start(self) -> None:
        """Attaches the IoT policy, connects the shadow, and requests state.

        Lock-free: callers hold self._lock. A no-op when a socket already
        exists; if the initial state request fails, the hood is put back in
        the no-socket shape the supervisor knows how to recover from.
        """
        if self._shadow is not None:
            # Already connected. Rebuilding here would orphan the previous
            # paho client with its network thread still running.
            return
        # MUST precede connect(). An already-open MQTT connection does not
        # pick up newly attached permissions, and the failure is silent:
        # connect, subscribe and publish all succeed and every message is
        # dropped (PROTOCOL.md section 3.3). Latched by the client, so a
        # reconnect does not re-attach - the binding persists on the identity.
        await self._prepare()
        shadow = self._shadow_factory(self)
        await shadow.connect()
        self._shadow = shadow
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
            raise

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
