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
    that was in flight before the command, is not its echo. ``ordinal`` is
    this command's place among writes that share that baseline: the echo
    AWS assigns it is ``baseline + ordinal + 1``, and a later version can
    arrive before an earlier one.     ``seq`` is the publish order across
    every baseline, which is what keeps an older command from covering a
    newer one that has already been confirmed. ``seen`` records each key
    a newer ``update/accepted`` has already carried at this command's
    value, and the version that carried it. One multi-key command is
    often echoed as several partial documents. A repeated version for a
    key already recorded fills nothing new.
    """

    def __init__(
        self,
        baseline: int | None,
        fields: dict[str, int],
        seq: int,
        ordinal: int,
    ) -> None:
        """Stores the version baseline and the fields this command set.

        Args:
            baseline: Shadow version already applied, or None when no
                versioned document has been applied yet.
            fields: Reported keys this command published.
            seq: Monotonic publish order for this hood.
            ordinal: Zero-based place among commands that share
                ``baseline``.
        """
        self.baseline = baseline
        self.fields = fields
        self.seq = seq
        self.ordinal = ordinal
        self.seen: dict[str, int] = {}


def _echo_matches(pending: _PendingWrite, reported: dict[str, Any]) -> bool:
    """Reports whether this document carries this command's values.

    A missing key is not a match. Extra keys are: the device raises
    ``power`` itself, so an echo of a light write can carry ``power`` too.

    Args:
        pending: The command being considered.
        reported: The reported object from ``update/accepted``.

    Returns:
        True when every field the command published is present and equal.
    """
    return all(
        key in reported and reported[key] == value
        for key, value in pending.fields.items()
    )


def _version_confirms(version: object, baseline: int | None) -> bool:
    """Reports whether a document is newer than a command's baseline.

    A missing version is not an echo: the rejection reread and an in-flight
    GET often arrive without moving the cursor, or at the same version the
    command was published against. A version equal to the baseline is that
    in-flight document. Greater-than is not by itself the acknowledgement.
    The caller still has to match the command this version belongs to, or
    a repeated level acks the wrong write. A QoS 1 redelivery repeats the
    version; the caller records versions it has already consumed.

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


def _expected_version(pending: _PendingWrite) -> int | None:
    """Returns the shadow version that belongs to this command.

    Args:
        pending: The command being considered.

    Returns:
        ``baseline + ordinal + 1``, or None when this command was
        published before any versioned document had been applied.
    """
    if pending.baseline is None:
        return None
    return pending.baseline + pending.ordinal + 1


def _echo_conflicts(
    pending: _PendingWrite,
    reported: dict[str, Any],
    only_keys: frozenset[str] | None = None,
) -> bool:
    """Reports whether this document contradicts the command.

    A key the document omits is not a contradiction. A different value
    for a key the command published is: noting the keys that do match
    would let a later partial complete a command this document refused.
    A key already recorded in ``pending.seen`` is not part of that check.
    The device can change it while the remaining keys are still arriving,
    and treating the new value as a refusal drops the key this document
    did confirm. ``only_keys`` is the same limit ``_note_echo_keys``
    uses: a superseded key, one a later command published, must not
    refuse the independent key this document is allowed to record.

    Args:
        pending: The command being considered.
        reported: The reported object from ``update/accepted``.
        only_keys: When set, only these keys can contradict. None
            considers every key the command published.

    Returns:
        True when some still-unconfirmed key is present and not equal.
    """
    return any(
        key not in pending.seen
        and (only_keys is None or key in only_keys)
        and key in reported
        and reported[key] != value
        for key, value in pending.fields.items()
    )


def _echo_has_value(pending: _PendingWrite, reported: dict[str, Any]) -> bool:
    """Reports whether this document carries any of the command's values.

    Args:
        pending: The command being considered.
        reported: The reported object from ``update/accepted``.

    Returns:
        True when at least one published key is present and equal.
    """
    return any(
        key in reported and reported[key] == value
        for key, value in pending.fields.items()
    )


def _note_echo_keys(
    pending: _PendingWrite,
    version: int,
    reported: dict[str, Any],
    only_keys: frozenset[str] | None = None,
) -> bool:
    """Records keys this document carries at the command's values.

    A key already recorded is left alone, including when this is the
    same version again. The command is complete once every key it
    published has been seen on some newer echo. ``only_keys`` limits
    which matches count: a document owned by another command must not
    satisfy a shared key on this one. The baseline check lives here so
    a partial cannot confirm a command published against a newer
    document. The full-match path returns before this function runs, so
    it checks the baseline itself.

    Args:
        pending: The command being updated.
        version: The document version. Callers pass one newer than the
            command's baseline.
        reported: The reported object from ``update/accepted``.
        only_keys: When set, only these keys may be recorded. None
            records every matching key.

    Returns:
        True when every field the command published has been seen.
    """
    if not _version_confirms(version, pending.baseline):
        return False
    for key, value in pending.fields.items():
        if key in pending.seen:
            continue
        if only_keys is not None and key not in only_keys:
            continue
        if key in reported and reported[key] == value:
            pending.seen[key] = version
    return set(pending.fields) <= set(pending.seen)


def _record_echo(
    pending: _PendingWrite,
    version: int,
    reported: dict[str, Any],
    retired: list[_PendingWrite],
    retired_sets: list[frozenset[str]],
    only_keys: frozenset[str] | None = None,
) -> bool:
    """Retires ``pending`` or remembers the keys this document confirmed.

    A full match retires immediately, and only when the document is
    newer than the baseline the command was published against. A delayed
    document at version 11 can still say ``fan: 2`` after a version-12
    document has already reported ``fan: 0``. The command published
    against that version 12 is not the delayed document's echo; retiring
    it drops the overlay and the stale fan value shows. A partial match
    remembers the keys and retires only once every key has been seen,
    including on an earlier echo. A document that adds nothing new
    records nothing: a QoS 1 redelivery must not retire the next command.

    Args:
        pending: The command this document may confirm.
        version: The document version.
        reported: The reported object from ``update/accepted``.
        retired: Commands this pass has retired. Appended to.
        retired_sets: Field sets of those commands. Appended to.
        only_keys: When set, a partial records only these keys. A full
            match still retires the whole command.

    Returns:
        True when this document newly recorded or retired the command.
    """
    if pending in retired or _echo_conflicts(pending, reported, only_keys):
        return False
    if _echo_matches(pending, reported):
        # This return never reaches ``_note_echo_keys``. The partial
        # path checks the baseline there; a full match has to do it
        # here or the delayed document above retires the newer command.
        if not _version_confirms(version, pending.baseline):
            return False
        retired.append(pending)
        retired_sets.append(frozenset(pending.fields))
        return True
    before = len(pending.seen)
    complete = _note_echo_keys(pending, version, reported, only_keys)
    if len(pending.seen) == before:
        return False
    if complete:
        retired.append(pending)
        retired_sets.append(frozenset(pending.fields))
    return True


def _later_command_fits(pending: _PendingWrite, claimed: list[frozenset[str]]) -> bool:
    """Reports whether a later command may retire from this same document.

    One ``{light: 1}`` must not acknowledge two ``light=1`` writes.
    A later command that publishes the same fields is skipped. A later
    command that only overlaps those fields is skipped too, unless it
    adds a key. A command on a different key is independent. Callers
    that are only noting a partial still have to reject an overlap:
    a superset may reuse a claimed field only when this same document
    carries every key the superset published. Collecting ``light`` from
    version 11 and ``fan`` from version 13 retires ``{light: 1, fan: 2}``
    before its own echo, and the visible light falls back to the earlier
    command.

    Args:
        pending: A command published after the one this version names.
        claimed: Field sets already taken by this document, including
            the version's own command.

    Returns:
        True when ``pending`` adds a key or shares no key with
        ``claimed``.
    """
    fields = frozenset(pending.fields)
    if any(fields == existing for existing in claimed):
        return False
    return all(not (fields & existing) or fields > existing for existing in claimed)


def _overlaps_claimed(pending: _PendingWrite, claimed: list[frozenset[str]]) -> bool:
    """Reports whether ``pending`` shares a key with a field set already taken.

    Args:
        pending: A command this document may also confirm.
        claimed: Field sets already taken by this document.

    Returns:
        True when any published key is already claimed.
    """
    fields = frozenset(pending.fields)
    return any(fields & existing for existing in claimed)


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
        # Device-reported state, with no optimistic keys in it. The visible
        # cache is this plus the pending commands that are still ahead of
        # the last confirmation of their key. Merging an echo onto the
        # visible cache stores the overlay as if the device had reported
        # it, and retiring the command then has nothing newer to reveal.
        self._reported: HoodState | None = None
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
        # Commands whose echo has not arrived, oldest first. The echo that
        # belongs to a command is the shadow version ``baseline + ordinal +
        # 1``: two writes at version 10 are accepted as 11 and 12, and 12
        # can arrive before 11. Spending 12 on the older write leaves the
        # newer one in the overlay, and a later GET stays covered. A
        # version no command expects retires nothing older than the newest
        # command that is still pending for every key it carries. A
        # version is consumed once, so a QoS 1 redelivery cannot retire
        # the next write of the same value. That expected version is not
        # exclusive: an unrelated update can take it, and the echo then
        # arrives later. A version already seen as that kind of miss is
        # remembered so the late echo is not handed to whichever command
        # the arithmetic now points at. One document can still carry
        # two different keys, and one multi-key command can be retired by
        # several partial echoes. PROTOCOL.md records the echo as
        # ``state.reported``; it does not echo a clientToken, so none is
        # sent. The queue is dropped when the session that published it is
        # gone; a later GET must be able to show what the device or the
        # phone did during the outage. Dangerous fields are never entered
        # here.
        self._pending_writes: list[_PendingWrite] = []
        self._next_pending_seq = 1
        # How many commands have been published at each baseline. The
        # ordinal is stable after an earlier command retires, so a late
        # echo still names the command it belongs to. Cleared with the
        # queue when the session that published those commands is gone:
        # leaving the count makes the next session's first write expect
        # the version that belonged to a command already dropped.
        self._baseline_counts: dict[int | None, int] = {}
        # Versions already applied to a queued command, including a
        # partial echo that recorded some of its keys. A redelivery must
        # not record those keys again or retire whatever is still queued.
        self._consumed_echo_versions: set[int] = set()
        # Expected versions that arrived as something else: an unrelated
        # update, or a document that contradicted the command the
        # arithmetic named. The echo of that command shows up later, and
        # treating ``baseline + ordinal + 1`` as exclusive ownership
        # retires the newest repeat instead. Cleared with the queue.
        # Leaving a miss behind makes the next session's first
        # non-contiguous echo look like the delayed command from the
        # session that already died.
        self._missed_echo_versions: set[int] = set()
        # Publish sequence of the newest command retired for this key.
        # An older command stays queued so its own echo can still match
        # it, and is left out of the visible cache. A newer command is
        # not: retiring the first of two ``light=1`` writes must not hide
        # the second, or a reordered older echo can never clear it and
        # the pending value covers a later GET.
        self._confirmed_seq: dict[str, int] = {}
        # Shadow version at which each reported key was last merged.
        # update/accepted is partial, so a newer document does not contain
        # the keys an older one changed. The global cursor cannot decide
        # that for a single key: version 12 reporting fan does not make
        # version 11's light stale, and version 11's light must not
        # overwrite a light already applied from version 14.
        self._field_versions: dict[str, int] = {}
        # Newest full get/accepted version applied. A snapshot versions
        # every key, including ones it omits: absence is the value. An
        # older partial must not fill a key back in. Newer partials still
        # use the per-key version above.
        self._snapshot_version: int | None = None
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
        """Records device-reported state and notifies listeners.

        Called by ZephyrClient for a document, a poll, or discover. The
        argument is authoritative reported state, not the optimistic
        cache. Listeners see that state with still-leading commands
        laid over it.

        Args:
            state: The newly received hood state, without optimistic keys.
        """
        self._reported = state
        self._publish_visible()

    def _publish_visible(self) -> None:
        """Rebuilds the visible cache and notifies listeners.

        Reported state stays free of optimistic keys. Retiring a command
        rebuilds from that reported state, so a newer value the overlay
        was hiding becomes visible instead of leaving the old command's
        value behind. An empty queue with no reported state yet clears
        the cache without notifying: there is no HoodState to hand a
        listener.
        """
        overlay = self._pending_overlay()
        if self._reported is None:
            if not overlay:
                self._state = None
                return
            visible = HoodState.from_reported(dict(overlay))
        elif overlay:
            visible = self._reported.merge(overlay)
        else:
            visible = self._reported
        self._state = visible
        for callback in list(self._listeners):
            try:
                callback(visible)
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
        shadow = self._shadow
        if shadow is None:
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
            await shadow.publish_state(dict(fields))
        except (ZephyrNotConnectedError, asyncio.CancelledError):
            # The shadow refused the write and destroyed its own connection
            # to do it (a message paho had already queued can only be
            # un-scheduled by discarding the client object it lives in).
            # CancelledError is the same teardown: disconnect waits out
            # loop_stop and then raises, and that is not a
            # ZephyrNotConnectedError. The ShadowClient survives either
            # one with no paho client inside it. _shadow staying set is
            # the shape nothing recovers from: async_ensure_running
            # declines to rebuild while _shadow is not None, and
            # needs_represign sees a generation that still matches, so
            # push would stay dark until the next credential rotation.
            #
            # After the await, not before. The join is inside
            # publish_state. Clearing first would let the next session
            # open while loop_stop is still running.
            self._forget_dead_shadow(shadow)
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
        if isinstance(baseline, bool) or not isinstance(baseline, int):
            baseline = None
        ordinal = self._baseline_counts.get(baseline, 0)
        self._baseline_counts[baseline] = ordinal + 1
        seq = self._next_pending_seq
        self._next_pending_seq = seq + 1
        self._pending_writes.append(_PendingWrite(baseline, dict(fields), seq, ordinal))
        # Laid over reported state, not merged into it. The next document
        # has to be able to reveal a newer device value once this command
        # retires. With no reported state yet, the visible cache is just
        # these keys; the next full document replaces that base.
        self._publish_visible()

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
        stays pending over that GET. The visible cache is rebuilt from
        reported state, so the dropped values do not linger until that GET.

        The baseline counts, consumed echo versions, missed expected
        versions, and per-key confirmations belong to the dropped
        commands. Leaving the counts makes the next write at this
        baseline expect a version that was already assigned, and a
        non-contiguous echo of the new value is then spent on the wrong
        command. Leaving a missed version does the same: the new
        session's echo is treated as the delayed command from the
        session that just died.
        """
        pending = bool(self._pending_writes)
        self._pending_writes.clear()
        self._baseline_counts.clear()
        self._consumed_echo_versions.clear()
        self._missed_echo_versions.clear()
        self._confirmed_seq.clear()
        if pending:
            self._publish_visible()

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
            if self._field_is_current(key, version)
        }

    def _field_is_current(self, key: str, version: int) -> bool:
        """Reports whether a partial may still change one key.

        The bound is the newer of the last merge of this key and the last
        full snapshot. A snapshot that omitted the key still counts: the
        omission is the reported value at that version.

        Args:
            key: Reported key the partial wants to merge.
            version: The partial document's version.

        Returns:
            True when ``version`` is at least that bound, or when neither
            bound exists yet.
        """
        bound = self._field_versions.get(key)
        floor = self._snapshot_version
        if floor is not None and (bound is None or floor > bound):
            bound = floor
        return bound is None or version >= bound

    def note_snapshot_version(self, version: object) -> None:
        """Records a full snapshot as a lower bound for every key.

        ``get/accepted`` is the whole reported document. A key it omits is
        absent at this version, not "unchanged", so a delayed older partial
        must not put that key back. Only moves the bound forward. A missing
        or non-integer version records nothing. Per-key versions still
        decide partials that are newer than this snapshot.

        Args:
            version: The GET's ``version``, or None when it had none.
        """
        if isinstance(version, bool) or not isinstance(version, int):
            return
        if self._snapshot_version is None or version > self._snapshot_version:
            self._snapshot_version = version

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

    def state_for_document(self, reported: object, *, replace: bool) -> HoodState:
        """Parses a shadow document onto authoritative reported state.

        A full GET replaces. A partial update merges onto the last reported
        document, never onto the visible cache. The visible cache already
        contains optimistic keys; merging onto it would store those keys
        as if the device had reported them, and retiring the command would
        then keep the optimistic value instead of a newer reported one.
        A non-dict reaches ``from_reported`` so the parse error happens
        before the version cursor moves.

        Args:
            reported: The reported block to apply.
            replace: True for a full snapshot.

        Returns:
            The authoritative state this document produces, with no
            optimistic overlay.
        """
        if not replace and self._reported is not None and isinstance(reported, dict):
            return self._reported.merge(reported)
        return HoodState.from_reported(reported)  # type: ignore[arg-type]

    def reconcile_reported(
        self,
        state: HoodState,
        reported: object,
        *,
        version: object,
        echoed: bool,
    ) -> HoodState:
        """Retires the commands this document echoes.

        A GET, including one at the current version, does not confirm a
        command. ``update/accepted`` retires the command whose echo this
        version is: the first write published at baseline 10 is version
        11, the next is version 12, whether or not 12 arrives first.
        Retiring the oldest matching value and then raising every later
        baseline strands the command the older echo belonged to, and that
        pending value hides a newer GET. A QoS 1 redelivery repeats the
        version and retires nothing else. One document can still carry a
        second key the version does not name, which is how a hood reports
        ``light`` and ``fan`` together. Value equality alone will not do:
        after ``1`` then ``0``, an in-flight document that still says
        ``0`` matches the latest write, and after ``1 → 2 → 1`` the first
        echo matches the last write.

        The returned state is authoritative. ``handle_state`` lays the
        commands that are still ahead of a newer confirmation of their
        key over it. An older command kept for echo matching is not part
        of that layer. A GET does not retire, but it does drop a command
        a newer echo has already superseded once this snapshot is past
        the version that command was waiting for. Otherwise that command
        stays queued after the GET that should have replaced it.

        Commands published before any numbered document stay unnumbered.
        Treating the first numbered echo as the end of that queue makes
        version 11 of an in-order ``1 → 2 → 1`` retire the newest write,
        and version 12 then shows ``2`` while that write is gone and no
        longer covers the echo. Several unnumbered commands that publish
        the same value retire oldest first. One matching command retires
        even when it is not the oldest. That path does not assign a
        baseline.

        Args:
            state: The state parsed from the document, without optimistic
                keys.
            reported: The reported object that document carried. Anything
                other than a dict is treated as carrying no keys.
            version: The document's ``version``, or None when it had none.
            echoed: True for ``update/accepted``. A GET is not an echo of
                a command this client published.

        Returns:
            ``state``, unchanged. Retirement is the side effect; the
            visible cache is rebuilt when the caller stores ``state``.
        """
        if echoed:
            self._retire_echo(version, reported)
        else:
            self._drop_superseded_commands(version)
        return state

    def _correlate_unversioned(
        self,
        version: int,
        reported: dict[str, Any],
        retired: list[_PendingWrite],
        retired_sets: list[frozenset[str]],
        claimed: list[frozenset[str]],
    ) -> bool:
        """Correlates commands published before any numbered document.

        Those commands have no expected version. Anchoring the end of
        the queue to the first numbered echo makes version 11 of an
        in-order ``1, 2, 1`` retire the last command, and version 12
        then shows ``light=2`` with nothing left to cover it. Several
        commands that share the value retire oldest first. A unique
        match retires that command even when a different value was
        published before it.         A partial notes only the oldest command
        it fits, so the two halves of one multi-key write still meet.
        A partial that overlaps a field set this document already claimed
        is skipped. The full-match pass above is what may reuse a claimed
        field, and only when the later command is entirely in this
        document. Survivors stay unnumbered: assigning a baseline here
        would make the next echo look like a back-calculated expected
        version.
        ``claimed`` already holds field sets this document has taken,
        including a versioned command this version actually belongs to,
        so one ``{light: 1}`` does not also retire an unnumbered repeat.

        Args:
            version: The document version that just arrived.
            reported: The reported object from ``update/accepted``.
            retired: Commands this pass has retired. Appended to.
            retired_sets: Field sets of those commands. Appended to.
            claimed: Field sets already taken by this document. Appended
                to as commands are recorded.

        Returns:
            True when this document newly recorded or retired a command.
        """
        candidates = [
            pending
            for pending in self._pending_writes
            if pending.baseline is None and pending not in retired
        ]
        if not candidates:
            return False
        full = [
            pending
            for pending in candidates
            if _version_confirms(version, pending.baseline)
            and _echo_matches(pending, reported)
        ]
        full.sort(key=lambda pending: pending.seq)
        recorded = False
        for pending in full:
            if not _later_command_fits(pending, claimed):
                continue
            if _record_echo(pending, version, reported, retired, retired_sets):
                recorded = True
                claimed.append(frozenset(pending.fields))
        full_ids = {id(pending) for pending in full}
        partials = [
            pending
            for pending in candidates
            if id(pending) not in full_ids
            and pending not in retired
            and _version_confirms(version, pending.baseline)
            and not _echo_conflicts(pending, reported)
            and _echo_has_value(pending, reported)
        ]
        partials.sort(key=lambda pending: pending.seq)
        for pending in partials:
            if not _later_command_fits(pending, claimed):
                continue
            # Overlap is the full-match pass's job. Noting light from the
            # first command's echo and fan from the third retires the
            # later ``{light, fan}`` before the document that actually
            # carries both, and the visible light falls back.
            if _overlaps_claimed(pending, claimed):
                continue
            if _record_echo(pending, version, reported, retired, retired_sets):
                recorded = True
                claimed.append(frozenset(pending.fields))
        return recorded

    def _is_newest_for_keys(
        self,
        pending: _PendingWrite,
        keys: set[str],
        retired: list[_PendingWrite],
    ) -> bool:
        """Reports whether no newer command still publishes one of ``keys``.

        A command already retired by this same document still holds its
        keys. One ``{fan: 1}`` would otherwise acknowledge both the
        unnumbered write and the later numbered repeat. A later command
        that publishes a different key does not block.

        Args:
            pending: The command being considered.
            keys: The keys this document may confirm on ``pending``.
            retired: Commands this pass has already retired.

        Returns:
            True when ``pending`` is the newest queued command for every
            key in ``keys``, ignoring commands already retired except
            that those keys stay taken for this document.
        """
        if any(keys & set(done.fields) for done in retired):
            return False
        return all(
            other.seq <= pending.seq or not keys & set(other.fields)
            for other in self._pending_writes
            if other not in retired
        )

    def _reconcile_independent_keys(
        self,
        owner: _PendingWrite,
        version: int,
        reported: dict[str, Any],
        retired: list[_PendingWrite],
        retired_sets: list[frozenset[str]],
    ) -> bool:
        """Retires keys this document carries that ``owner`` did not publish.

        The version belongs to ``owner``. Spending it on an older command
        that published the same keys acknowledges the wrong write, and a
        QoS 1 redelivery would then acknowledge the next one too. Keys
        the owner did not publish are a different command. Fan's echo
        lands on the version light was assigned when an unrelated update
        took the version fan expected. Returning without looking at
        those keys leaves fan pending, and the GET that reports fan 0
        stays hidden. The same return leaves the remaining key of a
        multi-key command unrecorded when it arrives in the later
        command's document. A command published against a newer baseline
        is not eligible: the document is older than that command.

        Args:
            owner: The command whose expected version is ``version``.
            version: The document version.
            reported: The reported object from ``update/accepted``.
            retired: Commands this pass has retired. Appended to.
            retired_sets: Field sets of those commands. Appended to.

        Returns:
            True when this document newly recorded or retired a command.
        """
        owner_keys = set(owner.fields)
        recorded = False
        for pending in self._pending_writes:
            if pending is owner or pending in retired or pending.baseline is None:
                continue
            if not _version_confirms(version, pending.baseline):
                continue
            if _echo_conflicts(pending, reported):
                continue
            independent = {
                key: value
                for key, value in pending.fields.items()
                if key not in owner_keys and key in reported and reported[key] == value
            }
            if not independent:
                continue
            if not self._is_newest_for_keys(pending, set(independent), retired):
                continue
            if _record_echo(
                pending,
                version,
                reported,
                retired,
                retired_sets,
                frozenset(independent),
            ):
                recorded = True
        return recorded

    def _command_is_newest_for_its_keys(self, pending: _PendingWrite) -> bool:
        """Reports whether no newer command still shares one of these keys.

        A document that matches no expected version may retire only this
        command. Retiring an older equal value leaves the newer repeat
        in the overlay, which is what hides the next GET.

        Args:
            pending: The command being considered.

        Returns:
            True when ``pending`` is the newest queued command for every
            key it published.
        """
        keys = set(pending.fields)
        return all(
            other.seq <= pending.seq or not keys & set(other.fields)
            for other in self._pending_writes
        )

    def _forget_dead_shadow(self, shadow: ShadowClient) -> None:
        """Drops a session whose disconnect has already finished.

        ``publish_state`` and ``request_state`` tear the paho client down
        before they raise. ``CancelledError`` is that teardown finishing
        after the caller was cancelled, the same hollow client as
        ``ZephyrNotConnectedError``: ``_shadow`` still set, nothing inside
        it, and ``async_ensure_running`` will not open another session.
        ``needs_represign`` does not either while the generation still
        matches. A session that has already replaced this one is left
        alone. Pending commands published on it are dropped with it.

        Args:
            shadow: The session the failed publish or reread was using.
        """
        if self._shadow is not shadow:
            return
        self._shadow = None
        self._connected = False
        self.discard_unconfirmed_writes()

    def _drop_superseded_commands(self, version: object) -> None:
        """Drops commands a newer snapshot has already replaced.

        An older repeated write stays queued so its own echo can still
        match it, and it does not paint once a newer command for that
        key has been confirmed. A GET newer than the version that older
        command was waiting for is not going to be followed by that
        echo as a document this client still has to apply. Leaving the
        command queued makes the next equal echo look like it still has
        work to do. A command that is still the newest for its key is
        kept: this GET must not confirm a write that has not been echoed.

        Args:
            version: The GET's ``version``, or None when it had none.
        """
        if isinstance(version, bool) or not isinstance(version, int):
            return
        kept: list[_PendingWrite] = []
        for pending in self._pending_writes:
            expected = _expected_version(pending)
            if expected is None or expected >= version or not pending.fields:
                kept.append(pending)
                continue
            superseded = True
            for key in pending.fields:
                confirmed = self._confirmed_seq.get(key)
                if confirmed is None or pending.seq >= confirmed:
                    superseded = False
                    break
            if not superseded:
                kept.append(pending)
        self._pending_writes = kept

    def _oldest_same_fields_missed(self, owner: _PendingWrite) -> _PendingWrite | None:
        """Returns an older repeat whose expected version already missed.

        ``owner`` is the command ``baseline + ordinal + 1`` names, and
        this document matches it. An unrelated update already took the
        version an older command with the same fields was waiting for, so
        this document is that older echo arriving late. Handing it to
        ``owner`` retires the newest ``light=1`` of ``1 → 2 → 1`` and the
        next document shows light 2.

        Args:
            owner: The command whose expected version is this document.

        Returns:
            The oldest queued command with the same fields whose expected
            version is in ``_missed_echo_versions``, or None when this
            document still belongs to ``owner``.
        """
        for pending in self._pending_writes:
            if pending.seq >= owner.seq:
                return None
            if pending.fields != owner.fields:
                continue
            expected = _expected_version(pending)
            if expected is not None and expected in self._missed_echo_versions:
                return pending
        return None

    def _oldest_conflict_match(
        self, owner: _PendingWrite, reported: dict[str, Any]
    ) -> _PendingWrite | None:
        """Returns the delayed echo this document carries when ``owner`` conflicts.

        The arithmetic named ``owner``, and the document contradicts it.
        An older command whose expected version was already a miss can
        still be fully present. That is the first ``light=1`` arriving at
        the version ``light=2`` was assigned. Only the oldest match is
        taken. A newer repeat of the same fields stays queued for its own
        document. A total miss, where ``owner``'s keys are absent, is not
        this case: reconcile retires the newest independent key there,
        and retiring the oldest as well would clear both copies.

        Args:
            owner: The command whose expected version is this document.
            reported: The reported object from ``update/accepted``.

        Returns:
            The oldest older command this document fully matches whose
            expected version was missed, or None.
        """
        for pending in self._pending_writes:
            if pending.seq >= owner.seq:
                return None
            expected = _expected_version(pending)
            if expected is None or expected not in self._missed_echo_versions:
                continue
            if _echo_matches(pending, reported):
                return pending
        return None

    def _note_later_commands(
        self,
        after: _PendingWrite,
        version: int,
        reported: dict[str, Any],
        retired: list[_PendingWrite],
        retired_sets: list[frozenset[str]],
        claimed: list[frozenset[str]],
    ) -> bool:
        """Records later commands this same document fully carries.

        A later command that overlaps a field set already claimed may
        retire only when every key it published is in this document. A
        partial overlap would collect light from one command and fan from
        another and finish ``{light: 1, fan: 2}`` before its own echo. A
        command on keys nobody has claimed still notes a partial.

        Args:
            after: The command this version has already been given to.
            version: The document version.
            reported: The reported object from ``update/accepted``.
            retired: Commands this pass has retired. Appended to.
            retired_sets: Field sets of those commands. Appended to.
            claimed: Field sets already taken. Appended to.

        Returns:
            True when this document newly recorded or retired a command.
        """
        recorded = False
        for pending in self._pending_writes:
            if pending.seq <= after.seq or pending in retired:
                continue
            if not _later_command_fits(pending, claimed):
                continue
            if _overlaps_claimed(pending, claimed) and not _echo_matches(
                pending, reported
            ):
                continue
            if _record_echo(pending, version, reported, retired, retired_sets):
                recorded = True
                claimed.append(frozenset(pending.fields))
        return recorded

    def _correlate_missed_versions(
        self,
        version: int,
        reported: dict[str, Any],
        retired: list[_PendingWrite],
        retired_sets: list[frozenset[str]],
    ) -> bool:
        """Retires a command whose expected version was taken by something else.

        No queued command expects ``version``. The document can still be
        the echo that was pushed back when an unrelated update took its
        slot. A newer command that published the same fields is left
        alone: the gap path retires that newest repeat, and retiring the
        older one here as well would clear both on one ``{light: 1}``.

        Args:
            version: The document version that just arrived.
            reported: The reported object from ``update/accepted``.
            retired: Commands this pass has retired. Appended to.
            retired_sets: Field sets of those commands. Appended to.

        Returns:
            True when this document newly recorded or retired a command.
        """
        recorded = False
        claimed = [frozenset(pending.fields) for pending in retired]
        for pending in self._pending_writes:
            if pending in retired or pending.baseline is None:
                continue
            expected = _expected_version(pending)
            if expected is None or expected not in self._missed_echo_versions:
                continue
            if not _version_confirms(version, pending.baseline):
                continue
            if not _echo_matches(pending, reported):
                continue
            if any(
                other.seq > pending.seq
                and other not in retired
                and other.fields == pending.fields
                for other in self._pending_writes
            ):
                continue
            if not _later_command_fits(pending, claimed):
                continue
            if _record_echo(pending, version, reported, retired, retired_sets):
                recorded = True
                claimed.append(frozenset(pending.fields))
        return recorded

    def _independent_keys(
        self, pending: _PendingWrite, retired: list[_PendingWrite]
    ) -> set[str]:
        """Returns keys no newer command still publishes.

        A later ``light=2`` supersedes ``light`` inside
        ``{light: 1, fan: 2}``. Fan is still this command's to confirm.
        Skipping the whole command because of the shared light leaves fan
        pending over a GET of fan 0. A command already retired by this
        document counts too: its keys stay taken.

        Args:
            pending: The command being considered.
            retired: Commands this pass has already retired.

        Returns:
            Published keys no newer queued or just-retired command publishes.
        """
        later: set[str] = set()
        for other in self._pending_writes:
            if other is pending or other in retired:
                continue
            if other.seq > pending.seq:
                later |= set(other.fields)
        for done in retired:
            if done.seq > pending.seq:
                later |= set(done.fields)
        return {key for key in pending.fields if key not in later}

    def _retire_independent_keys(
        self,
        pending: _PendingWrite,
        version: int,
        reported: dict[str, Any],
        retired: list[_PendingWrite],
        retired_sets: list[frozenset[str]],
    ) -> bool:
        """Confirms keys a later command did not supersede.

        The command is retired once every such key has been seen, even
        when a superseded key is not in ``seen``. Requiring the shared
        light as well skips the fan confirmation. An empty set means
        every key is shared with a later command, which is the older of
        two ``light=1`` writes, and that one must stay queued.

        Args:
            pending: The command being considered. Not the newest for
                every key it published.
            version: The document version.
            reported: The reported object from ``update/accepted``.
            retired: Commands this pass has retired. Appended to.
            retired_sets: Field sets of those commands. Appended to.

        Returns:
            True when this document newly recorded or retired the command.
        """
        independent = self._independent_keys(pending, retired)
        if not independent or not self._is_newest_for_keys(
            pending, independent, retired
        ):
            return False
        if any(
            key in reported and reported[key] != pending.fields[key]
            for key in independent
        ):
            return False
        recorded = _record_echo(
            pending,
            version,
            reported,
            retired,
            retired_sets,
            frozenset(independent),
        )
        if pending not in retired and independent <= set(pending.seen):
            retired.append(pending)
            retired_sets.append(frozenset(pending.fields))
            recorded = True
        return recorded

    def _retire_echo(self, version: object, reported: object) -> None:
        """Retires the commands this version echoes.

        The command published as ordinal N at a baseline belongs to
        version ``baseline + N + 1``. Two ``light=1`` writes at version
        10 therefore belong to versions 11 and 12. Version 12 retires the
        second even when it arrives first, and version 11 can still
        retire the first. Matching the oldest equal value instead gives
        12 to the first write and leaves the second pending over a later
        ``light=0``. That version is not exclusive. An unrelated update
        can take it, and the echo arrives later. When an older command
        published the same fields and its expected version was already
        that kind of miss, the document retires the older command. Giving
        it to the calculated owner retires the last ``light=1`` of
        ``1 → 2 → 1`` and the next document shows light 2.

        A document that is not the expected version of any queued command
        does not fall through to the oldest equal value. It can retire a
        numbered command whose expected version was already missed, when
        no newer command published the same fields. Otherwise it retires
        a numbered command when that command is the newest one still
        pending for every key it carries, which is how a gap between two
        light echoes still clears the later write. A command that is not
        newest can still confirm the keys no later command publishes, so
        a shared light does not throw away fan. An unrelated field at the
        version a light command expected leaves that light alone, and
        still retires a different key the document does carry. Returning
        before that key is considered leaves the earlier command pending
        over the GET.

        Commands that were published before any numbered document are not
        given expected versions from this echo, and the gap path does not
        treat the newest of them as the owner. They correlate on their
        own: one match retires that command, and several commands that
        publish the same value retire oldest first.

        A partial document records the keys it carries and does not hand
        the version to an older command that published the same keys.
        The command retires when every key has been seen. A key already
        seen is not a conflict when a later partial brings the rest: the
        device may have changed it, and refusing the document leaves the
        optimistic value over the newer one. One document can still
        retire a later command that adds a key, or a command on a
        different key, when every field of that command is in the
        document. It cannot retire a second command that published the
        same fields, and it cannot hand a later overlapping command the
        partial echoes of the earlier ones.

        A repeated delivery of a version already consumed retires nothing.
        The baseline stays where the command was published.

        Args:
            version: The document's ``version``, or None.
            reported: The reported object. Not a dict means nothing matches.
        """
        if not self._pending_writes or not isinstance(reported, dict):
            return
        if isinstance(version, bool) or not isinstance(version, int):
            return
        if version in self._consumed_echo_versions:
            return
        retired: list[_PendingWrite] = []
        retired_sets: list[frozenset[str]] = []
        recorded = False
        owner = next(
            (
                pending
                for pending in self._pending_writes
                if _expected_version(pending) == version
            ),
            None,
        )
        # Present and carrying one of the owner's values. A contradiction
        # or a total miss is not this command's echo. Keys the owner did
        # not publish are still reconciled below: returning here used to
        # strand fan when an unrelated update had already taken fan's
        # version, and the second key of a multi-key command when that
        # key arrived on the later command's version. A full match is
        # still not enough when an older command published the same
        # fields and its expected version was already a miss: this
        # document is that older echo, and the calculated owner stays
        # pending.
        owner_hit = False
        if (
            owner is not None
            and not _echo_conflicts(owner, reported)
            and (_echo_matches(owner, reported) or _echo_has_value(owner, reported))
        ):
            delayed = (
                self._oldest_same_fields_missed(owner)
                if _echo_matches(owner, reported)
                else None
            )
            target = delayed if delayed is not None else owner
            owner_hit = delayed is None
            if _record_echo(target, version, reported, retired, retired_sets):
                recorded = True
            claimed = [frozenset(target.fields), *retired_sets]
            if self._note_later_commands(
                target, version, reported, retired, retired_sets, claimed
            ):
                recorded = True
            if self._correlate_unversioned(
                version, reported, retired, retired_sets, claimed
            ):
                recorded = True
        else:
            if owner is not None and _echo_conflicts(owner, reported):
                delayed = self._oldest_conflict_match(owner, reported)
                if delayed is not None and _record_echo(
                    delayed, version, reported, retired, retired_sets
                ):
                    recorded = True
            # The version the arithmetic named was not this command's
            # echo. Remember it so a later document is not handed to
            # whichever command that arithmetic points at next.
            if owner is not None:
                self._missed_echo_versions.add(version)
            claimed = list(retired_sets)
            if self._correlate_unversioned(
                version, reported, retired, retired_sets, claimed
            ):
                recorded = True
        if owner is not None and self._reconcile_independent_keys(
            owner, version, reported, retired, retired_sets
        ):
            recorded = True
        if not owner_hit and owner is None:
            if self._correlate_missed_versions(
                version, reported, retired, retired_sets
            ):
                recorded = True
            for pending in self._pending_writes:
                # Unnumbered commands were correlated above. The newest
                # of them must not also take this version: that is the
                # end-anchor, reached by a different path.
                if pending.baseline is None or pending in retired:
                    continue
                if not _version_confirms(version, pending.baseline):
                    continue
                if any(
                    frozenset(pending.fields) == existing for existing in retired_sets
                ):
                    continue
                if self._command_is_newest_for_its_keys(pending):
                    if _record_echo(pending, version, reported, retired, retired_sets):
                        recorded = True
                    continue
                if self._retire_independent_keys(
                    pending, version, reported, retired, retired_sets
                ):
                    recorded = True
        if not recorded:
            return
        # Consumed before the queue changes, so a re-entrant delivery of
        # this same version cannot retire the command that is still there
        # or fill a key a partial echo already recorded.
        self._consumed_echo_versions.add(version)
        if not retired:
            return
        retire_ids = {id(pending) for pending in retired}
        self._pending_writes = [
            pending for pending in self._pending_writes if id(pending) not in retire_ids
        ]
        for pending in retired:
            for key in pending.fields:
                seen = self._confirmed_seq.get(key)
                if seen is None or pending.seq > seen:
                    self._confirmed_seq[key] = pending.seq

    def _pending_overlay(self) -> dict[str, int]:
        """Returns pending keys that are still ahead of a newer confirmation.

        Later commands win among those that qualify. A command older than
        one already confirmed for that key does not qualify: ``light=1``
        then ``light=2``, with the echo of ``2`` first, must not put ``1``
        back over the reported ``2``. The older command stays in the queue
        for its own echo. A newer command still qualifies when only an
        older one has been confirmed, so the second ``light=1`` stays
        visible until the echo that belongs to it arrives.

        Returns:
            Reported keys still waiting on a command that outranks the
            newest confirmation of that key.
        """
        overlay: dict[str, int] = {}
        for pending in self._pending_writes:
            for key, value in pending.fields.items():
                confirmed = self._confirmed_seq.get(key)
                if confirmed is not None and pending.seq < confirmed:
                    continue
                overlay[key] = value
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
            asyncio.CancelledError: The caller was cancelled. The join
                finishes first, and the same no-socket shape is left
                behind when ``shadow`` was still the live session.
        """
        async with self._lock:
            if self._shadow is not shadow:
                return
            try:
                await shadow.request_state()
            except (ZephyrNotConnectedError, asyncio.CancelledError):
                # request_state already disconnected, including when this
                # task was cancelled: the join finishes before
                # CancelledError propagates. Clear only the matching
                # reference, still inside this lock, and only now, so a
                # supervisor tick cannot observe a hollow client and also
                # cannot open the next session until that disconnect has
                # finished.
                self._forget_dead_shadow(shadow)
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
