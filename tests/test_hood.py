"""Tests for pyzephyrconnect.hood."""

import asyncio
import contextlib
import json
import logging
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from pyzephyrconnect.exceptions import (
    ZephyrNotConnectedError,
    ZephyrTransportError,
    ZephyrWriteError,
)
from pyzephyrconnect.hood import Hood
from pyzephyrconnect.models import HoodCapabilities, HoodState

FIXTURES = Path(__file__).parent / "fixtures"
THING = "aaaaaaaabbbbbbbbccccccccddddddddeeeeeeee"


def _caps(**overrides) -> HoodCapabilities:
    """Build HoodCapabilities from the discover fixture with overrides."""
    payload = json.loads((FIXTURES / "discoverdevice.json").read_text())
    payload.update(overrides)
    return HoodCapabilities.from_discover(payload)


def _hood(caps=None):
    """Build a Hood wired to a mocked shadow and return both."""
    shadow = MagicMock()
    shadow.connect = AsyncMock()

    async def _yielding_disconnect():
        """Disconnect double that yields twice before returning."""
        # A real teardown awaits a thread join; yield twice so lock-release
        # races between _stop and _start become observable to tests.
        await asyncio.sleep(0)
        await asyncio.sleep(0)

    shadow.disconnect = AsyncMock(side_effect=_yielding_disconnect)
    shadow.request_state = AsyncMock()
    shadow.publish_state = AsyncMock()
    hood = Hood(
        caps or _caps(),
        shadow_factory=lambda _hood: shadow,
        poll=AsyncMock(return_value=HoodState.from_reported({"power": 1})),
        prepare=AsyncMock(),
    )
    return hood, shadow


async def test_typed_methods_publish_the_vendor_field_names():
    """Tests that typed setters publish the vendor field names."""
    hood, shadow = _hood()
    await hood.async_start()

    await hood.async_set_light(2)
    shadow.publish_state.assert_awaited_with({"light": 2})

    await hood.async_set_clean_air(True)
    shadow.publish_state.assert_awaited_with({"setcleanairfunction": 1})

    await hood.async_reset_grease_filter()
    shadow.publish_state.assert_awaited_with({"resetgreasefilter": 1})


async def test_out_of_range_is_refused_before_anything_is_published():
    """Tests that an out-of-range write is refused before publishing.

    The device advertises its own limits. Catching this locally beats a
    silent no-op on hardware.
    """
    hood, shadow = _hood()
    await hood.async_start()

    with pytest.raises(ZephyrWriteError):
        await hood.async_set_fan(7)  # reference hood maxes at 6
    shadow.publish_state.assert_not_awaited()


async def test_absent_capability_maximum_permits_the_write():
    """Tests that a missing capability maximum still permits the write.

    Hoods we have never seen omit capability keys. A missing maximum must
    not become a blanket refusal to write.
    """
    hood, shadow = _hood(_caps(maxFanSpeed=None))
    await hood.async_start()

    await hood.async_set_fan(9)
    shadow.publish_state.assert_awaited_with({"fan": 9})


async def test_negative_values_are_always_refused():
    """Tests that a negative value raises ZephyrWriteError."""
    hood, _ = _hood()
    await hood.async_start()
    with pytest.raises(ZephyrWriteError):
        await hood.async_set_light(-1)


async def test_raw_writes_enforce_the_allowlist():
    """Tests that raw field writes enforce the writable allowlist.

    The allowlist used to live only in the probe CLI, so any other caller
    could write anything.
    """
    hood, shadow = _hood()
    await hood.async_start()

    with pytest.raises(ZephyrWriteError):
        await hood.async_set_fields({"usefantime": 0})
    shadow.publish_state.assert_not_awaited()


async def test_writing_before_start_raises_a_library_error():
    """Previously a bare RuntimeError, which escaped ZephyrError."""
    hood, _ = _hood()
    with pytest.raises(ZephyrNotConnectedError):
        await hood.async_set_light(1)


async def test_policy_is_attached_before_the_socket_opens():
    """Tests that the policy attach completes before connect.

    The single most dangerous failure in this protocol: without the policy,
    connect, subscribe and publish all succeed and every message is silently
    dropped, with no exception and no log line (PROTOCOL.md section 3.3).
    """
    order = []
    shadow = MagicMock()
    shadow.connect = AsyncMock(side_effect=lambda: order.append("connect"))
    shadow.request_state = AsyncMock()
    hood = Hood(
        _caps(),
        shadow_factory=lambda _h: shadow,
        poll=AsyncMock(),
        prepare=AsyncMock(side_effect=lambda: order.append("prepare")),
    )
    await hood.async_start()

    assert order == ["prepare", "connect"]


async def test_starting_twice_does_not_orphan_a_client():
    """Tests that a second start does not build a second client.

    The first paho client keeps its network thread running, so overwriting
    it leaks a thread and a socket per call.
    """
    made = []

    def factory(_h):
        """Shadow factory that records every client it builds."""
        shadow = MagicMock()
        shadow.connect = AsyncMock()
        shadow.request_state = AsyncMock()
        made.append(shadow)
        return shadow

    hood = Hood(_caps(), factory, AsyncMock(), AsyncMock())
    await hood.async_start()
    await hood.async_start()

    assert len(made) == 1


async def test_ensure_running_recovers_a_hood_whose_rebuild_failed():
    """Tests that ensure_running revives a hood after a failed rebuild.

    A transient connect failure during a supervisor rebuild leaves the
    hood with no socket but with consumer intent intact. It must come back
    on a later tick, not stay dead until a reload.
    """
    made = []

    def factory(_h):
        """Shadow factory whose second client fails to connect."""
        shadow = MagicMock()
        shadow.connect = AsyncMock(
            side_effect=ZephyrTransportError("boom") if len(made) == 1 else None
        )
        shadow.request_state = AsyncMock()
        shadow.disconnect = AsyncMock()
        made.append(shadow)
        return shadow

    hood = Hood(_caps(), factory, AsyncMock(), AsyncMock())
    await hood.async_start()  # made[0] connects

    with pytest.raises(ZephyrTransportError):
        await hood.async_reconnect()  # made[1] fails; _shadow None

    await hood.async_ensure_running()  # made[2] recovers
    assert len(made) == 3
    made[2].request_state.assert_awaited()


async def test_reconnect_does_not_start_a_hood_that_was_never_started():
    """Tests that reconnect skips a hood that was never started.

    The supervisor reconnects every hood it knows about. Discovering two
    hoods and starting one must not mean the other quietly comes up on the
    next credential refresh.
    """
    hood, shadow = _hood()
    await hood.async_reconnect()

    shadow.connect.assert_not_awaited()


async def test_a_write_during_a_reconnect_waits_rather_than_failing():
    """Tests that a write during a reconnect waits only until publish is legal.

    The supervisor rebuilds the socket about every 50 minutes. A write
    landing before the new session is up is not a disconnected hood, and
    must not surface as a failed command. It also must not wait for the
    state GET that follows CONNACK: that GET is not on the command path.
    The old socket is stopped before the new one connects.
    """
    import asyncio

    hood, shadow = _hood()
    await hood.async_start()
    shadow.publish_state.reset_mock()

    order: list[str] = []
    connack = asyncio.Event()
    get_release = asyncio.Event()

    async def slow_connect():
        """Connect double that blocks until the test releases CONNACK."""
        order.append("connect")
        await connack.wait()

    async def slow_get():
        """State GET that blocks until the test releases it."""
        order.append("get")
        await get_release.wait()

    async def disc():
        """Record disconnect relative to the replacement connect."""
        order.append("disconnect")

    shadow.connect.side_effect = slow_connect
    shadow.request_state.side_effect = slow_get
    shadow.disconnect.side_effect = disc

    reconnect = asyncio.create_task(hood.async_reconnect())
    await asyncio.sleep(0)

    early = asyncio.create_task(hood.async_set_light(1))
    await asyncio.sleep(0)
    assert not early.done()  # still before CONNACK; waiting, not raising

    connack.set()
    for _ in range(10):
        await asyncio.sleep(0)
        if early.done() and "get" in order:
            break
    assert early.done()
    assert not reconnect.done()  # parked on the state GET
    shadow.publish_state.assert_awaited_with({"light": 1})

    during_get = asyncio.create_task(hood.async_set_light(2))
    await asyncio.sleep(0)
    assert during_get.done()  # the GET is outside the lock
    shadow.publish_state.assert_awaited_with({"light": 2})

    get_release.set()
    await reconnect
    assert order == ["disconnect", "connect", "get"]
    assert shadow.connect.await_count == 2  # start, then this rebuild


async def test_listeners_are_notified_and_removable():
    """Tests that listeners get states and stop after removal."""
    hood, _ = _hood()
    seen = []
    remove = hood.add_listener(seen.append)
    hood.handle_state(HoodState.from_reported({"power": 1}))
    remove()
    hood.handle_state(HoodState.from_reported({"power": 0}))

    assert len(seen) == 1


async def test_a_raising_listener_does_not_block_the_others(caplog):
    """Tests that a raising listener is logged and others still run.

    One bad consumer must not stop the others from updating, and the
    failure must still be visible somewhere.
    """
    hood, _ = _hood()
    seen = []

    def bad(_state):
        """Listener that always raises RuntimeError."""
        raise RuntimeError("boom")

    hood.add_listener(bad)
    hood.add_listener(seen.append)

    state = HoodState.from_reported({"power": 1})
    with caplog.at_level(logging.ERROR):
        hood.handle_state(state)

    assert seen == [state]
    assert any(record.levelno == logging.ERROR for record in caplog.records)


async def test_not_connected_message_omits_the_thing_name():
    """Tests that the not-connected message omits the thing name.

    No thing name in the message: it identifies a home, and exception
    text ends up in logs users paste publicly. The wording must also cover
    every way a hood can end up without a shadow, not just 'never
    started'.
    """
    hood, _ = _hood()
    with pytest.raises(ZephyrNotConnectedError, match="not connected") as excinfo:
        await hood.async_set_light(1)

    assert THING not in str(excinfo.value)


async def test_destructive_write_is_pinned_and_logged(caplog):
    """Tests that the recirculating write payload and warning are pinned.

    setrecirculating changes filter accounting for the hood. Pin both the
    exact published payload and the warning so a future refactor cannot
    silently drop either.
    """
    hood, shadow = _hood()
    await hood.async_start()

    with caplog.at_level(logging.WARNING):
        await hood.async_set_recirculating(True)

    shadow.publish_state.assert_awaited_with({"setrecirculating": 1})
    assert "setrecirculating" in caplog.text
    assert any(record.levelno == logging.WARNING for record in caplog.records)


async def test_intent_survives_a_failed_supervisor_rebuild():
    """Tests that consumer intent survives a failed supervisor rebuild.

    A rebuild NOBODY asked for must not demote consumer intent back to
    'never started' - async_ensure_running is the sole recovery path and it
    keys off _should_run, not off having a socket.

    The supervisor-internal paths (async_reconnect, async_ensure_running,
    _stop_for_supervisor) go straight to _start/_stop and keep this
    semantics. Only the consumer-facing async_start rolls intent back - see
    test_a_failed_consumer_start_rolls_back_intent.
    """
    made = []

    def factory(_h):
        """Shadow factory whose second client fails to connect."""
        shadow = MagicMock()
        shadow.connect = AsyncMock(
            side_effect=ZephyrTransportError("boom") if len(made) == 1 else None
        )
        shadow.request_state = AsyncMock()
        shadow.disconnect = AsyncMock()
        made.append(shadow)
        return shadow

    hood = Hood(_caps(), factory, AsyncMock(), AsyncMock())
    await hood.async_start()  # made[0] connects

    with pytest.raises(ZephyrTransportError):
        await hood.async_reconnect()  # made[1] fails mid-rebuild

    assert hood._should_run is True
    assert hood._shadow is None

    await hood.async_ensure_running()

    assert len(made) == 3
    made[2].connect.assert_awaited()
    made[2].request_state.assert_awaited()


async def test_a_failed_consumer_start_rolls_back_intent():
    """Tests that a failed consumer start rolls back consumer intent.

    A start the CONSUMER asked for that raises must leave the hood
    genuinely stopped.

    Home Assistant's ConfigEntryNotReady pattern abandons the client whose
    setup failed and builds a fresh one on the retry. Leaving intent set
    would let this client's supervisor bring the abandoned hood up in the
    background, and its per-connection MQTT client IDs are identical to the
    replacement client's - AWS IoT treats two live connections sharing an ID
    as one session and evicts the working one for the zombie.
    """
    made = []

    def factory(_h):
        """Shadow factory whose every client fails to connect."""
        shadow = MagicMock()
        shadow.connect = AsyncMock(side_effect=ZephyrTransportError("boom"))
        shadow.request_state = AsyncMock()
        shadow.disconnect = AsyncMock()
        made.append(shadow)
        return shadow

    hood = Hood(_caps(), factory, AsyncMock(), AsyncMock())

    with pytest.raises(ZephyrTransportError):
        await hood.async_start()

    assert hood._should_run is False
    assert hood._shadow is None

    await hood.async_ensure_running()  # the next supervisor tick

    assert len(made) == 1  # not revived


async def test_a_failed_state_request_leaves_the_hood_recoverable():
    """Tests that a failed state request leaves the hood recoverable.

    request_state() raising AFTER _shadow was set produced the worst
    possible shape: the hood LOOKED healthy - a later start returns early and
    async_ensure_running declines to rebuild while _shadow is not None - but
    the state GET never happened and nothing ever retried it. _start must put
    the hood back into the no-socket state the supervisor knows how to
    recover from, and tear the half-built client down rather than leak its
    paho network thread.

    Driven through the supervisor's rebuild here, which is where recovery
    has to work: a consumer-facing async_start that raises rolls intent back
    on purpose (see test_a_failed_consumer_start_rolls_back_intent), so
    there is deliberately nothing left to recover on that path.
    """
    made = []

    def factory(_h):
        """Shadow factory whose second client fails its state request."""
        shadow = MagicMock()
        shadow.connect = AsyncMock()
        shadow.disconnect = AsyncMock()
        shadow.request_state = AsyncMock(
            side_effect=ZephyrTransportError("boom") if len(made) == 1 else None
        )
        made.append(shadow)
        return shadow

    hood = Hood(_caps(), factory, AsyncMock(), AsyncMock())
    await hood.async_start()  # made[0] connects and reads state

    with pytest.raises(ZephyrTransportError):
        await hood.async_reconnect()  # made[1]'s request_state raises

    assert hood._shadow is None  # not left looking connected
    assert hood._should_run is True  # consumer intent survives
    made[1].disconnect.assert_awaited_once()

    await hood.async_ensure_running()  # the next supervisor tick

    assert len(made) == 3
    made[2].request_state.assert_awaited()


async def test_async_stop_clears_intent_so_ensure_running_stays_off():
    """Tests that async_stop clears intent so no rebuild happens."""
    hood, shadow = _hood()
    await hood.async_start()
    await hood.async_stop()

    assert hood._should_run is False
    assert hood.connected is False

    await hood.async_ensure_running()

    shadow.connect.assert_awaited_once()  # no rebuild: intent was cleared


async def test_empty_fields_payload_is_refused():
    """Tests that an empty fields payload raises without publishing."""
    hood, shadow = _hood()
    await hood.async_start()

    with pytest.raises(ZephyrWriteError):
        await hood.async_set_fields({})

    shadow.publish_state.assert_not_awaited()


async def test_poll_records_state_and_notifies_listeners():
    """Tests that async_poll stores state and notifies listeners."""
    hood, _ = _hood()
    seen = []
    hood.add_listener(seen.append)

    state = await hood.async_poll()

    assert hood.state is state
    assert seen == [state]


async def test_stop_swaps_the_shadow_reference_before_the_await():
    """Tests that _stop clears _shadow before awaiting the teardown.

    Regression for the cancellation-landing-on-await bug: _shadow must
    already be None the instant the teardown await starts, not after it
    returns. Otherwise a cancellation there leaves _shadow pointing at a
    torn-down client while _should_run is still True, and
    async_ensure_running declines to rebuild forever - a permanently dark
    hood.
    """
    hood, shadow = _hood()
    await hood.async_start()

    never_set = asyncio.Event()

    async def hang() -> None:
        """Disconnect double that blocks forever."""
        await never_set.wait()

    shadow.disconnect = AsyncMock(side_effect=hang)

    task = asyncio.create_task(hood.async_stop())
    for _ in range(3):
        await asyncio.sleep(0)

    assert hood._shadow is None  # swap already happened before the await

    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task

    assert hood._should_run is False

    await hood.async_ensure_running()
    shadow.connect.assert_awaited_once()  # not revived


async def test_connected_flag_clears_before_a_failed_teardown_propagates():
    """Tests that connected clears even when disconnect raises.

    A disconnect() that raises must not leave the hood reporting
    connected=True with _shadow already torn down - that would mislead the
    derived client.connected and availability logic. The flag joins the
    swap on the clear-before-await side of _stop for exactly this reason.
    """
    hood, shadow = _hood()
    await hood.async_start()
    hood.handle_connection_change(True)
    shadow.disconnect = AsyncMock(side_effect=OSError("boom"))

    with pytest.raises(OSError):
        await hood.async_stop()

    assert hood.connected is False
    assert hood._shadow is None


async def test_typed_power_and_delay_timer_publish_shapes():
    """Tests that power and delay-timer setters publish vendor shapes."""
    hood, shadow = _hood()
    await hood.async_start()

    await hood.async_set_power(True)
    shadow.publish_state.assert_awaited_with({"power": 1})

    await hood.async_set_delay_timer(300)
    shadow.publish_state.assert_awaited_with({"setdelaytimer": 300})


async def test_a_write_refused_by_a_dead_socket_leaves_a_recoverable_hood():
    """Tests that a dead-socket write refusal leaves a recoverable hood.

    ShadowClient tears its own connection down when paho refuses a write
    it has already queued - the only way to stop that write actuating the
    hood on paho's next reconnect. The hood must not keep pointing at the
    hollowed-out client afterwards: async_ensure_running declines to rebuild
    while _shadow is set, and needs_represign sees a generation that still
    matches, so push would stay dark until the next credential rotation.
    """
    made = []

    def factory(_h):
        """Shadow factory whose first client refuses writes as dead."""
        shadow = MagicMock()
        shadow.connect = AsyncMock()
        shadow.disconnect = AsyncMock()
        shadow.request_state = AsyncMock()
        shadow.publish_state = AsyncMock(
            side_effect=ZephyrNotConnectedError("hood is not connected")
            if not made
            else None
        )
        made.append(shadow)
        return shadow

    hood = Hood(_caps(), factory, AsyncMock(), AsyncMock())
    await hood.async_start()
    hood.handle_connection_change(True)

    with pytest.raises(ZephyrNotConnectedError):
        await hood.async_set_light(1)

    assert hood._shadow is None
    assert hood.connected is False
    assert hood._should_run is True  # the consumer still wants it up
    # The refusal must not look like the light changed.
    assert hood.state is None

    await hood.async_ensure_running()  # the next supervisor tick

    assert len(made) == 2
    await hood.async_set_light(1)
    made[1].publish_state.assert_awaited_with({"light": 1})


async def test_a_successful_write_updates_state_before_any_shadow_message():
    """Tests that a successful write is visible before the echo arrives.

    The publish payload stays the written field only. Counters already in
    the cache survive: merging the partial payload over raw is what keeps
    them, and replacing the cache with that payload would zero them.
    """
    hood, shadow = _hood()
    await hood.async_start()
    hood.handle_state(HoodState.from_reported({"light": 0, "usegreasefiltertime": 642}))
    seen = []
    hood.add_listener(seen.append)

    await hood.async_set_light(1)

    shadow.publish_state.assert_awaited_with({"light": 1})
    assert hood.state is not None
    assert hood.state.light == 1
    assert hood.state.use_grease_filter_time == 642
    assert len(seen) == 1
    assert seen[0].light == 1


async def test_a_destructive_write_does_not_change_cached_state():
    """Tests that a destructive write waits for the device to confirm it.

    resetgreasefilter zeroes a counter that cannot be reconstructed, and
    setrecirculating changes filter accounting. Showing either locally
    before update/accepted would lie about a change the device may ignore.
    """
    hood, _shadow = _hood()
    await hood.async_start()
    hood.handle_state(
        HoodState.from_reported({"setrecirculating": 0, "usegreasefiltertime": 642})
    )

    await hood.async_set_recirculating(True)

    assert hood.state is not None
    assert hood.state.set_recirculating == 0
    assert hood.state.use_grease_filter_time == 642
    assert hood._pending_writes == []


async def test_a_failed_publish_does_not_pretend_the_write_landed():
    """Tests that a refused publish leaves state and listeners untouched."""
    hood, shadow = _hood()
    await hood.async_start()
    hood.handle_state(HoodState.from_reported({"light": 0, "usegreasefiltertime": 642}))
    before = hood.state
    seen = []
    hood.add_listener(seen.append)
    shadow.publish_state = AsyncMock(side_effect=ZephyrNotConnectedError("down"))

    with pytest.raises(ZephyrNotConnectedError):
        await hood.async_set_light(1)

    assert hood.state is before
    assert seen == []
    assert hood._shadow is None


async def test_an_abandoned_presign_does_not_mark_the_old_socket_current():
    """Tests that a presign abandoned before disconnect keeps the old generation.

    The credentials provider records the generation as it presigns. If that
    record stuck while the old socket was still the live one, the supervisor
    would see no mismatch and stop rebuilding a session signed under the
    previous credentials.
    """

    class _SplittingShadow:
        """Double that presigns offline, the way ShadowClient does."""

        prepares_transport_before_disconnect = True

        def __init__(self) -> None:
            """Installs the async methods Hood calls on a real shadow."""
            self.connect = AsyncMock()
            self.disconnect = AsyncMock()
            self.request_state = AsyncMock()
            self.finish_subscriptions = AsyncMock()
            self.open_until_connack = AsyncMock()
            self.prepare_transport = AsyncMock()

    made: list[_SplittingShadow] = []

    def factory(hood: Hood) -> _SplittingShadow:
        """Build a splitting double that aborts the rebuild during presign."""
        shadow = _SplittingShadow()

        async def prepare() -> None:
            """Stamp a generation on this socket, then drop consumer intent."""
            # On the shadow, not the hood. Committing it here would describe
            # the socket that is still live if this rebuild is abandoned.
            shadow.presigned_generation = 7
            hood._should_run = False

        shadow.prepare_transport = AsyncMock(side_effect=prepare)
        made.append(shadow)
        return shadow

    hood = Hood(_caps(), factory, AsyncMock(), AsyncMock())
    await hood.async_start()
    hood._presigned_generation = 1
    first = made[0]

    await hood.async_reconnect()

    assert hood._presigned_generation == 1
    assert hood._shadow is first
    first.disconnect.assert_not_awaited()
    first.open_until_connack.assert_not_awaited()


def _splitting_factory(made: list, prepare):
    """Build a shadow factory whose clients presign before disconnecting.

    Args:
        made: Collects every shadow the factory builds, in order.
        prepare: Async side effect installed on each shadow's
            ``prepare_transport``. Receives the shadow and its index.
    """

    class _SplittingShadow:
        """Double that presigns offline, the way ShadowClient does."""

        prepares_transport_before_disconnect = True

        def __init__(self) -> None:
            """Installs the async methods Hood calls on a real shadow."""
            self.presigned_generation: int | None = None
            self.connect = AsyncMock()
            self.disconnect = AsyncMock()
            self.request_state = AsyncMock()
            self.finish_subscriptions = AsyncMock()
            self.open_until_connack = AsyncMock()
            self.prepare_transport = AsyncMock()

    def factory(_hood: Hood) -> _SplittingShadow:
        """Build one splitting double and register ``prepare`` on it."""
        shadow = _SplittingShadow()
        index = len(made)

        async def run_prepare() -> None:
            """Run the test's presign side effect for this shadow."""
            await prepare(shadow, index)

        shadow.prepare_transport = AsyncMock(side_effect=run_prepare)
        made.append(shadow)
        return shadow

    return factory


async def test_overlapping_reconnects_keep_the_installed_generation():
    """Tests that a losing presign does not describe the socket that won.

    Both rebuilds presign before either takes the lock. The generation
    belongs to the socket that is installed. Recording the loser's
    generation would make needs_represign() treat an expiring URL as
    current.
    """
    made: list = []
    release_a = asyncio.Event()
    release_b = asyncio.Event()
    entered_a = asyncio.Event()
    entered_b = asyncio.Event()

    async def prepare(shadow, index: int) -> None:
        """Stamp this rebuild's generation and wait until released."""
        if index == 1:
            shadow.presigned_generation = 2
            entered_a.set()
            await release_a.wait()
        elif index == 2:
            shadow.presigned_generation = 3
            entered_b.set()
            await release_b.wait()

    hood = Hood(_caps(), _splitting_factory(made, prepare), AsyncMock(), AsyncMock())
    await hood.async_start()
    hood._presigned_generation = 1

    task_a = asyncio.create_task(hood.async_reconnect())
    await entered_a.wait()
    task_b = asyncio.create_task(hood.async_reconnect())
    await entered_b.wait()
    assert hood._presigned_generation == 1

    release_a.set()
    await task_a
    assert hood._shadow is made[1]
    assert hood._presigned_generation == 2

    release_b.set()
    await task_b
    assert hood._shadow is made[1]
    assert hood._presigned_generation == 2
    assert hood.needs_represign(3) is True
    assert hood.needs_represign(2) is False


async def test_a_failed_overlapping_presign_does_not_restore_an_older_generation():
    """Tests that a presign failure does not roll the installed generation back.

    The loser starts before the winner is installed, so the generation it
    would restore is the previous socket's. Writing that back after the
    winner is installed makes needs_represign() rebuild a URL that is
    already current, or skip one that is not.
    """
    made: list = []
    release_a = asyncio.Event()
    release_b = asyncio.Event()
    entered_a = asyncio.Event()
    entered_b = asyncio.Event()

    async def prepare(shadow, index: int) -> None:
        """Let the winner install, then fail the loser."""
        if index == 1:
            shadow.presigned_generation = 2
            entered_a.set()
            await release_a.wait()
        elif index == 2:
            entered_b.set()
            await release_b.wait()
            raise RuntimeError("presign failed")

    hood = Hood(_caps(), _splitting_factory(made, prepare), AsyncMock(), AsyncMock())
    await hood.async_start()
    hood._presigned_generation = 1

    task_a = asyncio.create_task(hood.async_reconnect())
    await entered_a.wait()
    task_b = asyncio.create_task(hood.async_reconnect())
    await entered_b.wait()

    release_a.set()
    await task_a
    assert hood._presigned_generation == 2

    release_b.set()
    with pytest.raises(RuntimeError, match="presign failed"):
        await task_b

    assert hood._shadow is made[1]
    assert hood._presigned_generation == 2
    assert hood.needs_represign(2) is False


async def test_a_failed_get_disconnects_before_another_session_opens():
    """Tests that a failed state GET finishes disconnect before a new connect.

    Clearing ``_shadow`` and releasing the lock first lets
    ``async_ensure_running`` open a session while the failed client's
    network thread is still stopping. Both use the same client ID.
    """
    made: list = []
    order: list[str] = []
    blocked = asyncio.Event()
    release = asyncio.Event()

    def factory(_hood: Hood):
        """Build a shadow that blocks disconnect on the failed rebuild."""
        index = len(made)
        shadow = MagicMock()

        async def connect() -> None:
            """Record this session opening."""
            order.append(f"connect-{index}")

        async def disconnect() -> None:
            """Block the failed session's teardown until the test releases it."""
            order.append(f"disconnect-start-{index}")
            if index == 1:
                blocked.set()
                await release.wait()
            order.append(f"disconnect-end-{index}")

        shadow.connect = AsyncMock(side_effect=connect)
        shadow.disconnect = AsyncMock(side_effect=disconnect)
        shadow.request_state = AsyncMock(
            side_effect=ZephyrTransportError("boom") if index == 1 else None
        )
        made.append(shadow)
        return shadow

    hood = Hood(_caps(), factory, AsyncMock(), AsyncMock())
    await hood.async_start()
    order.clear()

    reconnect = asyncio.create_task(hood.async_reconnect())
    await blocked.wait()
    ensure = asyncio.create_task(hood.async_ensure_running())
    await asyncio.sleep(0)
    assert "connect-2" not in order

    release.set()
    with pytest.raises(ZephyrTransportError):
        await reconnect
    await ensure

    assert order.index("disconnect-end-1") < order.index("connect-2")


async def test_a_failed_prepared_get_disconnects_before_another_session_opens():
    """Tests that the presign-first rebuild disconnects before a new connect.

    The state GET after CONNACK is outside the lock on success. On failure
    the disconnect still has to finish before ``async_ensure_running`` is
    allowed to open the replacement session.
    """
    made: list = []
    order: list[str] = []
    blocked = asyncio.Event()
    release = asyncio.Event()

    async def prepare(shadow, index: int) -> None:
        """No generation race in this test; presign returns immediately."""
        shadow.presigned_generation = 1

    factory = _splitting_factory(made, prepare)

    def tracking_factory(_hood: Hood):
        """Wrap the splitting factory and record connect versus disconnect."""
        shadow = factory(_hood)
        index = len(made) - 1

        async def connect() -> None:
            """Record a session opened through the non-split path."""
            order.append(f"connect-{index}")

        async def disconnect() -> None:
            """Block teardown of the session whose state GET failed."""
            order.append(f"disconnect-start-{index}")
            if index == 1:
                blocked.set()
                await release.wait()
            order.append(f"disconnect-end-{index}")

        shadow.connect = AsyncMock(side_effect=connect)
        shadow.disconnect = AsyncMock(side_effect=disconnect)
        if index == 1:
            shadow.request_state = AsyncMock(side_effect=ZephyrTransportError("boom"))
        return shadow

    hood = Hood(_caps(), tracking_factory, AsyncMock(), AsyncMock())
    await hood.async_start()
    order.clear()

    reconnect = asyncio.create_task(hood.async_reconnect())
    await blocked.wait()
    ensure = asyncio.create_task(hood.async_ensure_running())
    await asyncio.sleep(0)
    assert "connect-2" not in order

    release.set()
    with pytest.raises(ZephyrTransportError):
        await reconnect
    await ensure

    assert order.index("disconnect-end-1") < order.index("connect-2")


async def test_a_rejected_reread_on_a_dead_socket_clears_it():
    """Tests that a refused rejection-GET leaves a hood the supervisor can reopen.

    ``request_state`` tears its paho client down and raises. Leaving
    ``_shadow`` set afterwards means ``async_ensure_running`` will not
    rebuild and ``needs_represign`` still sees a matching generation.
    """
    hood, shadow = _hood()
    await hood.async_start()
    hood.handle_connection_change(True)
    shadow.connect.reset_mock()
    shadow.request_state = AsyncMock(
        side_effect=ZephyrNotConnectedError("hood is not connected")
    )

    hood.schedule_state_reread()
    task = hood._reread_task
    assert task is not None
    with pytest.raises(ZephyrNotConnectedError):
        await task

    assert hood._shadow is None
    assert hood.connected is False
    assert hood._should_run is True

    # The same double is what the factory hands back. The refusal belonged
    # to the dead session; the rebuilt one has to be able to read state.
    shadow.request_state = AsyncMock()
    await hood.async_ensure_running()
    shadow.connect.assert_awaited()


async def test_a_rejected_reread_leaves_a_newer_socket_in_place():
    """Tests that a reread for a replaced socket does not drop the new one.

    The rejection captured the previous session. By the time the reread
    runs, a rebuild may already have installed another. Clearing whichever
    ``_shadow`` happens to be set would drop that live session.
    """
    hood, shadow = _hood()
    await hood.async_start()
    newer = MagicMock()
    hood._shadow = newer
    shadow.request_state = AsyncMock(
        side_effect=ZephyrNotConnectedError("hood is not connected")
    )

    await hood._reread_after_rejection(shadow)

    shadow.request_state.assert_not_awaited()
    assert hood._shadow is newer
