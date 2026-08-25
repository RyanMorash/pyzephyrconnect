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
    payload = json.loads((FIXTURES / "discoverdevice.json").read_text())
    payload.update(overrides)
    return HoodCapabilities.from_discover(payload)


def _hood(caps=None):
    shadow = MagicMock()
    shadow.connect = AsyncMock()

    async def _yielding_disconnect():
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
    hood, shadow = _hood()
    await hood.async_start()

    await hood.async_set_light(2)
    shadow.publish_state.assert_awaited_with({"light": 2})

    await hood.async_set_clean_air(True)
    shadow.publish_state.assert_awaited_with({"setcleanairfunction": 1})

    await hood.async_reset_grease_filter()
    shadow.publish_state.assert_awaited_with({"resetgreasefilter": 1})


async def test_out_of_range_is_refused_before_anything_is_published():
    """The device advertises its own limits. Catching this locally beats a
    silent no-op on hardware."""
    hood, shadow = _hood()
    await hood.async_start()

    with pytest.raises(ZephyrWriteError):
        await hood.async_set_fan(7)          # reference hood maxes at 6
    shadow.publish_state.assert_not_awaited()


async def test_absent_capability_maximum_permits_the_write():
    """Hoods we have never seen omit capability keys. A missing maximum must
    not become a blanket refusal to write."""
    hood, shadow = _hood(_caps(maxFanSpeed=None))
    await hood.async_start()

    await hood.async_set_fan(9)
    shadow.publish_state.assert_awaited_with({"fan": 9})


async def test_negative_values_are_always_refused():
    hood, _ = _hood()
    await hood.async_start()
    with pytest.raises(ZephyrWriteError):
        await hood.async_set_light(-1)


async def test_raw_writes_enforce_the_allowlist():
    """The allowlist used to live only in the probe CLI, so any other caller
    could write anything."""
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
    """The single most dangerous failure in this protocol: without the policy,
    connect, subscribe and publish all succeed and every message is silently
    dropped, with no exception and no log line (PROTOCOL.md section 3.3)."""
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
    """The first paho client keeps its network thread running, so overwriting
    it leaks a thread and a socket per call."""
    made = []

    def factory(_h):
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
    """A transient connect failure during a supervisor rebuild leaves the
    hood with no socket but with consumer intent intact. It must come back
    on a later tick, not stay dead until a reload."""
    made = []

    def factory(_h):
        shadow = MagicMock()
        shadow.connect = AsyncMock(
            side_effect=ZephyrTransportError("boom") if len(made) == 1 else None
        )
        shadow.request_state = AsyncMock()
        shadow.disconnect = AsyncMock()
        made.append(shadow)
        return shadow

    hood = Hood(_caps(), factory, AsyncMock(), AsyncMock())
    await hood.async_start()                      # made[0] connects

    with pytest.raises(ZephyrTransportError):
        await hood.async_reconnect()              # made[1] fails; _shadow None

    await hood.async_ensure_running()             # made[2] recovers
    assert len(made) == 3
    made[2].request_state.assert_awaited()


async def test_reconnect_does_not_start_a_hood_that_was_never_started():
    """The supervisor reconnects every hood it knows about. Discovering two
    hoods and starting one must not mean the other quietly comes up on the
    next credential refresh."""
    hood, shadow = _hood()
    await hood.async_reconnect()

    shadow.connect.assert_not_awaited()


async def test_a_write_during_a_reconnect_waits_rather_than_failing():
    """The supervisor rebuilds the socket about every 50 minutes. A write
    landing in that window is not a disconnected hood, and must not surface
    to the user as a failed command."""
    import asyncio

    hood, shadow = _hood()
    await hood.async_start()

    release = asyncio.Event()

    async def slow_connect():
        await release.wait()

    shadow.connect = AsyncMock(side_effect=slow_connect)
    reconnect = asyncio.create_task(hood.async_reconnect())
    await asyncio.sleep(0)

    write = asyncio.create_task(hood.async_set_light(1))
    await asyncio.sleep(0)
    assert not write.done()          # waiting on the lock, not raising

    release.set()
    await reconnect
    await write
    shadow.publish_state.assert_awaited_with({"light": 1})


async def test_listeners_are_notified_and_removable():
    hood, _ = _hood()
    seen = []
    remove = hood.add_listener(seen.append)
    hood.handle_state(HoodState.from_reported({"power": 1}))
    remove()
    hood.handle_state(HoodState.from_reported({"power": 0}))

    assert len(seen) == 1


async def test_a_raising_listener_does_not_block_the_others(caplog):
    """One bad consumer must not stop the others from updating, and the
    failure must still be visible somewhere."""
    hood, _ = _hood()
    seen = []

    def bad(_state):
        raise RuntimeError("boom")

    hood.add_listener(bad)
    hood.add_listener(seen.append)

    state = HoodState.from_reported({"power": 1})
    with caplog.at_level(logging.ERROR):
        hood.handle_state(state)

    assert seen == [state]
    assert any(record.levelno == logging.ERROR for record in caplog.records)


async def test_not_connected_message_omits_the_thing_name():
    """No thing name in the message: it identifies a home, and exception
    text ends up in logs users paste publicly. The wording must also cover
    every way a hood can end up without a shadow, not just 'never
    started'."""
    hood, _ = _hood()
    with pytest.raises(ZephyrNotConnectedError, match="not connected") as excinfo:
        await hood.async_set_light(1)

    assert THING not in str(excinfo.value)


async def test_destructive_write_is_pinned_and_logged(caplog):
    """setrecirculating changes filter accounting for the hood. Pin both the
    exact published payload and the warning so a future refactor cannot
    silently drop either."""
    hood, shadow = _hood()
    await hood.async_start()

    with caplog.at_level(logging.WARNING):
        await hood.async_set_recirculating(True)

    shadow.publish_state.assert_awaited_with({"setrecirculating": 1})
    assert "setrecirculating" in caplog.text
    assert any(record.levelno == logging.WARNING for record in caplog.records)


async def test_intent_survives_a_failed_supervisor_rebuild():
    """A rebuild NOBODY asked for must not demote consumer intent back to
    'never started' - async_ensure_running is the sole recovery path and it
    keys off _should_run, not off having a socket.

    The supervisor-internal paths (async_reconnect, async_ensure_running,
    _stop_for_supervisor) go straight to _start/_stop and keep this
    semantics. Only the consumer-facing async_start rolls intent back - see
    test_a_failed_consumer_start_rolls_back_intent."""
    made = []

    def factory(_h):
        shadow = MagicMock()
        shadow.connect = AsyncMock(
            side_effect=ZephyrTransportError("boom") if len(made) == 1 else None
        )
        shadow.request_state = AsyncMock()
        shadow.disconnect = AsyncMock()
        made.append(shadow)
        return shadow

    hood = Hood(_caps(), factory, AsyncMock(), AsyncMock())
    await hood.async_start()                      # made[0] connects

    with pytest.raises(ZephyrTransportError):
        await hood.async_reconnect()              # made[1] fails mid-rebuild

    assert hood._should_run is True
    assert hood._shadow is None

    await hood.async_ensure_running()

    assert len(made) == 3
    made[2].connect.assert_awaited()
    made[2].request_state.assert_awaited()


async def test_a_failed_consumer_start_rolls_back_intent():
    """A start the CONSUMER asked for that raises must leave the hood
    genuinely stopped.

    Home Assistant's ConfigEntryNotReady pattern abandons the client whose
    setup failed and builds a fresh one on the retry. Leaving intent set
    would let this client's supervisor bring the abandoned hood up in the
    background, and its per-connection MQTT client IDs are identical to the
    replacement client's - AWS IoT treats two live connections sharing an ID
    as one session and evicts the working one for the zombie."""
    made = []

    def factory(_h):
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

    await hood.async_ensure_running()             # the next supervisor tick

    assert len(made) == 1                         # not revived


async def test_a_failed_state_request_leaves_the_hood_recoverable():
    """request_state() raising AFTER _shadow was set produced the worst
    possible shape: the hood LOOKED healthy - a later start returns early and
    async_ensure_running declines to rebuild while _shadow is not None - but
    the state GET never happened and nothing ever retried it. _start must put
    the hood back into the no-socket state the supervisor knows how to
    recover from, and tear the half-built client down rather than leak its
    paho network thread.

    Driven through the supervisor's rebuild here, which is where recovery
    has to work: a consumer-facing async_start that raises rolls intent back
    on purpose (see test_a_failed_consumer_start_rolls_back_intent), so
    there is deliberately nothing left to recover on that path."""
    made = []

    def factory(_h):
        shadow = MagicMock()
        shadow.connect = AsyncMock()
        shadow.disconnect = AsyncMock()
        shadow.request_state = AsyncMock(
            side_effect=ZephyrTransportError("boom") if len(made) == 1 else None
        )
        made.append(shadow)
        return shadow

    hood = Hood(_caps(), factory, AsyncMock(), AsyncMock())
    await hood.async_start()             # made[0] connects and reads state

    with pytest.raises(ZephyrTransportError):
        await hood.async_reconnect()     # made[1]'s request_state raises

    assert hood._shadow is None          # not left looking connected
    assert hood._should_run is True      # consumer intent survives
    made[1].disconnect.assert_awaited_once()

    await hood.async_ensure_running()    # the next supervisor tick

    assert len(made) == 3
    made[2].request_state.assert_awaited()


async def test_async_stop_clears_intent_so_ensure_running_stays_off():
    hood, shadow = _hood()
    await hood.async_start()
    await hood.async_stop()

    assert hood._should_run is False
    assert hood.connected is False

    await hood.async_ensure_running()

    shadow.connect.assert_awaited_once()  # no rebuild: intent was cleared


async def test_empty_fields_payload_is_refused():
    hood, shadow = _hood()
    await hood.async_start()

    with pytest.raises(ZephyrWriteError):
        await hood.async_set_fields({})

    shadow.publish_state.assert_not_awaited()


async def test_poll_records_state_and_notifies_listeners():
    hood, _ = _hood()
    seen = []
    hood.add_listener(seen.append)

    state = await hood.async_poll()

    assert hood.state is state
    assert seen == [state]


async def test_stop_swaps_the_shadow_reference_before_the_await():
    """Regression for the cancellation-landing-on-await bug: _shadow must
    already be None the instant the teardown await starts, not after it
    returns. Otherwise a cancellation there leaves _shadow pointing at a
    torn-down client while _should_run is still True, and
    async_ensure_running declines to rebuild forever - a permanently dark
    hood."""
    hood, shadow = _hood()
    await hood.async_start()

    never_set = asyncio.Event()

    async def hang() -> None:
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
    """A disconnect() that raises must not leave the hood reporting
    connected=True with _shadow already torn down - that would mislead the
    derived client.connected and availability logic. The flag joins the
    swap on the clear-before-await side of _stop for exactly this reason."""
    hood, shadow = _hood()
    await hood.async_start()
    hood.handle_connection_change(True)
    shadow.disconnect = AsyncMock(side_effect=OSError("boom"))

    with pytest.raises(OSError):
        await hood.async_stop()

    assert hood.connected is False
    assert hood._shadow is None


async def test_typed_power_and_delay_timer_publish_shapes():
    hood, shadow = _hood()
    await hood.async_start()

    await hood.async_set_power(True)
    shadow.publish_state.assert_awaited_with({"power": 1})

    await hood.async_set_delay_timer(300)
    shadow.publish_state.assert_awaited_with({"setdelaytimer": 300})


async def test_a_write_refused_by_a_dead_socket_leaves_a_recoverable_hood():
    """ShadowClient tears its own connection down when paho refuses a write
    it has already queued - the only way to stop that write actuating the
    hood on paho's next reconnect. The hood must not keep pointing at the
    hollowed-out client afterwards: async_ensure_running declines to rebuild
    while _shadow is set, and needs_represign sees a generation that still
    matches, so push would stay dark until the next credential rotation."""
    made = []

    def factory(_h):
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
    assert hood._should_run is True        # the consumer still wants it up

    await hood.async_ensure_running()      # the next supervisor tick

    assert len(made) == 2
    await hood.async_set_light(1)
    made[1].publish_state.assert_awaited_with({"light": 1})
