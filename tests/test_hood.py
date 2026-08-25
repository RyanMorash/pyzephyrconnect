import json
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
    shadow.disconnect = AsyncMock()
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
