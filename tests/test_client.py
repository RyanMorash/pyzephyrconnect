import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from pyzephyrconnect import client as client_module
from pyzephyrconnect.auth import Credentials
from pyzephyrconnect.client import ZephyrClient
from pyzephyrconnect.models import HoodState

FIXTURES = Path(__file__).parent / "fixtures"
THING = "aaaaaaaabbbbbbbbccccccccddddddddeeeeeeee"


@pytest.fixture
def wired(monkeypatch):
    """Replace the three collaborators, recording the order of calls."""
    order: list[str] = []
    discover = json.loads((FIXTURES / "discoverdevice.json").read_text())

    auth = MagicMock()
    auth.authenticate = AsyncMock(side_effect=lambda: order.append("authenticate"))
    auth.attach_policy = AsyncMock(side_effect=lambda: order.append("attach_policy"))
    auth.refresh = AsyncMock()
    auth.id_token = "ID"
    auth.identity_id = "us-west-2:abc"
    auth.mqtt_client_id = "us-west-2:abc-ha"
    auth.credentials = Credentials(
        "k", "s", "t", datetime.now(UTC) + timedelta(hours=1)
    )

    api = MagicMock()
    api.get_own_devices = AsyncMock(return_value=[{"thingName": THING}])
    api.discover_device = AsyncMock(return_value=discover)

    shadow = MagicMock()
    shadow.connect = AsyncMock(side_effect=lambda *a, **k: order.append("connect"))
    shadow.disconnect = AsyncMock()
    shadow.request_state = AsyncMock()
    shadow.publish_desired = AsyncMock()

    monkeypatch.setattr(client_module, "ZephyrAuth", MagicMock(return_value=auth))
    monkeypatch.setattr(client_module, "ZephyrApi", MagicMock(return_value=api))
    monkeypatch.setattr(client_module, "ShadowClient", MagicMock(return_value=shadow))
    return {"auth": auth, "api": api, "shadow": shadow, "order": order}


def _client():
    return ZephyrClient("u", "p", MagicMock())


async def test_setup_returns_parsed_capabilities(wired):
    caps = await _client().async_setup()
    assert len(caps) == 1
    assert caps[0].max_fan_speed == 6
    assert caps[0].thing_name == THING


async def test_policy_is_attached_before_the_socket_opens(wired):
    """Ordering is load-bearing: an already-open connection does not pick up
    newly attached permissions, and the failure is silent."""
    c = _client()
    await c.async_setup()
    await c.async_start(THING)

    order = wired["order"]
    assert order.index("attach_policy") < order.index("connect")
    assert order.index("authenticate") < order.index("attach_policy")


async def test_start_requests_initial_state(wired):
    c = _client()
    await c.async_setup()
    await c.async_start(THING)
    wired["shadow"].request_state.assert_awaited_once()


async def test_get_accepted_populates_state_and_notifies(wired):
    c = _client()
    await c.async_setup()
    await c.async_start(THING)

    seen = []
    c.add_listener(THING, lambda state: seen.append(state))
    c._handle_message(
        THING,
        f"$aws/things/{THING}/shadow/get/accepted",
        {"state": {"reported": {"fan": 4, "power": 1, "isOnline": 1}}},
    )

    assert c.state(THING).fan == 4
    assert seen[-1].power == 1


async def test_delta_merges_without_clearing_untouched_fields(wired):
    c = _client()
    await c.async_setup()
    await c.async_start(THING)
    c._handle_message(
        THING,
        f"$aws/things/{THING}/shadow/get/accepted",
        {"state": {"reported": {"fan": 0, "usegreasefiltertime": 642}}},
    )
    c._handle_message(
        THING, f"$aws/things/{THING}/shadow/update/delta", {"state": {"fan": 3}}
    )

    assert c.state(THING).fan == 3
    assert c.state(THING).use_grease_filter_time == 642


async def test_listener_can_be_removed(wired):
    c = _client()
    await c.async_setup()
    seen = []
    remove = c.add_listener(THING, lambda s: seen.append(s))
    remove()
    c._handle_message(
        THING, f"$aws/things/{THING}/shadow/get/accepted",
        {"state": {"reported": {"fan": 1}}},
    )
    assert seen == []


async def test_listener_exception_does_not_break_other_listeners(wired):
    c = _client()
    await c.async_setup()
    seen = []
    c.add_listener(THING, lambda s: (_ for _ in ()).throw(RuntimeError("boom")))
    c.add_listener(THING, lambda s: seen.append(s))
    c._handle_message(
        THING, f"$aws/things/{THING}/shadow/get/accepted",
        {"state": {"reported": {"fan": 1}}},
    )
    assert len(seen) == 1


async def test_refresh_is_skipped_while_credentials_are_fresh(wired):
    c = _client()
    await c.async_setup()
    assert await c.async_refresh_if_needed() is False
    wired["auth"].refresh.assert_not_awaited()


async def test_expiring_credentials_trigger_refresh_and_reconnect(wired):
    """The presigned URL is derived from credentials, so a refresh must
    rebuild the socket, not just swap the token."""
    c = _client()
    await c.async_setup()
    await c.async_start(THING)
    wired["auth"].credentials = Credentials(
        "k", "s", "t", datetime.now(UTC) + timedelta(seconds=30)
    )

    assert await c.async_refresh_if_needed() is True
    wired["auth"].refresh.assert_awaited_once()
    wired["shadow"].disconnect.assert_awaited()
    assert wired["shadow"].connect.await_count == 2


async def test_publish_desired_requires_a_started_connection(wired):
    c = _client()
    await c.async_setup()
    with pytest.raises(RuntimeError, match="async_start"):
        await c.async_publish_desired(THING, {"light": 1})


async def test_publish_desired_delegates_to_the_shadow(wired):
    c = _client()
    await c.async_setup()
    await c.async_start(THING)
    await c.async_publish_desired(THING, {"light": 1})
    wired["shadow"].publish_desired.assert_awaited_once_with({"light": 1})


async def test_poll_falls_back_to_https(wired):
    """When MQTT is down, discoverdevice still returns live state."""
    c = _client()
    await c.async_setup()
    state = await c.async_poll(THING)
    assert isinstance(state, HoodState)
    assert state.use_grease_filter_time == 642
    assert c.state(THING) is not None


async def test_non_dict_shadow_payload_is_ignored(wired):
    """A payload that is valid JSON but not an object (e.g. the literal
    `null`, which json.loads returns as None) must not raise, must not
    change cached state, and must not notify listeners."""
    c = _client()
    await c.async_setup()
    await c.async_start(THING)

    before = c.state(THING)
    seen = []
    c.add_listener(THING, lambda state: seen.append(state))

    c._handle_message(
        THING, f"$aws/things/{THING}/shadow/get/accepted", None
    )

    assert c.state(THING) is before
    assert seen == []


async def test_setup_strips_personal_data_from_cached_state(wired):
    """discoverdevice mixes state with device identifiers; those must never
    land in HoodState.raw."""
    c = _client()
    await c.async_setup()
    state = c.state(THING)
    assert state is not None
    for key in ("thingName", "SN", "MAC", "location"):
        assert key not in state.raw


async def test_setup_capabilities_still_carry_identifiers(wired):
    """The PII filter applies only to the state path - capabilities must
    still be built from the unfiltered payload."""
    caps = await _client().async_setup()
    assert caps[0].thing_name == THING
    assert caps[0].serial == "1234567XYZ"
    assert caps[0].mac == "00:00:5e:00:53:00"
