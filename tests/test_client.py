"""ZephyrClient: setup, per-hood wiring, message folding, and the supervisor.

The supervisor is a detached task. Tests drive its body deterministically
via `_run_supervisor_ticks` rather than sleeping - a test that waits a real
minute is a test nobody runs.
"""

import asyncio
import contextlib
import json
import logging
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from conftest import FakeResponse, FakeSession
from pyzephyrconnect import client as client_module
from pyzephyrconnect.auth import Credentials, CredentialsAuth, ZephyrTokens
from pyzephyrconnect.client import ZephyrClient
from pyzephyrconnect.const import DEFAULT_ENDPOINTS, Endpoints
from pyzephyrconnect.exceptions import (
    ZephyrAuthError,
    ZephyrError,
    ZephyrPolicyError,
)
from pyzephyrconnect.hood import Hood
from pyzephyrconnect.models import HoodState

FIXTURES = Path(__file__).parent / "fixtures"
THING = "aaaaaaaabbbbbbbbccccccccddddddddeeeeeeee"
OTHER = "ffffffff1111111122222222333333334444444"


def _auth_double(endpoints=DEFAULT_ENDPOINTS, order=None):
    """A fully specified auth double.

    Every attribute below is consumed by some test in this file, and a bare
    MagicMock attribute is truthy - which would silently satisfy (or break)
    the `credentials_expired` guard the supervisor keys on.
    """
    # Bound once, not `(order or [])` inside the side effect: `order` is
    # EMPTY at the moment attach_policy first runs, so the short-circuit
    # would build a throwaway list and the ordering assertion below would
    # pass vacuously on a list that never receives "attach_policy".
    recorder: list[str] = [] if order is None else order
    auth = MagicMock()
    auth.endpoints = endpoints
    auth.identity_id = "us-west-2:abc"
    auth.mqtt_client_id = "us-west-2:abc-ha"
    auth.credentials_expired = False          # explicit bool, never a Mock
    auth.async_get_tokens = AsyncMock()
    auth.async_get_credentials = AsyncMock(
        return_value=Credentials(
            "k", "s", "t", datetime.now(UTC) + timedelta(hours=1)
        )
    )
    auth.async_attach_policy = AsyncMock(
        side_effect=lambda: recorder.append("attach_policy")
    )
    return auth


# The `wired` fixture stashes its auth double here so `_client()` can hand
# the SAME object to every client built inside a test. The ordering and
# credential-expiry assertions all read wired["auth"], which only pins
# anything if the client under test is the one holding it.
_WIRED: dict[str, Any] = {}


@pytest.fixture
def wired(monkeypatch):
    """Replace the collaborators, recording the order of calls.

    ZephyrApi and ShadowClient are monkeypatched on the module; the auth
    object is not - it is a constructor argument now, so it is injected.
    """
    order: list[str] = []
    discover = json.loads((FIXTURES / "discoverdevice.json").read_text())

    auth = _auth_double(order=order)

    api = MagicMock()
    api.get_own_devices = AsyncMock(return_value=[{"thingName": THING}])
    api.discover_device = AsyncMock(return_value=discover)

    shadow = MagicMock()
    shadow.connect = AsyncMock(side_effect=lambda *a, **k: order.append("connect"))
    shadow.disconnect = AsyncMock()
    shadow.request_state = AsyncMock()
    shadow.publish_state = AsyncMock()

    monkeypatch.setattr(client_module, "ZephyrApi", MagicMock(return_value=api))
    monkeypatch.setattr(client_module, "ShadowClient", MagicMock(return_value=shadow))

    _WIRED["auth"] = auth
    try:
        yield {"auth": auth, "api": api, "shadow": shadow, "order": order}
    finally:
        _WIRED.clear()


@pytest.fixture(autouse=True)
async def _cancel_stray_supervisors():
    """Reap detached supervisors.

    _make_shadow starts one, and most tests here never call async_stop().
    Left pending, they are destroyed under a closing loop and asyncio logs
    the task and its coroutine - noise that hides real failures.
    """
    yield
    for task in asyncio.all_tasks() - {asyncio.current_task()}:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await task


def _client():
    return ZephyrClient(_WIRED["auth"])


def monkeypatch_interval(client, seconds: float) -> None:
    client._supervisor_interval = seconds


async def _run_supervisor_ticks(client, ticks: int) -> None:
    """Run the supervisor body `ticks` times, then cancel it.

    Retires the supervisor _make_shadow already started first. It reads the
    same _supervisor_interval attribute, so once the interval is zeroed both
    tasks spin on the shared _refresh_once and every tick is counted twice.
    """
    if client._supervisor is not None:
        client._supervisor.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await client._supervisor
        client._supervisor = None
    task = asyncio.create_task(client._supervise())
    for _ in range(ticks + 1):
        await asyncio.sleep(0)
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task


# -- setup ------------------------------------------------------------


async def test_setup_returns_hood_objects(wired):
    hoods = await _client().async_setup()
    assert len(hoods) == 1
    assert isinstance(hoods[0], Hood)
    assert hoods[0].thing_name == THING
    assert hoods[0].capabilities.max_fan_speed == 6


async def test_setup_seeds_state_from_discover(wired):
    """discoverdevice is the pre-MQTT read: a consumer must have state
    before the socket exists, not None until the first push arrives."""
    hoods = await _client().async_setup()
    assert hoods[0].state is not None
    assert hoods[0].state.use_grease_filter_time == 642


async def test_setup_strips_personal_data_from_seeded_state(wired):
    """discoverdevice mixes state with device identifiers; those must never
    land in HoodState.raw, whose default repr reaches any careless log."""
    hoods = await _client().async_setup()
    for key in ("thingName", "SN", "MAC", "location"):
        assert key not in hoods[0].state.raw


async def test_setup_capabilities_still_carry_identifiers(wired):
    """The PII filter applies only to the state path - capabilities must
    still be built from the unfiltered payload."""
    hoods = await _client().async_setup()
    assert hoods[0].capabilities.thing_name == THING
    assert hoods[0].capabilities.serial == "1234567XYZ"
    assert hoods[0].capabilities.mac == "00:00:5e:00:53:00"


async def test_a_device_with_no_thing_name_is_skipped_not_crashed(wired):
    """A KeyError here would escape ZephyrError and reach the consumer as an
    unknown crash rather than a setup retry."""
    wired["api"].get_own_devices = AsyncMock(
        return_value=[{"model": "orphan"}, {"thingName": THING}]
    )
    hoods = await _client().async_setup()
    assert len(hoods) == 1
    assert hoods[0].thing_name == THING


async def test_get_own_devices_returning_a_non_list_yields_no_hoods(wired, caplog):
    """A vendor response shape change (e.g. an error body decoding to a bare
    string) must not escape as an AttributeError/TypeError from the `for`
    loop below - it should be treated as zero devices."""
    wired["api"].get_own_devices = AsyncMock(return_value="T1")
    with caplog.at_level(logging.WARNING):
        hoods = await _client().async_setup()
    assert hoods == []
    assert "unexpected shape" in caplog.text


async def test_a_malformed_device_entry_is_skipped_not_crashed(wired, caplog):
    """A non-dict element in the devices list (e.g. None) must not reach
    device.get("thingName") and raise AttributeError."""
    wired["api"].get_own_devices = AsyncMock(
        return_value=[None, {"thingName": THING}]
    )
    with caplog.at_level(logging.WARNING):
        hoods = await _client().async_setup()
    assert len(hoods) == 1
    assert hoods[0].thing_name == THING
    assert "malformed device entry" in caplog.text


async def test_async_setup_refuses_to_run_twice(wired):
    """Re-running setup would replace started Hood objects while their
    sockets and the supervisor still reference the old ones. The guard is
    checked before the credential exchange, so a repeat call must not
    perform a second needless network round trip either."""
    client = _client()
    await client.async_setup()
    with pytest.raises(ZephyrError, match="already run"):
        await client.async_setup()

    wired["auth"].async_get_credentials.assert_awaited_once()


async def test_setup_with_zero_devices_still_refuses_to_run_twice(wired):
    """_hoods was the sentinel, so an account with no devices left it empty
    and a SECOND full setup - credential exchange, discovery and a fresh set
    of Hood objects sharing the existing supervisor - was permitted."""
    wired["api"].get_own_devices = AsyncMock(return_value=[])
    client = _client()

    assert await client.async_setup() == []
    assert client._setup_complete is True

    with pytest.raises(ZephyrError, match="already run"):
        await client.async_setup()


async def test_a_setup_that_fails_midway_can_be_retried_cleanly(wired):
    """The other half of the sentinel bug: a failure partway through the
    discovery loop left _hoods partially filled, which made the client look
    initialized and its failed setup unretryable forever. The retry must
    also start from empty - appending to the leftovers would return stale
    and duplicated hoods."""
    discover = json.loads((FIXTURES / "discoverdevice.json").read_text())
    calls = []

    async def discover_device(thing_name):
        calls.append(thing_name)
        if thing_name == OTHER and len(calls) == 2:
            # Fails on the SECOND device of the first attempt only.
            raise ZephyrError("discoverdevice failed")
        return {**discover, "thingName": thing_name}

    wired["api"].get_own_devices = AsyncMock(
        return_value=[{"thingName": THING}, {"thingName": OTHER}]
    )
    wired["api"].discover_device = AsyncMock(side_effect=discover_device)

    client = _client()
    with pytest.raises(ZephyrError):
        await client.async_setup()

    assert client._setup_complete is False
    assert len(client._hoods) == 1          # the partial result is there...

    hoods = await client.async_setup()      # ...and must not be retried into

    assert client._setup_complete is True
    assert [hood.thing_name for hood in hoods] == [THING, OTHER]


async def test_setup_performs_the_identity_exchange(wired):
    """Not just tokens: the config-flow ordering "async_setup(), then read
    identity_id for the unique ID" depends on the exchange having run."""
    await _client().async_setup()
    wired["auth"].async_get_credentials.assert_awaited()


async def test_setup_with_a_none_discover_body_raises_zephyr_error_not_attributeerror():
    """End-to-end through the REAL ZephyrApi, not the `wired` fixture's
    mocked one: a discoverdevice response that decodes to None (aiohttp's
    shape for an empty 200 body) must be rejected by ZephyrApi._post()
    before it ever reaches HoodCapabilities.from_discover(), which would
    otherwise blow up as a raw, uncategorized AttributeError instead of a
    ZephyrError subclass consumers are told to catch."""
    session = FakeSession(
        FakeResponse({"devices": [{"thingName": THING}]}),
        FakeResponse(None),
    )
    auth = _auth_double()
    auth.session = session
    auth.async_get_tokens = AsyncMock(
        return_value=ZephyrTokens(
            username="u@example.com",
            id_token="ID-TOKEN",
            refresh_token="R",
            identity_id="us-west-2:abc",
            expires_at=time.time() + 3600,
        )
    )

    with pytest.raises(ZephyrError):
        await ZephyrClient(auth).async_setup()


# -- identity ---------------------------------------------------------


async def test_identity_id_returns_the_auth_value(wired):
    client = _client()
    await client.async_setup()
    assert client.identity_id == "us-west-2:abc"


async def test_a_refetched_identity_reaches_new_shadow_client_ids(wired):
    """mqtt_client_id is derived from identity_id. A mid-session refetch
    (AbstractAuth._identity_override) must reach every shadow built AFTER
    it, not just client.identity_id - keeping a dead one in a shadow's
    client ID gets a connection where subscribe and publish succeed and
    every message is silently dropped."""
    auth = wired["auth"]
    client = _client()
    hoods = await client.async_setup()

    auth.identity_id = "us-west-2:new"
    auth.mqtt_client_id = "us-west-2:new-ha"
    client._make_shadow(hoods[0])

    assert client.identity_id == "us-west-2:new"
    args = client_module.ShadowClient.call_args.args
    assert args[1] == f"us-west-2:new-ha-{THING}"


def test_identity_id_raises_before_async_setup():
    """Before async_setup(), accessing identity_id propagates the auth error.

    Constructs the real auth object (the `wired` fixture is not used here),
    so this exercises AbstractAuth.identity_id's actual guard rather than a
    mock - see the "no tokens acquired yet" message on that property.
    """
    client = ZephyrClient(CredentialsAuth("u", "p", MagicMock()))
    with pytest.raises(ZephyrAuthError, match="no tokens acquired yet"):
        _ = client.identity_id


# -- construction -----------------------------------------------------


def test_from_credentials_builds_a_credentials_auth():
    session = MagicMock()
    client = ZephyrClient.from_credentials("u", "p", session)
    assert isinstance(client._auth, CredentialsAuth)
    assert client._auth.session is session


def test_from_credentials_threads_tokens_and_endpoints_through():
    """Restored tokens skip the SRP login entirely, and an endpoint override
    has to reach the auth object or REST and MQTT point at different clouds."""
    endpoints = Endpoints(device_api_base="https://staging.example.com/prod")
    tokens = ZephyrTokens(
        username="u",
        id_token="i",
        refresh_token="r",
        identity_id="us-west-2:restored",
        expires_at=time.time() + 3600,
    )
    client = ZephyrClient.from_credentials(
        "u", "p", MagicMock(), tokens=tokens, endpoints=endpoints
    )
    assert client._auth.endpoints is endpoints
    assert client._endpoints is endpoints
    # Restored tokens make the identity readable without a network call.
    assert client.identity_id == "us-west-2:restored"


def test_from_credentials_passes_token_updater_through(monkeypatch):
    """token_updater persists refreshed tokens; dropping it on the way to
    CredentialsAuth would make every consumer's persistence path a silent
    no-op - tokens would look like they're being saved but never are."""
    fake_auth_cls = MagicMock()
    monkeypatch.setattr(client_module, "CredentialsAuth", fake_auth_cls)

    sentinel = object()
    tokens = object()
    ZephyrClient.from_credentials(
        "u", "p", MagicMock(), tokens=tokens, token_updater=sentinel
    )

    kwargs = fake_auth_cls.call_args.kwargs
    assert kwargs["token_updater"] is sentinel
    assert kwargs["tokens"] is tokens


@pytest.mark.parametrize(
    "name",
    [
        "async_set_state",
        "async_start",
        "async_poll",
        "state",
        "capabilities",
        "add_listener",
        "async_refresh_if_needed",
    ],
)
def test_the_per_thing_client_surface_is_gone(name):
    """These moved onto Hood. Leaving a shim would keep consumers writing
    thing-name-keyed code against an object that no longer caches state."""
    assert not hasattr(ZephyrClient, name)


def test_the_legacy_auth_alias_is_gone():
    """client.py imported CredentialsAuth as ZephyrAuth during the
    transition. Anything still monkeypatching that name is testing a ghost."""
    assert not hasattr(client_module, "ZephyrAuth")


# -- wiring -----------------------------------------------------------


async def test_policy_is_attached_before_the_socket_opens(wired):
    """Ordering is load-bearing: an already-open connection does not pick up
    newly attached permissions, and the failure is silent."""
    hoods = await _client().async_setup()
    await hoods[0].async_start()

    order = wired["order"]
    assert order.index("attach_policy") < order.index("connect")


async def test_the_policy_is_attached_once_per_identity(wired):
    """Latched, because the binding persists on the identity - but keyed on
    WHICH identity, so a mid-session refetch re-attaches for the new one."""
    auth = wired["auth"]
    client = _client()
    await client.async_setup()

    await client._ensure_policy()
    await client._ensure_policy()
    assert auth.async_attach_policy.await_count == 1

    auth.identity_id = "us-west-2:new"
    await client._ensure_policy()
    assert auth.async_attach_policy.await_count == 2


async def test_concurrent_ensure_policy_calls_attach_exactly_once(wired):
    """Hoods start concurrently. The latch is a read-modify-write spanning
    an await, so without a lock both callers pass the check and both attach
    - and the interleaved writes can record an identity that never received
    the policy, which is the silent message-drop failure."""
    auth = wired["auth"]
    started = asyncio.Event()
    release = asyncio.Event()

    async def slow_attach():
        # Hold the attach open so the second caller is guaranteed to reach
        # _ensure_policy while the first is still inside it. Without this
        # the AsyncMock resolves without ever yielding and the race the
        # lock exists to close never occurs.
        started.set()
        await release.wait()

    auth.async_attach_policy = AsyncMock(side_effect=slow_attach)
    client = _client()
    await client.async_setup()

    first = asyncio.create_task(client._ensure_policy())
    await started.wait()
    second = asyncio.create_task(client._ensure_policy())
    # Let the second task run up to the lock it must now be waiting on.
    await asyncio.sleep(0)
    release.set()
    await asyncio.gather(first, second)

    assert auth.async_attach_policy.await_count == 1
    assert client._policy_attached_for == "us-west-2:abc"


async def test_an_identity_refetch_during_an_attach_is_not_latched_stale(wired):
    """The identity is re-read INSIDE the lock. A waiter that queued behind
    an attach for A must latch whichever identity is current when its OWN
    attach runs - latching A over a newer B would mark the new identity as
    attached-for while the policy never reached it."""
    auth = wired["auth"]
    started = asyncio.Event()
    release = asyncio.Event()
    attached_for: list[str] = []

    async def slow_attach():
        attached_for.append(auth.identity_id)
        started.set()
        await release.wait()

    auth.async_attach_policy = AsyncMock(side_effect=slow_attach)
    client = _client()
    await client.async_setup()

    first = asyncio.create_task(client._ensure_policy())
    await started.wait()
    second = asyncio.create_task(client._ensure_policy())
    await asyncio.sleep(0)
    # The refetch lands while the second caller is parked on the lock, so
    # it must NOT be short-circuited by the latch the first call is about
    # to write for the old identity.
    auth.identity_id = "us-west-2:new"
    started.clear()
    release.set()
    await asyncio.gather(first, second)

    assert attached_for == ["us-west-2:abc", "us-west-2:new"]
    assert client._policy_attached_for == "us-west-2:new"


async def test_the_mqtt_client_id_is_per_connection(wired):
    """AWS IoT treats two live connections with the same client ID as one
    session and evicts one for the other, so N hoods sharing the bare
    mqtt_client_id would flap forever. Identity-prefixed so the policy's
    prefix match still covers it. The FULL thing name, not a truncated
    8-char prefix - see test_two_hoods_sharing_an_8char_prefix_get_
    different_client_ids for why the truncated form was actively unsafe."""
    client = _client()
    hoods = await client.async_setup()
    client._make_shadow(hoods[0])

    args = client_module.ShadowClient.call_args.args
    assert args[0] == THING
    assert args[1] == f"us-west-2:abc-ha-{THING}"
    assert args[1] != wired["auth"].mqtt_client_id


async def test_two_hoods_sharing_an_8char_prefix_get_different_client_ids(wired):
    """The old truncated-to-8-chars form gave two things sharing that
    prefix IDENTICAL client IDs - AWS IoT evicts one same-ID session for
    the other, the exact failure the per-connection suffix exists to
    prevent. The full thing name must not collide the same way, and both
    IDs must still carry the identity prefix the IoT policy matches on."""
    similar = THING[:8] + "9" * (len(THING) - 8)
    assert similar[:8] == THING[:8]  # the truncated form WOULD have collided
    assert similar != THING

    first = json.loads((FIXTURES / "discoverdevice.json").read_text())
    second = json.loads((FIXTURES / "discoverdevice.json").read_text())
    second["thingName"] = similar
    wired["api"].get_own_devices = AsyncMock(
        return_value=[{"thingName": THING}, {"thingName": similar}]
    )
    wired["api"].discover_device = AsyncMock(
        side_effect=lambda thing: first if thing == THING else second
    )

    client = _client()
    hoods = await client.async_setup()
    assert len(hoods) == 2

    client._make_shadow(hoods[0])
    id_a = client_module.ShadowClient.call_args.args[1]
    client._make_shadow(hoods[1])
    id_b = client_module.ShadowClient.call_args.args[1]

    assert id_a != id_b
    assert id_a.startswith(wired["auth"].mqtt_client_id)
    assert id_b.startswith(wired["auth"].mqtt_client_id)


async def test_the_shadow_gets_the_credentials_provider_not_a_credential(wired):
    """The presigned URL is rebuilt on every connect, so the shadow needs
    the method - handing it one snapshot pins the socket to credentials that
    expire in an hour."""
    client = _client()
    hoods = await client.async_setup()
    client._make_shadow(hoods[0])

    args = client_module.ShadowClient.call_args.args
    assert args[4] is wired["auth"].async_get_credentials


async def test_an_endpoint_override_reaches_mqtt_too(wired):
    """Overriding endpoints must not silently apply to REST only - the MQTT
    host is a separate wiring path, and failing to thread it through leaves
    the override half-applied with nothing complaining."""
    endpoints = Endpoints(iot_endpoint="staging-ats.iot.us-west-2.amazonaws.com")
    client = ZephyrClient(_auth_double(endpoints=endpoints))
    hoods = await client.async_setup()
    client._make_shadow(hoods[0])

    passed = client_module.ShadowClient.call_args.kwargs["endpoints"]
    assert passed.iot_endpoint.startswith("staging-ats")


async def test_starting_a_hood_requests_its_current_state(wired):
    hoods = await _client().async_setup()
    await hoods[0].async_start()
    wired["shadow"].request_state.assert_awaited_once()


async def test_connected_is_derived_from_the_hoods(wired):
    """Derived rather than a single latched flag, which with more than one
    hood reported whichever shadow changed state last."""
    client = _client()
    hoods = await client.async_setup()
    assert client.connected is False

    hoods[0].handle_connection_change(True)
    assert client.connected is True

    hoods[0].handle_connection_change(False)
    assert client.connected is False


async def test_connection_change_wiring_is_pinned_per_hood(wired):
    """args[3] must be THIS hood's own handle_connection_change - wiring one
    hood's shadow to another's callback would make `connected` (and the
    supervisor's terminal-stop flip) attribute the wrong hood's socket
    state."""
    first = json.loads((FIXTURES / "discoverdevice.json").read_text())
    second = json.loads((FIXTURES / "discoverdevice.json").read_text())
    second["thingName"] = OTHER
    wired["api"].get_own_devices = AsyncMock(
        return_value=[{"thingName": THING}, {"thingName": OTHER}]
    )
    wired["api"].discover_device = AsyncMock(
        side_effect=lambda thing: first if thing == THING else second
    )

    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()
    await hoods[1].async_start()

    for i, hood in enumerate(hoods):
        call_args = client_module.ShadowClient.call_args_list[i]
        # `==`, not `is`: two separate attribute accesses of the SAME bound
        # method are equal (same __self__, same __func__) but never
        # identical - each access allocates a fresh bound-method object.
        assert call_args.args[3] == hood.handle_connection_change


# -- message handling -------------------------------------------------


async def test_get_accepted_replaces_and_update_accepted_merges(wired):
    """get/accepted carries a full document; update/accepted carries only
    what changed, so replacing on it would zero everything unmentioned."""
    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()

    client._handle_message(
        hoods[0], f"$aws/things/{THING}/shadow/get/accepted",
        {"state": {"reported": {"power": 1, "fan": 3}}},
    )
    client._handle_message(
        hoods[0], f"$aws/things/{THING}/shadow/update/accepted",
        {"state": {"reported": {"fan": 5}}},
    )

    assert hoods[0].state.power == 1
    assert hoods[0].state.fan == 5


async def test_update_accepted_keeps_counters_it_did_not_mention(wired):
    """Payload shape captured from the real device, including the top-level
    "version" key the handler must simply ignore."""
    client = _client()
    hoods = await client.async_setup()
    client._handle_message(
        hoods[0], f"$aws/things/{THING}/shadow/get/accepted",
        {"state": {"reported": {"fan": 0, "light": 0, "usegreasefiltertime": 642}}},
    )

    seen = []
    hoods[0].add_listener(seen.append)
    client._handle_message(
        hoods[0], f"$aws/things/{THING}/shadow/update/accepted",
        {"state": {"reported": {"light": 1, "power": 1}}, "version": 302691},
    )

    assert hoods[0].state.light == 1
    assert hoods[0].state.power == 1
    assert hoods[0].state.use_grease_filter_time == 642
    assert seen[-1].light == 1


async def test_update_delta_is_ignored(wired):
    """Nothing writes state.desired here, so a delta can only be stale or
    foreign. Merging one produces a phantom change."""
    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()
    client._handle_message(
        hoods[0], f"$aws/things/{THING}/shadow/get/accepted",
        {"state": {"reported": {"fan": 1}}},
    )
    client._handle_message(
        hoods[0], f"$aws/things/{THING}/shadow/update/delta",
        {"state": {"fan": 6}},
    )

    assert hoods[0].state.fan == 1


async def test_a_delta_notifies_nobody_and_logs_no_identifier(wired, caplog):
    """Folding a delta into the cache previously made the probe report a
    change the device had not - and might never - make, which disguised the
    state.desired/state.reported root-cause bug for a full debugging cycle.
    Payload shape captured from the real device."""
    client = _client()
    hoods = await client.async_setup()
    client._handle_message(
        hoods[0], f"$aws/things/{THING}/shadow/get/accepted",
        {"state": {"reported": {"fan": 0, "light": 0}}},
    )
    before = hoods[0].state

    seen = []
    hoods[0].add_listener(seen.append)
    with caplog.at_level(logging.DEBUG, logger="pyzephyrconnect.client"):
        client._handle_message(
            hoods[0], f"$aws/things/{THING}/shadow/update/delta",
            {"state": {"light": 1, "power": 1}, "version": 302688},
        )

    assert hoods[0].state is before
    assert seen == []
    # Leaf-only diagnostics: the full topic embeds the thing name.
    assert THING not in caplog.text


async def test_a_non_dict_payload_is_ignored(wired, caplog):
    """Valid JSON that is not an object (e.g. the literal `null`, which
    json.loads returns as None) must not raise, must not change state, and
    must not notify listeners. _on_message only catches parse errors, so
    this shape still reaches here."""
    client = _client()
    hoods = await client.async_setup()
    before = hoods[0].state

    seen = []
    hoods[0].add_listener(seen.append)
    with caplog.at_level(logging.WARNING, logger="pyzephyrconnect.client"):
        client._handle_message(
            hoods[0], f"$aws/things/{THING}/shadow/get/accepted", None
        )

    assert hoods[0].state is before
    assert seen == []
    # WARNING from the explicit shape guard specifically - not the broad
    # ERROR backstop below, which would also leave state/listeners untouched
    # and so could not be told apart from this guard without checking text.
    assert "unexpected shape" in caplog.text


async def test_a_rejection_never_logs_the_payload(wired, caplog):
    """A rejection can echo back the fields it rejected, including
    identifiers. Only the topic's leaf segment is safe to log."""
    client = _client()
    hoods = await client.async_setup()
    before = hoods[0].state

    with caplog.at_level(logging.WARNING, logger="pyzephyrconnect.client"):
        client._handle_message(
            hoods[0], f"$aws/things/{THING}/shadow/update/rejected",
            {"message": "rejected", "location": "40.0,-105.0"},
        )

    assert hoods[0].state is before
    assert "40.0" not in caplog.text
    assert THING not in caplog.text
    assert "rejected" in caplog.text


async def test_the_message_closure_is_pinned_to_its_own_hood(wired):
    """_make_shadow's on_message closes over the SPECIFIC hood it was built
    for. A lookup like `next(iter(self._hoods.values()))` instead of the
    closed-over `hood` would happen to work with exactly one hood and then
    silently misattribute every message once a second hood exists."""
    first = json.loads((FIXTURES / "discoverdevice.json").read_text())
    second = json.loads((FIXTURES / "discoverdevice.json").read_text())
    second["thingName"] = OTHER
    wired["api"].get_own_devices = AsyncMock(
        return_value=[{"thingName": THING}, {"thingName": OTHER}]
    )
    wired["api"].discover_device = AsyncMock(
        side_effect=lambda thing: first if thing == THING else second
    )

    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()
    await hoods[1].async_start()

    # hoods[0] IS next(iter(self._hoods.values())), so driving index 0
    # cannot tell the closure apart from a first-hood lookup.
    on_message_b = client_module.ShadowClient.call_args_list[1].args[2]
    state_a_before = hoods[0].state
    seen_a = []
    hoods[0].add_listener(seen_a.append)
    on_message_b(
        f"$aws/things/{OTHER}/shadow/get/accepted",
        {"state": {"reported": {"power": 1, "fan": 3}}},
    )
    assert hoods[1].state is not None and hoods[1].state.power == 1
    assert hoods[0].state is state_a_before
    assert seen_a == []


async def test_a_malformed_message_does_not_escape_onto_the_loop(wired, caplog):
    """_handle_message runs via loop.call_soon_threadsafe. An escaped
    exception hits asyncio's default handler, which logs the callback and
    its arguments - the topic and the raw payload - at ERROR."""
    client = _client()
    hoods = await client.async_setup()
    hoods[0].handle_state = MagicMock(side_effect=RuntimeError("boom"))

    with caplog.at_level(logging.ERROR, logger="pyzephyrconnect.client"):
        client._handle_message(
            hoods[0], f"$aws/things/{THING}/shadow/get/accepted",
            {"state": {"reported": {"fan": 1}}},
        )

    assert THING not in caplog.text


# -- polling ----------------------------------------------------------


async def test_poll_falls_back_to_https(wired):
    """When MQTT is down, discoverdevice still returns live state."""
    hoods = await _client().async_setup()
    state = await hoods[0].async_poll()
    assert isinstance(state, HoodState)
    assert state.use_grease_filter_time == 642


async def test_poll_strips_personal_data_too(wired):
    """Same flat payload as setup, same filter - and this path runs on every
    coordinator tick while push is down."""
    hoods = await _client().async_setup()
    state = await hoods[0].async_poll()
    for key in ("thingName", "SN", "MAC", "location"):
        assert key not in state.raw


# -- the supervisor ---------------------------------------------------


async def test_supervisor_rebuilds_the_socket_before_credentials_expire(wired):
    """A presigned URL cannot outlive its signature. Without this, push dies
    after an hour and paho retries a dead URL forever."""
    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()

    wired["auth"].credentials_expired = True
    await client._refresh_once()

    assert wired["shadow"].disconnect.await_count >= 1
    assert wired["shadow"].connect.await_count >= 2
    assert wired["shadow"].request_state.await_count >= 2


async def test_refresh_does_not_ask_a_method_that_renews_as_a_side_effect(wired):
    """async_get_credentials() renews when expired, so testing ITS result
    always reports "not expired" and the socket never gets rebuilt. The
    supervisor must ask the non-mutating property instead."""
    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()

    wired["auth"].credentials_expired = False
    assert await client._refresh_once() is False
    assert wired["shadow"].connect.await_count == 1      # no rebuild

    wired["auth"].credentials_expired = True
    assert await client._refresh_once() is True
    assert wired["shadow"].connect.await_count == 2      # rebuilt


async def test_refresh_reopens_a_wanted_hood_whose_socket_is_gone(wired):
    """Recovery: a hood whose rebuild failed last cycle is still wanted, and
    async_ensure_running is what brings it back on the next tick."""
    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()
    # Simulate a rebuild that died halfway: intent survives, socket does not.
    await hoods[0]._stop_for_supervisor()

    await client._refresh_once()

    assert wired["shadow"].connect.await_count == 2


async def test_one_hoods_failure_does_not_strand_the_others(wired):
    """Per-hood try/except: one transient connect failure must not abort the
    loop and leave later hoods on an expiring signature."""
    first = json.loads((FIXTURES / "discoverdevice.json").read_text())
    second = json.loads((FIXTURES / "discoverdevice.json").read_text())
    second["thingName"] = OTHER
    wired["api"].get_own_devices = AsyncMock(
        return_value=[{"thingName": THING}, {"thingName": OTHER}]
    )
    wired["api"].discover_device = AsyncMock(
        side_effect=lambda thing: first if thing == THING else second
    )

    client = _client()
    hoods = await client.async_setup()
    assert len(hoods) == 2
    wired["auth"].credentials_expired = True

    calls: list[str] = []

    async def boom():
        calls.append("first")
        raise OSError("transient DNS failure")

    async def ok():
        calls.append("second")

    hoods[0].async_reconnect = boom
    hoods[1].async_reconnect = ok

    assert await client._refresh_once() is True
    assert calls == ["first", "second"]


async def test_a_terminal_error_from_one_hood_is_not_swallowed(wired):
    """ZephyrPolicyError and ZephyrAuthError must reach _supervise so it can
    stop; swallowing them here is a hot loop that can never succeed."""
    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()

    async def denied():
        raise ZephyrPolicyError("denied")

    hoods[0].async_ensure_running = denied
    with pytest.raises(ZephyrPolicyError):
        await client._refresh_once()


async def test_a_transient_failure_does_not_end_supervision(wired):
    """The failure mode this guards against is not a logged error - it is
    push dying silently an hour later."""
    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()

    calls = []

    async def flaky():
        calls.append(1)
        if len(calls) == 1:
            raise OSError("transient DNS failure")
        return False

    client._refresh_once = flaky
    monkeypatch_interval(client, 0)          # see helper in this module
    await _run_supervisor_ticks(client, 2)

    assert len(calls) == 2                   # kept going after the OSError


async def test_supervisor_stops_on_a_policy_error(wired):
    """A denied subscribe closes the whole connection (PROTOCOL.md section 6).
    Retrying that forever is a hot loop that can never succeed."""
    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()
    # Non-vacuous setup: mark the hood connected BEFORE the terminal error,
    # so the final assertion proves the terminal branch's hood-stop actually
    # flipped the derived property rather than it never having been True.
    hoods[0].handle_connection_change(True)
    assert client.connected is True

    async def denied():
        raise ZephyrPolicyError("denied")

    client._refresh_once = denied
    monkeypatch_interval(client, 0)
    await _run_supervisor_ticks(client, 3)

    assert isinstance(client._supervisor_error, ZephyrPolicyError)
    assert client.connected is False


async def test_the_terminal_stop_preserves_consumer_intent(wired):
    """Stopping the hoods must not clear _should_run: a reauth that builds a
    new client is unaffected, and the recovery path needs the intent."""
    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()

    async def revoked():
        raise ZephyrAuthError("refresh token revoked")

    client._refresh_once = revoked
    monkeypatch_interval(client, 0)
    await _run_supervisor_ticks(client, 2)

    assert isinstance(client._supervisor_error, ZephyrAuthError)
    assert hoods[0]._should_run is True
    wired["shadow"].disconnect.assert_awaited()


async def test_the_terminal_log_names_the_type_not_the_message(wired, caplog):
    """ZephyrPolicyError text may name the policy, and identifiers do not
    belong at ERROR."""
    client = _client()
    await client.async_setup()

    async def denied():
        raise ZephyrPolicyError(f"denied for {THING}")

    client._refresh_once = denied
    monkeypatch_interval(client, 0)
    with caplog.at_level(logging.ERROR, logger="pyzephyrconnect.client"):
        await _run_supervisor_ticks(client, 2)

    assert "ZephyrPolicyError" in caplog.text
    assert THING not in caplog.text


async def test_a_terminal_error_reaches_the_consumer_via_poll(wired):
    """The supervisor runs detached, so its failure has to surface somewhere
    the consumer already looks - otherwise the hood just stops updating."""
    client = _client()
    hoods = await client.async_setup()
    client._supervisor_error = ZephyrAuthError("refresh token revoked")

    with pytest.raises(ZephyrAuthError):
        await hoods[0].async_poll()


async def test_polling_a_terminal_error_raises_a_fresh_instance_each_time(wired):
    """`raise type(err)(*err.args) from err` must build a NEW exception on
    every poll. Re-raising the stored object itself would append frames to
    ITS __traceback__ on every call - unbounded while a consumer keeps
    polling through a terminal error that never clears."""
    client = _client()
    hoods = await client.async_setup()
    client._supervisor_error = ZephyrAuthError("x")
    stored = client._supervisor_error
    assert stored.__traceback__ is None

    with pytest.raises(ZephyrAuthError) as excinfo1:
        await hoods[0].async_poll()
    assert excinfo1.value is not stored
    assert stored.__traceback__ is None

    with pytest.raises(ZephyrAuthError) as excinfo2:
        await hoods[0].async_poll()
    assert excinfo2.value is not stored
    assert stored.__traceback__ is None


async def test_a_running_supervisor_is_not_replaced(wired):
    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()
    first = client._supervisor
    assert first is not None

    client._ensure_supervisor()
    assert client._supervisor is first


async def test_a_finished_supervisor_counts_as_not_running(wired):
    """The terminal branch exits via `return`, leaving _supervisor holding a
    DONE task. A naive `is not None` check would then never restart
    supervision after a reauth on the same client - and the stale terminal
    error would make every later poll raise."""
    client = _client()
    await client.async_setup()

    finished = asyncio.create_task(asyncio.sleep(0))
    await finished
    client._supervisor = finished
    client._supervisor_error = ZephyrAuthError("stale")

    client._ensure_supervisor()

    assert client._supervisor is not finished
    assert client._supervisor_error is None


async def test_async_stop_cancels_and_awaits_the_supervisor(wired):
    """Cancelling without awaiting can leave a hood halfway through
    async_reconnect() with no socket and no supervisor, and lets the task be
    collected with an unretrieved CancelledError."""
    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()
    supervisor = client._supervisor
    assert supervisor is not None

    await client.async_stop()

    assert supervisor.done()
    assert client._supervisor is None
    assert hoods[0]._should_run is False
    wired["shadow"].disconnect.assert_awaited()


async def test_async_stop_isolates_one_hoods_teardown_failure(wired):
    """Each hood owns its own socket and paho thread, so one hood's
    disconnect blowing up must not strand the other - async_stop's per-hood
    try/except must still tear down (and clear _should_run on) hood B even
    though hood A's disconnect raised."""
    first = json.loads((FIXTURES / "discoverdevice.json").read_text())
    second = json.loads((FIXTURES / "discoverdevice.json").read_text())
    second["thingName"] = OTHER
    wired["api"].get_own_devices = AsyncMock(
        return_value=[{"thingName": THING}, {"thingName": OTHER}]
    )
    wired["api"].discover_device = AsyncMock(
        side_effect=lambda thing: first if thing == THING else second
    )

    shadow_a = MagicMock()
    shadow_a.connect = AsyncMock()
    shadow_a.disconnect = AsyncMock(side_effect=OSError("teardown failed"))
    shadow_a.request_state = AsyncMock()

    shadow_b = MagicMock()
    shadow_b.connect = AsyncMock()
    shadow_b.disconnect = AsyncMock()
    shadow_b.request_state = AsyncMock()

    client_module.ShadowClient.side_effect = (
        lambda thing_name, *a, **k: shadow_a if thing_name == THING else shadow_b
    )

    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()
    await hoods[1].async_start()

    await client.async_stop()          # must not raise

    shadow_a.disconnect.assert_awaited_once()
    shadow_b.disconnect.assert_awaited_once()
    assert hoods[0]._should_run is False
    assert hoods[1]._should_run is False


async def test_async_stop_tears_down_every_hood_before_honouring_a_cancel(wired):
    """Shutdown was asymmetric about cancellation: suppress(BaseException)
    around the supervisor await could swallow a caller's cancel outright,
    while a cancellation arriving during hood.async_stop() escaped the
    `except Exception` and stranded every remaining hood - a leaked paho
    network thread each. Both funnel here now (asyncio re-delivers a
    swallowed cancel at the next await, which is this loop): each hood is
    torn down, and only then is the cancellation re-raised so the caller
    that asked for it still sees it."""
    first = json.loads((FIXTURES / "discoverdevice.json").read_text())
    second = json.loads((FIXTURES / "discoverdevice.json").read_text())
    second["thingName"] = OTHER
    wired["api"].get_own_devices = AsyncMock(
        return_value=[{"thingName": THING}, {"thingName": OTHER}]
    )
    wired["api"].discover_device = AsyncMock(
        side_effect=lambda thing: first if thing == THING else second
    )

    shadow_a = MagicMock()
    shadow_a.connect = AsyncMock()
    shadow_a.disconnect = AsyncMock(side_effect=asyncio.CancelledError)
    shadow_a.request_state = AsyncMock()

    shadow_b = MagicMock()
    shadow_b.connect = AsyncMock()
    shadow_b.disconnect = AsyncMock()
    shadow_b.request_state = AsyncMock()

    client_module.ShadowClient.side_effect = (
        lambda thing_name, *a, **k: shadow_a if thing_name == THING else shadow_b
    )

    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()
    await hoods[1].async_start()

    with pytest.raises(asyncio.CancelledError):
        await client.async_stop()

    shadow_b.disconnect.assert_awaited_once()   # not stranded
    assert hoods[1]._should_run is False
    assert client._supervisor is None


async def test_async_stop_suppresses_a_supervisor_that_raised(wired):
    """`with contextlib.suppress(BaseException)` around awaiting the
    supervisor must swallow ANY exception it finished with, not just
    CancelledError - narrowing that guard would skip the hood-stopping loop
    entirely, leaking a paho thread per hood, and leave `_supervisor` set so
    `_ensure_supervisor` never restarts it."""
    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()

    async def boom():
        raise RuntimeError("supervisor died")

    task = asyncio.create_task(boom())
    await asyncio.sleep(0)
    assert task.done()
    client._supervisor = task

    await client.async_stop()          # must not raise

    assert client._supervisor is None
    assert hoods[0]._should_run is False
    wired["shadow"].disconnect.assert_awaited()


async def test_async_stop_is_safe_before_anything_started(wired):
    client = _client()
    await client.async_setup()
    await client.async_stop()


async def test_the_supervisor_interval_defaults_to_the_constant(wired):
    """An attribute, not the bare constant, only so tests can drive it -
    production must still tick once a minute."""
    from pyzephyrconnect import const

    assert _client()._supervisor_interval == const.SUPERVISOR_INTERVAL_SECONDS
