"""ZephyrClient: setup, per-hood wiring, message folding, and the supervisor.

The supervisor is a detached task. Tests drive its body deterministically
via `_run_supervisor_ticks` rather than sleeping - a test that waits a real
minute is a test nobody runs.
"""

import asyncio
import contextlib
import itertools
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
from pyzephyrconnect import const
from pyzephyrconnect.auth import Credentials, CredentialsAuth, ZephyrTokens
from pyzephyrconnect.client import ZephyrClient
from pyzephyrconnect.const import DEFAULT_ENDPOINTS, Endpoints
from pyzephyrconnect.exceptions import (
    ZephyrAuthError,
    ZephyrError,
    ZephyrNotConnectedError,
    ZephyrPolicyError,
    ZephyrTransportError,
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
    auth.mqtt_client_id = "us-west-2:abc-py"
    auth.credentials_expired = False  # explicit bool, never a Mock
    # Explicit int for the same reason: the supervisor compares this against
    # each hood's recorded generation, and a bare Mock attribute compares
    # unequal to everything - every tick would then look like a stale socket.
    auth.credentials_generation = 0
    auth.async_get_tokens = AsyncMock()
    credentials = Credentials("k", "s", "t", datetime.now(UTC) + timedelta(hours=1))

    def _exchange():
        """Bump the generation and return the cached credentials."""
        # A real exchange replaces the cached credentials, and both sites
        # that do so bump the generation. Modelling that here is what lets
        # these tests distinguish "the cache was replaced" from "the cache
        # looked expired" - the whole point of the counter.
        auth.credentials_generation += 1
        return credentials

    auth.async_get_credentials = AsyncMock(side_effect=_exchange)

    async def _presign_pair():
        """Return the credentials with the generation they belong to."""
        # Mirrors AbstractAuth.async_get_presign_credentials: the credentials
        # and the generation they belong to, taken as one consistent pair.
        # Modelled rather than stubbed with a bare Mock, because the per-hood
        # provider now records the generation THIS returns - a double that
        # let the two drift would hide the very bug the pair API exists for.
        creds = await auth.async_get_credentials()
        return creds, auth.credentials_generation

    auth.async_get_presign_credentials = AsyncMock(side_effect=_presign_pair)
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
    shadow.disconnect = AsyncMock()
    shadow.request_state = AsyncMock()
    shadow.publish_state = AsyncMock()

    # The real ShadowClient calls its credentials provider on every connect,
    # because that is when the presigned URL is (re)built. The double has to
    # as well: that call is what records the hood's presigned generation, and
    # a double that skips it leaves every started hood looking permanently
    # stale to the supervisor.
    wiring: dict[str, Any] = {}

    def build_shadow(*args, **kwargs):
        """Record the per-hood credentials provider and return the double."""
        # args[4] is the per-hood credentials provider ZephyrClient wires in.
        wiring["provider"] = args[4]
        return shadow

    async def connect(*args, **kwargs):
        """Record the connect and call the wired credentials provider."""
        order.append("connect")
        if (provider := wiring.get("provider")) is not None:
            await provider()

    shadow.connect = AsyncMock(side_effect=connect)

    monkeypatch.setattr(client_module, "ZephyrApi", MagicMock(return_value=api))
    monkeypatch.setattr(
        client_module, "ShadowClient", MagicMock(side_effect=build_shadow)
    )

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
    """Build a ZephyrClient around the shared wired auth double."""
    return ZephyrClient(_WIRED["auth"])


def monkeypatch_interval(client, seconds: float) -> None:
    """Set the client's supervisor interval for a test."""
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
    """Tests that async_setup returns Hood objects with capabilities."""
    hoods = await _client().async_setup()
    assert len(hoods) == 1
    assert isinstance(hoods[0], Hood)
    assert hoods[0].thing_name == THING
    assert hoods[0].capabilities.max_fan_speed == 6


async def test_setup_seeds_state_from_discover(wired):
    """Tests that setup seeds state from the discover payload.

    discoverdevice is the pre-MQTT read: a consumer must have state
    before the socket exists, not None until the first push arrives.
    """
    hoods = await _client().async_setup()
    assert hoods[0].state is not None
    assert hoods[0].state.use_grease_filter_time == 642


async def test_setup_strips_personal_data_from_seeded_state(wired):
    """Tests that setup strips personal data from the seeded state.

    discoverdevice mixes state with device identifiers; those must never
    land in HoodState.raw, whose default repr reaches any careless log.
    """
    hoods = await _client().async_setup()
    for key in ("thingName", "SN", "MAC", "location"):
        assert key not in hoods[0].state.raw


async def test_setup_capabilities_still_carry_identifiers(wired):
    """Tests that setup capabilities still carry identifiers.

    The PII filter applies only to the state path - capabilities must
    still be built from the unfiltered payload.
    """
    hoods = await _client().async_setup()
    assert hoods[0].capabilities.thing_name == THING
    assert hoods[0].capabilities.serial == "1234567XYZ"
    assert hoods[0].capabilities.mac == "00:00:5e:00:53:00"


async def test_a_device_with_no_thing_name_is_skipped_not_crashed(wired):
    """Tests that a device with no thingName is skipped, not crashed.

    A KeyError here would escape ZephyrError and reach the consumer as an
    unknown crash rather than a setup retry.
    """
    wired["api"].get_own_devices = AsyncMock(
        return_value=[{"model": "orphan"}, {"thingName": THING}]
    )
    hoods = await _client().async_setup()
    assert len(hoods) == 1
    assert hoods[0].thing_name == THING


async def test_get_own_devices_returning_a_non_list_yields_no_hoods(wired, caplog):
    """Tests that a non-list get_own_devices result yields no hoods.

    A vendor response shape change (e.g. an error body decoding to a bare
    string) must not escape as an AttributeError/TypeError from the `for`
    loop below - it should be treated as zero devices.
    """
    wired["api"].get_own_devices = AsyncMock(return_value="T1")
    with caplog.at_level(logging.WARNING):
        hoods = await _client().async_setup()
    assert hoods == []
    assert "unexpected shape" in caplog.text


async def test_a_malformed_device_entry_is_skipped_not_crashed(wired, caplog):
    """Tests that a malformed device entry is skipped, not crashed.

    A non-dict element in the devices list (e.g. None) must not reach
    device.get("thingName") and raise AttributeError.
    """
    wired["api"].get_own_devices = AsyncMock(return_value=[None, {"thingName": THING}])
    with caplog.at_level(logging.WARNING):
        hoods = await _client().async_setup()
    assert len(hoods) == 1
    assert hoods[0].thing_name == THING
    assert "malformed device entry" in caplog.text


async def test_a_malformed_thing_name_is_skipped_not_crashed(wired, caplog):
    """Tests that a malformed thingName is skipped, not crashed.

    Truthiness is not enough. A list or a dict passes `if not
    thing_name`, reaches self._hoods[thing_name] and raises an unhashable
    TypeError - which escapes the ZephyrError contract and reaches the
    consumer as an unknown crash instead of a setup retry.
    """
    wired["api"].get_own_devices = AsyncMock(
        return_value=[
            {"thingName": ["x"]},
            {"thingName": {}},
            {"thingName": THING},
        ]
    )
    with caplog.at_level(logging.WARNING):
        hoods = await _client().async_setup()

    assert [hood.thing_name for hood in hoods] == [THING]
    assert "malformed thingName" in caplog.text


async def test_concurrent_setups_serialise_instead_of_interleaving(wired):
    """Tests that concurrent setups serialise instead of interleaving.

    The one-run guard is checked before the first await, so two
    concurrent calls both passed it, both ran discovery, and interleaved
    their writes to _hoods. Serialised, the documented contract holds under
    concurrency too: the first call wins and the second raises already-run,
    having performed no discovery of its own.
    """
    calls = []

    async def get_own_devices():
        """Record the call, yield once, and return a single device."""
        calls.append(1)
        # A real round trip yields. Without one the first setup runs to
        # completion before the second coroutine is ever scheduled, and the
        # race this test exists for cannot be expressed at all.
        await asyncio.sleep(0)
        return [{"thingName": THING}]

    wired["api"].get_own_devices = AsyncMock(side_effect=get_own_devices)
    client = _client()

    outcomes = await asyncio.gather(
        client.async_setup(), client.async_setup(), return_exceptions=True
    )

    discovered = [out for out in outcomes if isinstance(out, list)]
    refused = [out for out in outcomes if isinstance(out, ZephyrError)]
    assert len(discovered) == 1
    assert [hood.thing_name for hood in discovered[0]] == [THING]
    assert len(refused) == 1
    assert "already run" in str(refused[0])
    assert len(calls) == 1


async def test_a_concurrent_setup_behind_a_failed_one_is_a_clean_retry(wired):
    """Tests that a concurrent setup behind a failed one is a clean retry.

    The other half of the serialised contract. The guard latches only on
    success, so a caller queued behind a FAILED setup is a retry, not an
    already-run refusal - two discoveries, and a client that ends up set
    up.
    """
    discover = json.loads((FIXTURES / "discoverdevice.json").read_text())
    attempts = 0
    order = []

    async def get_own_devices():
        """Fail the first attempt after yielding; succeed on the second."""
        nonlocal attempts
        attempts += 1
        mine = attempts
        order.append(f"start{mine}")
        await asyncio.sleep(0)
        order.append(f"end{mine}")
        if mine == 1:
            raise ZephyrError("discovery failed")
        return [{"thingName": THING}]

    wired["api"].get_own_devices = AsyncMock(side_effect=get_own_devices)
    wired["api"].discover_device = AsyncMock(return_value=discover)
    client = _client()

    first, second = await asyncio.gather(
        client.async_setup(), client.async_setup(), return_exceptions=True
    )

    assert isinstance(first, ZephyrError)
    assert "discovery failed" in str(first)
    assert [hood.thing_name for hood in second] == [THING]
    # The retry begins only once the failed attempt is over - overlapping
    # discoveries are what let two setups interleave their writes to _hoods.
    assert order == ["start1", "end1", "start2", "end2"]
    assert client._setup_complete is True


async def test_async_setup_refuses_to_run_twice(wired):
    """Tests that async_setup refuses to run twice.

    Re-running setup would replace started Hood objects while their
    sockets and the supervisor still reference the old ones. The guard is
    checked before the credential exchange, so a repeat call must not
    perform a second needless network round trip either.
    """
    client = _client()
    await client.async_setup()
    with pytest.raises(ZephyrError, match="already run"):
        await client.async_setup()

    wired["auth"].async_get_credentials.assert_awaited_once()


async def test_setup_with_zero_devices_still_refuses_to_run_twice(wired):
    """Tests that setup with zero devices still refuses to run twice.

    _hoods was the sentinel, so an account with no devices left it empty
    and a SECOND full setup - credential exchange, discovery and a fresh set
    of Hood objects sharing the existing supervisor - was permitted.
    """
    wired["api"].get_own_devices = AsyncMock(return_value=[])
    client = _client()

    assert await client.async_setup() == []
    assert client._setup_complete is True

    with pytest.raises(ZephyrError, match="already run"):
        await client.async_setup()


async def test_a_setup_that_fails_midway_can_be_retried_cleanly(wired):
    """Tests that a setup that fails midway can be retried cleanly.

    The other half of the sentinel bug: a failure partway through the
    discovery loop left _hoods partially filled, which made the client look
    initialized and its failed setup unretryable forever. The retry must
    also start from empty - appending to the leftovers would return stale
    and duplicated hoods.
    """
    discover = json.loads((FIXTURES / "discoverdevice.json").read_text())
    calls = []

    async def discover_device(thing_name):
        """Fail on the second device of the first attempt only."""
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
    assert len(client._hoods) == 1  # the partial result is there...

    hoods = await client.async_setup()  # ...and must not be retried into

    assert client._setup_complete is True
    assert [hood.thing_name for hood in hoods] == [THING, OTHER]


async def test_a_retried_setup_returns_only_what_the_retry_discovered(wired):
    """Tests that a retried setup returns only what the retry discovered.

    The sibling of the test above, and the one that pins the `_hoods = {}`
    reset rather than just tolerating it.

    There, both attempts saw the same two devices, so leftovers from the
    failed attempt were indistinguishable from the retry's own results. Here
    the account changes between attempts - a device removed in the vendor app
    while setup was failing - and stale entries become visible: without the
    reset the retry returns the device that no longer exists.
    """
    discover = json.loads((FIXTURES / "discoverdevice.json").read_text())
    calls = []

    async def discover_device(thing_name):
        """Fail on the second device of the first attempt only."""
        calls.append(thing_name)
        if thing_name == OTHER and len(calls) == 2:
            # Fails on the SECOND device of the first attempt only.
            raise ZephyrError("discoverdevice failed")
        return {**discover, "thingName": thing_name}

    wired["api"].get_own_devices = AsyncMock(
        side_effect=[
            [{"thingName": THING}, {"thingName": OTHER}],
            [{"thingName": OTHER}],
        ]
    )
    wired["api"].discover_device = AsyncMock(side_effect=discover_device)

    client = _client()
    with pytest.raises(ZephyrError):
        await client.async_setup()

    assert [thing for thing in client._hoods] == [THING]  # the leftover

    hoods = await client.async_setup()

    assert [hood.thing_name for hood in hoods] == [OTHER]
    assert list(client._hoods) == [OTHER]


async def test_setup_performs_the_identity_exchange(wired):
    """Tests that setup performs the identity exchange.

    Not just tokens: the config-flow ordering "async_setup(), then read
    identity_id for the unique ID" depends on the exchange having run.
    """
    await _client().async_setup()
    wired["auth"].async_get_credentials.assert_awaited()


async def test_setup_with_a_none_discover_body_raises_zephyr_error_not_attributeerror():
    """Tests that a None discover body raises ZephyrError, not AttributeError.

    End-to-end through the REAL ZephyrApi, not the `wired` fixture's
    mocked one: a discoverdevice response that decodes to None (aiohttp's
    shape for an empty 200 body) must be rejected by ZephyrApi._post()
    before it ever reaches HoodCapabilities.from_discover(), which would
    otherwise blow up as a raw, uncategorized AttributeError instead of a
    ZephyrError subclass consumers are told to catch.
    """
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
    """Tests that identity_id mirrors the auth object's value."""
    client = _client()
    await client.async_setup()
    assert client.identity_id == "us-west-2:abc"


async def test_a_refetched_identity_reaches_new_shadow_client_ids(wired):
    """Tests that a refetched identity reaches new shadow client IDs.

    mqtt_client_id is derived from identity_id. A mid-session refetch
    (AbstractAuth._identity_override) must reach every shadow built AFTER
    it, not just client.identity_id - keeping a dead one in a shadow's
    client ID gets a connection where subscribe and publish succeed and
    every message is silently dropped.
    """
    auth = wired["auth"]
    client = _client()
    hoods = await client.async_setup()

    auth.identity_id = "us-west-2:new"
    auth.mqtt_client_id = "us-west-2:new-py"
    client._make_shadow(hoods[0])

    assert client.identity_id == "us-west-2:new"
    args = client_module.ShadowClient.call_args.args
    assert args[1] == f"us-west-2:new-py-{THING}"


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
    """Tests that from_credentials builds a CredentialsAuth on the session."""
    session = MagicMock()
    client = ZephyrClient.from_credentials("u", "p", session)
    assert isinstance(client._auth, CredentialsAuth)
    assert client._auth.session is session


def test_from_credentials_threads_tokens_and_endpoints_through():
    """Tests that from_credentials threads tokens and endpoints through.

    Restored tokens skip the SRP login entirely, and an endpoint override
    has to reach the auth object or REST and MQTT point at different clouds.
    """
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


def test_from_credentials_threads_the_client_id_suffix_through():
    """Tests that from_credentials threads the client-ID suffix through.

    The convenience constructor is how most consumers build the auth object,
    so a suffix that stops here leaves every one of them on the default -
    two consumers on one account would then share a client ID and evict each
    other, which is the failure the suffix exists to prevent.
    """
    tokens = ZephyrTokens(
        username="u",
        id_token="i",
        refresh_token="r",
        identity_id="us-west-2:restored",
        expires_at=time.time() + 3600,
    )
    client = ZephyrClient.from_credentials(
        "u", "p", MagicMock(), tokens=tokens, client_id_suffix="-ha"
    )

    # Restored tokens make the client ID readable without a network call.
    assert client._auth.mqtt_client_id == "us-west-2:restored-ha"


def test_from_credentials_defaults_the_client_id_suffix_to_the_constant():
    """Tests that from_credentials defaults the suffix to the constant."""
    client = ZephyrClient.from_credentials("u", "p", MagicMock())

    assert client._auth.client_id_suffix == const.CLIENT_ID_SUFFIX


def test_from_credentials_passes_token_updater_through(monkeypatch):
    """Tests that from_credentials passes token_updater through.

    token_updater persists refreshed tokens; dropping it on the way to
    CredentialsAuth would make every consumer's persistence path a silent
    no-op - tokens would look like they're being saved but never are.
    """
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
    """Tests that the per-thing client surface is gone.

    These moved onto Hood. Leaving a shim would keep consumers writing
    thing-name-keyed code against an object that no longer caches state.
    """
    assert not hasattr(ZephyrClient, name)


def test_the_legacy_auth_alias_is_gone():
    """Tests that the legacy auth alias is gone.

    client.py imported CredentialsAuth as ZephyrAuth during the
    transition. Anything still monkeypatching that name is testing a ghost.
    """
    assert not hasattr(client_module, "ZephyrAuth")


# -- wiring -----------------------------------------------------------


async def test_policy_is_attached_before_the_socket_opens(wired):
    """Tests that the policy is attached before the socket opens.

    Ordering is load-bearing: an already-open connection does not pick up
    newly attached permissions, and the failure is silent.
    """
    hoods = await _client().async_setup()
    await hoods[0].async_start()

    order = wired["order"]
    assert order.index("attach_policy") < order.index("connect")


async def test_the_policy_is_attached_once_per_identity(wired):
    """Tests that the policy is attached once per identity.

    Latched, because the binding persists on the identity - but keyed on
    WHICH identity, so a mid-session refetch re-attaches for the new one.
    """
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
    """Tests that concurrent _ensure_policy calls attach exactly once.

    Hoods start concurrently. The latch is a read-modify-write spanning
    an await, so without a lock both callers pass the check and both attach
    - and the interleaved writes can record an identity that never received
    the policy, which is the silent message-drop failure.
    """
    auth = wired["auth"]
    started = asyncio.Event()
    release = asyncio.Event()

    async def slow_attach():
        """Hold the attach open so both callers overlap inside it."""
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
    """Tests that an identity refetch during an attach is not latched stale.

    The identity is re-read INSIDE the lock. A waiter that queued behind
    an attach for A must latch whichever identity is current when its OWN
    attach runs - latching A over a newer B would mark the new identity as
    attached-for while the policy never reached it.
    """
    auth = wired["auth"]
    started = asyncio.Event()
    release = asyncio.Event()
    attached_for: list[str] = []

    async def slow_attach():
        """Record the identity being attached and hold the attach open."""
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
    """Tests that the MQTT client ID is per connection.

    AWS IoT treats two live connections with the same client ID as one
    session and evicts one for the other, so N hoods sharing the bare
    mqtt_client_id would flap forever. Identity-prefixed so the policy's
    prefix match still covers it. The FULL thing name, not a truncated
    8-char prefix - see test_two_hoods_sharing_an_8char_prefix_get_
    different_client_ids for why the truncated form was actively unsafe.
    """
    client = _client()
    hoods = await client.async_setup()
    client._make_shadow(hoods[0])

    args = client_module.ShadowClient.call_args.args
    assert args[0] == THING
    assert args[1] == f"us-west-2:abc-py-{THING}"
    assert args[1] != wired["auth"].mqtt_client_id


async def test_two_hoods_sharing_an_8char_prefix_get_different_client_ids(wired):
    """Tests that hoods sharing an 8-char prefix get different client IDs.

    The old truncated-to-8-chars form gave two things sharing that
    prefix IDENTICAL client IDs - AWS IoT evicts one same-ID session for
    the other, the exact failure the per-connection suffix exists to
    prevent. The full thing name must not collide the same way, and both
    IDs must still carry the identity prefix the IoT policy matches on.
    """
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
    """Tests that the shadow gets the credentials provider, not a credential.

    The presigned URL is rebuilt on every connect, so the shadow needs a
    callable - handing it one snapshot pins the socket to credentials that
    expire in an hour.

    It is a per-hood wrapper rather than async_get_credentials itself: the
    connect that presigns the URL is exactly the moment that must record
    which credential generation the signature belongs to, so the supervisor
    can rebuild on a mismatch instead of trusting expiry. The record lives
    on the shadow until that shadow is installed. Noting it on the hood
    from the provider would let an abandoned presign describe the socket
    that is still live.
    """
    client = _client()
    hoods = await client.async_setup()
    client._make_shadow(hoods[0])

    provider = client_module.ShadowClient.call_args.args[4]
    assert provider is not wired["auth"].async_get_credentials

    creds = await provider()
    assert isinstance(creds, Credentials)
    wired["auth"].async_get_credentials.assert_awaited()
    assert hoods[0]._presigned_generation is None
    assert wired["shadow"].presigned_generation == wired["auth"].credentials_generation


async def test_the_recorded_generation_belongs_to_the_credentials_used(wired):
    """Tests that the recorded generation belongs to the credentials used.

    The pair must come from ONE call, not a fetch followed by a separate
    counter read.

    With an await between them a concurrent refresh records generation N+1
    against a URL signed under N: the socket then looks current to the
    supervisor and nothing re-presigns it before the OLDER credentials
    expire - the reverse direction of the bug the generation counter was
    added for.
    """
    creds = Credentials("pinned", "s", "t", datetime.now(UTC) + timedelta(hours=1))
    used = []

    async def presign_pair():
        """Return the pinned pair while a refresh moves the counter."""
        # The pair is taken atomically, and a refresh lands immediately
        # after. What the hood records must be the generation that came WITH
        # these credentials, not whatever the counter reads afterwards.
        wired["auth"].credentials_generation = 9
        return creds, 4

    wired["auth"].async_get_presign_credentials = AsyncMock(side_effect=presign_pair)

    async def connect(*args, **kwargs):
        """Call the wired provider and record the credentials it returns."""
        provider = client_module.ShadowClient.call_args.args[4]
        used.append(await provider())

    wired["shadow"].connect = AsyncMock(side_effect=connect)

    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()

    assert used == [creds]
    assert hoods[0]._presigned_generation == 4


async def test_an_endpoint_override_reaches_mqtt_too(wired):
    """Tests that an endpoint override reaches MQTT too.

    Overriding endpoints must not silently apply to REST only - the MQTT
    host is a separate wiring path, and failing to thread it through leaves
    the override half-applied with nothing complaining.
    """
    endpoints = Endpoints(iot_endpoint="staging-ats.iot.us-west-2.amazonaws.com")
    client = ZephyrClient(_auth_double(endpoints=endpoints))
    hoods = await client.async_setup()
    client._make_shadow(hoods[0])

    passed = client_module.ShadowClient.call_args.kwargs["endpoints"]
    assert passed.iot_endpoint.startswith("staging-ats")


async def test_starting_a_hood_requests_its_current_state(wired):
    """Tests that starting a hood requests its current shadow state."""
    hoods = await _client().async_setup()
    await hoods[0].async_start()
    wired["shadow"].request_state.assert_awaited_once()


async def test_connected_is_derived_from_the_hoods(wired):
    """Tests that connected is derived from the hoods.

    Derived rather than a single latched flag, which with more than one
    hood reported whichever shadow changed state last.
    """
    client = _client()
    hoods = await client.async_setup()
    assert client.connected is False

    hoods[0].handle_connection_change(True)
    assert client.connected is True

    hoods[0].handle_connection_change(False)
    assert client.connected is False


async def test_connection_change_wiring_is_pinned_per_hood(wired):
    """Tests that connection-change wiring is pinned per hood.

    args[3] must be THIS hood's own handle_connection_change - wiring one
    hood's shadow to another's callback would make `connected` (and the
    supervisor's terminal-stop flip) attribute the wrong hood's socket
    state.
    """
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
    """Tests that get/accepted replaces and update/accepted merges.

    get/accepted carries a full document; update/accepted carries only
    what changed, so replacing on it would zero everything unmentioned.
    """
    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()

    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/get/accepted",
        {"state": {"reported": {"power": 1, "fan": 3}}},
    )
    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/update/accepted",
        {"state": {"reported": {"fan": 5}}},
    )

    assert hoods[0].state.power == 1
    assert hoods[0].state.fan == 5


async def test_update_accepted_keeps_counters_it_did_not_mention(wired):
    """Tests that update/accepted keeps counters it did not mention.

    Payload shape captured from the real device, including the top-level
    "version" key the handler must simply ignore.
    """
    client = _client()
    hoods = await client.async_setup()
    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/get/accepted",
        {"state": {"reported": {"fan": 0, "light": 0, "usegreasefiltertime": 642}}},
    )

    seen = []
    hoods[0].add_listener(seen.append)
    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/update/accepted",
        {"state": {"reported": {"light": 1, "power": 1}}, "version": 302691},
    )

    assert hoods[0].state.light == 1
    assert hoods[0].state.power == 1
    assert hoods[0].state.use_grease_filter_time == 642
    assert seen[-1].light == 1


async def test_update_delta_is_ignored(wired):
    """Tests that update/delta is ignored.

    Nothing writes state.desired here, so a delta can only be stale or
    foreign. Merging one produces a phantom change.
    """
    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()
    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/get/accepted",
        {"state": {"reported": {"fan": 1}}},
    )
    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/update/delta",
        {"state": {"fan": 6}},
    )

    assert hoods[0].state.fan == 1


async def test_a_write_is_optimistic_and_the_echo_merges_over_it(wired):
    """Tests that a write shows up locally and the echo only adds device keys.

    power is not part of the publish. The device raises it itself, and that
    arrives on update/accepted. The grease counter must survive both steps.
    """
    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()
    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/get/accepted",
        {"state": {"reported": {"light": 0, "usegreasefiltertime": 642}}},
    )
    seen = []
    hoods[0].add_listener(seen.append)

    await hoods[0].async_set_light(1)

    wired["shadow"].publish_state.assert_awaited_with({"light": 1})
    assert hoods[0].state.light == 1
    assert hoods[0].state.power is None
    assert hoods[0].state.use_grease_filter_time == 642
    assert len(seen) == 1
    assert seen[0].light == 1

    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/update/accepted",
        {"state": {"reported": {"fan": 1, "power": 1}}, "version": 11},
    )

    assert hoods[0].state.light == 1
    assert hoods[0].state.fan == 1
    assert hoods[0].state.power == 1
    assert hoods[0].state.use_grease_filter_time == 642


async def test_a_delta_does_not_move_an_optimistic_snapshot(wired):
    """Tests that a delta is still dropped after an optimistic write.

    Optimistic state is not a reason to start trusting desired-vs-reported.
    """
    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()
    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/get/accepted",
        {"state": {"reported": {"light": 0, "fan": 0}}},
    )
    await hoods[0].async_set_light(1)

    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/update/delta",
        {"state": {"light": 3, "power": 1}, "version": 99},
    )

    assert hoods[0].state.light == 1
    assert hoods[0].state.power is None


async def test_a_stale_get_does_not_replace_a_newer_snapshot(wired):
    """Tests that an older shadow version is ignored and a newer one replaces.

    A missing version still applies, and does not move the cursor, so a
    later older document stays ignored.
    """
    client = _client()
    hoods = await client.async_setup()
    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/update/accepted",
        {
            "state": {"reported": {"light": 1, "usegreasefiltertime": 642}},
            "version": 10,
        },
    )

    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/get/accepted",
        {"state": {"reported": {"light": 0}}, "version": 9},
    )
    assert hoods[0].state.light == 1
    assert hoods[0].state.use_grease_filter_time == 642

    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/get/accepted",
        {
            "state": {"reported": {"light": 3, "usegreasefiltertime": 642}},
            "version": 11,
        },
    )
    assert hoods[0].state.light == 3

    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/get/accepted",
        {"state": {"reported": {"light": 4, "usegreasefiltertime": 642}}},
    )
    assert hoods[0].state.light == 4

    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/get/accepted",
        {"state": {"reported": {"light": 0}}, "version": 9},
    )
    assert hoods[0].state.light == 4


async def test_a_same_version_get_does_not_clobber_an_optimistic_write(wired):
    """Tests that a GET at the current version keeps an unconfirmed write.

    The write does not advance the shadow version. The document that was
    in flight before it comes back at that same version, and a strict
    older-than check lets it through. Pending fields stay until a document
    echoes them. Once it does, a later document may change the key.
    """
    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()
    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/get/accepted",
        {
            "state": {"reported": {"light": 0, "usegreasefiltertime": 642}},
            "version": 10,
        },
    )

    await hoods[0].async_set_light(1)
    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/get/accepted",
        {
            "state": {"reported": {"light": 0, "usegreasefiltertime": 642}},
            "version": 10,
        },
    )

    assert hoods[0].state.light == 1
    assert hoods[0].state.use_grease_filter_time == 642

    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/update/accepted",
        {"state": {"reported": {"light": 1}}, "version": 11},
    )
    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/get/accepted",
        {
            "state": {"reported": {"light": 3, "usegreasefiltertime": 642}},
            "version": 12,
        },
    )
    assert hoods[0].state.light == 3


async def test_an_earlier_echo_does_not_overwrite_a_later_optimistic_write(wired):
    """Tests that an earlier command's echo does not revert a later command.

    update/accepted can still carry the previous value of a key published
    after that command. That key stays as published. The echoed key is
    acknowledged and may change in a later document.
    """
    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()
    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/get/accepted",
        {
            "state": {"reported": {"light": 0, "fan": 0, "usegreasefiltertime": 642}},
            "version": 10,
        },
    )

    await hoods[0].async_set_light(1)
    await hoods[0].async_set_fan(2)
    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/update/accepted",
        {"state": {"reported": {"light": 1, "fan": 0}}, "version": 11},
    )

    assert hoods[0].state.light == 1
    assert hoods[0].state.fan == 2
    assert hoods[0].state.use_grease_filter_time == 642


async def test_repeating_a_level_is_not_acked_by_the_older_value(wired):
    """Tests that publishing 1 then 0 is not confirmed by the old 0.

    A GET that was in flight at version 10 still says 0, which is also
    the latest command. Value equality would drop that command, and the
    first command's echo (light 1, version 11) would then overwrite it.
    """
    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()
    seen = []
    hoods[0].add_listener(seen.append)
    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/get/accepted",
        {
            "state": {"reported": {"light": 0, "usegreasefiltertime": 642}},
            "version": 10,
        },
    )

    await hoods[0].async_set_light(1)
    await hoods[0].async_set_light(0)
    seen.clear()
    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/get/accepted",
        {
            "state": {"reported": {"light": 0, "usegreasefiltertime": 642}},
            "version": 10,
        },
    )
    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/update/accepted",
        {"state": {"reported": {"light": 1}}, "version": 11},
    )

    assert hoods[0].state.light == 0
    assert hoods[0].state.use_grease_filter_time == 642
    assert [state.light for state in seen] == [0, 0]
    assert hoods[0]._pending_writes

    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/update/accepted",
        {"state": {"reported": {"light": 0}}, "version": 12},
    )
    assert hoods[0].state.light == 0
    assert hoods[0]._pending_writes == []


async def test_an_earlier_repeated_level_does_not_ack_the_latest_write(wired):
    """Tests that 1 then 2 then 1 is not confirmed by the first echo.

    The first echo carries light 1 and a newer version. That matches the
    last command's value and is newer than every baseline. It is still
    the first command's echo. The middle echo (light 2) must not replace
    the latest 1 either.
    """
    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()
    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/get/accepted",
        {"state": {"reported": {"light": 0}}, "version": 10},
    )

    await hoods[0].async_set_light(1)
    await hoods[0].async_set_light(2)
    await hoods[0].async_set_light(1)
    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/update/accepted",
        {"state": {"reported": {"light": 1}}, "version": 11},
    )
    assert hoods[0].state.light == 1
    assert len(hoods[0]._pending_writes) == 2

    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/update/accepted",
        {"state": {"reported": {"light": 2}}, "version": 12},
    )
    assert hoods[0].state.light == 1
    assert len(hoods[0]._pending_writes) == 1

    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/update/accepted",
        {"state": {"reported": {"light": 1}}, "version": 13},
    )
    assert hoods[0].state.light == 1
    assert hoods[0]._pending_writes == []


async def test_a_missed_echo_does_not_hide_state_after_reconnect(wired):
    """Tests that a fresh document after reconnect is not the missed write.

    Stop and the supervisor rebuild share ``_stop``. Either one drops
    commands published on the socket that just died, so a higher-version
    GET can show a change the phone or the device made during the outage.
    A write on the replacement session stays pending over a resync that
    was already in flight.
    """
    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()
    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/get/accepted",
        {
            "state": {"reported": {"light": 0, "usegreasefiltertime": 642}},
            "version": 10,
        },
    )
    await hoods[0].async_set_light(1)
    assert hoods[0]._pending_writes

    await hoods[0].async_reconnect()

    assert hoods[0]._pending_writes == []
    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/get/accepted",
        {
            "state": {"reported": {"light": 4, "usegreasefiltertime": 642}},
            "version": 20,
        },
    )
    assert hoods[0].state.light == 4

    await hoods[0].async_set_light(2)
    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/get/accepted",
        {
            "state": {"reported": {"light": 4, "usegreasefiltertime": 700}},
            "version": 20,
        },
    )
    assert hoods[0].state.light == 2
    assert hoods[0].state.use_grease_filter_time == 700

    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/update/accepted",
        {"state": {"reported": {"light": 2}}, "version": 21},
    )
    assert hoods[0].state.light == 2
    assert hoods[0]._pending_writes == []


async def test_a_reordered_partial_echo_keeps_the_older_field(wired):
    """Tests that an older partial update is not dropped behind a newer one.

    update/accepted carries only the keys that changed. Version 12
    reporting fan does not contain the light change at version 11.
    Dropping version 11 strands the light command, and every later GET
    stays covered by that pending value. The older partial still applies
    its own key and retires its command. It does not move the version
    cursor backward, and it does not overwrite a key a newer document
    already applied.
    """
    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()
    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/get/accepted",
        {
            "state": {"reported": {"light": 0, "fan": 0, "usegreasefiltertime": 642}},
            "version": 10,
        },
    )

    await hoods[0].async_set_light(1)
    await hoods[0].async_set_fan(2)
    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/update/accepted",
        {"state": {"reported": {"fan": 2}}, "version": 12},
    )

    assert hoods[0].state.light == 1
    assert hoods[0].state.fan == 2
    assert len(hoods[0]._pending_writes) == 1
    assert hoods[0]._shadow_version == 12

    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/update/accepted",
        {"state": {"reported": {"light": 1}}, "version": 11},
    )
    assert hoods[0].state.light == 1
    assert hoods[0].state.fan == 2
    assert hoods[0]._pending_writes == []
    assert hoods[0]._shadow_version == 12

    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/get/accepted",
        {
            "state": {"reported": {"light": 5, "fan": 3, "usegreasefiltertime": 700}},
            "version": 13,
        },
    )
    assert hoods[0].state.light == 5
    assert hoods[0].state.fan == 3
    assert hoods[0].state.use_grease_filter_time == 700

    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/update/accepted",
        {"state": {"reported": {"light": 9}}, "version": 14},
    )
    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/update/accepted",
        {"state": {"reported": {"light": 1}}, "version": 13},
    )
    assert hoods[0].state.light == 9
    assert hoods[0].state.fan == 3
    assert hoods[0]._shadow_version == 14


async def test_retiring_an_echo_reveals_a_newer_reported_value(wired):
    """Tests that retiring a command reveals the reported value it hid.

    Another client's light=3 at version 12 is newer than this client's
    still-pending light=1. The overlay hides 3 until this client's own
    echo arrives. That echo is version 11, so it must not be merged, and
    retiring the command has to show 3. Merging the echo onto the visible
    cache would store 1 as if the device had reported it.
    """
    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()
    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/get/accepted",
        {
            "state": {"reported": {"light": 0, "usegreasefiltertime": 642}},
            "version": 10,
        },
    )

    await hoods[0].async_set_light(1)
    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/update/accepted",
        {"state": {"reported": {"light": 3}}, "version": 12},
    )
    assert hoods[0].state.light == 1
    assert hoods[0]._pending_writes

    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/update/accepted",
        {"state": {"reported": {"light": 1}}, "version": 11},
    )
    assert hoods[0].state.light == 3
    assert hoods[0].state.use_grease_filter_time == 642
    assert hoods[0]._pending_writes == []
    assert hoods[0]._shadow_version == 12


async def test_a_snapshot_blocks_an_older_update_of_an_omitted_field(wired):
    """Tests that a GET versions keys it does not mention.

    A version-12 snapshot without light makes light unknown. Recording a
    version only for keys present in reported leaves light at version 10,
    and a delayed version-11 update puts the obsolete light back. A partial
    newer than the snapshot may still change the key.
    """
    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()
    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/get/accepted",
        {
            "state": {"reported": {"light": 1, "fan": 0, "usegreasefiltertime": 642}},
            "version": 10,
        },
    )
    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/get/accepted",
        {
            "state": {"reported": {"fan": 2, "usegreasefiltertime": 700}},
            "version": 12,
        },
    )
    assert hoods[0].state.light is None
    assert hoods[0].state.fan == 2
    assert hoods[0].state.use_grease_filter_time == 700

    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/update/accepted",
        {"state": {"reported": {"light": 1}}, "version": 11},
    )
    assert hoods[0].state.light is None
    assert hoods[0].state.fan == 2
    assert hoods[0].state.use_grease_filter_time == 700

    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/update/accepted",
        {"state": {"reported": {"light": 4}}, "version": 13},
    )
    assert hoods[0].state.light == 4
    assert hoods[0].state.fan == 2


async def test_a_reordered_same_field_echo_does_not_restore_the_older_write(wired):
    """Tests that an older queued write does not cover a newer confirmation.

    light=1 then light=2, and the version-12 echo of 2 arrives first. The
    older command stays queued so the version-11 echo can still match it,
    but that command must not put 1 back over the reported 2. The later
    echo is too old to merge, and the cache stays at 2 with nothing pending.
    """
    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()
    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/get/accepted",
        {"state": {"reported": {"light": 0}}, "version": 10},
    )

    await hoods[0].async_set_light(1)
    await hoods[0].async_set_light(2)
    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/update/accepted",
        {"state": {"reported": {"light": 2}}, "version": 12},
    )
    assert hoods[0].state.light == 2
    assert len(hoods[0]._pending_writes) == 1
    assert hoods[0]._pending_writes[0].fields == {"light": 1}

    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/update/accepted",
        {"state": {"reported": {"light": 1}}, "version": 11},
    )
    assert hoods[0].state.light == 2
    assert hoods[0]._pending_writes == []
    assert hoods[0]._shadow_version == 12


async def test_a_redelivered_echo_does_not_retire_the_next_same_value(wired):
    """Tests that a QoS 1 replay of one echo does not ack a second write.

    Two light=1 commands share a baseline. The version-11 echo retires the
    first and advances the second command's baseline to that version. A
    redelivery of version 11 still matches the value, and must not retire
    the second. A GET at version 11 that still has the old light cannot
    replace it either. The second command waits for its own later echo.
    """
    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()
    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/get/accepted",
        {
            "state": {"reported": {"light": 0, "usegreasefiltertime": 642}},
            "version": 10,
        },
    )

    await hoods[0].async_set_light(1)
    await hoods[0].async_set_light(1)
    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/update/accepted",
        {"state": {"reported": {"light": 1}}, "version": 11},
    )
    assert hoods[0].state.light == 1
    assert len(hoods[0]._pending_writes) == 1

    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/update/accepted",
        {"state": {"reported": {"light": 1}}, "version": 11},
    )
    assert hoods[0].state.light == 1
    assert len(hoods[0]._pending_writes) == 1

    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/get/accepted",
        {
            "state": {"reported": {"light": 0, "usegreasefiltertime": 642}},
            "version": 11,
        },
    )
    assert hoods[0].state.light == 1
    assert hoods[0].state.use_grease_filter_time == 642

    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/update/accepted",
        {"state": {"reported": {"light": 1}}, "version": 12},
    )
    assert hoods[0].state.light == 1
    assert hoods[0]._pending_writes == []


async def test_a_reordered_same_value_echo_does_not_hide_a_later_get(wired):
    """Tests that echoes of two light=1 writes retire the command they belong to.

    Both writes share baseline 10, so they belong to versions 11 and 12.
    Version 12 arriving first used to retire the older write and raise the
    newer one's baseline to 12, and version 11 could not retire it. The
    pending light then covered a version-13 GET of light 0. A redelivery
    of version 12 must still leave that older write queued.
    """
    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()
    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/get/accepted",
        {
            "state": {"reported": {"light": 0, "usegreasefiltertime": 642}},
            "version": 10,
        },
    )

    await hoods[0].async_set_light(1)
    await hoods[0].async_set_light(1)
    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/update/accepted",
        {"state": {"reported": {"light": 1}}, "version": 12},
    )
    assert hoods[0].state.light == 1
    assert len(hoods[0]._pending_writes) == 1
    assert hoods[0]._pending_writes[0].ordinal == 0

    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/update/accepted",
        {"state": {"reported": {"light": 1}}, "version": 12},
    )
    assert len(hoods[0]._pending_writes) == 1

    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/update/accepted",
        {"state": {"reported": {"light": 1}}, "version": 11},
    )
    assert hoods[0].state.light == 1
    assert hoods[0]._pending_writes == []

    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/get/accepted",
        {
            "state": {"reported": {"light": 0, "usegreasefiltertime": 642}},
            "version": 13,
        },
    )
    assert hoods[0].state.light == 0
    assert hoods[0].state.use_grease_filter_time == 642
    assert hoods[0]._pending_writes == []


async def test_a_reordered_final_repeated_echo_does_not_hide_a_later_get(wired):
    """Tests that 1 then 2 then 1 retires each write when the last echo is first.

    The version-13 echo is the third write. Treating it as the oldest
    ``light=1`` and raising the other baselines leaves those commands
    pending, and a later GET stays covered. A redelivery of version 13
    must not retire the first write. The middle echo must not leave the
    cache at 2 once the final echo has been seen.
    """
    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()
    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/get/accepted",
        {
            "state": {"reported": {"light": 0, "usegreasefiltertime": 642}},
            "version": 10,
        },
    )

    await hoods[0].async_set_light(1)
    await hoods[0].async_set_light(2)
    await hoods[0].async_set_light(1)
    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/update/accepted",
        {"state": {"reported": {"light": 1}}, "version": 13},
    )
    assert hoods[0].state.light == 1
    assert len(hoods[0]._pending_writes) == 2

    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/update/accepted",
        {"state": {"reported": {"light": 1}}, "version": 13},
    )
    assert len(hoods[0]._pending_writes) == 2
    assert {pending.ordinal for pending in hoods[0]._pending_writes} == {0, 1}

    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/update/accepted",
        {"state": {"reported": {"light": 2}}, "version": 12},
    )
    assert hoods[0].state.light == 1
    assert len(hoods[0]._pending_writes) == 1

    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/update/accepted",
        {"state": {"reported": {"light": 1}}, "version": 11},
    )
    assert hoods[0].state.light == 1
    assert hoods[0]._pending_writes == []

    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/get/accepted",
        {
            "state": {"reported": {"light": 0, "usegreasefiltertime": 700}},
            "version": 14,
        },
    )
    assert hoods[0].state.light == 0
    assert hoods[0].state.use_grease_filter_time == 700
    assert hoods[0]._pending_writes == []


async def test_repeated_value_echoes_retire_in_every_arrival_order(wired):
    """Tests that every arrival order of repeated writes ends at the later GET.

    ``1 → 2 → 1`` and three ``light=1`` writes each have echoes at 11, 12,
    and 13. Whichever order those documents arrive, the queue has to be
    empty afterwards and a version-14 GET of light 0 has to show. The
    in-order and one-reordered cases above stay, and so does the QoS 1
    redelivery test.
    """
    sequences = (
        ((11, 1), (12, 2), (13, 1)),
        ((11, 1), (12, 1), (13, 1)),
    )
    for echoes in sequences:
        for order in itertools.permutations(echoes):
            client = _client()
            hoods = await client.async_setup()
            await hoods[0].async_start()
            client._handle_message(
                hoods[0],
                f"$aws/things/{THING}/shadow/get/accepted",
                {
                    "state": {"reported": {"light": 0, "usegreasefiltertime": 642}},
                    "version": 10,
                },
            )
            for _version, level in echoes:
                await hoods[0].async_set_light(level)
            for version, level in order:
                client._handle_message(
                    hoods[0],
                    f"$aws/things/{THING}/shadow/update/accepted",
                    {"state": {"reported": {"light": level}}, "version": version},
                )
            assert hoods[0]._pending_writes == []
            assert hoods[0].state.light == 1
            client._handle_message(
                hoods[0],
                f"$aws/things/{THING}/shadow/get/accepted",
                {
                    "state": {"reported": {"light": 0, "usegreasefiltertime": 700}},
                    "version": 14,
                },
            )
            assert hoods[0].state.light == 0
            assert hoods[0].state.use_grease_filter_time == 700


async def test_a_reordered_one_then_zero_echo_does_not_hide_a_later_get(wired):
    """Tests that 1 then 0 still clears when the echo of 0 arrives first.

    Version 12 belongs to the second write. It must not be spent on the
    first, or version 11 cannot retire what is left and the pending 0
    covers a newer light.
    """
    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()
    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/get/accepted",
        {
            "state": {"reported": {"light": 0, "usegreasefiltertime": 642}},
            "version": 10,
        },
    )

    await hoods[0].async_set_light(1)
    await hoods[0].async_set_light(0)
    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/update/accepted",
        {"state": {"reported": {"light": 0}}, "version": 12},
    )
    assert hoods[0].state.light == 0
    assert len(hoods[0]._pending_writes) == 1

    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/update/accepted",
        {"state": {"reported": {"light": 1}}, "version": 11},
    )
    assert hoods[0].state.light == 0
    assert hoods[0]._pending_writes == []

    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/get/accepted",
        {
            "state": {"reported": {"light": 4, "usegreasefiltertime": 642}},
            "version": 13,
        },
    )
    assert hoods[0].state.light == 4
    assert hoods[0].state.use_grease_filter_time == 642


async def test_a_gapped_repeated_echo_still_clears_before_the_later_get(wired):
    """Tests that an unrelated version between two light=1 echoes still clears.

    Version 11 belonging to another field must not consume either light
    write. Versions 12 and 13 are the two echoes, in that order or
    reversed, and a version-14 GET of light 0 has to show.
    """
    for order in ((12, 13), (13, 12)):
        client = _client()
        hoods = await client.async_setup()
        await hoods[0].async_start()
        client._handle_message(
            hoods[0],
            f"$aws/things/{THING}/shadow/get/accepted",
            {
                "state": {
                    "reported": {"light": 0, "fan": 0, "usegreasefiltertime": 642}
                },
                "version": 10,
            },
        )
        await hoods[0].async_set_light(1)
        await hoods[0].async_set_light(1)
        client._handle_message(
            hoods[0],
            f"$aws/things/{THING}/shadow/update/accepted",
            {"state": {"reported": {"fan": 3}}, "version": 11},
        )
        assert len(hoods[0]._pending_writes) == 2
        for version in order:
            client._handle_message(
                hoods[0],
                f"$aws/things/{THING}/shadow/update/accepted",
                {"state": {"reported": {"light": 1}}, "version": version},
            )
        assert hoods[0]._pending_writes == []
        client._handle_message(
            hoods[0],
            f"$aws/things/{THING}/shadow/get/accepted",
            {
                "state": {"reported": {"light": 0, "usegreasefiltertime": 642}},
                "version": 14,
            },
        )
        assert hoods[0].state.light == 0
        assert hoods[0].state.use_grease_filter_time == 642


async def test_one_echo_retires_every_queued_command_it_carries(wired):
    """Tests that one document can retire two queued commands.

    light=1 and fan=2 share a baseline. One update/accepted carries both
    values, plus power. Retiring only the oldest command raises the fan
    command's baseline to that version, so this document cannot confirm
    fan, and a later fan=0 stays hidden under the pending 2.
    """
    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()
    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/get/accepted",
        {
            "state": {"reported": {"light": 0, "fan": 0, "usegreasefiltertime": 642}},
            "version": 10,
        },
    )

    await hoods[0].async_set_light(1)
    await hoods[0].async_set_fan(2)
    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/update/accepted",
        {
            "state": {"reported": {"light": 1, "fan": 2, "power": 1}},
            "version": 11,
        },
    )
    assert hoods[0].state.light == 1
    assert hoods[0].state.fan == 2
    assert hoods[0].state.power == 1
    assert hoods[0]._pending_writes == []

    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/update/accepted",
        {"state": {"reported": {"fan": 0}}, "version": 12},
    )
    assert hoods[0].state.fan == 0
    assert hoods[0].state.use_grease_filter_time == 642
    assert hoods[0]._pending_writes == []


def _echo(client, hood, version, reported, *, snapshot=False):
    """Delivers one shadow document to ``hood``.

    Args:
        client: The client whose handler folds the document.
        hood: The hood the document belongs to.
        version: The document's shadow version.
        reported: The reported object.
        snapshot: True for a full GET. Otherwise ``update/accepted``.
    """
    leaf = "get/accepted" if snapshot else "update/accepted"
    client._handle_message(
        hood,
        f"$aws/things/{THING}/shadow/{leaf}",
        {"state": {"reported": reported}, "version": version},
    )


async def test_a_noncontiguous_echo_does_not_hide_the_later_get(wired):
    """Tests that a version nobody owns is not spent on the oldest write.

    Two ``light=1`` commands and a document that is not the older one's
    expected version used to retire the older write. The newer repeat
    stayed in the overlay and a GET of light 0 stayed covered. The GET
    has to show light 0 with nothing queued. The three inputs are: no
    versioned document yet, a gap after an unrelated field, and a
    reconnect that used to keep the old baseline counts.
    """
    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()
    assert hoods[0]._shadow_version is None

    await hoods[0].async_set_light(1)
    await hoods[0].async_set_light(1)
    _echo(client, hoods[0], 2, {"light": 1})
    assert len(hoods[0]._pending_writes) == 1
    assert hoods[0]._pending_writes[0].ordinal == 0
    _echo(
        client,
        hoods[0],
        3,
        {"light": 0, "usegreasefiltertime": 700},
        snapshot=True,
    )
    assert hoods[0].state.light == 0
    assert hoods[0].state.use_grease_filter_time == 700
    assert hoods[0]._pending_writes == []

    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()
    _echo(
        client,
        hoods[0],
        10,
        {"light": 0, "fan": 0, "usegreasefiltertime": 642},
        snapshot=True,
    )
    await hoods[0].async_set_light(1)
    await hoods[0].async_set_light(1)
    _echo(client, hoods[0], 11, {"fan": 3})
    assert len(hoods[0]._pending_writes) == 2
    _echo(client, hoods[0], 13, {"light": 1})
    assert len(hoods[0]._pending_writes) == 1
    assert hoods[0]._pending_writes[0].ordinal == 0
    _echo(
        client,
        hoods[0],
        14,
        {"light": 0, "fan": 0, "usegreasefiltertime": 700},
        snapshot=True,
    )
    assert hoods[0].state.light == 0
    assert hoods[0].state.fan == 0
    assert hoods[0].state.use_grease_filter_time == 700
    assert hoods[0]._pending_writes == []

    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()
    _echo(
        client,
        hoods[0],
        10,
        {"light": 0, "fan": 0, "usegreasefiltertime": 642},
        snapshot=True,
    )
    await hoods[0].async_set_light(1)
    await hoods[0].async_set_light(1)
    hoods[0].handle_connection_change(False)
    assert hoods[0]._pending_writes == []
    assert hoods[0]._baseline_counts == {}
    assert hoods[0]._confirmed_seq == {}
    assert hoods[0]._consumed_echo_versions == set()
    await hoods[0].async_set_light(1)
    await hoods[0].async_set_light(1)
    assert [pending.ordinal for pending in hoods[0]._pending_writes] == [0, 1]
    _echo(client, hoods[0], 12, {"light": 1})
    assert len(hoods[0]._pending_writes) == 1
    assert hoods[0]._pending_writes[0].ordinal == 0
    _echo(
        client,
        hoods[0],
        13,
        {"light": 0, "usegreasefiltertime": 700},
        snapshot=True,
    )
    assert hoods[0].state.light == 0
    assert hoods[0].state.use_grease_filter_time == 700
    assert hoods[0]._pending_writes == []


async def test_split_echoes_of_one_command_retire_it_before_the_get(wired):
    """Tests that partial echoes of one multi-key command retire it.

    Version 11 carrying only light, then version 12 carrying only fan,
    used to leave ``{light: 1, fan: 2}`` pending, and the GET stayed
    covered. Either order has to retire the command. A redelivery of the
    light partial must not fill a new key or retire anything else.
    """
    orders = (
        ((11, {"light": 1}), (12, {"fan": 2})),
        ((12, {"fan": 2}), (11, {"light": 1})),
    )
    for first, second in orders:
        client = _client()
        hoods = await client.async_setup()
        await hoods[0].async_start()
        _echo(
            client,
            hoods[0],
            10,
            {"light": 0, "fan": 0, "usegreasefiltertime": 642},
            snapshot=True,
        )
        await hoods[0].async_set_fields({"light": 1, "fan": 2})
        version, reported = first
        _echo(client, hoods[0], version, reported)
        assert len(hoods[0]._pending_writes) == 1
        _echo(client, hoods[0], version, reported)
        assert len(hoods[0]._pending_writes) == 1
        version, reported = second
        _echo(client, hoods[0], version, reported)
        assert hoods[0]._pending_writes == []
        _echo(
            client,
            hoods[0],
            13,
            {"light": 0, "fan": 0, "usegreasefiltertime": 700},
            snapshot=True,
        )
        assert hoods[0].state.light == 0
        assert hoods[0].state.fan == 0
        assert hoods[0].state.use_grease_filter_time == 700
        assert hoods[0]._pending_writes == []


async def test_a_partial_expected_echo_is_not_spent_on_the_older_subset(wired):
    """Tests that a partial of the later command does not retire the earlier one.

    ``light=1`` then ``{light: 1, fan: 2}``. Version 12 carrying only
    light belongs to the superset. Spending it on the older ``light=1``
    consumes 12, and the superset then never sees fan. The older command
    has to wait for version 11. Version 13 carrying fan retires the
    superset, and the GET shows both fields off.
    """
    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()
    _echo(
        client,
        hoods[0],
        10,
        {"light": 0, "fan": 0, "usegreasefiltertime": 642},
        snapshot=True,
    )
    await hoods[0].async_set_light(1)
    await hoods[0].async_set_fields({"light": 1, "fan": 2})
    _echo(client, hoods[0], 12, {"light": 1})
    assert [pending.fields for pending in hoods[0]._pending_writes] == [
        {"light": 1},
        {"light": 1, "fan": 2},
    ]
    assert hoods[0]._pending_writes[1].seen == {"light": 12}
    _echo(client, hoods[0], 12, {"light": 1})
    assert len(hoods[0]._pending_writes) == 2
    assert hoods[0]._pending_writes[1].seen == {"light": 12}

    _echo(client, hoods[0], 11, {"light": 1})
    assert [pending.fields for pending in hoods[0]._pending_writes] == [
        {"light": 1, "fan": 2}
    ]
    _echo(client, hoods[0], 13, {"fan": 2})
    assert hoods[0]._pending_writes == []
    _echo(
        client,
        hoods[0],
        14,
        {"light": 0, "fan": 0, "usegreasefiltertime": 700},
        snapshot=True,
    )
    assert hoods[0].state.light == 0
    assert hoods[0].state.fan == 0
    assert hoods[0].state.use_grease_filter_time == 700
    assert hoods[0]._pending_writes == []


async def test_one_document_retires_a_later_command_that_adds_a_key(wired):
    """Tests that a document which contains a later superset retires it.

    ``light=1`` then ``{light: 1, fan: 2}``, and version 11 carries both
    plus power. Retiring only the subset leaves the superset pending over
    the version-12 GET. The same two commands still clear when the full
    document is version 12 and the light echo is version 11. One
    ``{light: 1}`` still must not retire two ``light=1`` writes; that
    case is ``test_a_redelivered_echo_does_not_retire_the_next_same_value``.
    """
    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()
    _echo(
        client,
        hoods[0],
        10,
        {"light": 0, "fan": 0, "usegreasefiltertime": 642},
        snapshot=True,
    )
    await hoods[0].async_set_light(1)
    await hoods[0].async_set_fields({"light": 1, "fan": 2})
    _echo(client, hoods[0], 11, {"light": 1, "fan": 2, "power": 1})
    assert hoods[0]._pending_writes == []
    assert hoods[0].state.light == 1
    assert hoods[0].state.fan == 2
    _echo(
        client,
        hoods[0],
        12,
        {"light": 0, "fan": 0, "usegreasefiltertime": 700},
        snapshot=True,
    )
    assert hoods[0].state.light == 0
    assert hoods[0].state.fan == 0
    assert hoods[0].state.use_grease_filter_time == 700
    assert hoods[0]._pending_writes == []

    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()
    _echo(
        client,
        hoods[0],
        10,
        {"light": 0, "fan": 0, "usegreasefiltertime": 642},
        snapshot=True,
    )
    await hoods[0].async_set_light(1)
    await hoods[0].async_set_fields({"light": 1, "fan": 2})
    _echo(client, hoods[0], 12, {"light": 1, "fan": 2, "power": 1})
    assert [pending.fields for pending in hoods[0]._pending_writes] == [{"light": 1}]
    _echo(client, hoods[0], 11, {"light": 1})
    assert hoods[0]._pending_writes == []
    _echo(
        client,
        hoods[0],
        13,
        {"light": 0, "fan": 0, "usegreasefiltertime": 700},
        snapshot=True,
    )
    assert hoods[0].state.light == 0
    assert hoods[0].state.fan == 0
    assert hoods[0].state.use_grease_filter_time == 700


async def test_a_missed_echo_on_automatic_reconnect_does_not_hide_the_get(wired):
    """Tests that paho's own reconnect drops the dead session's commands.

    Automatic reconnect does not call ``_stop``. The disconnect callback
    is the only signal that the session which published the command is
    gone. Leaving the command pending paints it over the resync GET, so a
    change made while the socket was down never shows. A write after the
    callback belongs to the session that came back and stays pending over
    a resync that was already in flight.
    """
    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()
    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/get/accepted",
        {
            "state": {"reported": {"light": 0, "usegreasefiltertime": 642}},
            "version": 10,
        },
    )
    await hoods[0].async_set_light(1)
    assert hoods[0]._pending_writes

    hoods[0].handle_connection_change(False)

    assert hoods[0]._pending_writes == []
    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/get/accepted",
        {
            "state": {"reported": {"light": 4, "usegreasefiltertime": 700}},
            "version": 20,
        },
    )
    assert hoods[0].state.light == 4
    assert hoods[0].state.use_grease_filter_time == 700

    hoods[0].handle_connection_change(True)
    await hoods[0].async_set_light(2)
    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/get/accepted",
        {
            "state": {"reported": {"light": 4, "usegreasefiltertime": 710}},
            "version": 20,
        },
    )
    assert hoods[0].state.light == 2
    assert hoods[0].state.use_grease_filter_time == 710
    assert hoods[0]._pending_writes


async def test_a_rejection_lets_the_reread_restore_refused_fields(wired):
    """Tests that a rejection drops pending keys and a later write survives.

    The follow-up GET reuses the current version, because a rejected write
    does not bump it. Pending keys from the refused command would be
    painted back over that document. A command published after the
    rejection is a different write and stays in place.
    """
    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()
    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/get/accepted",
        {
            "state": {"reported": {"light": 0, "fan": 0, "usegreasefiltertime": 642}},
            "version": 10,
        },
    )

    await hoods[0].async_set_light(1)
    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/update/rejected",
        {"code": 400},
    )
    await asyncio.sleep(0)
    await hoods[0].async_set_fan(2)
    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/get/accepted",
        {
            "state": {"reported": {"light": 0, "fan": 0, "usegreasefiltertime": 642}},
            "version": 10,
        },
    )

    assert hoods[0].state.light == 0
    assert hoods[0].state.fan == 2
    assert hoods[0].state.use_grease_filter_time == 642


async def test_a_document_that_fails_to_parse_does_not_advance_the_version(wired):
    """Tests that an invalid reported block does not stick the version cursor.

    get/accepted and update/accepted both have to parse before recording
    the version. A list where reported should be an object raises, the
    handler swallows it, and a later valid document with a lower version
    must still apply. An empty list is falsy, so it must not be coerced
    into an empty object either: that would commit a snapshot and move
    both version cursors.
    """
    client = _client()
    hoods = await client.async_setup()
    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/update/accepted",
        {
            "state": {"reported": {"light": 1, "usegreasefiltertime": 642}},
            "version": 10,
        },
    )

    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/get/accepted",
        {"state": {"reported": [1]}, "version": 12},
    )
    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/update/accepted",
        {"state": {"reported": [1]}, "version": 13},
    )
    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/get/accepted",
        {"state": {"reported": []}, "version": 14},
    )
    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/update/accepted",
        {"state": {"reported": []}, "version": 15},
    )

    assert hoods[0].state.light == 1
    assert hoods[0].state.use_grease_filter_time == 642
    assert hoods[0]._shadow_version == 10
    assert hoods[0]._snapshot_version is None

    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/get/accepted",
        {
            "state": {"reported": {"light": 4, "usegreasefiltertime": 700}},
            "version": 11,
        },
    )
    assert hoods[0].state.light == 4
    assert hoods[0].state.use_grease_filter_time == 700
    assert hoods[0]._shadow_version == 11


async def test_a_non_object_state_block_does_not_advance_the_version(wired):
    """Tests that a non-object state block does not commit an empty snapshot.

    ``{"state": []}`` is not a document. Coercing it to ``{}`` clears the
    cached fields and moves both version cursors, so a later valid
    version-11 GET is ignored. A list does not.
    """
    client = _client()
    hoods = await client.async_setup()
    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/update/accepted",
        {
            "state": {"reported": {"light": 1, "usegreasefiltertime": 642}},
            "version": 10,
        },
    )

    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/get/accepted",
        {"state": [], "version": 12},
    )
    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/update/accepted",
        {"state": [], "version": 13},
    )

    assert hoods[0].state.light == 1
    assert hoods[0].state.use_grease_filter_time == 642
    assert hoods[0]._shadow_version == 10
    assert hoods[0]._snapshot_version is None

    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/get/accepted",
        {
            "state": {"reported": {"light": 4, "usegreasefiltertime": 700}},
            "version": 11,
        },
    )
    assert hoods[0].state.light == 4
    assert hoods[0].state.use_grease_filter_time == 700
    assert hoods[0]._shadow_version == 11


async def test_a_null_or_missing_state_block_does_not_advance_the_version(wired):
    """Tests that null or missing state does not commit an empty snapshot.

    JSON null and a missing key both look like ``None`` to ``dict.get``.
    Treating either as ``{}`` clears the cached fields, turns the omitted
    usage counters into 0, and sticks both version cursors. A null
    reported block is the same failure one level down, and so are the
    other non-objects ``false``, ``0``, and ``""``. A later valid
    version-11 GET has to apply.
    """
    client = _client()
    hoods = await client.async_setup()
    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/update/accepted",
        {
            "state": {"reported": {"light": 1, "usegreasefiltertime": 642}},
            "version": 10,
        },
    )

    bad_payloads = (
        {"state": None},
        {},
        {"state": {"reported": None}},
        {"state": False},
        {"state": 0},
        {"state": ""},
        {"state": {"reported": False}},
        {"state": {"reported": 0}},
        {"state": {"reported": ""}},
    )
    version = 12
    for payload in bad_payloads:
        for leaf in ("get/accepted", "update/accepted"):
            client._handle_message(
                hoods[0],
                f"$aws/things/{THING}/shadow/{leaf}",
                {**payload, "version": version},
            )
            version += 1

    assert hoods[0].state.light == 1
    assert hoods[0].state.use_grease_filter_time == 642
    assert hoods[0]._shadow_version == 10
    assert hoods[0]._snapshot_version is None

    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/get/accepted",
        {
            "state": {"reported": {"light": 4, "usegreasefiltertime": 700}},
            "version": 11,
        },
    )
    assert hoods[0].state.light == 4
    assert hoods[0].state.use_grease_filter_time == 700
    assert hoods[0]._shadow_version == 11


async def test_a_rejected_update_rereads_state_without_logging_the_thing(wired, caplog):
    """Tests that update/rejected schedules a GET and get/rejected does not.

    The log is the topic leaf only. The thing name identifies a home.
    """
    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()
    wired["shadow"].request_state.reset_mock()

    with caplog.at_level(logging.DEBUG, logger="pyzephyrconnect.client"):
        client._handle_message(
            hoods[0],
            f"$aws/things/{THING}/shadow/update/rejected",
            {"message": "rejected", "thingName": THING},
        )
        await asyncio.sleep(0)

    wired["shadow"].request_state.assert_awaited_once()
    assert THING not in caplog.text

    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/get/rejected",
        {"code": 404},
    )
    await asyncio.sleep(0)
    wired["shadow"].request_state.assert_awaited_once()


async def test_a_refused_write_does_not_update_state(wired):
    """Tests that ZephyrNotConnectedError leaves the cache alone."""
    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()
    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/get/accepted",
        {"state": {"reported": {"light": 0, "usegreasefiltertime": 642}}},
    )
    before = hoods[0].state
    seen = []
    hoods[0].add_listener(seen.append)
    wired["shadow"].publish_state = AsyncMock(
        side_effect=ZephyrNotConnectedError("hood is not connected")
    )

    with pytest.raises(ZephyrNotConnectedError):
        await hoods[0].async_set_light(1)

    assert hoods[0].state is before
    assert seen == []


async def test_a_delta_notifies_nobody_and_logs_no_identifier(wired, caplog):
    """Tests that a delta notifies nobody and logs no identifier.

    Folding a delta into the cache previously made the probe report a
    change the device had not - and might never - make, which disguised the
    state.desired/state.reported root-cause bug for a full debugging cycle.
    Payload shape captured from the real device.
    """
    client = _client()
    hoods = await client.async_setup()
    client._handle_message(
        hoods[0],
        f"$aws/things/{THING}/shadow/get/accepted",
        {"state": {"reported": {"fan": 0, "light": 0}}},
    )
    before = hoods[0].state

    seen = []
    hoods[0].add_listener(seen.append)
    with caplog.at_level(logging.DEBUG, logger="pyzephyrconnect.client"):
        client._handle_message(
            hoods[0],
            f"$aws/things/{THING}/shadow/update/delta",
            {"state": {"light": 1, "power": 1}, "version": 302688},
        )

    assert hoods[0].state is before
    assert seen == []
    # Leaf-only diagnostics: the full topic embeds the thing name.
    assert THING not in caplog.text


async def test_a_non_dict_payload_is_ignored(wired, caplog):
    """Tests that a non-dict payload is ignored.

    Valid JSON that is not an object (e.g. the literal `null`, which
    json.loads returns as None) must not raise, must not change state, and
    must not notify listeners. _on_message only catches parse errors, so
    this shape still reaches here.
    """
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
    """Tests that a rejection never logs the payload.

    A rejection can echo back the fields it rejected, including
    identifiers. Only the topic's leaf segment is safe to log.
    """
    client = _client()
    hoods = await client.async_setup()
    before = hoods[0].state

    with caplog.at_level(logging.WARNING, logger="pyzephyrconnect.client"):
        client._handle_message(
            hoods[0],
            f"$aws/things/{THING}/shadow/update/rejected",
            {"message": "rejected", "location": "40.0,-105.0"},
        )

    assert hoods[0].state is before
    assert "40.0" not in caplog.text
    assert THING not in caplog.text
    assert "rejected" in caplog.text


async def test_the_message_closure_is_pinned_to_its_own_hood(wired):
    """Tests that the message closure is pinned to its own hood.

    _make_shadow's on_message closes over the SPECIFIC hood it was built
    for. A lookup like `next(iter(self._hoods.values()))` instead of the
    closed-over `hood` would happen to work with exactly one hood and then
    silently misattribute every message once a second hood exists.
    """
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
    """Tests that a malformed message does not escape onto the loop.

    _handle_message runs via loop.call_soon_threadsafe. An escaped
    exception hits asyncio's default handler, which logs the callback and
    its arguments - the topic and the raw payload - at ERROR.
    """
    client = _client()
    hoods = await client.async_setup()
    hoods[0].handle_state = MagicMock(side_effect=RuntimeError("boom"))

    with caplog.at_level(logging.ERROR, logger="pyzephyrconnect.client"):
        client._handle_message(
            hoods[0],
            f"$aws/things/{THING}/shadow/get/accepted",
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
    """Tests that poll strips personal data too.

    Same flat payload as setup, same filter - and this path runs on every
    coordinator tick while push is down.
    """
    hoods = await _client().async_setup()
    state = await hoods[0].async_poll()
    for key in ("thingName", "SN", "MAC", "location"):
        assert key not in state.raw


# -- the supervisor ---------------------------------------------------


async def test_supervisor_rebuilds_the_socket_before_credentials_expire(wired):
    """Tests that the supervisor rebuilds the socket before expiry.

    A presigned URL cannot outlive its signature. Without this, push dies
    after an hour and paho retries a dead URL forever.
    """
    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()

    wired["auth"].credentials_expired = True
    await client._refresh_once()

    assert wired["shadow"].disconnect.await_count >= 1
    assert wired["shadow"].connect.await_count >= 2
    assert wired["shadow"].request_state.await_count >= 2


async def test_refresh_does_not_ask_a_method_that_renews_as_a_side_effect(wired):
    """Tests that the refresh keys on the non-mutating expiry property.

    async_get_credentials() renews when expired, so testing ITS result
    always reports "not expired" and the socket never gets rebuilt. The
    supervisor must ask the non-mutating property instead.
    """
    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()

    wired["auth"].credentials_expired = False
    assert await client._refresh_once() is False
    assert wired["shadow"].connect.await_count == 1  # no rebuild

    wired["auth"].credentials_expired = True
    assert await client._refresh_once() is True
    assert wired["shadow"].connect.await_count == 2  # rebuilt


async def test_a_rest_driven_refresh_still_rebuilds_the_socket(wired):
    """Expiry alone lies, and this is the scenario where it does.

    ZephyrApi calls async_get_tokens() on every REST request, and
    CredentialsAuth._acquire replaces the cached AWS credentials as a side
    effect - so an ordinary poll can refresh them minutes before the
    supervisor ticks. A rebuild keyed on `credentials_expired` then sees a
    perfectly fresh cache and skips, while the live socket still carries a
    signature presigned against the credentials that were just discarded.
    AWS IoT drops that session at the OLD expiry and paho retries the dead
    URL until the NEXT one, ~50 minutes of silent push loss.
    """
    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()
    assert wired["shadow"].connect.await_count == 1

    # A REST call refreshed the credentials. Nothing about the cache looks
    # wrong - only the generation records that the socket no longer matches.
    wired["auth"].credentials_generation += 1
    wired["auth"].credentials_expired = False

    assert await client._refresh_once() is True
    assert wired["shadow"].disconnect.await_count == 1
    assert wired["shadow"].connect.await_count == 2
    assert wired["shadow"].request_state.await_count == 2

    # The reconnect re-presigned under the current generation, so the next
    # tick must leave a healthy socket alone rather than churning it.
    assert await client._refresh_once() is False
    assert wired["shadow"].connect.await_count == 2
    assert wired["shadow"].disconnect.await_count == 1


async def test_a_hood_started_after_the_refresh_is_not_rebuilt(wired):
    """The generation is recorded per hood, not per client.

    Hoods start at different moments - a second hood added while the first
    is running presigns under whatever credentials are current then. Keying
    the rebuild on a client-wide "credentials changed" flag would drop that
    healthy socket for nothing.
    """
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
    await hoods[0].async_start()  # presigned under generation N
    wired["auth"].credentials_generation += 1
    await hoods[1].async_start()  # presigns under the new one

    reconnected: list[str] = []

    async def record_first():
        """Record a reconnect of the first hood."""
        reconnected.append("first")

    async def record_second():
        """Record a reconnect of the second hood."""
        reconnected.append("second")

    hoods[0].async_reconnect = record_first
    hoods[1].async_reconnect = record_second

    assert await client._refresh_once() is True
    assert reconnected == ["first"]


async def test_a_generation_mismatch_does_not_start_a_hood_that_never_ran(wired):
    """needs_represign requires a live socket, not just consumer intent.

    The supervisor loops over every hood on the account, so a credential
    change must not bring up push for a hood the consumer never started -
    the same guard async_reconnect carries, made explicit one level up so
    the decision does not depend on a no-op deeper down.
    """
    client = _client()
    hoods = await client.async_setup()  # discovered, never started
    wired["auth"].credentials_generation += 1

    assert hoods[0].needs_represign(wired["auth"].credentials_generation) is False
    assert await client._refresh_once() is False
    assert wired["shadow"].connect.await_count == 0


async def test_refresh_reopens_a_wanted_hood_whose_socket_is_gone(wired):
    """Tests that refresh reopens a wanted hood whose socket is gone.

    Recovery: a hood whose rebuild failed last cycle is still wanted, and
    async_ensure_running is what brings it back on the next tick.
    """
    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()
    # Simulate a rebuild that died halfway: intent survives, socket does not.
    await hoods[0]._stop_for_supervisor()

    await client._refresh_once()

    assert wired["shadow"].connect.await_count == 2


async def test_one_hoods_failure_does_not_strand_the_others(wired):
    """Tests that one hood's failure does not strand the others.

    Per-hood try/except: one transient connect failure must not abort the
    loop and leave later hoods on an expiring signature.
    """
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
    # Started, so both hoods hold a socket presigned under the CURRENT
    # generation - the refresh below moves it and puts both in the rebuild
    # branch. Without live sockets they would take the recovery branch
    # instead and this test would pass vacuously.
    await hoods[0].async_start()
    await hoods[1].async_start()
    wired["auth"].credentials_expired = True

    calls: list[str] = []

    async def boom():
        """Record the call and raise a transient OSError."""
        calls.append("first")
        raise OSError("transient DNS failure")

    async def ok():
        """Record a successful reconnect."""
        calls.append("second")

    hoods[0].async_reconnect = boom
    hoods[1].async_reconnect = ok

    assert await client._refresh_once() is True
    assert calls == ["first", "second"]


async def test_a_terminal_error_from_one_hood_is_not_swallowed(wired):
    """Tests that a terminal error from one hood is not swallowed.

    ZephyrPolicyError and ZephyrAuthError must reach _supervise so it can
    stop; swallowing them here is a hot loop that can never succeed.
    """
    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()

    async def denied():
        """Raise a terminal ZephyrPolicyError."""
        raise ZephyrPolicyError("denied")

    hoods[0].async_ensure_running = denied
    with pytest.raises(ZephyrPolicyError):
        await client._refresh_once()


async def test_a_transient_failure_does_not_end_supervision(wired):
    """Tests that a transient failure does not end supervision.

    The failure mode this guards against is not a logged error - it is
    push dying silently an hour later.
    """
    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()

    calls = []

    async def flaky():
        """Fail with a transient OSError on the first tick only."""
        calls.append(1)
        if len(calls) == 1:
            raise OSError("transient DNS failure")
        return False

    client._refresh_once = flaky
    monkeypatch_interval(client, 0)  # see helper in this module
    await _run_supervisor_ticks(client, 2)

    assert len(calls) == 2  # kept going after the OSError


async def test_supervisor_stops_on_a_policy_error(wired):
    """Tests that the supervisor stops on a policy error.

    A denied subscribe closes the whole connection (PROTOCOL.md section 6).
    Retrying that forever is a hot loop that can never succeed.
    """
    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()
    # Non-vacuous setup: mark the hood connected BEFORE the terminal error,
    # so the final assertion proves the terminal branch's hood-stop actually
    # flipped the derived property rather than it never having been True.
    hoods[0].handle_connection_change(True)
    assert client.connected is True

    async def denied():
        """Raise a terminal ZephyrPolicyError to end supervision."""
        raise ZephyrPolicyError("denied")

    client._refresh_once = denied
    monkeypatch_interval(client, 0)
    await _run_supervisor_ticks(client, 3)

    assert isinstance(client._supervisor_error, ZephyrPolicyError)
    assert client.connected is False


async def test_the_terminal_stop_preserves_consumer_intent(wired):
    """Tests that the terminal stop preserves consumer intent.

    Stopping the hoods must not clear _should_run: a reauth that builds a
    new client is unaffected, and the recovery path needs the intent.
    """
    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()

    async def revoked():
        """Raise a terminal ZephyrAuthError."""
        raise ZephyrAuthError("refresh token revoked")

    client._refresh_once = revoked
    monkeypatch_interval(client, 0)
    await _run_supervisor_ticks(client, 2)

    assert isinstance(client._supervisor_error, ZephyrAuthError)
    assert hoods[0]._should_run is True
    wired["shadow"].disconnect.assert_awaited()


async def test_the_terminal_log_names_the_type_not_the_message(wired, caplog):
    """Tests that the terminal log names the type, not the message.

    ZephyrPolicyError text may name the policy, and identifiers do not
    belong at ERROR.
    """
    client = _client()
    await client.async_setup()

    async def denied():
        """Raise a ZephyrPolicyError whose message names the thing."""
        raise ZephyrPolicyError(f"denied for {THING}")

    client._refresh_once = denied
    monkeypatch_interval(client, 0)
    with caplog.at_level(logging.ERROR, logger="pyzephyrconnect.client"):
        await _run_supervisor_ticks(client, 2)

    assert "ZephyrPolicyError" in caplog.text
    assert THING not in caplog.text


async def test_a_terminal_error_reaches_the_consumer_via_poll(wired):
    """Tests that a terminal error reaches the consumer via poll.

    The supervisor runs detached, so its failure has to surface somewhere
    the consumer already looks - otherwise the hood just stops updating.
    """
    client = _client()
    hoods = await client.async_setup()
    client._supervisor_error = ZephyrAuthError("refresh token revoked")

    with pytest.raises(ZephyrAuthError):
        await hoods[0].async_poll()


async def test_polling_a_terminal_error_raises_a_fresh_instance_each_time(wired):
    """Tests that each poll of a terminal error raises a fresh instance.

    `raise type(err)(*err.args) from err` must build a NEW exception on
    every poll. Re-raising the stored object itself would append frames to
    ITS __traceback__ on every call - unbounded while a consumer keeps
    polling through a terminal error that never clears.
    """
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


async def test_a_supervisor_with_nothing_to_supervise_retires_and_re_arms(wired):
    """A supervisor with no started hoods must end, not tick forever.

    The running task holds this client strongly through every sleep, so an
    abandoned client - Home Assistant raises ConfigEntryNotReady and builds a
    fresh one - would otherwise stay alive for the process lifetime, burning
    an hourly credential refresh and, worse, reviving its hoods onto MQTT
    client IDs identical to the replacement client's.
    """
    client = _client()
    hoods = await client.async_setup()
    monkeypatch_interval(client, 0)

    # The consumer-facing start fails, so Hood.async_start rolls its intent
    # back and the supervisor _make_shadow just armed has nothing to watch.
    healthy_connect = wired["shadow"].connect.side_effect
    wired["shadow"].connect.side_effect = ZephyrTransportError("boom")
    with pytest.raises(ZephyrTransportError):
        await hoods[0].async_start()

    supervisor = client._supervisor
    assert supervisor is not None
    assert hoods[0]._should_run is False

    for _ in range(5):
        await asyncio.sleep(0)

    assert supervisor.done()
    assert supervisor.exception() is None  # retired, did not crash

    # Re-armed by the next start: _ensure_supervisor counts a DONE task as
    # not running, so nothing has to remember to restart it.
    wired["shadow"].connect.side_effect = healthy_connect
    await hoods[0].async_start()

    assert client._supervisor is not supervisor
    assert not client._supervisor.done()


async def test_stopping_the_last_hood_retires_the_supervisor_too(wired):
    """Tests that stopping the last hood retires the supervisor too.

    The other way to end up with nothing to supervise. `hood.async_stop()`
    deliberately does not cancel the supervisor - only `client.async_stop()`
    does - so the supervisor has to notice for itself.
    """
    client = _client()
    hoods = await client.async_setup()
    monkeypatch_interval(client, 0)
    await hoods[0].async_start()

    supervisor = client._supervisor
    assert supervisor is not None
    for _ in range(3):
        await asyncio.sleep(0)
    assert not supervisor.done()  # still wanted

    await hoods[0].async_stop()
    for _ in range(5):
        await asyncio.sleep(0)

    assert supervisor.done()
    assert supervisor.exception() is None


async def test_a_socketless_wanted_hood_recovers_instead_of_reconnecting(wired):
    """Tests that a socketless wanted hood recovers instead of reconnecting.

    needs_represign requires a live socket, not just intent plus a stale
    generation.

    A hood the supervisor stopped after a terminal error keeps its intent and
    loses its shadow, and its recorded generation stays frozen at whatever it
    last presigned under - so a later credential change makes the generations
    mismatch on a hood that has no socket to represign. That must take the
    recovery branch (async_ensure_running), not async_reconnect, whose _stop
    half has nothing to tear down and whose rebuilt-count would lie.
    """
    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()
    await hoods[0]._stop_for_supervisor()  # intent survives, socket gone

    assert hoods[0]._should_run is True
    assert hoods[0]._shadow is None

    wired["auth"].credentials_generation += 1
    current = wired["auth"].credentials_generation
    assert hoods[0].needs_represign(current) is False

    reconnected: list[str] = []

    async def record_reconnect():
        """Record that the rebuild branch was taken."""
        reconnected.append("reconnect")

    hoods[0].async_reconnect = record_reconnect

    assert await client._refresh_once() is False  # not the rebuild branch
    assert reconnected == []
    assert wired["shadow"].connect.await_count == 2  # recovery brought it back


async def test_a_running_supervisor_is_not_replaced(wired):
    """Tests that _ensure_supervisor keeps an already running task."""
    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()
    first = client._supervisor
    assert first is not None

    client._ensure_supervisor()
    assert client._supervisor is first


async def test_a_finished_supervisor_counts_as_not_running(wired):
    """Tests that a finished supervisor counts as not running.

    The terminal branch exits via `return`, leaving _supervisor holding a
    DONE task. A naive `is not None` check would then never restart
    supervision after a reauth on the same client - and the stale terminal
    error would make every later poll raise.
    """
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
    """Tests that async_stop cancels and awaits the supervisor.

    Cancelling without awaiting can leave a hood halfway through
    async_reconnect() with no socket and no supervisor, and lets the task be
    collected with an unretrieved CancelledError.
    """
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
    """Tests that async_stop isolates one hood's teardown failure.

    Each hood owns its own socket and paho thread, so one hood's
    disconnect blowing up must not strand the other - async_stop's per-hood
    try/except must still tear down (and clear _should_run on) hood B even
    though hood A's disconnect raised.
    """
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

    await client.async_stop()  # must not raise

    shadow_a.disconnect.assert_awaited_once()
    shadow_b.disconnect.assert_awaited_once()
    assert hoods[0]._should_run is False
    assert hoods[1]._should_run is False


async def test_async_stop_tears_down_every_hood_before_honouring_a_cancel(wired):
    """Tests that async_stop tears down all hoods before honouring a cancel.

    Shutdown was asymmetric about cancellation: a cancellation arriving
    during hood.async_stop() escaped the `except Exception` and stranded
    every remaining hood - a leaked paho network thread each. This is the
    mid-loop half of the funnel (the supervisor-await half is pinned by
    test_async_stop_honours_a_cancel_landing_on_the_supervisor_await); both
    set the same flag, so each hood is torn down and only then is the
    cancellation re-raised so the caller that asked for it still sees it.
    """
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

    shadow_b.disconnect.assert_awaited_once()  # not stranded
    assert hoods[1]._should_run is False
    assert client._supervisor is None


async def test_async_stop_suppresses_a_supervisor_that_raised(wired):
    """Tests that async_stop suppresses a supervisor that raised.

    The `except Exception` around awaiting the supervisor must swallow
    whatever ordinary exception it finished with, not just CancelledError -
    letting it out would skip the hood-stopping loop entirely, leaking a
    paho thread per hood, and leave `_supervisor` set so
    `_ensure_supervisor` never restarts it.
    """
    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()

    async def boom():
        """Raise RuntimeError to simulate a crashed supervisor."""
        raise RuntimeError("supervisor died")

    task = asyncio.create_task(boom())
    await asyncio.sleep(0)
    assert task.done()
    client._supervisor = task

    await client.async_stop()  # must not raise

    assert client._supervisor is None
    assert hoods[0]._should_run is False
    wired["shadow"].disconnect.assert_awaited()


async def _stubborn_supervisor() -> None:
    """A supervisor that survives its first cancel long enough to be caught.

    `async_stop` cancels the supervisor and awaits it. If the task finished
    instantly the await would never suspend, and a cancel aimed at THIS
    method could not land there - the very case under test. Absorbing the
    first CancelledError and sleeping before re-raising holds the await
    open for one real tick, which is the window the tests below aim at.
    """
    try:
        await asyncio.sleep(3600)
    except asyncio.CancelledError:
        await asyncio.sleep(0.05)
        raise


async def test_async_stop_honours_a_cancel_landing_on_the_supervisor_await(
    wired,
):
    """Tests that a cancel landing on the supervisor await is honoured.

    A caller's cancel delivered DURING `await self._supervisor` must not
    be swallowed. Python never re-delivers a caught cancellation, so the
    hood-loop funnel cannot rescue this one: blanket suppression here let
    async_stop return normally while the caller (wait_for, a task group)
    believed it had cancelled - the cancellation contract, silently broken.
    Teardown still comes first: every hood is stopped, and only then is the
    CancelledError re-raised.
    """
    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()
    client._supervisor.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await client._supervisor
    client._supervisor = asyncio.create_task(_stubborn_supervisor())
    await asyncio.sleep(0)  # let it reach its sleep

    stop_task = asyncio.create_task(client.async_stop())
    for _ in range(2):  # reach the supervisor await
        await asyncio.sleep(0)
    stop_task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await stop_task

    wired["shadow"].disconnect.assert_awaited()  # torn down before it flew
    assert hoods[0]._should_run is False
    assert client._supervisor is None


async def test_async_stop_does_not_mistake_its_own_cancel_for_the_callers(
    wired,
):
    """Tests that async_stop does not mistake its own cancel for the caller's.

    The discrimination pin. `async_stop` cancels the supervisor itself,
    so `await self._supervisor` raises CancelledError on the ordinary path
    too - the same exception type as the case above. Only
    `current_task().cancelling()` separates them, and reading it wrong here
    would turn every clean shutdown into a spurious CancelledError at the
    consumer.
    """
    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()
    client._supervisor.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await client._supervisor
    client._supervisor = asyncio.create_task(_stubborn_supervisor())
    await asyncio.sleep(0)

    await client.async_stop()  # must not raise

    assert client._supervisor is None
    assert hoods[0]._should_run is False
    wired["shadow"].disconnect.assert_awaited()


async def test_async_stop_is_safe_before_anything_started(wired):
    """Tests that async_stop is safe before any hood has started."""
    client = _client()
    await client.async_setup()
    await client.async_stop()


async def test_the_supervisor_interval_defaults_to_the_constant(wired):
    """Tests that the supervisor interval defaults to the constant.

    An attribute, not the bare constant, only so tests can drive it -
    production must still tick once a minute.
    """
    from pyzephyrconnect import const

    assert _client()._supervisor_interval == const.SUPERVISOR_INTERVAL_SECONDS
