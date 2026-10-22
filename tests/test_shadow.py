"""Tests for pyzephyrconnect.shadow."""

import asyncio
import json
import logging
import ssl
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from pyzephyrconnect import shadow as shadow_module
from pyzephyrconnect.auth import Credentials
from pyzephyrconnect.exceptions import (
    ZephyrNotConnectedError,
    ZephyrPolicyError,
    ZephyrTransportError,
    ZephyrWriteError,
)
from pyzephyrconnect.hood import Hood
from pyzephyrconnect.models import HoodCapabilities
from pyzephyrconnect.shadow import ShadowClient, ShadowTopics

FIXTURES = Path(__file__).parent / "fixtures"

THING = "aaaaaaaabbbbbbbbccccccccddddddddeeeeeeee"
CREDS = Credentials("k", "s", "t", datetime.now(UTC) + timedelta(hours=1))


def test_topics_are_built_from_the_thing_name():
    """Tests that the shadow topics embed the thing name."""
    t = ShadowTopics(THING)
    assert t.get == f"$aws/things/{THING}/shadow/get"
    assert t.update == f"$aws/things/{THING}/shadow/update"
    assert t.update_delta == f"$aws/things/{THING}/shadow/update/delta"


def test_subscription_set_covers_reads_and_rejections():
    """Tests that subscriptions cover reads and rejections, not writes."""
    subs = ShadowTopics(THING).subscriptions
    assert f"$aws/things/{THING}/shadow/get/accepted" in subs
    assert f"$aws/things/{THING}/shadow/update/delta" in subs
    assert f"$aws/things/{THING}/shadow/update/rejected" in subs
    # The write topic itself is published to, never subscribed.
    assert f"$aws/things/{THING}/shadow/update" not in subs


@pytest.fixture
def fake_paho(monkeypatch):
    """Mocked paho client patched into the shadow module."""
    client = MagicMock()
    client.subscribe.return_value = (0, 1)
    client.publish.return_value = MagicMock(rc=0)

    def fire_connack(*args, **kwargs):
        """Simulate CONNACK and grant every shadow subscription."""
        # Real paho invokes on_connect from its network thread once CONNACK
        # arrives. Without this the mock never fires it, connect() blocks on
        # its event and every connect test fails on a 15s timeout.
        client.on_connect(client, None, {}, 0, None)
        # _on_connect subscribes to all 6 shadow topics. Grant them all by
        # default so tests that don't care about subscription behavior still
        # connect successfully instead of hanging on _subscribed.wait().
        granted = MagicMock()
        granted.is_failure = False
        for _ in range(len(ShadowTopics(THING).subscriptions)):
            client.on_subscribe(client, None, 1, [granted], None)

    client.connect_async.side_effect = fire_connack
    monkeypatch.setattr(shadow_module.mqtt, "Client", MagicMock(return_value=client))
    return client


async def _default_provider():
    """Provide the static test credentials."""
    return CREDS


def _make(on_message=None):
    """Build a ShadowClient wired with mock callbacks."""
    return ShadowClient(
        THING, f"{THING}-py", on_message or MagicMock(), MagicMock(), _default_provider
    )


def _shadow(credentials_provider=_default_provider, **kwargs):
    """A ShadowClient on the new 5-argument constructor."""
    return ShadowClient(
        THING,
        "us-west-2:abc-py",
        lambda topic, payload: None,
        lambda connected: None,
        credentials_provider,
        **kwargs,
    )


async def _connect(shadow):
    """Drive connect() to completion against the fake paho client.

    fake_paho's connect_async side_effect fires on_connect/on_subscribe
    synchronously, but call_soon_threadsafe only schedules those callbacks -
    they land once connect() itself yields to the loop (inside its own
    asyncio.wait_for calls). So a plain await is enough; no separate
    task/simulate step is needed against this fixture.
    """
    await shadow.connect(timeout=1)


async def test_connect_uses_a_presigned_websocket_path(fake_paho):
    """Tests that connect sets a presigned SigV4 websocket path."""
    sc = _make()
    await _connect(sc)

    path = fake_paho.ws_set_options.call_args.kwargs["path"]
    assert path.startswith("/mqtt?X-Amz-Algorithm=AWS4-HMAC-SHA256")
    assert "X-Amz-Signature=" in path
    assert "X-Amz-Security-Token=" in path
    fake_paho.tls_set_context.assert_called_once()


async def test_connect_uses_the_suffixed_client_id(fake_paho):
    """Tests that connect builds the client with the suffixed ID."""
    await _connect(_make())
    assert shadow_module.mqtt.Client.call_args.kwargs["client_id"] == f"{THING}-py"


async def test_connect_targets_port_443(fake_paho):
    """Tests that connect_async targets port 443."""
    await _connect(_make())
    args = fake_paho.connect_async.call_args.args
    assert args[1] == 443


async def test_connecting_log_omits_the_client_id_and_thing_name(fake_paho, caplog):
    """Tests that the connect log omits client ID and thing name.

    Pins the scrubbed DEBUG connect log: it may name the endpoint, but
    never the per-connection client ID (identity + thing name) or the bare
    thing name - both are personal data, and a careless future edit that
    logs `self._client_id` directly must fail this test.
    """
    sc = _shadow()
    with caplog.at_level(logging.DEBUG, logger="pyzephyrconnect.shadow"):
        await _connect(sc)

    assert "connecting to" in caplog.text
    assert "us-west-2:abc-py" not in caplog.text
    assert THING not in caplog.text


async def test_denied_subscribe_surfaces_as_a_policy_error_from_connect(fake_paho):
    """Tests that a denied subscribe raises ZephyrPolicyError.

    The denial must reach the caller through connect() - not by raising
    inside paho's callback, which would silently kill the network thread
    instead. See the module docstring and _on_subscribe's docstring.
    """
    denied = MagicMock()
    denied.is_failure = True

    def fire_connack_then_deny_subscribe(*args, **kwargs):
        """Simulate CONNACK and then deny every subscription."""
        fake_paho.on_connect(fake_paho, None, {}, 0, None)
        # _on_connect subscribes to 6 topics; deny all of them.
        for _ in range(6):
            fake_paho.on_subscribe(fake_paho, None, 1, [denied], None)

    fake_paho.connect_async.side_effect = fire_connack_then_deny_subscribe

    with pytest.raises(ZephyrPolicyError, match="attach"):
        await _connect(_make())


async def test_granted_subscribes_let_connect_succeed(fake_paho):
    """Tests that connect succeeds when all subscribes are granted."""
    granted = MagicMock()
    granted.is_failure = False

    def fire_connack_then_grant_subscribes(*args, **kwargs):
        """Simulate CONNACK and grant every subscription."""
        fake_paho.on_connect(fake_paho, None, {}, 0, None)
        for _ in range(6):
            fake_paho.on_subscribe(fake_paho, None, 1, [granted], None)

    fake_paho.connect_async.side_effect = fire_connack_then_grant_subscribes

    await _connect(_make())  # must not raise


async def test_request_state_publishes_an_empty_get(fake_paho):
    """Tests that request_state publishes an empty GET payload."""
    sc = _make()
    await _connect(sc)
    await sc.request_state()

    topic, payload = fake_paho.publish.call_args.args[:2]
    assert topic == f"$aws/things/{THING}/shadow/get"
    assert json.loads(payload) == {}


async def test_publish_state_wraps_fields_in_state_reported(fake_paho):
    """Tests that publish_state wraps fields in state.reported.

    This device only acts on state.reported - see the module-level note
    in shadow.py. Publishing state.desired is accepted by AWS and silently
    ignored by the hardware, which was the root cause of a real bug; the
    absence of "desired" anywhere in the payload is the regression guard.
    """
    sc = _make()
    await _connect(sc)
    await sc.publish_state({"light": 1})

    topic, payload = fake_paho.publish.call_args.args[:2]
    assert topic == f"$aws/things/{THING}/shadow/update"
    assert json.loads(payload) == {"state": {"reported": {"light": 1}}}
    assert "desired" not in payload
    assert fake_paho.publish.call_args.kwargs["qos"] == 1


async def test_publish_state_rejects_an_empty_payload(fake_paho):
    """Tests that publish_state raises ZephyrWriteError on an empty dict."""
    sc = _make()
    await _connect(sc)
    with pytest.raises(ZephyrWriteError):
        await sc.publish_state({})


async def test_reconnect_uses_capped_exponential_backoff(fake_paho):
    """Tests that reconnect uses capped exponential backoff.

    paho retries indefinitely at a fixed short interval by default. An
    expired credential would otherwise become a hot reconnect loop against
    AWS IoT.
    """
    await _connect(_make())
    kwargs = fake_paho.reconnect_delay_set.call_args.kwargs
    assert kwargs["min_delay"] >= 1
    assert kwargs["max_delay"] <= 300


async def test_incoming_message_is_dispatched_with_parsed_json(fake_paho):
    """Tests that an incoming message is dispatched as parsed JSON.

    Callbacks arrive on paho's thread and are marshalled onto the loop
    with call_soon_threadsafe, so the dispatch needs a loop tick to land.
    """
    received = []
    sc = _make(on_message=lambda topic, payload: received.append((topic, payload)))
    await _connect(sc)

    msg = MagicMock()
    msg.topic = f"$aws/things/{THING}/shadow/get/accepted"
    msg.payload = json.dumps({"state": {"reported": {"fan": 2}}}).encode()
    sc._on_message(fake_paho, None, msg)
    await asyncio.sleep(0)

    assert received[0][0].endswith("get/accepted")
    assert received[0][1]["state"]["reported"]["fan"] == 2


async def test_malformed_payload_is_dropped_without_dispatching(fake_paho):
    """Tests that a malformed payload is dropped without dispatch.

    A parse error inside a paho callback thread would kill the network
    loop and silently stop all updates. The payload must be dropped, and the
    consumer must not be handed anything.
    """
    received = []
    sc = _make(on_message=lambda topic, payload: received.append((topic, payload)))
    await _connect(sc)

    msg = MagicMock()
    msg.topic = f"$aws/things/{THING}/shadow/get/accepted"
    msg.payload = b"not json"
    sc._on_message(fake_paho, None, msg)
    await asyncio.sleep(0)

    assert received == []


async def test_malformed_payload_warning_omits_the_thing_name(fake_paho, caplog):
    """Tests that the malformed-payload warning omits the thing name.

    The full topic ($aws/things/<thingName>/shadow/...) contains personal
    data. Only the topic leaf (accepted/delta/rejected) may be logged.
    """
    sc = _make()
    await _connect(sc)

    msg = MagicMock()
    msg.topic = f"$aws/things/{THING}/shadow/get/accepted"
    msg.payload = b"not json"
    with caplog.at_level("WARNING"):
        sc._on_message(fake_paho, None, msg)

    assert THING not in caplog.text
    assert "accepted" in caplog.text


async def test_publish_failure_raises_transport_error_without_the_thing_name(
    fake_paho,
):
    """Tests that a failed publish raises without the thing name.

    A failed publish must not leak the full thing-bearing topic into the
    exception message.
    """
    fake_paho.publish.return_value = MagicMock(rc=1)
    sc = _make()
    await _connect(sc)

    with pytest.raises(shadow_module.ZephyrTransportError) as excinfo:
        await sc.request_state()

    assert THING not in str(excinfo.value)
    assert "get" in str(excinfo.value)


def test_dispatch_on_a_closed_loop_returns_without_raising():
    """Tests that dispatch on a closed loop returns without raising.

    paho's network thread must never see a RuntimeError from a
    torn-down/closed event loop - that would kill the thread just like an
    uncaught exception in a callback would.
    """
    sc = _make()
    loop = asyncio.new_event_loop()
    loop.close()
    sc._loop = loop

    sc._dispatch(MagicMock())  # must not raise


async def test_connect_asks_the_provider_for_fresh_credentials(fake_paho):
    """Tests that every connect asks the provider for credentials.

    A presigned URL cannot outlive its signature. Every connect attempt
    must re-presign, or a reconnect after expiry retries a dead URL.
    """
    calls = []

    async def provider():
        """Credentials provider that counts its invocations."""
        calls.append(1)
        return Credentials("k", "s", "t", datetime.now(UTC) + timedelta(hours=1))

    shadow = _shadow(credentials_provider=provider)
    await _connect(shadow)
    await shadow.disconnect()
    await _connect(shadow)

    assert len(calls) == 2


async def test_tls_context_is_not_built_on_the_event_loop(fake_paho):
    """Tests that a prebuilt TLS context is handed to paho.

    paho's tls_set() calls load_default_certs() inline, which Home
    Assistant reports as a blocking call on the loop. Hand it a finished
    context instead.
    """
    shadow = _shadow()
    await _connect(shadow)

    client = shadow._client
    client.tls_set.assert_not_called()
    client.tls_set_context.assert_called_once()
    ctx = client.tls_set_context.call_args.args[0]
    # Design Risks 10-11: a default context - CERT_REQUIRED, hostname
    # checking on, and NOT the TWCA-augmented REST context.
    assert (
        ctx.verify_mode is ssl.VERIFY_DEFAULT or ctx.verify_mode.name == "CERT_REQUIRED"
    )
    assert ctx.check_hostname is True


async def test_publish_empty_state_raises_a_library_error(fake_paho):
    """ValueError escapes a consumer catching ZephyrError."""
    shadow = _shadow()
    await _connect(shadow)
    with pytest.raises(ZephyrWriteError):
        await shadow.publish_state({})


async def test_teardown_disconnects_before_stopping_the_network_thread(fake_paho):
    """Tests that disconnect precedes loop_stop in teardown.

    disconnect() BEFORE loop_stop(): the network thread is what writes the
    DISCONNECT packet, so stopping it first would queue the packet and never
    send it.
    """
    shadow = _shadow()
    await _connect(shadow)
    await shadow.disconnect()

    calls = [c for c in fake_paho.method_calls if c[0] in ("disconnect", "loop_stop")]
    names = [c[0] for c in calls]
    assert names.index("disconnect") < names.index("loop_stop")


def test_teardown_stops_the_network_thread_even_if_disconnect_raises():
    """Tests that loop_stop still runs when disconnect raises.

    loop_stop() is what JOINS paho's network thread. Skipping it because
    disconnect() raised leaks the very thread this function exists to reap -
    hence the try/finally rather than two plain statements.
    """
    client = MagicMock()
    client.disconnect.side_effect = OSError("socket already gone")

    with pytest.raises(OSError):
        ShadowClient._teardown(client)

    client.loop_stop.assert_called_once()


async def test_cancelled_handshake_tears_down_the_paho_client(fake_paho):
    """Tests that a cancelled handshake still tears down the client.

    A cancellation arriving mid-handshake must still tear down the paho
    client and its network thread via the shielded teardown in disconnect()
    - not leave it dangling because the outer connect() task was cancelled.
    """
    fake_paho.connect_async.side_effect = None  # nothing fires; connect blocks

    shadow = _shadow()
    task = asyncio.create_task(shadow.connect(timeout=30))
    # connect() awaits asyncio.to_thread() (for the TLS context) before
    # constructing the paho client; that resolves on a real background
    # thread, which needs actual wall-clock time to land - not just a
    # handful of bare sleep(0) yields, which burn microseconds and can
    # exhaust their budget before the worker thread ever runs on a loaded
    # CI runner. Poll with a real deadline until the client exists so the
    # cancel below lands mid handshake (awaiting _connected.wait()) rather
    # than before self._client is even assigned.
    deadline = asyncio.get_running_loop().time() + 5.0
    while shadow._client is None:
        assert asyncio.get_running_loop().time() < deadline, (
            "connect() never reached client construction"
        )
        # Real sleep, not sleep(0): the client is built after an
        # asyncio.to_thread() hop, and a bare yield gives the worker
        # thread no wall-clock time on a loaded CI runner.
        await asyncio.sleep(0.01)
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task

    assert fake_paho.disconnect.called
    assert fake_paho.loop_stop.called
    assert shadow._client is None


async def test_disconnect_is_idempotent(fake_paho):
    """Tests that a second disconnect is a no-op instead of raising."""
    shadow = _shadow()
    await _connect(shadow)

    await shadow.disconnect()
    await shadow.disconnect()  # must not raise

    assert fake_paho.loop_stop.call_count == 1


async def test_connect_over_a_live_client_tears_the_old_one_down_first(fake_paho):
    """Tests that reconnecting tears the old client down first.

    connect() is the ~50-minute reconnect path; connecting over a live
    client must tear the old one down first instead of leaking its network
    thread and reusing stale readiness events.
    """
    shadow = _shadow()
    await _connect(shadow)
    first_client = shadow._client

    await _connect(shadow)  # fixture fires connect again

    assert first_client.loop_stop.called


async def test_a_raising_teardown_does_not_mask_a_policy_failure(fake_paho, caplog):
    """Tests that a raising teardown keeps the policy error.

    The supervisor keys terminal-vs-retry on the exception TYPE. A
    teardown that raises on the way out of a failed handshake must not
    REPLACE the handshake failure: an OSError from loop_stop() standing in
    for a ZephyrPolicyError would tell the supervisor to retry forever
    against a policy the identity will never have.
    """
    denied = MagicMock()
    denied.is_failure = True

    def fire_connack_then_deny_subscribe(*args, **kwargs):
        """Simulate CONNACK and then deny every subscription."""
        fake_paho.on_connect(fake_paho, None, {}, 0, None)
        for _ in range(6):
            fake_paho.on_subscribe(fake_paho, None, 1, [denied], None)

    fake_paho.connect_async.side_effect = fire_connack_then_deny_subscribe
    fake_paho.loop_stop.side_effect = OSError("network thread already gone")

    with pytest.raises(ZephyrPolicyError, match="attach"):
        await _connect(_make())

    # The teardown failure is not lost either - it is logged, not silent.
    assert "teardown after a failed handshake" in caplog.text


async def test_a_raising_teardown_does_not_mask_a_handshake_timeout(fake_paho):
    """Tests that a raising teardown keeps the timeout error.

    Same masking, retryable side: the timeout is what tells the caller to
    retry, and an OSError in its place is unclassifiable.
    """
    fake_paho.connect_async.side_effect = None  # nothing fires; connect times out
    fake_paho.disconnect.side_effect = OSError("socket already gone")

    with pytest.raises(ZephyrTransportError, match="timed out"):
        await _make().connect(timeout=0.01)


async def test_a_raising_teardown_still_drops_the_client_reference(fake_paho):
    """Tests that the client reference drops despite teardown errors.

    Swallowing the teardown error must not leave a half-torn-down client
    behind: disconnect() clears _client before the await, so the next
    connect() builds a fresh one instead of reusing a dead handle.
    """
    fake_paho.connect_async.side_effect = None
    fake_paho.disconnect.side_effect = OSError("socket already gone")

    shadow = _shadow()
    with pytest.raises(ZephyrTransportError):
        await shadow.connect(timeout=0.01)

    assert shadow._client is None


async def test_a_cancelled_disconnect_completes_the_teardown_before_raising(
    fake_paho, monkeypatch
):
    """Tests that a cancelled disconnect finishes the teardown first.

    asyncio.shield protects the WORK from cancellation, but it delivers
    CancelledError to the CALLER immediately. A bare `await shield(...)`
    therefore returns while paho's thread is still being reaped: the hood
    lock releases and a reconnect can overlap the old client, which the
    broker resolves by evicting one of them (same client ID). disconnect()
    must see the teardown through, THEN honour the cancel.
    """
    shadow = _shadow()
    await _connect(shadow)

    order: list[str] = []
    gate = asyncio.get_running_loop().create_future()

    def gated_to_thread(fn, *args, **kwargs):
        """Gate asyncio.to_thread work behind the test's future."""

        # Stands in for the worker thread: the teardown does not run until
        # the test opens the gate, so "still in flight" is deterministic.
        async def run():
            """Run the teardown once the gate opens."""
            await gate
            fn(*args, **kwargs)
            order.append("teardown-done")

        return run()

    monkeypatch.setattr(shadow_module.asyncio, "to_thread", gated_to_thread)

    task = asyncio.create_task(shadow.disconnect())
    await asyncio.sleep(0.01)  # park on the shield
    task.cancel()
    await asyncio.sleep(0.01)  # deliver the cancel
    assert not order, "teardown ran before the gate opened"

    gate.set_result(None)
    with pytest.raises(asyncio.CancelledError):
        await task
    order.append("cancel-raised")

    assert order == ["teardown-done", "cancel-raised"]
    assert fake_paho.loop_stop.called


def _get_publishes(fake_paho) -> list:
    """Every publish to this thing's shadow/get topic, in order."""
    return [
        call
        for call in fake_paho.publish.call_args_list
        if call.args[0] == f"$aws/things/{THING}/shadow/get"
    ]


async def test_a_write_is_refused_before_paho_can_queue_it(fake_paho):
    """A write with no live session must never reach paho at all.

    paho puts a qos-1 message into its out-queue BEFORE trying to send it and
    leaves it there on failure, so handing it a message off a dead socket
    schedules an actuation for whenever its own auto-reconnect succeeds -
    minutes later, with no caller waiting and nothing to cancel it.
    """
    sc = _make()
    await _connect(sc)
    fake_paho.publish.reset_mock()
    fake_paho.is_connected.return_value = False

    with pytest.raises(ZephyrNotConnectedError) as excinfo:
        await sc.publish_state({"light": 1})

    fake_paho.publish.assert_not_called()
    # The message names a home if it names the thing; it ends up in logs
    # users paste publicly.
    assert THING not in str(excinfo.value)


async def test_the_dead_client_precheck_tears_the_connection_down_too(fake_paho):
    """The precheck refusal is a teardown path, not just a raise.

    Hood._publish drops its ShadowClient reference on
    ZephyrNotConnectedError because the shadow is documented to have
    destroyed its own connection first. A refusal WITHOUT a teardown
    orphaned a live paho client nothing holds a reference to any more, and
    its auto-reconnect keeps the old session alive under the same client ID
    the supervisor's replacement uses - AWS IoT then evicts one for the
    other, forever.
    """
    sc = _make()
    await _connect(sc)
    fake_paho.is_connected.return_value = False

    with pytest.raises(ZephyrNotConnectedError):
        await sc.publish_state({"light": 1})

    assert fake_paho.disconnect.called
    assert fake_paho.loop_stop.called
    assert sc._client is None


async def test_a_state_request_refused_by_the_precheck_tears_down_too(fake_paho):
    """Tests that a refused state request tears the connection down.

    request_state routes through the same wrapper, so it gets the same
    semantics: the refusal that proves the session is dead is also what
    stops paho resurrecting it behind the supervisor's back.
    """
    sc = _make()
    await _connect(sc)
    fake_paho.is_connected.return_value = False

    with pytest.raises(ZephyrNotConnectedError):
        await sc.request_state()

    assert fake_paho.loop_stop.called
    assert sc._client is None


async def test_a_hood_rebuilds_with_a_fresh_client_after_a_precheck_refusal(
    fake_paho,
):
    """End to end over a real Hood and a real ShadowClient.

    The two halves have to agree: the shadow tears its connection down, and
    the hood drops its reference to it. If either side skips its half the
    hood is stuck - _shadow set but hollow means async_ensure_running
    declines to rebuild, and a live orphaned paho client means the rebuild
    fights the old session for their shared client ID.
    """
    caps = HoodCapabilities.from_discover(
        json.loads((FIXTURES / "discoverdevice.json").read_text())
    )
    made: list[ShadowClient] = []

    def factory(_hood):
        """Shadow factory that records every client it builds."""
        made.append(_shadow())
        return made[-1]

    hood = Hood(caps, factory, AsyncMock(), AsyncMock())
    await hood.async_start()
    assert len(made) == 1

    fake_paho.is_connected.return_value = False

    with pytest.raises(ZephyrNotConnectedError):
        await hood.async_set_light(1)

    assert made[0]._client is None  # the dead session is really gone
    assert hood._shadow is None  # ...and nothing points at it
    assert hood._should_run is True  # the consumer still wants it up

    # The rebuilt socket is live again, as a real one would be.
    fake_paho.is_connected.return_value = True
    await hood.async_ensure_running()  # the next supervisor tick

    assert len(made) == 2  # a FRESH client, not the hollow one
    assert hood._shadow is made[1]


async def test_an_in_flight_disconnect_blocks_a_writer_before_recovery(
    fake_paho, monkeypatch
):
    """Tests that recovery waits out a disconnect the GET already started.

    ``request_state`` clears the paho client and joins its thread before
    the hood lock is taken. A write in that window must not treat the
    second disconnect as finished: it would drop ``Hood._shadow`` and
    ``async_ensure_running`` would open another session on this client ID
    while ``loop_stop`` is still running. A second and a third
    cancellation during that join must not finish it early either.
    ``finish_subscriptions`` aborts through the same ``disconnect``.
    """
    caps = HoodCapabilities.from_discover(
        json.loads((FIXTURES / "discoverdevice.json").read_text())
    )
    made: list[ShadowClient] = []

    def factory(_hood):
        """Shadow factory that records every client it builds."""
        made.append(_shadow())
        return made[-1]

    hood = Hood(caps, factory, AsyncMock(), AsyncMock())
    await hood.async_start()
    fake_paho.is_connected.return_value = False

    order: list[str] = []
    entered = asyncio.Event()
    gate = asyncio.get_running_loop().create_future()
    real_to_thread = shadow_module.asyncio.to_thread

    async def to_thread(fn, *args, **kwargs):
        """Hold the network-thread join. Every other worker runs now."""
        if getattr(fn, "__name__", "") != "_teardown":
            return await real_to_thread(fn, *args, **kwargs)
        entered.set()
        await gate
        fn(*args, **kwargs)
        order.append("teardown-done")
        return None

    def connect_async(*args, **kwargs):
        """Record a new session opening relative to the blocked join."""
        order.append("connect")
        return fire(*args, **kwargs)

    fire = fake_paho.connect_async.side_effect
    fake_paho.connect_async.side_effect = connect_async
    monkeypatch.setattr(shadow_module.asyncio, "to_thread", to_thread)

    reading = asyncio.create_task(hood._read_state_outside_lock(made[0]))
    await entered.wait()
    write = asyncio.create_task(hood.async_set_light(1))
    for _ in range(50):
        await asyncio.sleep(0)
        if hood._lock.locked() and not write.done():
            break
    else:  # pragma: no cover - the assertion message is the failure
        raise AssertionError("write did not block on the in-flight disconnect")

    ensure = asyncio.create_task(hood.async_ensure_running())
    await asyncio.sleep(0)
    assert "connect" not in order
    assert not ensure.done()
    # A second and a third cancel during the follow-up wait. One cancel is
    # not the case that drops the join and lets the writer clear _shadow.
    for _ in range(3):
        reading.cancel()
        await asyncio.sleep(0)
        assert not reading.done()
    assert hood._shadow is made[0]
    assert "connect" not in order

    fake_paho.is_connected.return_value = True
    gate.set_result(None)
    with pytest.raises(asyncio.CancelledError):
        await reading
    with pytest.raises(ZephyrNotConnectedError):
        await write
    await ensure

    assert order.index("teardown-done") < order.index("connect")
    assert hood._shadow is made[1]
    assert made[0]._client is None


async def test_a_refused_rebuild_get_blocks_recovery_until_loop_stop(
    fake_paho, monkeypatch
):
    """Tests that a refused rebuild GET cannot overlap its own teardown.

    ``finish_subscriptions`` and ``request_state`` run after the hood lock
    is released, and a refusal disconnects there. ``disconnect`` clears the
    paho client before ``loop_stop`` joins. A write in that window used to
    treat the second disconnect as finished, drop ``Hood._shadow``, and let
    ``async_ensure_running`` open the same client ID while the join was
    still running. A second and a third cancellation during that join is
    the same hole. The recovery connect has to follow ``loop_stop``.
    """
    caps = HoodCapabilities.from_discover(
        json.loads((FIXTURES / "discoverdevice.json").read_text())
    )
    made: list[ShadowClient] = []

    def factory(_hood):
        """Shadow factory that records every client it builds."""
        made.append(_shadow())
        return made[-1]

    hood = Hood(caps, factory, AsyncMock(), AsyncMock())
    await hood.async_start()

    order: list[str] = []
    entered = asyncio.Event()
    gate = asyncio.get_running_loop().create_future()
    real_to_thread = shadow_module.asyncio.to_thread
    teardowns = 0

    async def to_thread(fn, *args, **kwargs):
        """Let the old session stop. Hold the refusal's join."""
        if getattr(fn, "__name__", "") != "_teardown":
            return await real_to_thread(fn, *args, **kwargs)
        nonlocal teardowns
        teardowns += 1
        if teardowns == 1:
            fn(*args, **kwargs)
            order.append("old-stopped")
            return None
        entered.set()
        await gate
        fn(*args, **kwargs)
        order.append("teardown-done")
        return None

    def connect_async(*args, **kwargs):
        """Record a new session opening relative to the blocked join."""
        order.append("connect")
        return fire(*args, **kwargs)

    fire = fake_paho.connect_async.side_effect
    fake_paho.connect_async.side_effect = connect_async
    # The replacement's CONNACK still succeeds. The GET after it is refused,
    # which is what disconnects before the handler takes the hood lock.
    fake_paho.is_connected.return_value = False
    monkeypatch.setattr(shadow_module.asyncio, "to_thread", to_thread)

    reconnect = asyncio.create_task(hood.async_reconnect())
    await entered.wait()
    write = asyncio.create_task(hood.async_set_light(1))
    for _ in range(50):
        await asyncio.sleep(0)
        if hood._lock.locked() and not write.done():
            break
    else:  # pragma: no cover - the assertion message is the failure
        raise AssertionError("write did not block on the in-flight disconnect")

    ensure = asyncio.create_task(hood.async_ensure_running())
    await asyncio.sleep(0)
    assert order.count("connect") == 1  # the replacement, not recovery
    assert "teardown-done" not in order
    assert not ensure.done()
    # request_state's disconnect is the join outside the hood lock. A
    # second and a third cancel have to keep waiting on it. The writer
    # must not clear the hood's socket while that join is still blocked.
    for _ in range(3):
        reconnect.cancel()
        await asyncio.sleep(0)
        assert not reconnect.done()
    assert hood._shadow is made[1]
    assert order.count("connect") == 1

    fake_paho.is_connected.return_value = True
    gate.set_result(None)
    with pytest.raises(asyncio.CancelledError):
        await reconnect
    with pytest.raises(ZephyrNotConnectedError):
        await write
    await ensure

    assert order.index("teardown-done") < order.index(
        "connect", order.index("teardown-done")
    )
    assert hood._shadow is made[2]
    assert made[1]._client is None


async def test_a_refused_subscription_disconnect_blocks_recovery_through_three_cancels(
    fake_paho, monkeypatch
):
    """Tests that finish_subscriptions' disconnect outlives three cancels.

    The refusal happens after the hood lock is released. ``disconnect``
    clears the paho client and then joins ``loop_stop``. A writer in that
    window, and a second and third cancellation of the reconnect, must not
    drop ``Hood._shadow`` or let ``async_ensure_running`` open the same
    client ID before the join returns.
    """
    caps = HoodCapabilities.from_discover(
        json.loads((FIXTURES / "discoverdevice.json").read_text())
    )
    made: list[ShadowClient] = []

    def factory(_hood):
        """Shadow factory that records every client it builds."""
        made.append(_shadow())
        return made[-1]

    hood = Hood(caps, factory, AsyncMock(), AsyncMock())
    await hood.async_start()

    order: list[str] = []
    entered = asyncio.Event()
    gate = asyncio.get_running_loop().create_future()
    real_to_thread = shadow_module.asyncio.to_thread
    teardowns = 0
    denied = MagicMock()
    denied.is_failure = True

    async def to_thread(fn, *args, **kwargs):
        """Let the old session stop. Hold the subscription refusal's join."""
        if getattr(fn, "__name__", "") != "_teardown":
            return await real_to_thread(fn, *args, **kwargs)
        nonlocal teardowns
        teardowns += 1
        if teardowns == 1:
            fn(*args, **kwargs)
            order.append("old-stopped")
            return None
        entered.set()
        await gate
        fn(*args, **kwargs)
        order.append("teardown-done")
        return None

    fire = fake_paho.connect_async.side_effect
    replacement = True

    def connect_async(*args, **kwargs):
        """Deny the replacement's subscriptions. Let recovery connect."""
        nonlocal replacement
        order.append("connect")
        if not replacement:
            return fire(*args, **kwargs)
        replacement = False
        fake_paho.on_connect(fake_paho, None, {}, 0, None)
        for _ in range(len(ShadowTopics(THING).subscriptions)):
            fake_paho.on_subscribe(fake_paho, None, 1, [denied], None)
        return None

    fake_paho.connect_async.side_effect = connect_async
    monkeypatch.setattr(shadow_module.asyncio, "to_thread", to_thread)

    reconnect = asyncio.create_task(hood.async_reconnect())
    await entered.wait()
    write = asyncio.create_task(hood.async_set_light(1))
    for _ in range(50):
        await asyncio.sleep(0)
        if hood._lock.locked() and not write.done():
            break
    else:  # pragma: no cover - the assertion message is the failure
        raise AssertionError("write did not block on the in-flight disconnect")

    ensure = asyncio.create_task(hood.async_ensure_running())
    await asyncio.sleep(0)
    for _ in range(3):
        reconnect.cancel()
        await asyncio.sleep(0)
        assert not reconnect.done()
        assert not write.done()
    assert hood._shadow is made[1]
    assert order.count("connect") == 1
    assert "teardown-done" not in order
    assert not ensure.done()

    gate.set_result(None)
    with pytest.raises(asyncio.CancelledError):
        await reconnect
    with pytest.raises(ZephyrNotConnectedError):
        await write
    await ensure

    assert order.index("teardown-done") < order.index(
        "connect", order.index("teardown-done")
    )
    assert hood._shadow is made[2]
    assert made[1]._client is None


async def test_a_second_cancel_during_disconnect_waits_out_loop_stop(
    fake_paho, monkeypatch
):
    """Tests that a second and third cancel cannot overlap the disconnect join.

    One cancellation is absorbed and the join still finishes. Another
    cancellation during the follow-up wait used to cancel the ``to_thread``
    task, mark that future done, and let ``async_ensure_running`` open the
    same client ID while ``loop_stop`` was still running. The recovery
    connect has to follow the join. ``async_stop`` would clear the intent
    to run, so this uses ``async_reconnect``, which leaves it set.
    """
    caps = HoodCapabilities.from_discover(
        json.loads((FIXTURES / "discoverdevice.json").read_text())
    )
    made: list[ShadowClient] = []

    def factory(_hood):
        """Shadow factory that records every client it builds."""
        made.append(_shadow())
        return made[-1]

    hood = Hood(caps, factory, AsyncMock(), AsyncMock())
    await hood.async_start()

    order: list[str] = []
    entered = asyncio.Event()
    gate = asyncio.get_running_loop().create_future()
    real_to_thread = shadow_module.asyncio.to_thread

    async def to_thread(fn, *args, **kwargs):
        """Hold loop_stop. Let TLS context work through."""
        if getattr(fn, "__name__", "") != "_teardown":
            return await real_to_thread(fn, *args, **kwargs)
        entered.set()
        await gate
        fn(*args, **kwargs)
        order.append("teardown-done")
        return None

    def connect_async(*args, **kwargs):
        """Record a new session opening relative to the blocked join."""
        order.append("connect")
        return fire(*args, **kwargs)

    fire = fake_paho.connect_async.side_effect
    fake_paho.connect_async.side_effect = connect_async
    monkeypatch.setattr(shadow_module.asyncio, "to_thread", to_thread)

    reconnect = asyncio.create_task(hood.async_reconnect())
    await entered.wait()
    # The first cancel lands in the shielded wait. Yield so the follow-up
    # wait is the one that receives the second cancel.
    for _ in range(3):
        reconnect.cancel()
        await asyncio.sleep(0)
        assert not reconnect.done()
    assert "connect" not in order

    ensure = asyncio.create_task(hood.async_ensure_running())
    await asyncio.sleep(0)
    assert "connect" not in order
    assert not ensure.done()

    gate.set_result(None)
    with pytest.raises(asyncio.CancelledError):
        await reconnect
    await ensure

    assert order.index("teardown-done") < order.index("connect")
    assert hood._shadow is made[-1]
    assert made[0]._client is None


async def test_a_refused_write_tears_the_connection_down_so_it_cannot_fire_later(
    fake_paho,
):
    """The socket can still die between the liveness check and the publish.

    MQTT_ERR_NO_CONN means paho took the message and could not send it - it
    is sitting in _out_messages, and paho's auto-reconnect would deliver it.
    The only way to un-schedule it is to destroy the client object it lives
    in, so this branch disconnects before refusing: every reconnect path here
    builds a fresh mqtt.Client, so nothing inherits the queue.
    """
    sc = _make()
    await _connect(sc)
    fake_paho.publish.return_value = MagicMock(rc=shadow_module.mqtt.MQTT_ERR_NO_CONN)

    with pytest.raises(ZephyrNotConnectedError):
        await sc.publish_state({"light": 1})

    assert fake_paho.loop_stop.called  # the queued write died with it
    assert sc._client is None


async def test_a_no_conn_state_request_is_torn_down_too(fake_paho):
    """Tests that a NO_CONN state request tears the client down.

    request_state routes through the same publish path. A GET stranded in
    the out-queue comes back as a state report long after the caller gave
    up, so it gets the same guarantee.
    """
    sc = _make()
    await _connect(sc)
    fake_paho.publish.return_value = MagicMock(rc=shadow_module.mqtt.MQTT_ERR_NO_CONN)

    with pytest.raises(ZephyrNotConnectedError):
        await sc.request_state()

    assert fake_paho.loop_stop.called
    assert sc._client is None


async def test_a_paho_reconnect_re_issues_the_shadow_get(fake_paho):
    """Tests that a paho auto-reconnect re-issues the shadow GET.

    paho re-fires on_connect on its OWN auto-reconnect, and nothing else
    re-reads the shadow there: without a fresh GET, every state change during
    the outage stays invisible until the hourly supervisor represign.
    """
    sc = _make()
    await _connect(sc)

    assert len(_get_publishes(fake_paho)) == 1  # the initial handshake

    sc._on_connect(fake_paho, None, {}, 0, None)  # paho auto-reconnected

    assert len(_get_publishes(fake_paho)) == 2


async def test_the_reconnect_get_follows_the_subscribes_on_the_same_client(
    fake_paho,
):
    """Tests that the reconnect GET follows the subscribes.

    Ordering is what makes the GET useful: MQTT processes the SUBSCRIBEs
    first on this connection, so get/accepted lands on a live subscription.
    And it goes to the CALLBACK's client - self._client is still unset
    during the first handshake, so using it would skip this entirely.
    """
    sc = _make()
    await _connect(sc)

    names = [call[0] for call in fake_paho.method_calls]
    last_subscribe = max(i for i, name in enumerate(names) if name == "subscribe")
    first_publish = min(i for i, name in enumerate(names) if name == "publish")
    assert first_publish > last_subscribe

    # The callback's client, which the fixture passes as the SAME object the
    # subscribes went to - self._client is still None at this point on the
    # first handshake.
    assert _get_publishes(fake_paho)[0].args[1] == "{}"


async def test_reconnect_presigns_before_the_old_socket_stops(fake_paho, monkeypatch):
    """Tests that presign and the TLS context run before disconnect.

    Both are local work. Doing them while the old session is still up is
    what keeps a command off the rebuild's critical path. Disconnect still
    finishes before the replacement connect_async: two live sessions on one
    client ID evict each other.
    """
    order: list[str] = []

    async def provider():
        """Record a presign and return the static credentials."""
        order.append("presign")
        return CREDS

    async def to_thread(fn, *args, **kwargs):
        """Record the worker function, then run it on this thread."""
        order.append(fn.__name__)
        return fn(*args, **kwargs)

    monkeypatch.setattr(shadow_module.asyncio, "to_thread", to_thread)

    fire = fake_paho.connect_async.side_effect

    def connect_async(*args, **kwargs):
        """Record the handshake relative to disconnect."""
        order.append("connect_async")
        return fire(*args, **kwargs)

    def disconnect(*args, **kwargs):
        """Record teardown of the live session."""
        order.append("disconnect")

    fake_paho.connect_async.side_effect = connect_async
    fake_paho.disconnect.side_effect = disconnect

    caps = HoodCapabilities.from_discover(
        json.loads((FIXTURES / "discoverdevice.json").read_text())
    )

    def factory(_hood):
        """Build a real shadow client against the fake broker."""
        return _shadow(provider)

    hood = Hood(caps, factory, AsyncMock(), AsyncMock())
    await hood.async_start()
    started = len(order)
    await hood.async_reconnect()
    rebuild = order[started:]
    assert rebuild[0] == "presign"
    assert rebuild.index("create_default_context") < rebuild.index("disconnect")
    assert rebuild.index("disconnect") < rebuild.index("connect_async")


async def test_a_write_during_rebuild_does_not_wait_for_subscriptions(
    fake_paho, monkeypatch
):
    """Tests that a command publishes once CONNACK is in, not after SUBACKs.

    Six QoS-1 subscriptions are still waited out before push is trusted.
    They are not on the path a write has to take.
    """
    caps = HoodCapabilities.from_discover(
        json.loads((FIXTURES / "discoverdevice.json").read_text())
    )
    hood = Hood(caps, lambda _hood: _shadow(), AsyncMock(), AsyncMock())
    await hood.async_start()

    entered = asyncio.Event()
    release = asyncio.Event()
    original = ShadowClient.finish_subscriptions

    async def blocking_finish(self, timeout: float = 15.0):
        """Park the subscription wait so a write can slip through."""
        entered.set()
        await release.wait()
        await original(self, timeout)

    monkeypatch.setattr(ShadowClient, "finish_subscriptions", blocking_finish)

    reconnect = asyncio.create_task(hood.async_reconnect())
    await entered.wait()
    write = asyncio.create_task(hood.async_set_light(1))
    await asyncio.sleep(0)
    assert write.done()
    release.set()
    await reconnect
    assert hood.state is not None
    assert hood.state.light == 1
