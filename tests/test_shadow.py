import asyncio
import json
import logging
import ssl
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest

from pyzephyrconnect import shadow as shadow_module
from pyzephyrconnect.auth import Credentials
from pyzephyrconnect.exceptions import (
    ZephyrPolicyError,
    ZephyrTransportError,
    ZephyrWriteError,
)
from pyzephyrconnect.shadow import ShadowClient, ShadowTopics

THING = "aaaaaaaabbbbbbbbccccccccddddddddeeeeeeee"
CREDS = Credentials("k", "s", "t", datetime.now(UTC) + timedelta(hours=1))


def test_topics_are_built_from_the_thing_name():
    t = ShadowTopics(THING)
    assert t.get == f"$aws/things/{THING}/shadow/get"
    assert t.update == f"$aws/things/{THING}/shadow/update"
    assert t.update_delta == f"$aws/things/{THING}/shadow/update/delta"


def test_subscription_set_covers_reads_and_rejections():
    subs = ShadowTopics(THING).subscriptions
    assert f"$aws/things/{THING}/shadow/get/accepted" in subs
    assert f"$aws/things/{THING}/shadow/update/delta" in subs
    assert f"$aws/things/{THING}/shadow/update/rejected" in subs
    # The write topic itself is published to, never subscribed.
    assert f"$aws/things/{THING}/shadow/update" not in subs


@pytest.fixture
def fake_paho(monkeypatch):
    client = MagicMock()
    client.subscribe.return_value = (0, 1)
    client.publish.return_value = MagicMock(rc=0)

    def fire_connack(*args, **kwargs):
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
    monkeypatch.setattr(
        shadow_module.mqtt, "Client", MagicMock(return_value=client)
    )
    return client


async def _default_provider():
    return CREDS


def _make(on_message=None):
    return ShadowClient(
        THING, f"{THING}-ha", on_message or MagicMock(), MagicMock(), _default_provider
    )


def _shadow(credentials_provider=_default_provider, **kwargs):
    """A ShadowClient on the new 5-argument constructor."""
    return ShadowClient(
        THING,
        "us-west-2:abc-ha",
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
    sc = _make()
    await _connect(sc)

    path = fake_paho.ws_set_options.call_args.kwargs["path"]
    assert path.startswith("/mqtt?X-Amz-Algorithm=AWS4-HMAC-SHA256")
    assert "X-Amz-Signature=" in path
    assert "X-Amz-Security-Token=" in path
    fake_paho.tls_set_context.assert_called_once()


async def test_connect_uses_the_suffixed_client_id(fake_paho):
    await _connect(_make())
    assert shadow_module.mqtt.Client.call_args.kwargs["client_id"] == f"{THING}-ha"


async def test_connect_targets_port_443(fake_paho):
    await _connect(_make())
    args = fake_paho.connect_async.call_args.args
    assert args[1] == 443


async def test_connecting_log_omits_the_client_id_and_thing_name(fake_paho, caplog):
    """Pins the scrubbed DEBUG connect log: it may name the endpoint, but
    never the per-connection client ID (identity + thing name) or the bare
    thing name - both are personal data, and a careless future edit that
    logs `self._client_id` directly must fail this test."""
    sc = _shadow()
    with caplog.at_level(logging.DEBUG, logger="pyzephyrconnect.shadow"):
        await _connect(sc)

    assert "connecting to" in caplog.text
    assert "us-west-2:abc-ha" not in caplog.text
    assert THING not in caplog.text


async def test_denied_subscribe_surfaces_as_a_policy_error_from_connect(fake_paho):
    """The denial must reach the caller through connect() - not by raising
    inside paho's callback, which would silently kill the network thread
    instead. See the module docstring and _on_subscribe's docstring."""
    denied = MagicMock()
    denied.is_failure = True

    def fire_connack_then_deny_subscribe(*args, **kwargs):
        fake_paho.on_connect(fake_paho, None, {}, 0, None)
        # _on_connect subscribes to 6 topics; deny all of them.
        for _ in range(6):
            fake_paho.on_subscribe(fake_paho, None, 1, [denied], None)

    fake_paho.connect_async.side_effect = fire_connack_then_deny_subscribe

    with pytest.raises(ZephyrPolicyError, match="attach"):
        await _connect(_make())


async def test_granted_subscribes_let_connect_succeed(fake_paho):
    granted = MagicMock()
    granted.is_failure = False

    def fire_connack_then_grant_subscribes(*args, **kwargs):
        fake_paho.on_connect(fake_paho, None, {}, 0, None)
        for _ in range(6):
            fake_paho.on_subscribe(fake_paho, None, 1, [granted], None)

    fake_paho.connect_async.side_effect = fire_connack_then_grant_subscribes

    await _connect(_make())  # must not raise


async def test_request_state_publishes_an_empty_get(fake_paho):
    sc = _make()
    await _connect(sc)
    await sc.request_state()

    topic, payload = fake_paho.publish.call_args.args[:2]
    assert topic == f"$aws/things/{THING}/shadow/get"
    assert json.loads(payload) == {}


async def test_publish_state_wraps_fields_in_state_reported(fake_paho):
    """This device only acts on state.reported - see the module-level note
    in shadow.py. Publishing state.desired is accepted by AWS and silently
    ignored by the hardware, which was the root cause of a real bug; the
    absence of "desired" anywhere in the payload is the regression guard."""
    sc = _make()
    await _connect(sc)
    await sc.publish_state({"light": 1})

    topic, payload = fake_paho.publish.call_args.args[:2]
    assert topic == f"$aws/things/{THING}/shadow/update"
    assert json.loads(payload) == {"state": {"reported": {"light": 1}}}
    assert "desired" not in payload


async def test_publish_state_rejects_an_empty_payload(fake_paho):
    sc = _make()
    await _connect(sc)
    with pytest.raises(ZephyrWriteError):
        await sc.publish_state({})


async def test_reconnect_uses_capped_exponential_backoff(fake_paho):
    """paho retries indefinitely at a fixed short interval by default. An
    expired credential would otherwise become a hot reconnect loop against
    AWS IoT."""
    await _connect(_make())
    kwargs = fake_paho.reconnect_delay_set.call_args.kwargs
    assert kwargs["min_delay"] >= 1
    assert kwargs["max_delay"] <= 300


async def test_incoming_message_is_dispatched_with_parsed_json(fake_paho):
    """Callbacks arrive on paho's thread and are marshalled onto the loop
    with call_soon_threadsafe, so the dispatch needs a loop tick to land."""
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
    """A parse error inside a paho callback thread would kill the network
    loop and silently stop all updates. The payload must be dropped, and the
    consumer must not be handed anything."""
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
    """The full topic ($aws/things/<thingName>/shadow/...) contains personal
    data. Only the topic leaf (accepted/delta/rejected) may be logged."""
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
    """A failed publish must not leak the full thing-bearing topic into the
    exception message."""
    fake_paho.publish.return_value = MagicMock(rc=1)
    sc = _make()
    await _connect(sc)

    with pytest.raises(shadow_module.ZephyrTransportError) as excinfo:
        await sc.request_state()

    assert THING not in str(excinfo.value)
    assert "get" in str(excinfo.value)


def test_dispatch_on_a_closed_loop_returns_without_raising():
    """paho's network thread must never see a RuntimeError from a
    torn-down/closed event loop - that would kill the thread just like an
    uncaught exception in a callback would."""
    sc = _make()
    loop = asyncio.new_event_loop()
    loop.close()
    sc._loop = loop

    sc._dispatch(MagicMock())  # must not raise


async def test_connect_asks_the_provider_for_fresh_credentials(fake_paho):
    """A presigned URL cannot outlive its signature. Every connect attempt
    must re-presign, or a reconnect after expiry retries a dead URL."""
    calls = []

    async def provider():
        calls.append(1)
        return Credentials("k", "s", "t", datetime.now(UTC) + timedelta(hours=1))

    shadow = _shadow(credentials_provider=provider)
    await _connect(shadow)
    await shadow.disconnect()
    await _connect(shadow)

    assert len(calls) == 2


async def test_tls_context_is_not_built_on_the_event_loop(fake_paho):
    """paho's tls_set() calls load_default_certs() inline, which Home
    Assistant reports as a blocking call on the loop. Hand it a finished
    context instead."""
    shadow = _shadow()
    await _connect(shadow)

    client = shadow._client
    client.tls_set.assert_not_called()
    client.tls_set_context.assert_called_once()
    ctx = client.tls_set_context.call_args.args[0]
    # Design Risks 10-11: a default context - CERT_REQUIRED, hostname
    # checking on, and NOT the TWCA-augmented REST context.
    assert ctx.verify_mode is ssl.VERIFY_DEFAULT or ctx.verify_mode.name == "CERT_REQUIRED"
    assert ctx.check_hostname is True


async def test_publish_empty_state_raises_a_library_error(fake_paho):
    """ValueError escapes a consumer catching ZephyrError."""
    shadow = _shadow()
    await _connect(shadow)
    with pytest.raises(ZephyrWriteError):
        await shadow.publish_state({})


async def test_teardown_disconnects_before_stopping_the_network_thread(fake_paho):
    """disconnect() BEFORE loop_stop(): the network thread is what writes the
    DISCONNECT packet, so stopping it first would queue the packet and never
    send it."""
    shadow = _shadow()
    await _connect(shadow)
    await shadow.disconnect()

    calls = [c for c in fake_paho.method_calls if c[0] in ("disconnect", "loop_stop")]
    names = [c[0] for c in calls]
    assert names.index("disconnect") < names.index("loop_stop")


def test_teardown_stops_the_network_thread_even_if_disconnect_raises():
    """loop_stop() is what JOINS paho's network thread. Skipping it because
    disconnect() raised leaks the very thread this function exists to reap -
    hence the try/finally rather than two plain statements."""
    client = MagicMock()
    client.disconnect.side_effect = OSError("socket already gone")

    with pytest.raises(OSError):
        ShadowClient._teardown(client)

    client.loop_stop.assert_called_once()


async def test_cancelled_handshake_tears_down_the_paho_client(fake_paho):
    """A cancellation arriving mid-handshake must still tear down the paho
    client and its network thread via the shielded teardown in disconnect()
    - not leave it dangling because the outer connect() task was cancelled."""
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
    shadow = _shadow()
    await _connect(shadow)

    await shadow.disconnect()
    await shadow.disconnect()  # must not raise

    assert fake_paho.loop_stop.call_count == 1


async def test_connect_over_a_live_client_tears_the_old_one_down_first(fake_paho):
    """connect() is the ~50-minute reconnect path; connecting over a live
    client must tear the old one down first instead of leaking its network
    thread and reusing stale readiness events."""
    shadow = _shadow()
    await _connect(shadow)
    first_client = shadow._client

    await _connect(shadow)  # fixture fires connect again

    assert first_client.loop_stop.called


async def test_a_raising_teardown_does_not_mask_a_policy_failure(fake_paho, caplog):
    """The supervisor keys terminal-vs-retry on the exception TYPE. A
    teardown that raises on the way out of a failed handshake must not
    REPLACE the handshake failure: an OSError from loop_stop() standing in
    for a ZephyrPolicyError would tell the supervisor to retry forever
    against a policy the identity will never have."""
    denied = MagicMock()
    denied.is_failure = True

    def fire_connack_then_deny_subscribe(*args, **kwargs):
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
    """Same masking, retryable side: the timeout is what tells the caller to
    retry, and an OSError in its place is unclassifiable."""
    fake_paho.connect_async.side_effect = None  # nothing fires; connect times out
    fake_paho.disconnect.side_effect = OSError("socket already gone")

    with pytest.raises(ZephyrTransportError, match="timed out"):
        await _make().connect(timeout=0.01)


async def test_a_raising_teardown_still_drops_the_client_reference(fake_paho):
    """Swallowing the teardown error must not leave a half-torn-down client
    behind: disconnect() clears _client before the await, so the next
    connect() builds a fresh one instead of reusing a dead handle."""
    fake_paho.connect_async.side_effect = None
    fake_paho.disconnect.side_effect = OSError("socket already gone")

    shadow = _shadow()
    with pytest.raises(ZephyrTransportError):
        await shadow.connect(timeout=0.01)

    assert shadow._client is None
