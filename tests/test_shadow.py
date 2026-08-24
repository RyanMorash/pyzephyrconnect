import asyncio
import json
from datetime import UTC, datetime
from unittest.mock import MagicMock

import pytest

from pyzephyrconnect import shadow as shadow_module
from pyzephyrconnect.auth import Credentials
from pyzephyrconnect.exceptions import ZephyrPolicyError
from pyzephyrconnect.shadow import ShadowClient, ShadowTopics

THING = "aaaaaaaabbbbbbbbccccccccddddddddeeeeeeee"
CREDS = Credentials("AKIA", "SECRET", "TOKEN", datetime(2030, 1, 1, tzinfo=UTC))


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


def _make(on_message=None):
    return ShadowClient(
        THING, f"{THING}-ha", on_message or MagicMock(), MagicMock()
    )


async def test_connect_uses_a_presigned_websocket_path(fake_paho):
    sc = _make()
    await sc.connect(CREDS)

    path = fake_paho.ws_set_options.call_args.kwargs["path"]
    assert path.startswith("/mqtt?X-Amz-Algorithm=AWS4-HMAC-SHA256")
    assert "X-Amz-Signature=" in path
    assert "X-Amz-Security-Token=" in path
    fake_paho.tls_set.assert_called_once()


async def test_connect_uses_the_suffixed_client_id(fake_paho):
    await _make().connect(CREDS)
    assert shadow_module.mqtt.Client.call_args.kwargs["client_id"] == f"{THING}-ha"


async def test_connect_targets_port_443(fake_paho):
    await _make().connect(CREDS)
    args = fake_paho.connect_async.call_args.args
    assert args[1] == 443


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
        await _make().connect(CREDS)


async def test_granted_subscribes_let_connect_succeed(fake_paho):
    granted = MagicMock()
    granted.is_failure = False

    def fire_connack_then_grant_subscribes(*args, **kwargs):
        fake_paho.on_connect(fake_paho, None, {}, 0, None)
        for _ in range(6):
            fake_paho.on_subscribe(fake_paho, None, 1, [granted], None)

    fake_paho.connect_async.side_effect = fire_connack_then_grant_subscribes

    await _make().connect(CREDS)  # must not raise


async def test_request_state_publishes_an_empty_get(fake_paho):
    sc = _make()
    await sc.connect(CREDS)
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
    await sc.connect(CREDS)
    await sc.publish_state({"light": 1})

    topic, payload = fake_paho.publish.call_args.args[:2]
    assert topic == f"$aws/things/{THING}/shadow/update"
    assert json.loads(payload) == {"state": {"reported": {"light": 1}}}
    assert "desired" not in payload


async def test_publish_state_rejects_an_empty_payload(fake_paho):
    sc = _make()
    await sc.connect(CREDS)
    with pytest.raises(ValueError):
        await sc.publish_state({})


async def test_reconnect_uses_capped_exponential_backoff(fake_paho):
    """paho retries indefinitely at a fixed short interval by default. An
    expired credential would otherwise become a hot reconnect loop against
    AWS IoT."""
    await _make().connect(CREDS)
    kwargs = fake_paho.reconnect_delay_set.call_args.kwargs
    assert kwargs["min_delay"] >= 1
    assert kwargs["max_delay"] <= 300


async def test_incoming_message_is_dispatched_with_parsed_json(fake_paho):
    """Callbacks arrive on paho's thread and are marshalled onto the loop
    with call_soon_threadsafe, so the dispatch needs a loop tick to land."""
    received = []
    sc = _make(on_message=lambda topic, payload: received.append((topic, payload)))
    await sc.connect(CREDS)

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
    await sc.connect(CREDS)

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
    await sc.connect(CREDS)

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
    await sc.connect(CREDS)

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
