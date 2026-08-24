"""MQTT device shadow transport over a presigned WebSocket.

paho runs its network loop on a background thread, so every callback here
executes off the event loop. Callbacks marshal onto the loop with
call_soon_threadsafe and swallow their own exceptions - an exception raised
inside a paho callback kills the network thread and updates stop arriving
with no error anywhere.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

import paho.mqtt.client as mqtt

from . import const
from .auth import Credentials
from .exceptions import ZephyrPolicyError, ZephyrTransportError
from .presign import build_presigned_url

_LOGGER = logging.getLogger(__name__)


class ShadowTopics:
    """Classic shadow topic names for one thing."""

    def __init__(self, thing_name: str) -> None:
        self._base = f"$aws/things/{thing_name}/shadow"

    @property
    def get(self) -> str:
        return f"{self._base}/get"

    @property
    def get_accepted(self) -> str:
        return f"{self._base}/get/accepted"

    @property
    def get_rejected(self) -> str:
        return f"{self._base}/get/rejected"

    @property
    def update(self) -> str:
        """The write path. Publishing here actuates hardware."""
        return f"{self._base}/update"

    @property
    def update_accepted(self) -> str:
        return f"{self._base}/update/accepted"

    @property
    def update_rejected(self) -> str:
        return f"{self._base}/update/rejected"

    @property
    def update_delta(self) -> str:
        return f"{self._base}/update/delta"

    @property
    def update_documents(self) -> str:
        return f"{self._base}/update/documents"

    @property
    def subscriptions(self) -> tuple[str, ...]:
        return (
            self.get_accepted,
            self.get_rejected,
            self.update_accepted,
            self.update_rejected,
            self.update_delta,
            self.update_documents,
        )


class ShadowClient:
    """One MQTT connection to one thing's shadow."""

    def __init__(
        self,
        thing_name: str,
        client_id: str,
        on_message: Callable[[str, dict[str, Any]], None],
        on_connection_change: Callable[[bool], None],
    ) -> None:
        self.topics = ShadowTopics(thing_name)
        self._client_id = client_id
        self._on_message_cb = on_message
        self._on_connection_cb = on_connection_change
        self._client: mqtt.Client | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._connected = asyncio.Event()
        self._subscribed = asyncio.Event()
        self._subscribe_error: ZephyrPolicyError | None = None
        self._pending_subscribes = 0

    # -- paho callbacks (background thread) ---------------------------

    def _dispatch(self, fn: Callable[..., None], *args: Any) -> None:
        if self._loop is None or self._loop.is_closed():
            return
        try:
            self._loop.call_soon_threadsafe(fn, *args)
        except RuntimeError:
            # The loop closed between the check above and this call (e.g.
            # during shutdown). A closed loop is not an error worth
            # propagating into paho's network thread - see module docstring.
            return

    def _on_connect(self, client, userdata, flags, reason_code, properties=None):
        if reason_code != 0:
            _LOGGER.warning("MQTT connect refused: %s", reason_code)
            return
        topics = self.topics.subscriptions
        self._dispatch(self._reset_subscription_state, len(topics))
        for topic in topics:
            client.subscribe(topic, qos=1)
        self._dispatch(self._connected.set)
        self._dispatch(self._on_connection_cb, True)

    def _reset_subscription_state(self, expected: int) -> None:
        self._pending_subscribes = expected
        self._subscribe_error = None
        self._subscribed.clear()
        if expected == 0:
            self._subscribed.set()

    def _on_disconnect(self, client, userdata, flags, reason_code, properties=None):
        self._dispatch(self._connected.clear)
        self._dispatch(self._on_connection_cb, False)

    def _on_subscribe(self, client, userdata, mid, reason_code_list, properties):
        """Record the GRANTED QoS for connect() to observe.

        paho resolves the subscribe even when the broker refused the topic.
        Granted QoS 128 means denied, and the cause is almost always a
        missing IoT policy on the Cognito identity.

        This callback runs on paho's background network thread and must
        NEVER raise: paho's on_subscribe dispatch re-raises callback
        exceptions by default, and the thread runner has no handler for
        them, so an exception here silently kills the network thread. The
        result is dispatched onto the event loop instead, where connect()
        can observe and raise it safely.
        """
        denied = any(getattr(code, "is_failure", False) for code in reason_code_list)
        self._dispatch(self._record_subscribe_result, denied)

    def _record_subscribe_result(self, denied: bool) -> None:
        if denied:
            if self._subscribe_error is None:
                self._subscribe_error = ZephyrPolicyError(
                    "AWS IoT denied a shadow subscription (granted QoS 128). "
                    f"Confirm {const.POLICY_NAME} is attached to this identity "
                    "with attach_policy() BEFORE connecting - an open "
                    "connection does not pick up new permissions."
                )
            self._subscribed.set()
            return
        self._pending_subscribes = max(0, self._pending_subscribes - 1)
        if self._pending_subscribes == 0:
            self._subscribed.set()

    def _on_message(self, client, userdata, message):
        try:
            payload = json.loads(message.payload)
        except (ValueError, TypeError):
            # Log only the topic leaf (e.g. "accepted"/"delta"/"rejected") -
            # the full topic contains the thing name, which is personal data.
            _LOGGER.warning(
                "Discarding malformed payload on %s",
                message.topic.rsplit("/", 1)[-1],
            )
            return
        self._dispatch(self._on_message_cb, message.topic, payload)

    # -- async surface -------------------------------------------------

    async def connect(self, credentials: Credentials, timeout: float = 15.0) -> None:
        self._loop = asyncio.get_running_loop()
        url = build_presigned_url(
            credentials.access_key,
            credentials.secret_key,
            credentials.session_token,
            endpoint=const.IOT_ENDPOINT,
            region=const.REGION,
            now=datetime.now(UTC),
        )
        parts = urlsplit(url)

        client = mqtt.Client(
            callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
            client_id=self._client_id,
            transport="websockets",
            protocol=mqtt.MQTTv311,
        )
        client.ws_set_options(path=f"{parts.path}?{parts.query}")
        # The IoT ATS endpoint chains to Amazon Root CA 1, which system trust
        # stores already carry. Only the vendor REST host needs the extra CAs.
        client.tls_set()
        # paho retries indefinitely at a fixed short interval by default. Cap
        # the backoff so an expired credential does not become a hot loop.
        client.reconnect_delay_set(min_delay=1, max_delay=120)
        client.on_connect = self._on_connect
        client.on_disconnect = self._on_disconnect
        client.on_subscribe = self._on_subscribe
        client.on_message = self._on_message

        _LOGGER.debug(
            "connecting to %s as %s", const.IOT_ENDPOINT, self._client_id
        )
        client.connect_async(const.IOT_ENDPOINT, 443, keepalive=30)
        client.loop_start()
        self._client = client

        try:
            await asyncio.wait_for(self._connected.wait(), timeout)
        except TimeoutError as err:
            await self.disconnect()
            raise ZephyrTransportError(
                f"MQTT connection to {const.IOT_ENDPOINT} timed out"
            ) from err

        try:
            await asyncio.wait_for(self._subscribed.wait(), timeout)
        except TimeoutError as err:
            await self.disconnect()
            raise ZephyrTransportError(
                "MQTT connected but shadow subscriptions did not complete in time"
            ) from err

        if self._subscribe_error is not None:
            error, self._subscribe_error = self._subscribe_error, None
            await self.disconnect()
            raise error

    async def disconnect(self) -> None:
        if self._client is None:
            return
        self._client.loop_stop()
        self._client.disconnect()
        self._client = None
        self._connected.clear()

    def _publish(self, topic: str, payload: dict[str, Any]) -> None:
        if self._client is None:
            raise ZephyrTransportError("not connected")
        info = self._client.publish(topic, json.dumps(payload), qos=1)
        if info.rc != mqtt.MQTT_ERR_SUCCESS:
            # Name the operation (get/update), not the full topic - the full
            # topic contains the thing name, which is personal data.
            operation = topic.rsplit("/shadow/", 1)[-1]
            raise ZephyrTransportError(
                f"publish to shadow/{operation} failed: rc={info.rc}"
            )

    async def request_state(self) -> None:
        """Ask for the full shadow. The reply lands on get/accepted."""
        self._publish(self.topics.get, {})

    async def publish_state(self, fields: dict[str, Any]) -> None:
        """WRITE PATH - actuates hardware.

        Publishes to state.reported, not state.desired. That is backwards
        from the usual AWS IoT shadow convention (reported is normally
        device-authored), but it is demonstrably how this product works:
        the vendor iOS app's own MQTT traffic writes state.reported when
        the user taps a control, and a direct experiment confirmed that
        publishing state.reported physically actuates the hood. Writing
        state.desired instead is accepted by AWS - the publish succeeds and
        nothing complains - but the device silently ignores it, which was
        the original form of this bug.

        Callers are responsible for allowlisting fields. Only the probe CLI
        should reach this until the write path has been validated.
        """
        if not fields:
            raise ValueError("refusing to publish an empty reported state")
        self._publish(self.topics.update, {"state": {"reported": fields}})
