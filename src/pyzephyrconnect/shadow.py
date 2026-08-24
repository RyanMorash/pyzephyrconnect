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

    # -- paho callbacks (background thread) ---------------------------

    def _dispatch(self, fn: Callable[..., None], *args: Any) -> None:
        if self._loop is not None:
            self._loop.call_soon_threadsafe(fn, *args)

    def _on_connect(self, client, userdata, flags, reason_code, properties=None):
        if reason_code != 0:
            _LOGGER.warning("MQTT connect refused: %s", reason_code)
            return
        for topic in self.topics.subscriptions:
            client.subscribe(topic, qos=1)
        self._dispatch(self._connected.set)
        self._dispatch(self._on_connection_cb, True)

    def _on_disconnect(self, client, userdata, flags, reason_code, properties=None):
        self._dispatch(self._connected.clear)
        self._dispatch(self._on_connection_cb, False)

    def _on_subscribe(self, client, userdata, mid, reason_code_list, properties):
        """Validate the GRANTED QoS.

        paho resolves the subscribe even when the broker refused the topic.
        Granted QoS 128 means denied, and the cause is almost always a
        missing IoT policy on the Cognito identity.
        """
        for code in reason_code_list:
            if getattr(code, "is_failure", False):
                raise ZephyrPolicyError(
                    "AWS IoT denied a shadow subscription (granted QoS 128). "
                    f"Confirm {const.POLICY_NAME} is attached to this identity "
                    "with attach_policy() BEFORE connecting - an open "
                    "connection does not pick up new permissions."
                )

    def _on_message(self, client, userdata, message):
        try:
            payload = json.loads(message.payload)
        except (ValueError, TypeError):
            _LOGGER.warning("Discarding malformed payload on %s", message.topic)
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
            raise ZephyrTransportError(f"publish to {topic} failed: rc={info.rc}")

    async def request_state(self) -> None:
        """Ask for the full shadow. The reply lands on get/accepted."""
        self._publish(self.topics.get, {})

    async def publish_desired(self, fields: dict[str, Any]) -> None:
        """WRITE PATH - actuates hardware.

        Callers are responsible for allowlisting fields. Only the probe CLI
        should reach this until the write path has been validated.
        """
        if not fields:
            raise ValueError("refusing to publish an empty desired state")
        self._publish(self.topics.update, {"state": {"desired": fields}})
