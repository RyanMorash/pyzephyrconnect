"""MQTT device shadow transport over a presigned WebSocket.

paho runs its network loop on a background thread, so every callback here
executes off the event loop. Callbacks marshal onto the loop with
call_soon_threadsafe and swallow their own exceptions - an exception raised
inside a paho callback kills the network thread and updates stop arriving
with no error anywhere.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import ssl
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

import paho.mqtt.client as mqtt

from . import const
from .auth import Credentials
from .const import DEFAULT_ENDPOINTS, Endpoints
from .exceptions import (
    ZephyrNotConnectedError,
    ZephyrPolicyError,
    ZephyrTransportError,
    ZephyrWriteError,
)
from .presign import build_presigned_url

_LOGGER = logging.getLogger(__name__)


class _PublishQueued(Exception):
    """Internal: paho accepted the message but had no socket to send it.

    Never escapes this module. _publish is synchronous and cannot tear the
    connection down itself, so it raises this for its async callers to act
    on - they disconnect, then raise ZephyrNotConnectedError.
    """


class ShadowTopics:
    """Classic shadow topic names for one thing."""

    def __init__(self, thing_name: str) -> None:
        """Anchors every topic under $aws/things/<thing_name>/shadow.

        Args:
            thing_name: The AWS IoT thing name whose shadow to address.
        """
        self._base = f"$aws/things/{thing_name}/shadow"

    @property
    def get(self) -> str:
        """The read-request topic. The reply arrives on get/accepted."""
        return f"{self._base}/get"

    @property
    def get_accepted(self) -> str:
        """Where the full shadow document arrives after a get."""
        return f"{self._base}/get/accepted"

    @property
    def get_rejected(self) -> str:
        """Errors for a get; 404 means no shadow document exists yet."""
        return f"{self._base}/get/rejected"

    @property
    def update(self) -> str:
        """The write path. Publishing here actuates hardware."""
        return f"{self._base}/update"

    @property
    def update_accepted(self) -> str:
        """Confirmed state changes; carries only the fields that changed."""
        return f"{self._base}/update/accepted"

    @property
    def update_rejected(self) -> str:
        """Where the broker reports rejected writes."""
        return f"{self._base}/update/rejected"

    @property
    def update_delta(self) -> str:
        """Desired-vs-reported deltas.

        Subscribed but never merged into cached state: nothing in this
        system writes state.desired (see publish_state), so a delta here
        is never device-authored.
        """
        return f"{self._base}/update/delta"

    @property
    def update_documents(self) -> str:
        """Before/after document pairs for each accepted update."""
        return f"{self._base}/update/documents"

    @property
    def subscriptions(self) -> tuple[str, ...]:
        """Every topic to subscribe to.

        The response topics only, not the publish topics.
        """
        return (
            self.get_accepted,
            self.get_rejected,
            self.update_accepted,
            self.update_rejected,
            self.update_delta,
            self.update_documents,
        )


class ShadowClient:
    """One MQTT connection to one thing's shadow.

    Attributes:
        topics: The ShadowTopics naming every shadow topic for this
            thing.
    """

    def __init__(
        self,
        thing_name: str,
        client_id: str,
        on_message: Callable[[str, dict[str, Any]], None],
        on_connection_change: Callable[[bool], None],
        credentials_provider: Callable[[], Awaitable[Credentials]],
        *,
        endpoints: Endpoints = DEFAULT_ENDPOINTS,
    ) -> None:
        """Stores the wiring; no network I/O happens until connect().

        Args:
            thing_name: The AWS IoT thing name whose shadow to speak to.
            client_id: The MQTT client ID presented to AWS IoT.
            on_message: Called on the event loop with the topic and the
                decoded payload of each incoming shadow message.
            on_connection_change: Called on the event loop with True when
                the session comes up and False when it drops.
            credentials_provider: Awaited for fresh AWS credentials on
                every connect attempt; see connect() for why.
            endpoints: The AWS region and hosts to connect to.
        """
        self.topics = ShadowTopics(thing_name)
        self._client_id = client_id
        self._on_message_cb = on_message
        self._on_connection_cb = on_connection_change
        self._credentials_provider = credentials_provider
        self._endpoints = endpoints
        self._client: mqtt.Client | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._connected = asyncio.Event()
        self._subscribed = asyncio.Event()
        self._subscribe_error: ZephyrPolicyError | None = None
        self._pending_subscribes = 0

    # -- paho callbacks (background thread) ---------------------------

    def _dispatch(self, fn: Callable[..., None], *args: Any) -> None:
        """Marshals a call from paho's network thread onto the event loop.

        Dropping the call when the loop is missing or closed is
        deliberate - see the module docstring for why nothing on paho's
        thread may raise.

        Args:
            fn: The callable to run on the event loop.
            *args: Positional arguments passed through to fn.
        """
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
        """Subscribes to the shadow topics and refreshes state on (re)connect.

        Runs on paho's network thread, on the initial CONNACK and again on
        paho's own auto-reconnects. A refused CONNACK only logs: the
        readiness events stay unset, so a connect() waiting on them times
        out with ZephyrTransportError instead of half-succeeding.

        Args:
            client: The paho client that fired the callback. Used instead
                of self._client, which is still unset during the first
                handshake.
            userdata: Unused paho callback argument.
            flags: Unused CONNACK flags.
            reason_code: The CONNACK result; nonzero means the broker
                refused the connection.
            properties: Unused MQTT v5 properties.
        """
        if reason_code != 0:
            _LOGGER.warning("MQTT connect refused: %s", reason_code)
            return
        topics = self.topics.subscriptions
        self._dispatch(self._reset_subscription_state, len(topics))
        for topic in topics:
            client.subscribe(topic, qos=1)
        try:
            # paho re-fires on_connect on ITS OWN auto-reconnect, and nothing
            # else re-reads the shadow there: every state change during the
            # outage stays invisible until the hourly supervisor represign
            # rebuilds the socket and Hood._start issues a fresh GET. The
            # broker processes the SUBSCRIBEs above first on this same
            # connection, so get/accepted lands on a live subscription. On the
            # initial connect this merely duplicates Hood._start's
            # request_state - a second empty GET, which is harmless.
            #
            # The callback's `client`, NOT self._client: during the first
            # handshake connect() has not assigned self._client yet, so this
            # would silently skip exactly the path it exists to cover.
            #
            # Runs on paho's network thread, so it may never raise - see the
            # module docstring. Best-effort: the next represign re-reads
            # anyway.
            client.publish(self.topics.get, "{}", qos=1)
        except Exception:  # noqa: BLE001
            pass
        self._dispatch(self._connected.set)
        self._dispatch(self._on_connection_cb, True)

    def _reset_subscription_state(self, expected: int) -> None:
        """Arms subscription tracking for a batch of expected SUBACKs.

        Runs on the event loop, dispatched from _on_connect. Zero expected
        topics counts as already subscribed.

        Args:
            expected: How many SUBACKs must be granted before the
                subscribed event sets.
        """
        self._pending_subscribes = expected
        self._subscribe_error = None
        self._subscribed.clear()
        if expected == 0:
            self._subscribed.set()

    def _on_disconnect(self, client, userdata, flags, reason_code, properties=None):
        """Marks the session down and notifies the owner.

        Runs on paho's network thread.
        """
        self._dispatch(self._connected.clear)
        self._dispatch(self._on_connection_cb, False)

    def _on_subscribe(self, client, userdata, mid, reason_code_list, properties):
        """Records the GRANTED QoS for connect() to observe.

        paho resolves the subscribe even when the broker refused the topic.
        Granted QoS 128 means denied, and the cause is almost always a
        missing IoT policy on the Cognito identity.

        This callback runs on paho's background network thread and must
        NEVER raise: paho's on_subscribe dispatch re-raises callback
        exceptions by default, and the thread runner has no handler for
        them, so an exception here silently kills the network thread. The
        result is dispatched onto the event loop instead, where connect()
        can observe and raise it safely.

        Args:
            client: Unused paho callback argument.
            userdata: Unused paho callback argument.
            mid: Unused message ID of the SUBSCRIBE being acknowledged.
            reason_code_list: One granted-QoS code per requested topic; a
                failure code means the broker denied that subscription.
            properties: Unused MQTT v5 properties.
        """
        denied = any(getattr(code, "is_failure", False) for code in reason_code_list)
        self._dispatch(self._record_subscribe_result, denied)

    def _record_subscribe_result(self, denied: bool) -> None:
        """Folds one SUBACK result into the readiness state.

        Runs on the event loop, dispatched from _on_subscribe. A denial
        records a ZephyrPolicyError and sets the subscribed event early,
        so connect() wakes and raises it instead of waiting out its
        timeout.

        Args:
            denied: Whether the broker refused any topic in the SUBACK.
        """
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
        """Decodes an incoming publish and hands it to the owner's callback.

        Runs on paho's network thread; the callback itself is dispatched
        onto the event loop. Malformed JSON is dropped with a warning that
        names only the topic leaf - the full topic embeds the thing name,
        which is personal data.

        Args:
            client: Unused paho callback argument.
            userdata: Unused paho callback argument.
            message: The incoming MQTT message; its payload must be JSON.
        """
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

    async def connect(self, timeout: float = 15.0) -> None:
        """Opens the WebSocket and subscribes to the shadow topics.

        Credentials are fetched from the provider on every attempt rather
        than captured once: the presigned URL embeds a SigV4 signature that
        expires with them, so a reconnect must re-presign or it will retry a
        URL AWS IoT has already stopped accepting.

        Args:
            timeout: Seconds to wait for the CONNACK, and again for the
                shadow subscriptions, before giving up.

        Raises:
            ZephyrTransportError: The connection or the shadow
                subscriptions did not complete within the timeout.
            ZephyrPolicyError: AWS IoT denied a shadow subscription -
                almost always a missing IoT policy on the Cognito
                identity.
        """
        self._loop = asyncio.get_running_loop()
        if self._client is not None:
            # connect() is the ~50-minute reconnect path; connecting over a
            # live client would leak its network thread and reuse stale
            # readiness events.
            await self.disconnect()
        self._connected.clear()
        self._subscribed.clear()
        credentials = await self._credentials_provider()
        url = build_presigned_url(
            credentials.access_key,
            credentials.secret_key,
            credentials.session_token,
            endpoint=self._endpoints.iot_endpoint,
            region=self._endpoints.region,
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
        # stores already carry. Only the vendor REST host needs the extra CAs,
        # so this is a plain default context - NOT the TWCA one.
        #
        # Built in a worker thread and handed to paho finished. paho's
        # tls_set() constructs the context inline on the calling thread: it
        # does ssl.SSLContext(...) and then, because ca_certs is None,
        # context.load_default_certs() - which Home Assistant instruments as
        # a blocking call. connect() is async and runs on the event loop, and
        # this path executes on every connect including every supervisor
        # reconnect.
        client.tls_set_context(await asyncio.to_thread(ssl.create_default_context))
        # paho retries indefinitely at a fixed short interval by default. Cap
        # the backoff so an expired credential does not become a hot loop.
        client.reconnect_delay_set(min_delay=1, max_delay=120)
        client.on_connect = self._on_connect
        client.on_disconnect = self._on_disconnect
        client.on_subscribe = self._on_subscribe
        client.on_message = self._on_message

        _LOGGER.debug("connecting to %s", self._endpoints.iot_endpoint)
        client.connect_async(self._endpoints.iot_endpoint, 443, keepalive=30)
        client.loop_start()
        self._client = client

        try:
            try:
                await asyncio.wait_for(self._connected.wait(), timeout)
            except TimeoutError as err:
                raise ZephyrTransportError(
                    f"MQTT connection to {self._endpoints.iot_endpoint} timed out"
                ) from err
            try:
                await asyncio.wait_for(self._subscribed.wait(), timeout)
            except TimeoutError as err:
                raise ZephyrTransportError(
                    "MQTT connected but shadow subscriptions did not complete in time"
                ) from err
            if self._subscribe_error is not None:
                error, self._subscribe_error = self._subscribe_error, None
                raise error
        except BaseException:
            # Covers the ZephyrTransportError raises above, ZephyrPolicyError,
            # AND CancelledError: whatever interrupts the handshake, the paho
            # client and its network thread must be torn down before the
            # exception leaves - nothing outside holds a reference yet.
            try:
                await self.disconnect()
            except Exception:  # noqa: BLE001
                # The teardown failure must not REPLACE the handshake
                # failure - the caller's terminal-vs-retry decision keys on
                # the original exception's type. An OSError out of
                # loop_stop() standing in for a ZephyrPolicyError would tell
                # the supervisor to retry forever against a policy the
                # identity will never have.
                _LOGGER.exception("teardown after a failed handshake")
            raise

    async def disconnect(self) -> None:
        """Tears down the paho client and joins its network thread.

        A no-op with no client. The reference and readiness events are
        cleared before the first await, so a newer connection completing
        during a slow teardown is not clobbered. The join runs in a worker
        thread and is shielded: a cancellation arriving mid-teardown still
        sees the thread stopped (best-effort) before it propagates.
        """
        if self._client is None:
            return
        client, self._client = self._client, None
        # Clear before the await, not after: a slow teardown (loop_stop
        # joins a thread parked in recv) could otherwise let a NEWER
        # connection complete inside that window and have its events
        # clobbered here, leaving the object connected-but-unsubscribed.
        self._connected.clear()
        self._subscribed.clear()
        # Off the loop: loop_stop() JOINS paho's network thread (see
        # paho/mqtt/client.py), and that thread is frequently inside a
        # synchronous socket recv. A thread join on the event loop was
        # tolerable once at shutdown; this now runs on every ~50-minute
        # supervisor rebuild, per hood.
        #
        # Shielded: disconnect() runs inside connect()'s `except
        # BaseException` cleanup. A SECOND cancellation arriving while this
        # teardown work item is still queued on the executor would cancel it
        # before the executor picks it up, leaking a paho client whose
        # network thread is already running - the exact leak this cleanup
        # exists to prevent, one level down.
        teardown = asyncio.ensure_future(asyncio.to_thread(self._teardown, client))
        try:
            await asyncio.shield(teardown)
        except asyncio.CancelledError:
            # shield surfaces OUR cancellation immediately while the work
            # item runs on; returning now would release the hood lock with
            # paho's thread still alive, letting a new connect overlap the
            # old client. Best-effort: see the teardown through, THEN
            # honour the cancel. (A second cancel during this wait still
            # wins - unavoidable, and strictly rarer.)
            with contextlib.suppress(BaseException):
                await teardown
            raise

    @staticmethod
    def _teardown(client: mqtt.Client) -> None:
        """Sends DISCONNECT, then joins the network thread, in that order.

        Runs in a worker thread: loop_stop() blocks on a thread join that
        must never happen on the event loop.

        Args:
            client: The paho client to shut down.
        """
        # disconnect() BEFORE loop_stop(). The network thread is what writes
        # the DISCONNECT packet; stopping it first means the packet is queued
        # and never sent, and the broker only notices via keepalive timeout.
        try:
            client.disconnect()
        finally:
            # In a finally, so a disconnect() that raises cannot skip it.
            # loop_stop() is what JOINS paho's network thread - this
            # function exists to stop that thread leaking, and letting a
            # failed DISCONNECT packet cancel the join is exactly the leak
            # it guards against. Ordering above is preserved.
            client.loop_stop()

    def _publish(self, topic: str, payload: dict[str, Any]) -> None:
        """Hands one message to paho; callers must use _publish_or_disconnect.

        Args:
            topic: The shadow topic to publish to.
            payload: The JSON-serializable message body.

        Raises:
            ZephyrNotConnectedError: No post-CONNACK session exists to
                carry the write.
            _PublishQueued: paho accepted the message with no socket to
                write it on. Never seen outside this module.
            ZephyrTransportError: paho refused the publish outright.
        """
        # is_connected() reflects post-CONNACK state (paho sets it in
        # _handle_connack BEFORE dispatching on_connect), so this is the real
        # question - "is there a session that can carry this write?" - not
        # "did we ever build a client object?". Refusing here is what keeps a
        # write from being parked in paho's out-queue in the first place;
        # connect() only returns after the _connected event, so the
        # handshake-time request_state still passes.
        if self._client is None or not self._client.is_connected():
            # No thing name in the message: it identifies a home, and
            # exception text ends up in logs users paste publicly.
            #
            # Raised, not torn down here: this method is synchronous and
            # cannot await disconnect(). _publish_or_disconnect catches this
            # refusal exactly like _PublishQueued and tears the connection
            # down before re-raising - see the reasoning there.
            raise ZephyrNotConnectedError("hood is not connected")
        info = self._client.publish(topic, json.dumps(payload), qos=1)
        if info.rc == mqtt.MQTT_ERR_NO_CONN:
            # The socket died between the check above and this call. paho
            # inserts a qos>0 message into _out_messages BEFORE trying to
            # send it and, on NO_CONN, leaves it there in the "needs
            # publishing" state - so paho's own auto-reconnect would deliver
            # this write minutes later and actuate the hood with no caller
            # waiting. Signal the async layer to tear the connection down.
            raise _PublishQueued
        if info.rc != mqtt.MQTT_ERR_SUCCESS:
            # Name the operation (get/update), not the full topic - the full
            # topic contains the thing name, which is personal data.
            operation = topic.rsplit("/shadow/", 1)[-1]
            raise ZephyrTransportError(
                f"publish to shadow/{operation} failed: rc={info.rc}"
            )

    async def _publish_or_disconnect(self, topic: str, payload: dict[str, Any]) -> None:
        """Publishes, tearing the connection down rather than queuing a write.

        A refused write must never actuate hardware later. Tearing the
        connection down discards the queued message with the paho client
        object itself - every reconnect path here builds a FRESH mqtt.Client
        (connect() replaces it, disconnect() drops the reference), so nothing
        inherits the out-queue and the write can never fire.

        Both callers route through this, so `request_state` gets the same
        guarantee on both refusal paths: a GET stranded in the out-queue
        would come back as a state report long after the caller gave up, and
        a GET refused against a dead client leaves the same orphaned session
        a refused write does.

        Args:
            topic: The shadow topic to publish to.
            payload: The JSON-serializable message body.

        Raises:
            ZephyrNotConnectedError: The publish was refused - no live
                session, or paho queued it with no socket - and the
                connection has been torn down.
            ZephyrTransportError: paho refused the publish outright.
        """
        try:
            self._publish(topic, payload)
        except (_PublishQueued, ZephyrNotConnectedError):
            # BOTH refusals tear down, and for related reasons.
            #
            # _PublishQueued: paho accepted the message with no socket to
            # write it on, and discarding the client object is the only way
            # to un-schedule the write its auto-reconnect would deliver.
            #
            # The dead-client precheck: a refused write marks this
            # connection dead on both sides. The teardown kills paho's
            # auto-reconnect, so the old session can never come back and
            # fight the supervisor's rebuild - both hold the same client ID,
            # and AWS IoT evicts one for the other, forever. It also makes
            # Hood's reference-drop consistent on EVERY path: Hood._publish
            # drops its ShadowClient on ZephyrNotConnectedError assuming the
            # teardown already happened, so refusing without one orphaned a
            # live paho thread nothing held a reference to any more.
            #
            # Only a refused WRITE forces the supervisor rebuild path. A
            # transient blip with nothing being published tears nothing down
            # and paho's own reconnect still recovers it.
            #
            # Best-effort teardown; the caller still gets the refusal below
            # either way, and the write must not be reported as accepted.
            with contextlib.suppress(Exception):
                await self.disconnect()
            # `from None`: the internal signal carries no information the
            # caller can use, and chaining it into the traceback only adds a
            # frame naming this module's internals.
            raise ZephyrNotConnectedError("hood is not connected") from None

    async def request_state(self) -> None:
        """Asks for the full shadow; the reply lands on get/accepted.

        Raises:
            ZephyrNotConnectedError: The GET was refused and the
                connection torn down; see _publish_or_disconnect.
            ZephyrTransportError: paho refused the publish outright.
        """
        await self._publish_or_disconnect(self.topics.get, {})

    async def publish_state(self, fields: dict[str, Any]) -> None:
        """Publishes reported state - the WRITE PATH; it actuates hardware.

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

        Args:
            fields: The state.reported fields to write. Must be non-empty
                and already allowlisted by the caller.

        Raises:
            ZephyrWriteError: fields is empty; an empty reported state is
                never published.
            ZephyrNotConnectedError: The write was refused and the
                connection torn down rather than left to deliver later.
            ZephyrTransportError: paho refused the publish outright.
        """
        if not fields:
            raise ZephyrWriteError("refusing to publish an empty reported state")
        await self._publish_or_disconnect(
            self.topics.update, {"state": {"reported": fields}}
        )
