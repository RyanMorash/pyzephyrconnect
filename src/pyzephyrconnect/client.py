"""Facade tying auth, REST and MQTT into one lifecycle.

Read strategy is hybrid by design: discoverdevice supplies capabilities and
an initial state over plain HTTPS before MQTT exists, MQTT then carries live
push, and discoverdevice remains available as a fallback so consumers degrade
to slower updates instead of going unavailable.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

import aiohttp

from .api import ZephyrApi
from .auth import ZephyrAuth
from .models import HoodCapabilities, HoodState
from .shadow import ShadowClient

_LOGGER = logging.getLogger(__name__)

StateListener = Callable[[HoodState], None]

# discoverdevice responses are a flat dict mixing shadow-state fields with
# device identifiers. These must never enter HoodState.raw (its default
# dataclass repr, and hence any careless log of a cached state, would carry
# them). Shadow messages over MQTT carry a clean state.reported block with
# none of these keys - see tests/fixtures/shadow_get_accepted.json versus
# tests/fixtures/discoverdevice.json - so only discoverdevice-derived state
# construction needs filtering; HoodCapabilities legitimately keeps them.
_PERSONAL_DATA_KEYS = ("thingName", "SN", "MAC", "location")


class ZephyrClient:
    """One authenticated account and the hoods under it."""

    def __init__(
        self, username: str, password: str, session: aiohttp.ClientSession
    ) -> None:
        self._auth = ZephyrAuth(username, password)
        self._api = ZephyrApi(session)
        self._capabilities: dict[str, HoodCapabilities] = {}
        self._states: dict[str, HoodState] = {}
        self._listeners: dict[str, list[StateListener]] = {}
        self._shadows: dict[str, ShadowClient] = {}
        self._connected = False

    @property
    def connected(self) -> bool:
        return self._connected

    @property
    def identity_id(self) -> str:
        """Cognito identity ID for this account.

        Stable across sessions and unique per account, which makes it the
        natural key for a consumer that needs to identify this account (for
        example a Home Assistant config entry's unique ID).

        Raises ZephyrAuthError if async_setup() has not run yet.
        """
        return self._auth.identity_id

    def capabilities(self, thing_name: str) -> HoodCapabilities | None:
        return self._capabilities.get(thing_name)

    def state(self, thing_name: str) -> HoodState | None:
        return self._states.get(thing_name)

    async def async_setup(self) -> list[HoodCapabilities]:
        """Authenticate and discover every hood on the account."""
        await self._auth.authenticate()
        devices = await self._api.get_own_devices(self._auth.id_token)
        for device in devices:
            thing_name = device["thingName"]
            payload = await self._api.discover_device(
                self._auth.id_token, thing_name
            )
            caps = HoodCapabilities.from_discover(payload)
            self._capabilities[thing_name] = caps
            state_payload = {
                k: v for k, v in payload.items() if k not in _PERSONAL_DATA_KEYS
            }
            self._states[thing_name] = HoodState.from_reported(state_payload)
        return list(self._capabilities.values())

    async def async_start(self, thing_name: str) -> None:
        """Attach the IoT policy, then open the shadow connection.

        The ordering is mandatory. Attaching after connecting produces a
        connection where subscribe and publish succeed and every message is
        silently dropped.
        """
        await self._auth.attach_policy()

        shadow = ShadowClient(
            thing_name,
            self._auth.mqtt_client_id,
            lambda topic, payload: self._handle_message(
                thing_name, topic, payload
            ),
            self._handle_connection_change,
        )
        await shadow.connect(self._auth.credentials)
        self._shadows[thing_name] = shadow
        await shadow.request_state()

    async def async_stop(self) -> None:
        for shadow in self._shadows.values():
            await shadow.disconnect()
        self._shadows.clear()
        self._connected = False

    async def async_poll(self, thing_name: str) -> HoodState:
        """Read current state over HTTPS. Used at setup and while degraded."""
        payload = await self._api.discover_device(self._auth.id_token, thing_name)
        state_payload = {
            k: v for k, v in payload.items() if k not in _PERSONAL_DATA_KEYS
        }
        state = HoodState.from_reported(state_payload)
        self._states[thing_name] = state
        self._notify(thing_name, state)
        return state

    async def async_refresh_if_needed(self) -> bool:
        """Renew credentials and rebuild sockets if inside the margin.

        Returns True when a refresh happened. The presigned WebSocket URL is
        derived from the credentials, so refreshing without reconnecting
        leaves the socket authorised by an expiring signature.
        """
        if not self._auth.credentials.expired:
            return False

        _LOGGER.debug("credentials near expiry; refreshing and reconnecting")
        await self._auth.refresh()
        for thing_name, shadow in list(self._shadows.items()):
            await shadow.disconnect()
            await shadow.connect(self._auth.credentials)
            await shadow.request_state()
        return True

    async def async_set_state(
        self, thing_name: str, fields: dict[str, Any]
    ) -> None:
        """WRITE PATH - actuates hardware.

        Writes state.reported, not state.desired: that is what the vendor
        app does and what this device acts on. Writing state.desired is
        accepted by AWS IoT but silently ignored by the hardware - see
        ShadowClient.publish_state for the full explanation.

        Callers must allowlist fields themselves. Until the validation gate
        in the plan is complete, the probe CLI is the only permitted caller.
        """
        shadow = self._shadows.get(thing_name)
        if shadow is None:
            raise RuntimeError(f"async_start() has not been called for {thing_name}")
        await shadow.publish_state(fields)

    def add_listener(
        self, thing_name: str, callback: StateListener
    ) -> Callable[[], None]:
        self._listeners.setdefault(thing_name, []).append(callback)

        def remove() -> None:
            try:
                self._listeners[thing_name].remove(callback)
            except (KeyError, ValueError):
                pass

        return remove

    # -- internals -----------------------------------------------------

    def _handle_connection_change(self, connected: bool) -> None:
        self._connected = connected

    def _handle_message(
        self, thing_name: str, topic: str, payload: dict[str, Any]
    ) -> None:
        """Fold an incoming shadow message into the cached state.

        get/accepted carries a full document; update/accepted carries only
        what changed, so it is merged rather than replacing the cache.
        update/delta is deliberately NOT merged - see the comment on that
        branch below.

        Runs on the asyncio loop: ShadowClient._dispatch schedules this via
        loop.call_soon_threadsafe. Nothing here may raise - an escaped
        exception hits asyncio's default exception handler, which logs the
        callback and its arguments (the topic, which embeds the thing name,
        and the raw payload) at ERROR. _on_message only catches JSON *parse*
        errors, so valid-but-wrong-shaped JSON (e.g. the literal `null`, or
        an array) still reaches here - hence the explicit shape guard below
        in addition to the try/except backstop. Diagnostics are limited to
        the topic's leaf segment (accepted/delta/rejected), which carries no
        identifiers.
        """
        if not isinstance(payload, dict):
            _LOGGER.warning(
                "shadow message on %s had an unexpected shape (not an "
                "object); ignoring",
                topic.rsplit("/", 1)[-1],
            )
            return

        try:
            if topic.endswith("/rejected"):
                # Do not log the payload: a rejection can echo back the
                # desired/reported fields it rejected, including identifiers.
                _LOGGER.warning(
                    "shadow operation rejected on %s", topic.rsplit("/", 1)[-1]
                )
                return

            state_block = payload.get("state") or {}
            if topic.endswith("/get/accepted"):
                reported = state_block.get("reported") or {}
                new_state = HoodState.from_reported(reported)
            elif topic.endswith("/update/accepted"):
                reported = state_block.get("reported") or {}
                current = self._states.get(thing_name)
                new_state = (
                    current.merge(reported)
                    if current
                    else HoodState.from_reported(reported)
                )
            elif topic.endswith("/update/delta"):
                # A shadow delta is desired-vs-reported difference - a wish,
                # not confirmed device state. This vendor never writes
                # state.desired (see ShadowClient.publish_state), so any
                # delta observed here can only originate from a stale or
                # foreign desired write and never represents what the
                # hardware actually did. Folding it into the cache
                # previously made the probe report a "change" the device
                # had not - and might never - make, which is exactly what
                # disguised the state.desired/state.reported root-cause bug.
                # Deliberately a no-op: log at DEBUG and drop it.
                _LOGGER.debug(
                    "ignoring shadow delta on %s (never device-authored)",
                    topic.rsplit("/", 1)[-1],
                )
                return
            else:
                return

            self._states[thing_name] = new_state
            self._notify(thing_name, new_state)
        except Exception:  # noqa: BLE001
            # Mirrors _notify: one malformed message must not escape onto
            # the event loop. Log leaf-only - never the thing name, full
            # topic, or payload.
            _LOGGER.exception(
                "unhandled error processing shadow message on %s",
                topic.rsplit("/", 1)[-1],
            )

    def _notify(self, thing_name: str, state: HoodState) -> None:
        for callback in list(self._listeners.get(thing_name, [])):
            try:
                callback(state)
            except Exception:  # noqa: BLE001
                # One bad consumer must not stop the others from updating.
                _LOGGER.exception("state listener raised")
