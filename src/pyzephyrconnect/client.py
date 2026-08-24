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
            self._states[thing_name] = HoodState.from_reported(payload)
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
        state = HoodState.from_reported(payload)
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

    async def async_publish_desired(
        self, thing_name: str, fields: dict[str, Any]
    ) -> None:
        """WRITE PATH - actuates hardware.

        Callers must allowlist fields themselves. Until the validation gate
        in the plan is complete, the probe CLI is the only permitted caller.
        """
        shadow = self._shadows.get(thing_name)
        if shadow is None:
            raise RuntimeError(f"async_start() has not been called for {thing_name}")
        await shadow.publish_desired(fields)

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

        get/accepted carries a full document; update/accepted and
        update/delta carry only what changed, so both are merged rather than
        replacing the cache.
        """
        if topic.endswith("/rejected"):
            _LOGGER.warning("shadow operation rejected: %s", payload)
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
            # delta carries the changed keys directly under "state".
            current = self._states.get(thing_name)
            new_state = (
                current.merge(state_block)
                if current
                else HoodState.from_reported(state_block)
            )
        else:
            return

        self._states[thing_name] = new_state
        self._notify(thing_name, new_state)

    def _notify(self, thing_name: str, state: HoodState) -> None:
        for callback in list(self._listeners.get(thing_name, [])):
            try:
                callback(state)
            except Exception:  # noqa: BLE001
                # One bad consumer must not stop the others from updating.
                _LOGGER.exception("state listener raised")
