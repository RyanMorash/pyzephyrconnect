"""Vendor REST endpoints.

The session is injected rather than owned, so Home Assistant can pass its
shared client session. The SSL context (system trust plus the TWCA
workaround anchors) is applied per request, which means a shared session
needs no special construction.
"""

from __future__ import annotations

import asyncio
import logging
import ssl
from importlib import resources
from typing import Any

import aiohttp

from .auth import AbstractAuth
from .exceptions import (
    ZephyrAuthError,
    ZephyrCertificateError,
    ZephyrDataError,
    ZephyrError,
    ZephyrTransportError,
)

_LOGGER = logging.getLogger(__name__)

CERT_BUNDLE = "twca.pem"
# Validity of the bundled TWCA anchors. With additive trust (system store
# plus these anchors) this is no longer load-bearing for verification - it's
# tracked here for reference and exercised by the test suite, not used as
# the sole diagnosis in the error path below.
CERT_BUNDLE_EXPIRY = "2030"


def build_ssl_context() -> ssl.SSLContext:
    """System trust store, plus the bundled TWCA CAs as extra anchors.

    The vendor's HTTPS host presents a chain whose intermediate omits the
    Subject Key Identifier extension, which OpenSSL 3.x rejects under normal
    system trust. This works around that specific defect by adding the TWCA
    certificates as supplementary trust anchors on top of - not instead of -
    the system trust store. verify_mode stays CERT_REQUIRED and hostname
    checking stays on.

    This is deliberately NOT certificate pinning. Pinning would replace the
    system trust store with only the bundled CAs, which breaks every other
    host outright and breaks the vendor host itself the day it rotates to a
    mainstream CA. Adding the TWCA anchors alongside the system store fixes
    the SKI defect for this vendor while leaving normal trust intact
    everywhere else, and survives a future CA rotation.
    """
    ctx = ssl.create_default_context()
    with resources.as_file(
        resources.files("pyzephyrconnect.certs").joinpath(CERT_BUNDLE)
    ) as path:
        ctx.load_verify_locations(cafile=str(path))
    return ctx


class ZephyrApi:
    """Client for the vendor's two REST endpoints.

    The auth object owns the session and the token, so this class is
    agnostic to how credentials are obtained - which is what lets a consumer
    supply its own AbstractAuth. The SSL context (system trust plus the TWCA
    workaround anchors) is applied per request, so a shared session needs no
    special construction.
    """

    def __init__(
        self,
        auth: AbstractAuth,
        *,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        self._auth = auth
        # Deliberately NOT built here. build_ssl_context() calls
        # SSLContext.load_default_certs and load_verify_locations, both of
        # which Home Assistant instruments as blocking calls and reports when
        # they run on the event loop - and this constructor runs on the loop
        # inside async_setup_entry. Built lazily in a worker thread instead.
        self._ssl = ssl_context

    async def _get_ssl(self) -> ssl.SSLContext:
        """The SSL context, built off the event loop on first use."""
        if self._ssl is None:
            self._ssl = await asyncio.to_thread(build_ssl_context)
        return self._ssl

    def _headers(self, id_token: str) -> dict[str, str]:
        # Bare token, no "Bearer " prefix - the API rejects the prefixed form.
        return {
            "Authorization": id_token,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    async def _post(self, url: str, **kwargs: Any) -> Any:
        tokens = await self._auth.async_get_tokens()
        ssl_context = await self._get_ssl()
        try:
            async with self._auth.session.post(
                url,
                headers=self._headers(tokens.id_token),
                ssl=ssl_context,
                **kwargs,
            ) as response:
                if response.status == 403:
                    raise ZephyrAuthError(
                        f"{url} returned 403 - the ID token is rejected or expired"
                    )
                if response.status >= 400:
                    raise ZephyrError(f"{url} returned HTTP {response.status}")
                # The API sends text/plain for some responses.
                try:
                    body = await response.json(content_type=None)
                except (ValueError, UnicodeDecodeError) as err:
                    # json.JSONDecodeError is a ValueError, and aiohttp does
                    # not wrap it. A vendor maintenance page or WAF
                    # interstitial returns non-JSON HTML here - transient,
                    # not a data-shape bug the caller should treat as fatal.
                    raise ZephyrTransportError(
                        f"{url} returned an unparseable body"
                    ) from err
                if not isinstance(body, dict):
                    # aiohttp returns None for an empty 200 body; a bare
                    # list or string is equally unusable to every caller of
                    # this method.
                    raise ZephyrDataError(
                        f"{url} returned an unexpected body shape"
                    )
                return body
        except aiohttp.ClientConnectorCertificateError as err:
            # Must stay ABOVE the ClientError clause - it is a subclass, and
            # the certificate diagnosis is the valuable one.
            raise ZephyrCertificateError(
                f"TLS verification failed for {url}. The presented chain is "
                f"trusted by neither the system CA store nor the bundled "
                f"TWCA anchors ({CERT_BUNDLE}) added to work around the "
                "vendor's SKI-less intermediate. The vendor likely changed "
                "its certificate chain again - recapture it and update the "
                "TWCA bundle if needed. Do not disable verification."
            ) from err
        except (aiohttp.ClientError, TimeoutError) as err:
            # DNS failure, connection reset, timeout: retryable transport
            # noise. Left unwrapped it escapes the "consumers catch
            # ZephyrError" contract from async_setup() and async_poll().
            raise ZephyrTransportError(
                f"request to {url} failed: {err}"
            ) from err

    async def get_own_devices(self) -> list[dict[str, Any]]:
        """Return the caller's devices.

        Note: the response includes precise device coordinates. Treat the
        payload as personal data and never log it.
        """
        # Empty body, not "{}" - matches the captured request exactly.
        payload = await self._post(self._auth.endpoints.device_api_list, data=b"")
        devices = payload.get("devices") or []
        _LOGGER.debug("getowndevices returned %d device(s)", len(devices))
        return devices

    async def discover_device(self, thing_name: str) -> dict[str, Any]:
        """Return capabilities merged with current state for one thing."""
        return await self._post(
            self._auth.endpoints.device_api_discover,
            json={"thingName": thing_name},
        )
