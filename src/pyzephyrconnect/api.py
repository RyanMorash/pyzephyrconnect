"""Vendor REST endpoints.

The session is injected rather than owned, so Home Assistant can pass its
shared client session. The SSL context (system trust plus the TWCA
workaround anchors) is applied per request, which means a shared session
needs no special construction.
"""

from __future__ import annotations

import logging
import ssl
from importlib import resources
from typing import Any

import aiohttp

from . import const
from .exceptions import ZephyrAuthError, ZephyrCertificateError, ZephyrError

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
    """Client for the vendor's two REST endpoints."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        self._session = session
        self._ssl = ssl_context if ssl_context is not None else build_ssl_context()

    def _headers(self, id_token: str) -> dict[str, str]:
        # Bare token, no "Bearer " prefix - the API rejects the prefixed form.
        return {
            "Authorization": id_token,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    async def _post(self, url: str, id_token: str, **kwargs: Any) -> Any:
        try:
            async with self._session.post(
                url, headers=self._headers(id_token), ssl=self._ssl, **kwargs
            ) as response:
                if response.status == 403:
                    raise ZephyrAuthError(
                        f"{url} returned 403 - the ID token is rejected or expired"
                    )
                if response.status >= 400:
                    raise ZephyrError(f"{url} returned HTTP {response.status}")
                # The API sends text/plain for some responses.
                return await response.json(content_type=None)
        except aiohttp.ClientConnectorCertificateError as err:
            raise ZephyrCertificateError(
                f"TLS verification failed for {url}. The presented chain is "
                f"trusted by neither the system CA store nor the bundled "
                f"TWCA anchors ({CERT_BUNDLE}) added to work around the "
                "vendor's SKI-less intermediate. The vendor likely changed "
                "its certificate chain again - recapture it and update the "
                "TWCA bundle if needed. Do not disable verification."
            ) from err

    async def get_own_devices(self, id_token: str) -> list[dict[str, Any]]:
        """Return the caller's devices.

        Note: the response includes precise device coordinates. Treat the
        payload as personal data and never log it.
        """
        # Empty body, not "{}" - matches the captured request exactly.
        payload = await self._post(const.DEVICE_API_LIST, id_token, data=b"")
        devices = payload.get("devices") or []
        _LOGGER.debug("getowndevices returned %d device(s)", len(devices))
        return devices

    async def discover_device(
        self, id_token: str, thing_name: str
    ) -> dict[str, Any]:
        """Return capabilities merged with current state for one thing."""
        return await self._post(
            const.DEVICE_API_DISCOVER, id_token, json={"thingName": thing_name}
        )
