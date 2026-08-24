"""Vendor REST endpoints.

The session is injected rather than owned, so Home Assistant can pass its
shared client session. The pinned SSL context is applied per request, which
means a shared session needs no special construction.
"""

from __future__ import annotations

import logging
import ssl
from importlib import resources
from typing import Any

import aiohttp

from . import const
from .exceptions import ZephyrCertificateError, ZephyrError

_LOGGER = logging.getLogger(__name__)

CERT_BUNDLE = "twca.pem"
# Validity of the bundled CA set; surfaced in the error message so an
# operator hitting this in 2030 knows immediately what expired.
CERT_BUNDLE_EXPIRY = "2030"


def build_ssl_context() -> ssl.SSLContext:
    """SSL context trusting the bundled TWCA CA set.

    The vendor's intermediate omits the Subject Key Identifier extension and
    is rejected by OpenSSL 3.x under system trust. Loading the CAs as trust
    anchors satisfies verification without weakening it - verify_mode stays
    CERT_REQUIRED and hostname checking stays on.
    """
    # Passing cafile directly to create_default_context() is deliberate: it
    # makes the context skip ssl.SSLContext.load_default_certs() entirely.
    # Creating the context first and calling load_verify_locations()
    # afterward would instead ADD the bundle on top of the system trust
    # store, defeating the pin (and failing on any machine with extra
    # locally-installed CAs, e.g. a mkcert dev root).
    with resources.as_file(
        resources.files("pyzephyrconnect.certs").joinpath(CERT_BUNDLE)
    ) as path:
        ctx = ssl.create_default_context(cafile=str(path))
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
                    raise ZephyrError(
                        f"{url} returned 403 - the ID token is rejected or expired"
                    )
                if response.status >= 400:
                    raise ZephyrError(f"{url} returned HTTP {response.status}")
                # The API sends text/plain for some responses.
                return await response.json(content_type=None)
        except aiohttp.ClientConnectorCertificateError as err:
            raise ZephyrCertificateError(
                f"TLS verification failed for {url}. The bundled CA set "
                f"({CERT_BUNDLE}, valid to {CERT_BUNDLE_EXPIRY}) does not "
                "cover the presented chain - the vendor likely rotated CAs. "
                "Recapture the chain; do not disable verification."
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
