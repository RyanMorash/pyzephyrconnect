import ssl
import time
from importlib import resources
from unittest.mock import AsyncMock, MagicMock

import aiohttp
import pytest

from conftest import FakeResponse, FakeSession
from pyzephyrconnect import const
from pyzephyrconnect.api import CERT_BUNDLE, ZephyrApi, build_ssl_context
from pyzephyrconnect.auth import ZephyrTokens
from pyzephyrconnect.const import DEFAULT_ENDPOINTS, Endpoints
from pyzephyrconnect.exceptions import (
    ZephyrAuthError,
    ZephyrCertificateError,
    ZephyrError,
    ZephyrTransportError,
)

THING = "aaaaaaaabbbbbbbbccccccccddddddddeeeeeeee"


def _fake_auth(session, endpoints=DEFAULT_ENDPOINTS):
    auth = MagicMock()
    auth.session = session
    auth.endpoints = endpoints
    auth.async_get_tokens = AsyncMock(
        return_value=ZephyrTokens(
            username="u@example.com",
            id_token="ID-TOKEN",
            refresh_token="R",
            identity_id="us-west-2:abc",
            expires_at=time.time() + 3600,
        )
    )
    return auth


TWCA_SUBJECT_COMMON_NAMES = {
    "TWCA Root Certification Authority",
    "TWCA Global Root CA",
    "TWCA Secure SSL Certification Authority",
}


def _common_name(cert: dict) -> str | None:
    for rdn in cert.get("subject", ()):
        for key, value in rdn:
            if key == "commonName":
                return value
    return None


def test_ssl_context_adds_twca_anchors_without_replacing_system_trust():
    """The context must add the TWCA CAs as extra anchors on top of the
    system trust store, not replace the store with just the three of them -
    that would be pinning, which breaks the moment the vendor rotates to a
    mainstream CA."""
    ctx = build_ssl_context()
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True

    ca_certs = ctx.get_ca_certs()
    common_names = {_common_name(cert) for cert in ca_certs}
    assert TWCA_SUBJECT_COMMON_NAMES <= common_names

    # System trust store is still loaded alongside the TWCA anchors. The
    # exact count varies by machine/OS, so just assert it's well beyond the
    # three bundled CAs.
    assert len(ca_certs) > 3


def test_twca_anchors_outlive_the_old_leaf_pin():
    """The whole point of trusting the TWCA CAs rather than the leaf:
    validity must extend past 2026-10-15, when the vendor's leaf expires.

    Checked against the bundle file directly (not the merged context) since
    some system trust stores already carry same-named TWCA roots, which
    would make a name-filtered read of the merged context ambiguous about
    which cert - system's or the bundle's - is being checked."""
    with resources.as_file(
        resources.files("pyzephyrconnect.certs").joinpath(CERT_BUNDLE)
    ) as path:
        bundle_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        bundle_ctx.load_verify_locations(cafile=str(path))
    twca_certs = bundle_ctx.get_ca_certs()

    assert {_common_name(cert) for cert in twca_certs} == TWCA_SUBJECT_COMMON_NAMES
    assert len(twca_certs) == 3
    for cert in twca_certs:
        assert cert["notAfter"].endswith("2030 GMT")


async def test_get_own_devices_sends_a_bare_token_and_empty_body():
    """The vendor API takes the raw ID token with NO 'Bearer ' prefix and a
    genuinely empty body - not '{}'. Both matter."""
    session = FakeSession(
        FakeResponse({"message": "Success", "devices": [{"thingName": THING}]})
    )
    api = ZephyrApi(_fake_auth(session))
    devices = await api.get_own_devices()

    assert devices == [{"thingName": THING}]
    call = session.calls[0]
    assert call["url"] == const.DEVICE_API_LIST
    assert call["headers"]["Authorization"] == "ID-TOKEN"
    assert not call["headers"]["Authorization"].startswith("Bearer")
    assert call["data"] == b""


async def test_discover_device_posts_the_thing_name():
    session = FakeSession(FakeResponse({"maxFanSpeed": 6}))
    api = ZephyrApi(_fake_auth(session))
    result = await api.discover_device(THING)

    assert result == {"maxFanSpeed": 6}
    assert session.calls[0]["url"] == const.DEVICE_API_DISCOVER
    assert session.calls[0]["json"] == {"thingName": THING}


async def test_requests_pass_the_pinned_ssl_context():
    ctx = build_ssl_context()
    session = FakeSession(FakeResponse({"devices": []}))
    await ZephyrApi(_fake_auth(session), ssl_context=ctx).get_own_devices()
    assert session.calls[0]["ssl"] is ctx


async def test_certificate_failure_raises_an_actionable_error():
    """A generic SSLError here sends the operator hunting through their
    system trust store. Name the bundle instead."""

    class ExplodingSession:
        def post(self, url, **kwargs):
            raise aiohttp.ClientConnectorCertificateError(
                connection_key=None,
                certificate_error=ssl.SSLCertVerificationError("bad chain"),
            )

    with pytest.raises(ZephyrCertificateError, match="twca.pem"):
        await ZephyrApi(_fake_auth(ExplodingSession())).get_own_devices()


async def test_missing_devices_key_returns_empty_list():
    session = FakeSession(FakeResponse({"message": "Success"}))
    assert await ZephyrApi(_fake_auth(session)).get_own_devices() == []


async def test_403_response_raises_zephyr_auth_error():
    """A 403 means the ID token is rejected or expired, which is an
    auth-class failure. The HA integration routes on exception TYPE to
    decide reauth vs. transient retry, so this must be ZephyrAuthError
    specifically (a ZephyrError subclass), not the generic base."""
    session = FakeSession(FakeResponse({}, status=403))
    with pytest.raises(ZephyrAuthError) as excinfo:
        await ZephyrApi(_fake_auth(session)).get_own_devices()
    assert isinstance(excinfo.value, ZephyrError)


async def test_other_4xx_response_raises_generic_zephyr_error():
    session = FakeSession(FakeResponse({}, status=400))
    with pytest.raises(ZephyrError) as excinfo:
        await ZephyrApi(_fake_auth(session)).get_own_devices()
    assert not isinstance(excinfo.value, ZephyrAuthError)


async def test_authorization_header_is_a_bare_token():
    """PROTOCOL.md section 4: the API rejects a 'Bearer ' prefix. This is
    trivially easy to break while refactoring onto AbstractAuth."""
    session = FakeSession(FakeResponse({"devices": []}))
    api = ZephyrApi(_fake_auth(session))
    await api.get_own_devices()

    assert session.calls[0]["headers"]["Authorization"] == "ID-TOKEN"
    assert not session.calls[0]["headers"]["Authorization"].startswith("Bearer")


async def test_getowndevices_sends_a_zero_length_body():
    """PROTOCOL.md section 4: Content-Length 0, not '{}'."""
    session = FakeSession(FakeResponse({"devices": []}))
    api = ZephyrApi(_fake_auth(session))
    await api.get_own_devices()

    assert session.calls[0]["data"] == b""


async def test_every_request_asks_auth_for_a_current_token():
    """Refresh lives in the request path now, so a token that went stale
    between calls is renewed without the consumer doing anything."""
    session = FakeSession(
        FakeResponse({"devices": []}), FakeResponse({"thingName": "t"})
    )
    auth = _fake_auth(session)
    api = ZephyrApi(auth)
    await api.get_own_devices()
    await api.discover_device("t")

    assert auth.async_get_tokens.await_count == 2


async def test_endpoint_override_reaches_the_url_requested():
    session = FakeSession(FakeResponse({"devices": []}))
    auth = _fake_auth(
        session, endpoints=Endpoints(device_api_base="https://staging.example/prod")
    )
    await ZephyrApi(auth).get_own_devices()

    assert session.calls[0]["url"] == "https://staging.example/prod/getowndevices"


class _RaisingSession:
    def __init__(self, exc):
        self._exc = exc

    def post(self, url, **kwargs):
        raise self._exc


async def test_transient_network_failure_wraps_in_transport_error():
    """New clause in _post: aiohttp.ClientError/TimeoutError must surface as
    ZephyrTransportError so a consumer catching ZephyrError catches
    everything on the setup and poll paths."""
    api = ZephyrApi(_fake_auth(_RaisingSession(aiohttp.ClientConnectionError())))
    with pytest.raises(ZephyrTransportError):
        await api.get_own_devices()


async def test_certificate_failure_still_wins_over_the_transport_clause():
    """ClientConnectorCertificateError subclasses ClientError; the cert
    clause is listed first and must keep winning - the diagnosis it carries
    is the valuable one."""
    exc = aiohttp.ClientConnectorCertificateError(
        connection_key=MagicMock(), certificate_error=ssl.SSLError("boom")
    )
    api = ZephyrApi(_fake_auth(_RaisingSession(exc)))
    with pytest.raises(ZephyrCertificateError):
        await api.get_own_devices()


async def test_ssl_context_is_built_once_and_cached(monkeypatch):
    import pyzephyrconnect.api as api_module

    calls = []
    real = api_module.build_ssl_context
    monkeypatch.setattr(
        api_module, "build_ssl_context", lambda: calls.append(1) or real()
    )
    session = FakeSession(
        FakeResponse({"devices": []}), FakeResponse({"devices": []})
    )
    api = ZephyrApi(_fake_auth(session))
    await api.get_own_devices()
    await api.get_own_devices()

    assert len(calls) == 1
