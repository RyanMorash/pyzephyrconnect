import ssl

import aiohttp
import pytest

from conftest import FakeResponse, FakeSession
from pyzephyrconnect import const
from pyzephyrconnect.api import ZephyrApi, build_ssl_context
from pyzephyrconnect.exceptions import ZephyrCertificateError

TOKEN = "id-token-value"
THING = "aaaaaaaabbbbbbbbccccccccddddddddeeeeeeee"


def test_ssl_context_loads_the_bundled_cas():
    ctx = build_ssl_context()
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert len(ctx.get_ca_certs()) == 3


def test_ssl_context_cas_outlive_the_old_leaf_pin():
    """The whole point of pinning CAs rather than the leaf: validity must
    extend past 2026-10-15, when the vendor's leaf expires."""
    for cert in build_ssl_context().get_ca_certs():
        assert cert["notAfter"].endswith("2030 GMT")


async def test_get_own_devices_sends_a_bare_token_and_empty_body():
    """The vendor API takes the raw ID token with NO 'Bearer ' prefix and a
    genuinely empty body - not '{}'. Both matter."""
    session = FakeSession(
        FakeResponse({"message": "Success", "devices": [{"thingName": THING}]})
    )
    api = ZephyrApi(session)
    devices = await api.get_own_devices(TOKEN)

    assert devices == [{"thingName": THING}]
    call = session.calls[0]
    assert call["url"] == const.DEVICE_API_LIST
    assert call["headers"]["Authorization"] == TOKEN
    assert not call["headers"]["Authorization"].startswith("Bearer")
    assert call["data"] == b""


async def test_discover_device_posts_the_thing_name():
    session = FakeSession(FakeResponse({"maxFanSpeed": 6}))
    api = ZephyrApi(session)
    result = await api.discover_device(TOKEN, THING)

    assert result == {"maxFanSpeed": 6}
    assert session.calls[0]["url"] == const.DEVICE_API_DISCOVER
    assert session.calls[0]["json"] == {"thingName": THING}


async def test_requests_pass_the_pinned_ssl_context():
    ctx = build_ssl_context()
    session = FakeSession(FakeResponse({"devices": []}))
    await ZephyrApi(session, ctx).get_own_devices(TOKEN)
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
        await ZephyrApi(ExplodingSession()).get_own_devices(TOKEN)


async def test_missing_devices_key_returns_empty_list():
    session = FakeSession(FakeResponse({"message": "Success"}))
    assert await ZephyrApi(session).get_own_devices(TOKEN) == []
