"""Fake aiohttp objects. No test in this suite touches the network."""

import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


class FakeResponse:
    def __init__(self, payload, status=200, json_exc=None):
        self._payload = payload
        self.status = status
        # Raised by json() instead of returning a value, when set - lets a
        # test simulate a non-JSON body (a maintenance page, a WAF
        # interstitial) without touching the network.
        self._json_exc = json_exc

    async def json(self, content_type=None):
        if self._json_exc is not None:
            raise self._json_exc
        # Returned as-is, including None - aiohttp's real json() returns
        # None for an empty 200 body, and callers must see that literally
        # rather than some FakeResponse-specific coercion.
        return self._payload

    async def text(self):
        return json.dumps(self._payload)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class FakeSession:
    """Records calls and returns queued responses. `post` returns an async
    context manager, matching aiohttp rather than being a coroutine."""

    def __init__(self, *responses):
        self._responses = list(responses)
        self.calls = []

    def post(self, url, **kwargs):
        self.calls.append({"url": url, **kwargs})
        if not self._responses:
            raise AssertionError(f"unexpected POST to {url}")
        return self._responses.pop(0)


@pytest.fixture
def discover_payload() -> dict:
    return json.loads((FIXTURES / "discoverdevice.json").read_text())
