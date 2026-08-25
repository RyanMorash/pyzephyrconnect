"""Fake aiohttp objects. No test in this suite touches the network."""

import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


class FakeResponse:
    """Fake aiohttp response that returns a queued payload."""

    def __init__(self, payload, status=200, json_exc=None):
        """Initialize the fake response."""
        self._payload = payload
        self.status = status
        # Raised by json() instead of returning a value, when set - lets a
        # test simulate a non-JSON body (a maintenance page, a WAF
        # interstitial) without touching the network.
        self._json_exc = json_exc

    async def json(self, content_type=None):
        """Return the queued payload, or raise the configured exception."""
        if self._json_exc is not None:
            raise self._json_exc
        # Returned as-is, including None - aiohttp's real json() returns
        # None for an empty 200 body, and callers must see that literally
        # rather than some FakeResponse-specific coercion.
        return self._payload

    async def text(self):
        """Return the payload serialized as JSON text."""
        return json.dumps(self._payload)

    async def __aenter__(self):
        """Enter the async context, returning the response itself."""
        return self

    async def __aexit__(self, *exc):
        """Exit the async context without suppressing exceptions."""
        return False


class FakeSession:
    """Records calls and returns queued responses.

    `post` returns an async context manager, matching aiohttp rather
    than being a coroutine.
    """

    def __init__(self, *responses):
        """Initialize the fake session with queued responses."""
        self._responses = list(responses)
        self.calls = []

    def post(self, url, **kwargs):
        """Record the call and return the next queued response."""
        self.calls.append({"url": url, **kwargs})
        if not self._responses:
            raise AssertionError(f"unexpected POST to {url}")
        return self._responses.pop(0)


@pytest.fixture
def discover_payload() -> dict:
    """Return the parsed discoverdevice.json fixture payload."""
    return json.loads((FIXTURES / "discoverdevice.json").read_text())
