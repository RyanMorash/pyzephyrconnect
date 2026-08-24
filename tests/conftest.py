"""Fake aiohttp objects. No test in this suite touches the network."""

import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


class FakeResponse:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status = status

    async def json(self, content_type=None):
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
