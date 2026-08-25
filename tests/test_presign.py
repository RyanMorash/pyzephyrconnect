"""Tests for SigV4 WebSocket presigning.

There is no published AWS test vector for iotdevicegateway WebSocket
presigning, so these tests pin the canonical request (which is
hand-verifiable against the SigV4 specification), determinism, and the
structural invariants that break real connections. End-to-end proof comes
from the live connect in Task 8.
"""

from datetime import UTC, datetime
from urllib.parse import parse_qs, urlsplit

import pytest

from pyzephyrconnect.presign import _signing_key, build_presigned_url, canonical_request

ENDPOINT = "a1nqxu0hki9zw3-ats.iot.us-west-2.amazonaws.com"
NOW = datetime(2026, 8, 23, 12, 0, 0, tzinfo=UTC)
KEY = "AKIDEXAMPLE"
SECRET = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
TOKEN = "SESSIONTOKEN/with+special=chars"


def _url(**kw) -> str:
    """Build a presigned URL from the test constants with overrides."""
    params = dict(
        access_key=KEY, secret_key=SECRET, session_token=TOKEN,
        endpoint=ENDPOINT, region="us-west-2", now=NOW,
    )
    params.update(kw)
    return build_presigned_url(**params)


def test_url_shape():
    """Tests that the URL is wss to the endpoint with path /mqtt."""
    url = _url()
    parts = urlsplit(url)
    assert parts.scheme == "wss"
    assert parts.netloc == ENDPOINT
    assert parts.path == "/mqtt"


def test_required_query_parameters_present():
    """Tests that all required SigV4 query parameters are present."""
    q = parse_qs(urlsplit(_url()).query)
    assert q["X-Amz-Algorithm"] == ["AWS4-HMAC-SHA256"]
    assert q["X-Amz-SignedHeaders"] == ["host"]
    assert q["X-Amz-Date"] == ["20260823T120000Z"]
    assert q["X-Amz-Credential"] == [
        f"{KEY}/20260823/us-west-2/iotdevicegateway/aws4_request"
    ]
    assert len(q["X-Amz-Signature"][0]) == 64
    assert q["X-Amz-Security-Token"] == [TOKEN]


def test_security_token_is_excluded_from_the_signature():
    """Tests that the session token does not affect the signature.

    AWS IoT requires the session token be appended AFTER signing.
    Including it in the canonical query string produces a signature the
    broker rejects, and the failure looks like a generic handshake error.
    """
    with_token = parse_qs(urlsplit(_url()).query)["X-Amz-Signature"][0]
    without = parse_qs(
        urlsplit(_url(session_token=None)).query
    )["X-Amz-Signature"][0]
    assert with_token == without


def test_signature_is_deterministic():
    """Tests that identical inputs produce identical URLs."""
    assert _url() == _url()


@pytest.mark.parametrize(
    "override",
    [
        {"secret_key": "different-secret"},
        {"access_key": "AKIDOTHER"},
        {"region": "us-east-1"},
        {"now": datetime(2026, 8, 23, 12, 0, 1, tzinfo=UTC)},
    ],
)
def test_signature_changes_when_any_signed_input_changes(override):
    """Tests that changing any signed input changes the signature."""
    base = parse_qs(urlsplit(_url()).query)["X-Amz-Signature"][0]
    other = parse_qs(urlsplit(_url(**override)).query)["X-Amz-Signature"][0]
    assert base != other


def test_canonical_request_matches_sigv4_specification():
    """Tests that the canonical request matches the SigV4 layout.

    Hand-verifiable against the SigV4 spec: method, URI, sorted query,
    canonical headers terminated by a newline, a blank line, signed headers,
    then the SHA-256 of an empty payload.
    """
    cr = canonical_request(
        access_key=KEY, endpoint=ENDPOINT, region="us-west-2", now=NOW
    )
    lines = cr.split("\n")
    assert lines[0] == "GET"
    assert lines[1] == "/mqtt"
    assert lines[2].startswith("X-Amz-Algorithm=AWS4-HMAC-SHA256&")
    assert "X-Amz-Security-Token" not in lines[2]
    assert lines[3] == f"host:{ENDPOINT}"
    assert lines[4] == ""
    assert lines[5] == "host"
    assert lines[6] == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )


def test_query_string_is_sorted():
    """Tests that the canonical query string is sorted.

    SigV4 requires lexicographically sorted parameters. An unsorted
    canonical query produces a valid-looking but rejected signature.
    """
    cr = canonical_request(
        access_key=KEY, endpoint=ENDPOINT, region="us-west-2", now=NOW
    )
    qs = cr.split("\n")[2]
    keys = [p.split("=")[0] for p in qs.split("&")]
    assert keys == sorted(keys)


def test_signing_key_matches_the_published_aws_vector():
    """Tests that _signing_key matches the published AWS vector.

    AWS documents the intermediate signing key for this exact input in
    "Examples of how to derive a signing key for Signature Version 4".

    There is no published vector for iotdevicegateway WebSocket presigning,
    so this pins the HMAC derivation chain — the part most likely to be
    silently wrong — against an authority outside this codebase.
    """
    derived = _signing_key(
        "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        "20150830",
        "us-east-1",
        service="iam",
    )
    assert derived.hex() == (
        "c4afb1cc5771d871763a393e44b703571b55cc28424d1a5e86da6ed3c154a4b9"
    )
