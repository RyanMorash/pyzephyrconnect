"""Tests for pyzephyrconnect.auth token models."""

import time
import traceback

import pytest

from pyzephyrconnect.auth import AbstractAuth, ZephyrTokens
from pyzephyrconnect.exceptions import ZephyrDataError


def _tokens(**overrides):
    """Build a valid ZephyrTokens with optional field overrides."""
    base = {
        "username": "user@example.com",
        "id_token": "ID",
        "refresh_token": "REFRESH",
        "identity_id": "us-west-2:00000000-1111-2222-3333-444455556666",
        "expires_at": time.time() + 3600,
    }
    return ZephyrTokens(**{**base, **overrides})


def test_tokens_round_trip_through_primitives():
    """Tests that tokens round-trip through JSON primitives.

    The auth docs require JSON-serializable auth data so the consumer can
    persist it. json.dumps must work without a custom encoder.
    """
    import json

    original = _tokens()
    restored = ZephyrTokens.from_dict(json.loads(json.dumps(original.as_dict())))
    assert restored == original


def test_tokens_carry_the_username():
    """Tests that tokens carry the username.

    SECRET_HASH is HMAC(client_secret, username + client_id); pycognito
    recomputes it on every refresh. Tokens without a username are inert.
    """
    assert _tokens().username == "user@example.com"


def test_expired_is_true_inside_the_refresh_margin():
    """Tests that expired is True inside the refresh margin, else False."""
    assert _tokens(expires_at=time.time() + 60).expired is True
    assert _tokens(expires_at=time.time() + 3600).expired is False


def test_abstract_auth_cannot_be_instantiated():
    """Tests that instantiating AbstractAuth directly raises TypeError."""
    with pytest.raises(TypeError):
        AbstractAuth(session=None)


def test_from_dict_with_a_missing_key_raises_zephyr_data_error():
    """Tests that from_dict with a missing key raises ZephyrDataError.

    README tells consumers to call from_dict() on restored storage. A
    corrupted or partial record must not escape as a raw KeyError.
    """
    data = _tokens().as_dict()
    del data["refresh_token"]
    with pytest.raises(ZephyrDataError):
        ZephyrTokens.from_dict(data)


def test_from_dict_with_an_unparseable_expiry_raises_zephyr_data_error():
    """Tests that an unparseable expires_at raises ZephyrDataError."""
    data = _tokens().as_dict()
    data["expires_at"] = "soon"
    with pytest.raises(ZephyrDataError):
        ZephyrTokens.from_dict(data)


def test_from_dict_rejects_a_non_string_field_instead_of_coercing_it():
    """Tests that from_dict rejects a non-string field instead of coercing.

    str() coercion was worse than no validation at all: a corrupted None
    became the literal "None", a perfectly usable string that passes every
    later check and fails far away - as a SECRET_HASH Cognito rejects, or an
    MQTT client ID whose messages AWS IoT silently drops.
    """
    data = _tokens().as_dict()
    data["username"] = None
    with pytest.raises(ZephyrDataError):
        ZephyrTokens.from_dict(data)


def test_from_dict_rejects_an_empty_string_field():
    """Tests that an empty string field raises ZephyrDataError."""
    data = _tokens().as_dict()
    data["identity_id"] = ""
    with pytest.raises(ZephyrDataError):
        ZephyrTokens.from_dict(data)


def test_from_dict_rejects_a_non_finite_expiry():
    """Tests that from_dict rejects a non-finite expiry.

    float("nan") parses fine and then compares False against everything,
    so `expired` would be permanently False - tokens that are never
    refreshed and a socket that dies on credentials nothing renews.
    """
    data = _tokens().as_dict()
    data["expires_at"] = float("nan")
    with pytest.raises(ZephyrDataError):
        ZephyrTokens.from_dict(data)


def test_from_dict_rejects_a_huge_expiry():
    """Tests that from_dict rejects a huge expiry.

    A persisted expires_at can be an arbitrarily large int (e.g.
    corrupted storage), and float() on an int too large to represent raises
    OverflowError rather than ValueError. from_dict must still raise the
    documented ZephyrDataError, not let OverflowError escape.
    """
    data = _tokens().as_dict()
    data["expires_at"] = 10**400
    with pytest.raises(ZephyrDataError):
        ZephyrTokens.from_dict(data)


def test_a_huge_expiry_never_reaches_the_traceback():
    """Tests that a huge expiry never reaches the traceback.

    Same leak concern as the unparseable-string case: the huge int must
    not be threaded into the ZephyrDataError's chained traceback via
    OverflowError's own message.
    """
    huge = 10**400
    data = _tokens().as_dict()
    data["expires_at"] = huge

    with pytest.raises(ZephyrDataError) as excinfo:
        ZephyrTokens.from_dict(data)

    rendered = "".join(traceback.format_exception(excinfo.value))
    assert str(huge) not in rendered
    assert "expires_at" in rendered  # the field name still says which


def test_an_unparseable_expiry_never_reaches_the_traceback():
    """Tests that an unparseable expiry never reaches the traceback.

    float("<garbage>") names the value it could not convert in its own
    message, and the outer `raise ... from err` threads that message into the
    ZephyrDataError's chained traceback - so a consumer that logs the
    exception prints a field out of persisted token storage in full. Only the
    field NAME may escape; the value is caller data of unknown sensitivity.
    """
    leaked = "eyJhbGciOiJIUzI1NiJ9-not-a-number"
    data = _tokens().as_dict()
    data["expires_at"] = leaked

    with pytest.raises(ZephyrDataError) as excinfo:
        ZephyrTokens.from_dict(data)

    rendered = "".join(traceback.format_exception(excinfo.value))
    assert leaked not in rendered
    assert "expires_at" in rendered  # the field name still says which
