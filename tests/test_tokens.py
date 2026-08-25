import time

import pytest

from pyzephyrconnect.auth import AbstractAuth, ZephyrTokens


def _tokens(**overrides):
    base = {
        "username": "user@example.com",
        "id_token": "ID",
        "refresh_token": "REFRESH",
        "identity_id": "us-west-2:00000000-1111-2222-3333-444455556666",
        "expires_at": time.time() + 3600,
    }
    return ZephyrTokens(**{**base, **overrides})


def test_tokens_round_trip_through_primitives():
    """The auth docs require JSON-serializable auth data so the consumer can
    persist it. json.dumps must work without a custom encoder."""
    import json

    original = _tokens()
    restored = ZephyrTokens.from_dict(json.loads(json.dumps(original.as_dict())))
    assert restored == original


def test_tokens_carry_the_username():
    """SECRET_HASH is HMAC(client_secret, username + client_id); pycognito
    recomputes it on every refresh. Tokens without a username are inert."""
    assert _tokens().username == "user@example.com"


def test_expired_is_true_inside_the_refresh_margin():
    assert _tokens(expires_at=time.time() + 60).expired is True
    assert _tokens(expires_at=time.time() + 3600).expired is False


def test_abstract_auth_cannot_be_instantiated():
    with pytest.raises(TypeError):
        AbstractAuth(session=None)
