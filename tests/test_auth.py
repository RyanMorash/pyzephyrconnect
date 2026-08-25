import time
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from pyzephyrconnect import auth as auth_module
from pyzephyrconnect.auth import AbstractAuth, Credentials, ZephyrAuth, ZephyrTokens
from pyzephyrconnect.exceptions import ZephyrAuthError, ZephyrTransportError

IDENTITY = "us-west-2:00000000-1111-2222-3333-444455556666"


def _creds_response(expires_in_seconds=3600):
    return {
        "Credentials": {
            "AccessKeyId": "AKIA",
            # Note: SecretKey, NOT SecretAccessKey. This differs from STS and
            # is a documented trap in PROTOCOL.md section 3.2.
            "SecretKey": "SECRET",
            "SessionToken": "TOKEN",
            "Expiration": datetime.now(UTC)
            + timedelta(seconds=expires_in_seconds),
        }
    }


@pytest.fixture
def fake_aws(monkeypatch):
    """Replace pycognito and boto3 with recording doubles."""
    cognito = MagicMock()
    cognito.id_token = "ID-TOKEN"
    monkeypatch.setattr(auth_module, "Cognito", MagicMock(return_value=cognito))

    identity = MagicMock()
    identity.get_id.return_value = {"IdentityId": IDENTITY}
    identity.get_credentials_for_identity.return_value = _creds_response()

    iot = MagicMock()
    iot.list_attached_policies.return_value = {"policies": []}

    def client(service, **kwargs):
        return {"cognito-identity": identity, "iot": iot}[service]

    monkeypatch.setattr(auth_module.boto3, "client", MagicMock(side_effect=client))
    return {"cognito": cognito, "identity": identity, "iot": iot}


async def test_authenticate_runs_srp_and_exchanges_credentials(fake_aws):
    a = ZephyrAuth("user@example.com", "pw")
    await a.authenticate()

    fake_aws["cognito"].authenticate.assert_called_once_with(password="pw")
    assert a.id_token == "ID-TOKEN"
    assert a.credentials.secret_key == "SECRET"


async def test_user_pool_region_is_passed_explicitly(fake_aws):
    """Without it pycognito falls back to ambient AWS config and raises a
    misleading ResourceNotFoundException."""
    await ZephyrAuth("u", "p").authenticate()
    kwargs = auth_module.Cognito.call_args.kwargs
    assert kwargs["user_pool_region"] == "us-west-2"
    assert kwargs["client_secret"], "SRP fails without the client secret"


async def test_identity_id_keeps_its_region_prefix(fake_aws):
    """The full 'us-west-2:uuid' is what the IoT policy variable resolves to
    and is the correct MQTT client ID base. Stripping it breaks delivery."""
    a = ZephyrAuth("u", "p")
    await a.authenticate()
    assert a.identity_id == IDENTITY
    assert a.identity_id.startswith("us-west-2:")


async def test_mqtt_client_id_is_suffixed(fake_aws):
    """A bare identity ID collides with the phone app and the two sessions
    evict each other in a reconnect loop."""
    a = ZephyrAuth("u", "p")
    await a.authenticate()
    assert a.mqtt_client_id == f"{IDENTITY}-ha"


async def test_attach_policy_is_skipped_when_already_attached(fake_aws):
    fake_aws["iot"].list_attached_policies.return_value = {
        "policies": [{"policyName": "RangeHoodPolicy"}]
    }
    a = ZephyrAuth("u", "p")
    await a.authenticate()
    await a.attach_policy()
    fake_aws["iot"].attach_policy.assert_not_called()


async def test_attach_policy_attaches_when_missing(fake_aws):
    a = ZephyrAuth("u", "p")
    await a.authenticate()
    await a.attach_policy()
    fake_aws["iot"].attach_policy.assert_called_once_with(
        policyName="RangeHoodPolicy", target=IDENTITY
    )


async def test_refresh_renews_without_a_full_srp_round_trip(fake_aws):
    """Re-running SRP costs multiple round trips and the pool may rate-limit."""
    a = ZephyrAuth("u", "p")
    await a.authenticate()
    fake_aws["cognito"].authenticate.reset_mock()

    await a.refresh()

    fake_aws["cognito"].renew_access_token.assert_called_once()
    fake_aws["cognito"].authenticate.assert_not_called()
    # get_id is only valid once; the identity must be reused.
    assert fake_aws["identity"].get_id.call_count == 1


async def test_authentication_failure_is_wrapped(fake_aws):
    fake_aws["cognito"].authenticate.side_effect = Exception("Incorrect username")
    with pytest.raises(ZephyrAuthError):
        await ZephyrAuth("u", "bad").authenticate()


async def test_exchange_failure_during_authenticate_is_wrapped(fake_aws):
    """The identity exchange (get_id/get_credentials_for_identity) runs
    after SRP login succeeds. A botocore ClientError from it (e.g. an
    invalid/expired token) must surface as ZephyrAuthError, not raw
    botocore - the HA integration routes on exception TYPE for reauth."""
    fake_aws["identity"].get_credentials_for_identity.side_effect = Exception(
        "ClientError: NotAuthorizedException"
    )
    with pytest.raises(ZephyrAuthError):
        await ZephyrAuth("u", "p").authenticate()


async def test_exchange_failure_during_refresh_is_wrapped(fake_aws):
    """refresh() shares _exchange with authenticate() and must wrap its
    failures the same way."""
    a = ZephyrAuth("u", "p")
    await a.authenticate()
    fake_aws["identity"].get_credentials_for_identity.side_effect = Exception(
        "ClientError: NotAuthorizedException"
    )
    with pytest.raises(ZephyrAuthError):
        await a.refresh()


def test_credentials_expire_early_by_the_refresh_margin():
    """Reporting 'valid' until the last second guarantees a mid-flight
    expiry, because rebuilding the socket is not instant."""
    nearly = Credentials(
        "k", "s", "t", datetime.now(UTC) + timedelta(seconds=60)
    )
    plenty = Credentials(
        "k", "s", "t", datetime.now(UTC) + timedelta(seconds=3600)
    )
    assert nearly.expired is True
    assert plenty.expired is False


def _stored_tokens(expires_in=-1):
    return ZephyrTokens(
        username="user@example.com",
        id_token="OLD-ID",
        refresh_token="REFRESH",
        identity_id=IDENTITY,
        expires_at=time.time() + expires_in,
    )


class _StaticAuth(AbstractAuth):
    """The documented consumer path: implement one method, nothing else."""

    def __init__(self, tokens, session):
        super().__init__(session)
        self._static = tokens

    async def async_get_tokens(self):
        return self._static


async def test_a_minimal_subclass_satisfies_the_whole_client_contract(fake_aws):
    """ZephyrClient consumes async_get_credentials, credentials_expired,
    mqtt_client_id and async_attach_policy. If any of those live only on
    CredentialsAuth, a custom AbstractAuth satisfies the type checker and
    AttributeErrors at runtime - which is exactly the consumer the abstract
    class exists for."""
    auth = _StaticAuth(_stored_tokens(3600), MagicMock())

    creds = await auth.async_get_credentials()
    assert creds.secret_key == "SECRET"
    assert auth.credentials_expired is False
    assert auth.mqtt_client_id == f"{IDENTITY}-ha"
    await auth.async_attach_policy()
    fake_aws["iot"].attach_policy.assert_called_once()


# -- _classify --------------------------------------------------------


def _client_error(code):
    return ClientError({"Error": {"Code": code}}, "GetCredentialsForIdentity")


def test_classify_maps_not_authorized_client_error_to_auth_error():
    err = AbstractAuth._classify(_client_error("NotAuthorizedException"))
    assert isinstance(err, ZephyrAuthError)


def test_classify_maps_too_many_requests_to_transport_error():
    """A Cognito rate limit at the hourly refresh is noise, not a
    rejection - it must not be treated as terminal."""
    err = AbstractAuth._classify(_client_error("TooManyRequestsException"))
    assert isinstance(err, ZephyrTransportError)


def test_classify_maps_plain_oserror_to_transport_error():
    err = AbstractAuth._classify(OSError("connection reset"))
    assert isinstance(err, ZephyrTransportError)


def test_classify_matches_pycognito_terminal_exceptions_by_type_name():
    """pycognito raises ForceChangePasswordException, SoftwareToken/SMS
    MFAChallengeException etc. directly - never wrapped in ClientError.
    These mean "needs the user", not "retry", so _classify must catch them
    too. Matched on type(err).__name__ (not isinstance) so this module
    never has to import pycognito's exception classes; a locally-defined
    class with the same name proves the matching is name-based."""

    class ForceChangePasswordException(Exception):
        pass

    err = AbstractAuth._classify(ForceChangePasswordException("boom"))
    assert isinstance(err, ZephyrAuthError)


# -- repr security ------------------------------------------------------


def test_zephyr_tokens_repr_hides_secrets():
    """A refresh token is good for ~30 days and alone is enough to take
    over the account; it must never land in a log or traceback via repr."""
    tokens = _stored_tokens()
    text = repr(tokens)
    assert "REFRESH" not in text
    assert tokens.refresh_token not in text
    assert tokens.id_token not in text


def test_credentials_repr_hides_secrets():
    creds = Credentials(
        "AKIA", "SECRET", "TOKEN", datetime.now(UTC) + timedelta(seconds=3600)
    )
    text = repr(creds)
    assert "SECRET" not in text
    assert "TOKEN" not in text


# -- credential cache keyed to identity ----------------------------------


async def test_credentials_cache_is_keyed_to_identity(fake_aws):
    """A subclass's tokens object can be swapped for a different account's
    underneath the cache. If the new tokens resolve to a different
    identity, the cached credentials must not be served, even though they
    are not yet expired - PROTOCOL.md section 3.3: a client ID built on the
    wrong identity connects fine and silently drops every message."""
    other_identity = "us-west-2:99999999-8888-7777-6666-555544443333"
    auth = _StaticAuth(_stored_tokens(3600), MagicMock())

    first = await auth.async_get_credentials()
    assert first.secret_key == "SECRET"
    assert fake_aws["identity"].get_credentials_for_identity.call_count == 1

    auth._static = ZephyrTokens(
        username="user@example.com",
        id_token="NEW-ID",
        refresh_token="REFRESH",
        identity_id=other_identity,
        expires_at=time.time() + 3600,
    )

    second = await auth.async_get_credentials()

    assert fake_aws["identity"].get_credentials_for_identity.call_count == 2
    assert second is not first


# -- _exchange transient-failure gating ----------------------------------


async def test_exchange_transient_failure_propagates_without_refetch(fake_aws):
    """A stored identity paired with a transient OSError (a socket blip,
    not Cognito rejecting the identity) must not trigger a second get_id
    round trip, and must surface through the ZephyrError contract rather
    than as a raw OSError."""
    fake_aws["identity"].get_credentials_for_identity.side_effect = OSError(
        "connection reset"
    )
    auth = _StaticAuth(_stored_tokens(3600), MagicMock())

    with pytest.raises(ZephyrTransportError):
        await auth.async_get_credentials()

    assert fake_aws["identity"].get_id.call_count == 0


# -- canary: the real pycognito exception --------------------------------


def test_classify_matches_the_real_pycognito_force_change_password_exception():
    """_classify matches pycognito's terminal exceptions by type NAME, not
    isinstance, so this module never has to import pycognito's exception
    classes. That means a rename or a module move in a future pycognito
    release would not be caught by type-checking - it would just silently
    stop matching and fall through to ZephyrTransportError. This test
    imports the REAL class from the installed package (not a same-named
    local stand-in, unlike
    test_classify_matches_pycognito_terminal_exceptions_by_type_name above)
    so a rename fails this test loudly instead."""
    from pycognito.exceptions import ForceChangePasswordException

    err = ForceChangePasswordException("must change password")
    result = AbstractAuth._classify(err)
    assert isinstance(result, ZephyrAuthError)


# -- identity override reset on account swap -----------------------------


class _RecordingAuth(_StaticAuth):
    """Like CredentialsAuth: records every _on_identity_refetched call."""

    def __init__(self, tokens, session):
        super().__init__(tokens, session)
        self.refetched_identities: list[str] = []

    def _on_identity_refetched(self, identity_id):
        self.refetched_identities.append(identity_id)


async def test_identity_override_resets_when_tokens_change_accounts(fake_aws):
    """A stored identity_id can go stale - the exchange rejects it and
    refetches, setting _identity_override (covered by the
    override-write-back and _on_identity_refetched-hook lines that were
    previously uncovered). If the auth's tokens are later swapped for a
    DIFFERENT account's, that override must not survive the swap: serving
    the old identity's credentials and client ID under the new tokens is
    the PROTOCOL.md section 3.3 silent-drop failure. The second
    async_get_credentials() call must do a fresh exchange and resolve to
    the new tokens' own identity, not the stale override."""
    refetched_identity = "us-west-2:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    other_account_identity = "us-west-2:99999999-8888-7777-6666-555544443333"

    # First exchange: the stored identity is rejected, forcing a refetch.
    fake_aws["identity"].get_credentials_for_identity.side_effect = [
        _client_error("ResourceNotFoundException"),
        _creds_response(),
    ]
    fake_aws["identity"].get_id.return_value = {"IdentityId": refetched_identity}

    auth = _RecordingAuth(_stored_tokens(3600), MagicMock())
    await auth.async_get_credentials()

    assert auth.identity_id == refetched_identity
    assert auth.refetched_identities == [refetched_identity]

    # Second exchange, under a different account's tokens entirely.
    fake_aws["identity"].get_credentials_for_identity.side_effect = None
    fake_aws["identity"].get_credentials_for_identity.return_value = (
        _creds_response()
    )
    fake_aws["identity"].get_id.return_value = {
        "IdentityId": other_account_identity
    }
    exchanges_before = fake_aws["identity"].get_credentials_for_identity.call_count

    auth._static = ZephyrTokens(
        username="other@example.com",
        id_token="OTHER-ID",
        refresh_token="OTHER-REFRESH",
        identity_id=other_account_identity,
        expires_at=time.time() + 3600,
    )
    await auth.async_get_credentials()

    assert (
        fake_aws["identity"].get_credentials_for_identity.call_count
        > exchanges_before
    ), "swapping to a new account's tokens must trigger a fresh exchange"
    assert auth.identity_id == other_account_identity
