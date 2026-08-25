import logging
import time
import traceback
from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from pyzephyrconnect import auth as auth_module
from pyzephyrconnect.auth import AbstractAuth, Credentials, CredentialsAuth, ZephyrTokens
from pyzephyrconnect.exceptions import (
    ZephyrAuthError,
    ZephyrPolicyError,
    ZephyrTransportError,
)

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
    cognito.refresh_token = "REFRESH-TOKEN"
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


# -- CredentialsAuth ------------------------------------------------------
#
# Ported from the deleted ZephyrAuth suite: explicit user_pool_region,
# policy-attach failure wrapping, and the accessor-raises-before-auth
# contract. The "SecretKey, not SecretAccessKey" and "attaches when
# missing" behaviours already have first-class coverage at the AbstractAuth
# level (see test_a_minimal_subclass_satisfies_the_whole_client_contract
# and the cache/exchange sections below) and are not duplicated here.


def _not_authorized():
    return ClientError(
        {"Error": {"Code": "NotAuthorizedException", "Message": "expired"}},
        "InitiateAuth",
    )


async def test_user_pool_region_is_passed_explicitly(fake_aws):
    """Without it pycognito falls back to ambient AWS config and raises a
    misleading ResourceNotFoundException."""
    auth = CredentialsAuth("u", "p", MagicMock())
    await auth.async_get_tokens()

    kwargs = auth_module.Cognito.call_args.kwargs
    assert kwargs["user_pool_region"] == "us-west-2"
    assert kwargs["client_secret"], "SRP fails without the client secret"


def test_accessor_raises_before_any_tokens_are_acquired():
    """Mirrors the deleted ZephyrAuth contract: identity-derived state
    touched before any tokens exist must fail loudly, not return stale or
    empty data."""
    auth = CredentialsAuth("u", "p", MagicMock())
    with pytest.raises(ZephyrAuthError):
        _ = auth.identity_id


def _iot_error(code):
    return ClientError({"Error": {"Code": code, "Message": "no"}}, "AttachPolicy")


async def test_attach_policy_wraps_a_refused_attach_in_zephyr_policy_error(
    fake_aws,
):
    """A genuine authorization refusal stays terminal - retrying cannot
    grant a permission the identity does not have."""
    fake_aws["iot"].attach_policy.side_effect = _iot_error("AccessDeniedException")
    auth = CredentialsAuth("u", "p", MagicMock())

    with pytest.raises(ZephyrPolicyError) as excinfo:
        await auth.async_attach_policy()

    # Still identifier-free: the message reaches ERROR logs users paste
    # into public issues, and the identity ID is a stable account handle.
    assert IDENTITY not in str(excinfo.value)


@pytest.mark.parametrize(
    "code", ["AccessDeniedException", "UnauthorizedException", "ResourceNotFoundException"]
)
async def test_the_terminal_attach_codes_stay_policy_errors(fake_aws, code):
    fake_aws["iot"].attach_policy.side_effect = _iot_error(code)
    auth = CredentialsAuth("u", "p", MagicMock())

    with pytest.raises(ZephyrPolicyError):
        await auth.async_attach_policy()


async def test_a_throttled_attach_stays_retryable(fake_aws):
    """The supervisor keys terminal-vs-retry on the exception TYPE. A
    throttled IoT endpoint during a supervisor rebuild is transient, and
    wrapping it as a policy error permanently stops every hood over a blip
    that would have cleared on the next tick."""
    fake_aws["iot"].attach_policy.side_effect = _iot_error(
        "TooManyRequestsException"
    )
    auth = CredentialsAuth("u", "p", MagicMock())

    with pytest.raises(ZephyrTransportError):
        await auth.async_attach_policy()


async def test_an_unreachable_attach_endpoint_stays_retryable(fake_aws):
    """Not every failure is a ClientError - a socket error never reaches
    botocore's error shape at all, and it is the most obviously transient
    case there is."""
    fake_aws["iot"].attach_policy.side_effect = OSError("connection reset")
    auth = CredentialsAuth("u", "p", MagicMock())

    with pytest.raises(ZephyrTransportError):
        await auth.async_attach_policy()


async def test_a_rejected_credential_at_attach_surfaces_as_an_auth_error(
    fake_aws,
):
    """_classify's own split still applies underneath: a rejected
    credential means the user must reauth, which is neither a retry nor a
    policy problem."""
    fake_aws["iot"].attach_policy.side_effect = _iot_error(
        "NotAuthorizedException"
    )
    auth = CredentialsAuth("u", "p", MagicMock())

    with pytest.raises(ZephyrAuthError):
        await auth.async_attach_policy()


async def test_srp_runs_when_no_tokens_are_supplied(fake_aws):
    auth = CredentialsAuth("user@example.com", "pw", MagicMock())
    tokens = await auth.async_get_tokens()

    fake_aws["cognito"].authenticate.assert_called_once_with(password="pw")
    assert tokens.id_token == "ID-TOKEN"
    assert tokens.username == "user@example.com"


async def test_unexpired_stored_tokens_skip_the_network_entirely(fake_aws):
    """The whole point of persistence: a restart must not re-run SRP."""
    auth = CredentialsAuth(
        "user@example.com", "pw", MagicMock(), tokens=_stored_tokens(3600)
    )
    tokens = await auth.async_get_tokens()

    assert tokens.id_token == "OLD-ID"
    fake_aws["cognito"].authenticate.assert_not_called()


async def test_expired_stored_tokens_refresh_instead_of_full_srp(fake_aws):
    auth = CredentialsAuth(
        "user@example.com", "pw", MagicMock(), tokens=_stored_tokens()
    )
    await auth.async_get_tokens()

    fake_aws["cognito"].renew_access_token.assert_called_once()
    fake_aws["cognito"].authenticate.assert_not_called()


async def test_rejected_refresh_token_falls_back_to_srp(fake_aws):
    """Cognito refresh tokens expire (30 days by default) and can be
    revoked. That must reauthenticate, not surface an error."""
    fake_aws["cognito"].renew_access_token.side_effect = _not_authorized()
    auth = CredentialsAuth(
        "user@example.com", "pw", MagicMock(), tokens=_stored_tokens()
    )
    tokens = await auth.async_get_tokens()

    fake_aws["cognito"].authenticate.assert_called_once_with(password="pw")
    assert tokens.id_token == "ID-TOKEN"


async def test_token_updater_fires_so_the_consumer_can_persist(fake_aws):
    seen = []
    auth = CredentialsAuth(
        "user@example.com", "pw", MagicMock(), token_updater=seen.append
    )
    await auth.async_get_tokens()

    assert len(seen) == 1
    assert seen[0].refresh_token


async def test_stale_identity_id_is_discarded_and_refetched_once(fake_aws):
    """A persisted identity_id survives restarts, so a wrong one becomes
    permanent. It decides the MQTT client ID and the IoT policy principal."""
    identity = fake_aws["identity"]
    identity.get_credentials_for_identity.side_effect = [
        _not_authorized(),
        _creds_response(),
    ]
    auth = CredentialsAuth(
        "user@example.com", "pw", MagicMock(), tokens=_stored_tokens(3600)
    )
    await auth.async_get_credentials()

    assert identity.get_id.call_count == 1
    assert identity.get_credentials_for_identity.call_count == 2


async def test_concurrent_callers_trigger_only_one_login(fake_aws):
    """ZephyrApi asks for tokens on every request and the supervisor asks too,
    so an expired token can be requested by several callers at once. The pool
    rate-limits (PROTOCOL.md section 3.1)."""
    import asyncio

    auth = CredentialsAuth("user@example.com", "pw", MagicMock())
    await asyncio.gather(*(auth.async_get_tokens() for _ in range(5)))

    assert fake_aws["cognito"].authenticate.call_count == 1


async def test_identity_id_is_read_not_reconstructed(fake_aws):
    """Consumers use this as a config entry's permanent unique ID, so it must
    come from the tokens rather than by stripping a suffix off a value
    derived from it."""
    auth = CredentialsAuth("user@example.com", "pw", MagicMock())
    await auth.async_get_tokens()

    assert auth.identity_id == IDENTITY
    assert auth.mqtt_client_id == f"{auth.identity_id}-ha"


async def test_identity_id_survives_a_refresh(fake_aws):
    """Password changes and token refreshes must not change the account key -
    the identity pool keys this on the user pool's immutable sub claim."""
    auth = CredentialsAuth(
        "user@example.com", "pw", MagicMock(), tokens=_stored_tokens()
    )
    first = (await auth.async_get_tokens()).identity_id
    auth._tokens = _stored_tokens()          # force another refresh
    assert (await auth.async_get_tokens()).identity_id == first


async def test_mqtt_client_id_keeps_the_region_prefix_and_suffix(fake_aws):
    """The policy pins client ID to identity; the suffix is what lets this
    coexist with the phone app instead of evicting it."""
    auth = CredentialsAuth("user@example.com", "pw", MagicMock())
    await auth.async_get_tokens()

    assert auth.mqtt_client_id == f"{IDENTITY}-ha"
    assert auth.mqtt_client_id.startswith("us-west-2:")


class _StaticAuth(AbstractAuth):
    """The documented consumer path: implement one method, nothing else."""

    def __init__(self, tokens, session):
        super().__init__(session)
        self._static = tokens

    async def async_get_tokens(self):
        return self._static


async def test_a_minimal_subclass_satisfies_the_whole_client_contract(fake_aws):
    """ZephyrClient consumes async_get_credentials, credentials_expired,
    credentials_generation, mqtt_client_id and async_attach_policy. If any of
    those live only on CredentialsAuth, a custom AbstractAuth satisfies the
    type checker and AttributeErrors at runtime - which is exactly the
    consumer the abstract class exists for."""
    auth = _StaticAuth(_stored_tokens(3600), MagicMock())

    creds = await auth.async_get_credentials()
    assert creds.secret_key == "SECRET"
    assert auth.credentials_expired is False
    # An int the supervisor can compare, on the ABSTRACT class: the socket
    # rebuild is keyed on it, so a subclass without one silently disables
    # every reconnect.
    assert isinstance(auth.credentials_generation, int)
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


async def test_throttled_exchange_is_not_retried_with_an_extra_get_id(fake_aws):
    """The refetch used to fire on ANY ClientError, so Cognito throttling
    the exchange immediately spent a second request on get_id - doubling
    the load against the exact rate limit _classify deliberately treats as
    retryable. Only codes that mean the stored identity itself is wrong may
    trigger the refetch."""
    fake_aws["identity"].get_credentials_for_identity.side_effect = _client_error(
        "TooManyRequestsException"
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


# -- _acquire cache invariants and refresh-failure classification --------


async def test_acquire_populates_the_credentials_cache_so_get_credentials_skips_reexchange(
    fake_aws,
):
    """_acquire runs its own _exchange but, before this fix, never wrote
    _credentials_for or cleared _identity_override - so async_get_credentials()'s
    cache check (_credentials_for == current_identity) could never match and
    every call performed a second, pointless exchange right after the first."""
    auth = CredentialsAuth("user@example.com", "pw", MagicMock())
    await auth.async_get_tokens()
    calls_after_acquire = fake_aws["identity"].get_credentials_for_identity.call_count

    await auth.async_get_credentials()

    assert (
        fake_aws["identity"].get_credentials_for_identity.call_count
        == calls_after_acquire
    )


async def test_replacing_the_cached_credentials_moves_the_generation(fake_aws):
    """The counter must move at EVERY site that replaces _credentials.

    _acquire is the one that made expiry an unreliable rebuild trigger:
    ZephyrApi asks for tokens on every REST request, so a poll lands here
    and swaps the credentials out from under sockets presigned against the
    old ones - leaving a cache that looks fresh and signatures that are not.
    A cached read must NOT move it, or every supervisor tick would rebuild."""
    auth = CredentialsAuth("user@example.com", "pw", MagicMock())
    assert auth.credentials_generation == 0

    await auth.async_get_tokens()             # the REST-driven refresh path
    after_acquire = auth.credentials_generation
    assert after_acquire > 0

    await auth.async_get_credentials()        # served from the cache
    assert auth.credentials_generation == after_acquire

    # Tokens still fresh, credentials gone: this drops through to the
    # exchange inside async_get_credentials - the OTHER assignment site,
    # which has to move the counter too or a supervisor-driven renewal
    # would leave every socket looking current.
    auth._credentials = None
    await auth.async_get_credentials()
    assert auth.credentials_generation == after_acquire + 1


async def test_second_stale_identity_clears_a_leftover_override(fake_aws):
    """A stale _identity_override left over from an earlier exchange must not
    survive a later _acquire that resolves its own, different corrected
    identity - otherwise identity_id/mqtt_client_id keep serving the OLDER
    override forever while the tokens themselves move on, which is the
    PROTOCOL.md section 3.3 silent-drop failure applied twice in a row."""
    corrected = "us-west-2:corrected"
    identity = fake_aws["identity"]
    identity.get_credentials_for_identity.side_effect = [
        _client_error("ResourceNotFoundException"),
        _creds_response(),
    ]
    identity.get_id.return_value = {"IdentityId": corrected}
    auth = CredentialsAuth(
        "user@example.com", "pw", MagicMock(), tokens=_stored_tokens()
    )
    auth._identity_override = "us-west-2:old-override"

    await auth.async_get_tokens()

    assert auth.identity_id == corrected


async def test_refresh_path_retains_stored_refresh_token_when_cognito_omits_one(
    fake_aws,
):
    """renew_access_token does not necessarily rotate the refresh token, so
    pycognito can leave Cognito.refresh_token unset after a refresh. The
    previously stored refresh token must be carried forward, not dropped -
    losing it silently breaks the NEXT refresh."""
    fake_aws["cognito"].refresh_token = None
    stored = _stored_tokens()
    auth = CredentialsAuth("user@example.com", "pw", MagicMock(), tokens=stored)

    tokens = await auth.async_get_tokens()

    assert tokens.refresh_token == stored.refresh_token


async def test_transient_refresh_failure_raises_instead_of_burning_an_srp_login(
    fake_aws,
):
    """A DNS blip, timeout or throttling during renew_access_token is not
    Cognito rejecting the refresh token - it must surface as a retryable
    ZephyrTransportError, not silently fall back to a rate-limited SRP login
    (PROTOCOL.md section 3.1) that also misreports the actual cause."""
    fake_aws["cognito"].renew_access_token.side_effect = OSError("connection reset")
    auth = CredentialsAuth(
        "user@example.com", "pw", MagicMock(), tokens=_stored_tokens()
    )

    with pytest.raises(ZephyrTransportError):
        await auth.async_get_tokens()

    fake_aws["cognito"].authenticate.assert_not_called()


async def test_refresh_failure_log_is_scrubbed_of_the_rejection_detail(
    fake_aws, caplog
):
    """The DEBUG refresh-failure log must record only the exception TYPE,
    never its message - botocore's ClientError echoes the Message field
    back verbatim, and that field can carry a secret. Drives the same
    NotAuthorizedException -> SRP-fallback path as
    test_rejected_refresh_token_falls_back_to_srp, but asserts on the log
    instead of the outcome, to catch a future edit that logs str(err)."""
    fake_aws["cognito"].renew_access_token.side_effect = ClientError(
        {
            "Error": {
                "Code": "NotAuthorizedException",
                "Message": "refresh token invalid: SECRET-SENTINEL",
            }
        },
        "InitiateAuth",
    )
    auth = CredentialsAuth(
        "user@example.com", "pw", MagicMock(), tokens=_stored_tokens()
    )

    with caplog.at_level(logging.DEBUG, logger="pyzephyrconnect.auth"):
        await auth.async_get_tokens()

    assert "refresh failed" in caplog.text
    assert "SECRET-SENTINEL" not in caplog.text


async def test_refresh_uses_the_username_that_minted_the_refresh_token(fake_aws):
    """SECRET_HASH is HMAC(client_secret, username + client_id) and
    pycognito recomputes it on every REFRESH_TOKEN_AUTH call, so the refresh
    must use the username the stored refresh token was minted under - the
    documented reason ZephyrTokens carries one. Building Cognito from the
    constructor argument instead made the field decorative and sent a hash
    Cognito rejects whenever a consumer rebuilt the object with a
    differently spelled username while restoring the same tokens."""
    stored = ZephyrTokens(
        username="old@example.com",
        id_token="OLD-ID",
        refresh_token="REFRESH",
        identity_id=IDENTITY,
        expires_at=time.time() - 1,
    )
    auth = CredentialsAuth("new@example.com", "pw", MagicMock(), tokens=stored)

    tokens = await auth.async_get_tokens()

    fake_aws["cognito"].renew_access_token.assert_called_once()
    assert auth_module.Cognito.call_args.kwargs["username"] == "old@example.com"
    # And the tokens the refresh produced still carry it, so the NEXT
    # refresh reproduces the same hash instead of drifting back.
    assert tokens.username == "old@example.com"


async def test_srp_minted_tokens_carry_the_constructor_username(fake_aws):
    """The counterpart: an SRP login authenticates as the username this
    object was constructed with, so its tokens must record that one, not
    whatever a discarded stored record happened to hold."""
    fake_aws["cognito"].renew_access_token.side_effect = _not_authorized()
    stored = ZephyrTokens(
        username="old@example.com",
        id_token="OLD-ID",
        refresh_token="REFRESH",
        identity_id=IDENTITY,
        expires_at=time.time() - 1,
    )
    auth = CredentialsAuth("new@example.com", "pw", MagicMock(), tokens=stored)

    tokens = await auth.async_get_tokens()

    fake_aws["cognito"].authenticate.assert_called_once_with(password="pw")
    assert tokens.username == "new@example.com"


async def test_refresh_path_replays_the_stored_identity_without_refetching(fake_aws):
    """The refresh path passes stored.identity_id into _exchange, so a
    healthy stored identity must be reused as-is - a get_id round trip here
    would mean the refresh path is refetching identities it has no reason
    to doubt."""
    auth = CredentialsAuth(
        "user@example.com", "pw", MagicMock(), tokens=_stored_tokens()
    )
    await auth.async_get_tokens()

    assert fake_aws["identity"].get_id.call_count == 0


def _sentinel_client_error(code, operation):
    """A botocore error whose MESSAGE carries a value that must never be
    rendered. botocore echoes request parameters and identifiers back in
    Message, and str(ClientError) interpolates it."""
    return ClientError(
        {"Error": {"Code": code, "Message": "context: SECRET-SENTINEL"}},
        operation,
    )


async def test_srp_classification_traceback_omits_the_botocore_message(fake_aws):
    """_classify scrubs the raw message on purpose. Chaining the original
    with `from err` puts it straight back: the supervisor's
    _LOGGER.exception renders the whole chain at ERROR, and that is what
    users paste into public issues. `from None` is what keeps the
    scrubbing real - while the type name and AWS code survive, so the
    failure is still diagnosable."""
    fake_aws["cognito"].authenticate.side_effect = _sentinel_client_error(
        "TooManyRequestsException", "InitiateAuth"
    )
    auth = CredentialsAuth("u", "p", MagicMock())

    with pytest.raises(ZephyrTransportError) as excinfo:
        await auth.async_get_tokens()

    rendered = "".join(traceback.format_exception(excinfo.value))
    assert "SECRET-SENTINEL" not in rendered
    # Diagnosability is pinned too - scrubbing must not become silence.
    assert "TooManyRequestsException" in rendered
    assert "ClientError" in rendered


async def test_attach_policy_error_traceback_omits_the_botocore_message(fake_aws):
    """Same reasoning at the ZephyrPolicyError site: its message is
    deliberately identifier-free, and a chained cause would render the
    identity ID and request context the wording exists to withhold."""
    fake_aws["iot"].attach_policy.side_effect = _sentinel_client_error(
        "AccessDeniedException", "AttachPolicy"
    )
    auth = CredentialsAuth("u", "p", MagicMock())

    with pytest.raises(ZephyrPolicyError) as excinfo:
        await auth.async_attach_policy()

    rendered = "".join(traceback.format_exception(excinfo.value))
    assert "SECRET-SENTINEL" not in rendered
    assert IDENTITY not in rendered
    # The actionable guidance still reaches the log.
    assert "silently dropped" in rendered
