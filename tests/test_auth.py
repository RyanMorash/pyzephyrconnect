from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest

from pyzephyrconnect import auth as auth_module
from pyzephyrconnect.auth import Credentials, ZephyrAuth
from pyzephyrconnect.exceptions import ZephyrAuthError

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
