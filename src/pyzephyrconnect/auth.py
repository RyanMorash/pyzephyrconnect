"""Cognito authentication and AWS IoT policy attachment.

pycognito and boto3 are synchronous. Every blocking call here is wrapped in
asyncio.to_thread so callers get a purely async surface. Auth runs roughly
once an hour, so the thread hop costs nothing.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import boto3
from botocore import UNSIGNED
from botocore.config import Config
from pycognito import Cognito

from . import const
from .exceptions import ZephyrAuthError, ZephyrPolicyError

_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class Credentials:
    access_key: str
    secret_key: str
    session_token: str
    expiration: datetime

    @property
    def expired(self) -> bool:
        """True once inside the refresh margin.

        Deliberately pessimistic: rebuilding the MQTT socket takes time, and
        credentials that expire mid-handshake fail opaquely.
        """
        margin = timedelta(seconds=const.REFRESH_MARGIN_SECONDS)
        return datetime.now(UTC) >= (self.expiration - margin)


class ZephyrAuth:
    """Owns the Cognito session and the derived AWS credentials."""

    def __init__(self, username: str, password: str) -> None:
        self._username = username
        self._password = password
        self._user: Cognito | None = None
        self._identity_id: str | None = None
        self._credentials: Credentials | None = None

    @property
    def id_token(self) -> str:
        if self._user is None:
            raise ZephyrAuthError("authenticate() has not been called")
        return self._user.id_token

    @property
    def identity_id(self) -> str:
        if self._identity_id is None:
            raise ZephyrAuthError("authenticate() has not been called")
        return self._identity_id

    @property
    def credentials(self) -> Credentials:
        if self._credentials is None:
            raise ZephyrAuthError("authenticate() has not been called")
        return self._credentials

    @property
    def mqtt_client_id(self) -> str:
        """Identity ID plus a stable suffix.

        The IoT policy pins the client ID to the identity. Using the bare
        identity ID makes this library and the phone app evict each other.
        """
        return f"{self.identity_id}{const.CLIENT_ID_SUFFIX}"

    # -- blocking bodies, run in a worker thread ----------------------

    def _srp_login(self) -> Cognito:
        user = Cognito(
            const.USER_POOL,
            const.CLIENT_ID,
            client_secret=const.CLIENT_SECRET,
            username=self._username,
            # Must be explicit; otherwise pycognito reads ambient AWS config
            # and raises a confusing ResourceNotFoundException.
            user_pool_region=const.REGION,
        )
        user.authenticate(password=self._password)
        return user

    def _exchange(self) -> tuple[str, Credentials]:
        client = boto3.client(
            "cognito-identity",
            region_name=const.REGION,
            config=Config(signature_version=UNSIGNED),
        )
        logins = {const.PROVIDER: self.id_token}
        identity_id = self._identity_id or client.get_id(
            IdentityPoolId=const.IDENTITY_POOL, Logins=logins
        )["IdentityId"]
        raw = client.get_credentials_for_identity(
            IdentityId=identity_id, Logins=logins
        )["Credentials"]
        return identity_id, Credentials(
            access_key=raw["AccessKeyId"],
            # "SecretKey", not "SecretAccessKey" - differs from STS.
            secret_key=raw["SecretKey"],
            session_token=raw["SessionToken"],
            expiration=raw["Expiration"],
        )

    def _attach(self) -> None:
        creds = self.credentials
        client = boto3.client(
            "iot",
            region_name=const.REGION,
            aws_access_key_id=creds.access_key,
            aws_secret_access_key=creds.secret_key,
            aws_session_token=creds.session_token,
        )
        try:
            attached = client.list_attached_policies(target=self.identity_id)
            names = [p["policyName"] for p in attached.get("policies", [])]
            if const.POLICY_NAME in names:
                return
        except Exception:  # noqa: BLE001 - listing is best-effort
            _LOGGER.debug("list_attached_policies failed; attaching anyway")

        try:
            client.attach_policy(
                policyName=const.POLICY_NAME, target=self.identity_id
            )
        except Exception as err:  # noqa: BLE001
            raise ZephyrPolicyError(
                f"Could not attach {const.POLICY_NAME} to {self.identity_id}. "
                "Without it the MQTT connection succeeds but every message is "
                "silently dropped."
            ) from err

    # -- async surface -------------------------------------------------

    async def authenticate(self) -> None:
        try:
            self._user = await asyncio.to_thread(self._srp_login)
            self._identity_id, self._credentials = await asyncio.to_thread(
                self._exchange
            )
        except Exception as err:  # noqa: BLE001
            raise ZephyrAuthError(f"Cognito authentication failed: {err}") from err
        _LOGGER.debug("authenticated; credentials expire %s",
                      self._credentials.expiration)

    async def refresh(self) -> None:
        """Renew tokens and re-exchange. Cheaper than a full SRP login."""
        if self._user is None:
            raise ZephyrAuthError("authenticate() has not been called")
        try:
            await asyncio.to_thread(self._user.renew_access_token)
            self._identity_id, self._credentials = await asyncio.to_thread(
                self._exchange
            )
        except Exception as err:  # noqa: BLE001
            raise ZephyrAuthError(f"Token renewal failed: {err}") from err

    async def attach_policy(self) -> None:
        """Bind the IoT policy to this identity.

        MUST run before connecting. An open MQTT connection does not pick up
        newly attached permissions.
        """
        await asyncio.to_thread(self._attach)
