"""Cognito authentication and AWS IoT policy attachment.

pycognito and boto3 are synchronous. Every blocking call here is wrapped in
asyncio.to_thread so callers get a purely async surface. Auth runs roughly
once an hour, so the thread hop costs nothing.
"""

from __future__ import annotations

import asyncio
import logging
import time
from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass, field, replace  # noqa: F401 - replace: Task 6
from datetime import UTC, datetime, timedelta
from typing import Any

import aiohttp
import boto3
from botocore import UNSIGNED
from botocore.config import Config
from botocore.exceptions import ClientError
from pycognito import Cognito

from . import const
from .const import DEFAULT_ENDPOINTS, Endpoints
from .exceptions import (
    ZephyrAuthError,
    ZephyrError,
    ZephyrPolicyError,
    ZephyrTransportError,
)

_LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class ZephyrTokens:
    """Consumer-persistable auth state.

    Primitives only - the auth documentation asks for JSON-serializable
    data so the consumer, not the library, owns storage.

    `username` is not decoration: Cognito's SECRET_HASH is
    HMAC-SHA256(client_secret, username + client_id), and pycognito
    recomputes it on every REFRESH_TOKEN_AUTH call. Tokens without it
    cannot be refreshed.

    `identity_id` is the full "us-west-2:uuid" string. The region prefix is
    load-bearing - it is what the IoT policy's
    ${cognito-identity.amazonaws.com:sub} resolves to, and it is the basis
    of the MQTT client ID. Never strip it.
    """

    username: str
    # repr=False on both: a refresh token is valid for ~30 days and is on its
    # own enough to take over the account. The default dataclass repr would
    # put it in any log line or traceback that captures this object, and
    # Home Assistant users paste logs into public issues.
    id_token: str = field(repr=False)
    refresh_token: str = field(repr=False)
    identity_id: str
    expires_at: float

    @property
    def expired(self) -> bool:
        """True once inside the refresh margin.

        Deliberately pessimistic for the same reason Credentials.expired is:
        rebuilding the MQTT socket takes time.
        """
        return time.time() >= (self.expires_at - const.REFRESH_MARGIN_SECONDS)

    def as_dict(self) -> dict[str, str | float]:
        return {
            "username": self.username,
            "id_token": self.id_token,
            "refresh_token": self.refresh_token,
            "identity_id": self.identity_id,
            "expires_at": self.expires_at,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ZephyrTokens:
        return cls(
            username=str(data["username"]),
            id_token=str(data["id_token"]),
            refresh_token=str(data["refresh_token"]),
            identity_id=str(data["identity_id"]),
            expires_at=float(data["expires_at"]),
        )


class AbstractAuth(ABC):
    """Supplies valid Zephyr cloud tokens - and everything derived from them.

    Implement `async_get_tokens()` and nothing else: the identity exchange,
    the AWS credential cache, the MQTT client ID and the IoT policy attach
    are all concrete here, built on the one abstract method. That is what
    makes the class implementable by a consumer - ZephyrClient consumes
    async_get_credentials, credentials_expired, mqtt_client_id and
    async_attach_policy, so if those lived only on CredentialsAuth, a custom
    subclass would satisfy the type checker and AttributeError at runtime.

    Only the ID token crosses the abstract boundary. The AWS credentials
    derived from it last an hour and are bound to a live socket; nothing
    about them is worth delegating or persisting.

    CredentialsAuth is the built-in implementation for the simple case.
    """

    def __init__(
        self,
        session: aiohttp.ClientSession,
        endpoints: Endpoints = DEFAULT_ENDPOINTS,
    ) -> None:
        self.session = session
        self.endpoints = endpoints
        self._credentials: Credentials | None = None
        # Set when the exchange discovers a stored identity_id is stale.
        # Runtime authority over tokens.identity_id from that point on.
        self._identity_override: str | None = None
        self._seen_tokens: ZephyrTokens | None = None
        # Serialises the identity exchange - distinct from any lock a
        # subclass uses for token acquisition.
        self._aws_lock = asyncio.Lock()

    @abstractmethod
    async def async_get_tokens(self) -> ZephyrTokens:
        """Return valid, unexpired tokens, refreshing if necessary.

        Called on every REST request and by the credential supervisor, so
        implementations should return a cached value while it is fresh.
        """

    @property
    def identity_id(self) -> str:
        """Cognito identity ID, the full region-prefixed string.

        Stable per account: the identity pool keys this on the user pool's
        immutable `sub` claim, so it survives password and email changes and
        is idempotent across calls - the natural unique key for a consumer
        that needs to identify this account.

        Available after the first async_get_credentials(), which
        ZephyrClient.async_setup() performs (and CredentialsAuth also makes
        it available after async_get_tokens()). Raises ZephyrAuthError
        before that.
        """
        if self._identity_override is not None:
            return self._identity_override
        if self._seen_tokens is None:
            raise ZephyrAuthError("no tokens acquired yet")
        return self._seen_tokens.identity_id

    @property
    def mqtt_client_id(self) -> str:
        """Identity ID plus a stable suffix.

        The IoT policy pins the client ID to the identity. Using the bare
        identity ID makes this library and the phone app evict each other.
        Derived from identity_id, never the other way around.
        """
        return f"{self.identity_id}{const.CLIENT_ID_SUFFIX}"

    @property
    def credentials_expired(self) -> bool:
        """True when the cached AWS credentials need renewing.

        A plain property on purpose. The supervisor must be able to ask "do
        these need replacing?" without async_get_credentials() renewing them
        as a side effect, which would make the answer always False and the
        socket never get rebuilt.
        """
        return self._credentials is None or self._credentials.expired

    async def async_get_credentials(self) -> Credentials:
        """AWS credentials for SigV4-presigning the MQTT WebSocket URL.

        Derived from the ID token rather than persisted: they last an hour
        and are bound to a live socket, so there is nothing worth storing.
        """
        tokens = await self.async_get_tokens()
        self._seen_tokens = tokens
        if not self.credentials_expired:
            assert self._credentials is not None
            return self._credentials
        async with self._aws_lock:
            if not self.credentials_expired:
                assert self._credentials is not None
                return self._credentials
            stored_identity = self._identity_override or tokens.identity_id
            try:
                identity_id, credentials = await asyncio.to_thread(
                    self._exchange, tokens.id_token, stored_identity
                )
            except ZephyrError:
                raise
            except Exception as err:  # noqa: BLE001
                # This is the path a restart with persisted tokens takes, so
                # a raw botocore exception here escapes the "consumers catch
                # ZephyrError" contract exactly at boot. Classify: rejection
                # is terminal, a network blip is retryable.
                raise self._classify(err) from err
            if identity_id != stored_identity:
                # The stored identity was stale and _exchange refetched it.
                # This MUST take effect: mqtt_client_id derives from it, and
                # a client ID built on a dead identity gets a connection
                # where subscribe and publish succeed and every message is
                # silently dropped (PROTOCOL.md section 3.3).
                self._identity_override = identity_id
                self._on_identity_refetched(identity_id)
            self._credentials = credentials
            return self._credentials

    async def async_attach_policy(self) -> None:
        """Bind the IoT policy to this identity.

        MUST run before connecting. An open MQTT connection does not pick up
        newly attached permissions.
        """
        credentials = await self.async_get_credentials()
        await asyncio.to_thread(self._attach, self.identity_id, credentials)

    def _on_identity_refetched(self, identity_id: str) -> None:
        """Hook: a stored identity_id was stale and has been replaced.

        Default no-op. CredentialsAuth overrides it to write the corrected
        value back into its persisted tokens. ZephyrClient also re-attaches
        the IoT policy for the new identity - see _ensure_policy.
        """

    @staticmethod
    def _classify(err: Exception) -> ZephyrError:
        """Terminal credential rejection, or retryable infrastructure noise?

        The supervisor keys terminal-vs-retry on the exception TYPE, so
        wrapping everything in ZephyrAuthError turns a DNS blip or a Cognito
        TooManyRequestsException at the hourly refresh into a permanent stop
        and a reauth prompt. Only genuine rejections may become auth errors.
        """
        code = ""
        if isinstance(err, ClientError):
            code = err.response.get("Error", {}).get("Code", "")
        if code in {
            "NotAuthorizedException",
            "UserNotFoundException",
            "UserNotConfirmedException",
            "PasswordResetRequiredException",
            "AccessDeniedException",
        }:
            return ZephyrAuthError(f"credentials rejected: {code}")
        return ZephyrTransportError(f"cloud request failed: {err}")

    # -- blocking bodies, run in a worker thread ----------------------

    def _identity_client(self):
        return boto3.client(
            "cognito-identity",
            region_name=self.endpoints.region,
            config=Config(signature_version=UNSIGNED),
        )

    def _exchange(
        self, id_token: str, identity_id: str | None
    ) -> tuple[str, Credentials]:
        """Trade an ID token for AWS credentials.

        A persisted identity_id is replayed when we have one, but it can be
        stale - and unlike an in-memory value, a bad one survives restarts.
        On failure it is discarded and refetched once before giving up.
        """
        client = self._identity_client()
        logins = {self.endpoints.provider: id_token}

        def fetch(iid: str | None) -> tuple[str, dict]:
            resolved = iid or client.get_id(
                IdentityPoolId=self.endpoints.identity_pool, Logins=logins
            )["IdentityId"]
            raw = client.get_credentials_for_identity(
                IdentityId=resolved, Logins=logins
            )["Credentials"]
            return resolved, raw

        try:
            resolved, raw = fetch(identity_id)
        except Exception:
            if identity_id is None:
                raise
            _LOGGER.debug("stored identity ID rejected; refetching")
            resolved, raw = fetch(None)

        return resolved, Credentials(
            access_key=raw["AccessKeyId"],
            # "SecretKey", not "SecretAccessKey" - differs from STS.
            secret_key=raw["SecretKey"],
            session_token=raw["SessionToken"],
            expiration=raw["Expiration"],
        )

    def _attach(self, identity_id: str, creds: Credentials) -> None:
        client = boto3.client(
            "iot",
            region_name=self.endpoints.region,
            aws_access_key_id=creds.access_key,
            aws_secret_access_key=creds.secret_key,
            aws_session_token=creds.session_token,
        )
        try:
            attached = client.list_attached_policies(target=identity_id)
            names = [p["policyName"] for p in attached.get("policies", [])]
            if const.POLICY_NAME in names:
                return
        except Exception:  # noqa: BLE001 - listing is best-effort
            _LOGGER.debug("list_attached_policies failed; attaching anyway")

        try:
            client.attach_policy(
                policyName=const.POLICY_NAME, target=identity_id
            )
        except Exception as err:  # noqa: BLE001
            # No identity ID in the message: it is a stable account
            # identifier, and exception text reaches ERROR logs users paste
            # into public issues.
            raise ZephyrPolicyError(
                f"Could not attach {const.POLICY_NAME} to this identity. "
                "Without it the MQTT connection succeeds but every message is "
                "silently dropped."
            ) from err


@dataclass(frozen=True, slots=True)
class Credentials:
    access_key: str
    # repr=False on both: these are bearer credentials good for an hour. The
    # default dataclass repr would put them in any log line or traceback
    # that captures this object, and Home Assistant users paste logs into
    # public issues.
    secret_key: str = field(repr=False)
    session_token: str = field(repr=False)
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
