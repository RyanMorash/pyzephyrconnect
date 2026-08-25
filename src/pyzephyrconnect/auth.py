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
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
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
    ZephyrDataError,
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
        try:
            return cls(
                username=str(data["username"]),
                id_token=str(data["id_token"]),
                refresh_token=str(data["refresh_token"]),
                identity_id=str(data["identity_id"]),
                expires_at=float(data["expires_at"]),
            )
        except (KeyError, TypeError, ValueError) as err:
            raise ZephyrDataError("persisted tokens are malformed") from err


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
        # Identity the cached _credentials were minted for. An AbstractAuth
        # instance is documented as one account, but nothing stops a
        # subclass from swapping in a different account's tokens underneath
        # it (e.g. a config-entry reload reusing the same object) - without
        # this, async_get_credentials would keep serving the old identity's
        # cached credentials as "not expired" instead of noticing the swap
        # and re-exchanging. That is the PROTOCOL.md section 3.3 failure
        # mode: a client ID built on the wrong identity connects fine and
        # silently drops every message.
        self._credentials_for: str | None = None
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

        Deliberately NOT identity-aware: the supervisor calls this without
        tokens in hand, so it can only read expiry. async_get_credentials()
        is what actually gates the cache on identity, via _credentials_for.
        """
        return self._credentials is None or self._credentials.expired

    async def async_get_credentials(self) -> Credentials:
        """AWS credentials for SigV4-presigning the MQTT WebSocket URL.

        Derived from the ID token rather than persisted: they last an hour
        and are bound to a live socket, so there is nothing worth storing.
        """
        tokens = await self.async_get_tokens()
        if (
            self._seen_tokens is not None
            and self._seen_tokens.identity_id != tokens.identity_id
        ):
            # The tokens now name a different identity than before. A stale
            # _identity_override from the PREVIOUS tokens must not mask the
            # change - serving the old identity's credentials and client ID
            # is the PROTOCOL.md section 3.3 silent-drop failure.
            self._identity_override = None
        self._seen_tokens = tokens
        current_identity = self._identity_override or tokens.identity_id
        if not self.credentials_expired and self._credentials_for == current_identity:
            assert self._credentials is not None
            return self._credentials
        async with self._aws_lock:
            # Re-resolve: another waiter may have updated _identity_override
            # or refreshed _credentials while this coroutine was blocked.
            current_identity = self._identity_override or tokens.identity_id
            if (
                not self.credentials_expired
                and self._credentials_for == current_identity
            ):
                assert self._credentials is not None
                return self._credentials
            stored_identity = current_identity
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
            self._credentials_for = identity_id
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
        # pycognito raises its own terminal exceptions that never go through
        # botocore/ClientError - a forced password change or an MFA
        # challenge means "needs the user", not "retry". Matched on the
        # type name (not isinstance) - not to avoid importing pycognito
        # (this module already imports Cognito from it), but because
        # pycognito's exception classes have moved between modules/versions
        # in its history, and a name string survives that churn while an
        # import path does not. test_auth.py has a canary test that
        # imports the real class and asserts against it directly, so a
        # rename shows up as a loud test failure instead of a silent
        # classification gap.
        #
        # TokenVerificationException is deliberately NOT in this set: it
        # can be raised for a transient JWKS fetch failure, not just a bad
        # token, so it stays retryable here. A genuinely invalid token
        # still surfaces terminally - as a ClientError from the next
        # Cognito call - so nothing is lost by not treating it as terminal
        # at this layer.
        if type(err).__name__ in {
            "ForceChangePasswordException",
            "SoftwareTokenMFAChallengeException",
            "SMSMFAChallengeException",
            "MFAChallengeException",
        }:
            return ZephyrAuthError(f"credentials rejected: {type(err).__name__}")
        # No raw exception text here: botocore's ParamValidationError (and
        # others) can echo parameter values back in the message, which may
        # include tokens - and this lands in ERROR logs users paste into
        # public issues. The AWS error code itself is not a secret, so it
        # is kept - "cloud request failed: ClientError" alone collapsed
        # every botocore failure into one indistinguishable message.
        detail = f" ({code})" if code else ""
        return ZephyrTransportError(
            f"cloud request failed: {type(err).__name__}{detail}"
        )

    # -- blocking bodies, run in a worker thread ----------------------

    def _identity_client(self) -> Any:
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
        except Exception as err:
            if not identity_id:
                # Nothing stored to have been stale - give up immediately.
                raise
            if not isinstance(err, ClientError):
                # A transient error (socket, timeout, DNS) rather than
                # Cognito rejecting the stored identity. Refetching would
                # not help and only spends a second round trip before the
                # caller's own retry - propagate it as-is.
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


class CredentialsAuth(AbstractAuth):
    """Built-in auth: SRP login, with refresh-token reuse.

    pycognito and boto3 are synchronous. Every blocking call is wrapped in
    asyncio.to_thread so callers get a purely async surface. renew_access_token
    also performs JWKS verification, which is a network call - it must stay
    in the worker thread.
    """

    def __init__(
        self,
        username: str,
        password: str,
        session: aiohttp.ClientSession,
        *,
        tokens: ZephyrTokens | None = None,
        token_updater: Callable[[ZephyrTokens], None] | None = None,
        endpoints: Endpoints = DEFAULT_ENDPOINTS,
    ) -> None:
        super().__init__(session, endpoints)
        self._username = username
        self._password = password
        self._tokens = tokens
        self._token_updater = token_updater
        self._user: Cognito | None = None
        # Restored tokens make identity_id readable immediately.
        self._seen_tokens = tokens
        # Serialises token acquisition. Without it, concurrent callers each
        # run a full SRP login against a pool that rate-limits (PROTOCOL.md
        # section 3.1), and ZephyrApi asks for tokens on every request.
        # Distinct from the inherited _aws_lock guarding the exchange.
        self._lock = asyncio.Lock()

    def _on_identity_refetched(self, identity_id: str) -> None:
        """Persist a corrected identity into the stored tokens.

        The base class already routes mqtt_client_id through its override;
        this makes the correction survive a restart instead of being
        rediscovered by a failed exchange every time.
        """
        if self._tokens is not None:
            self._tokens = replace(self._tokens, identity_id=identity_id)
            if self._token_updater is not None:
                self._token_updater(self._tokens)

    # -- blocking bodies, run in a worker thread ----------------------

    def _cognito(self, *, refresh_token: str | None = None) -> Cognito:
        return Cognito(
            self.endpoints.user_pool,
            self.endpoints.client_id,
            client_secret=self.endpoints.client_secret,
            username=self._username,
            refresh_token=refresh_token,
            # Must be explicit; otherwise pycognito reads ambient AWS config
            # and raises a confusing ResourceNotFoundException.
            user_pool_region=self.endpoints.region,
        )

    def _srp_login(self) -> Cognito:
        user = self._cognito()
        user.authenticate(password=self._password)
        return user

    def _refresh(self, refresh_token: str) -> Cognito:
        user = self._cognito(refresh_token=refresh_token)
        user.renew_access_token()
        return user

    # _identity_client, _exchange and _attach are inherited from
    # AbstractAuth: they operate on tokens and endpoints, nothing
    # Cognito-login-specific, and hoisting them is what makes AbstractAuth
    # implementable by consumers.

    # -- async surface -------------------------------------------------

    async def async_get_tokens(self) -> ZephyrTokens:
        if self._tokens is not None and not self._tokens.expired:
            return self._tokens
        async with self._lock:
            # Re-check under the lock: whoever held it may have refreshed
            # while we waited, and a second login would be wasted and
            # rate-limitable.
            if self._tokens is not None and not self._tokens.expired:
                return self._tokens
            return await self._acquire()

    async def _acquire(self) -> ZephyrTokens:
        """Refresh or log in. Caller holds self._lock."""
        stored = self._tokens
        user: Cognito | None = None

        if stored is not None:
            try:
                user = await asyncio.to_thread(self._refresh, stored.refresh_token)
            except Exception as err:  # noqa: BLE001
                # Refresh tokens expire (30 days by default) and can be
                # revoked - that must reauthenticate rather than surface an
                # error. But a DNS blip, timeout or throttling during the
                # refresh call is not a rejection, and burning a rate-limited
                # SRP login (PROTOCOL.md section 3.1) to paper over a
                # transient failure both wastes it and misreports the cause
                # to the caller. Classify first: only a genuine
                # ZephyrAuthError falls through to SRP below.
                _LOGGER.debug("refresh failed (%s)", type(err).__name__)
                classified = self._classify(err)
                if not isinstance(classified, ZephyrAuthError):
                    raise classified from err

        if user is None:
            try:
                user = await asyncio.to_thread(self._srp_login)
            except Exception as err:  # noqa: BLE001
                # Classify - a DNS failure or pool throttling here must NOT
                # become ZephyrAuthError, which the supervisor treats as
                # terminal and the consumer maps to a reauth prompt.
                raise self._classify(err) from err

        self._user = user
        try:
            identity_id, credentials = await asyncio.to_thread(
                self._exchange,
                user.id_token,
                stored.identity_id if stored is not None else None,
            )
        except ZephyrError:
            raise
        except Exception as err:  # noqa: BLE001
            raise self._classify(err) from err

        self._credentials = credentials
        self._credentials_for = identity_id
        # The tokens built two lines below carry the authoritative identity
        # from THIS exchange, so any older override is stale. Keeping it
        # lets identity_id/mqtt_client_id diverge from the tokens after two
        # successive stale-identity events - the PROTOCOL.md section 3.3
        # silent-drop failure.
        self._identity_override = None
        self._tokens = ZephyrTokens(
            username=self._username,
            id_token=user.id_token,
            refresh_token=user.refresh_token or (
                stored.refresh_token if stored else ""
            ),
            identity_id=identity_id,
            # The AWS credential expiry stands in for the token expiry.
            # Both are one hour from this same exchange, so they track - but
            # that is an assumption, not a guarantee. If they ever diverge,
            # read the `exp` claim off the ID token instead.
            expires_at=credentials.expiration.timestamp(),
        )
        self._seen_tokens = self._tokens
        if self._token_updater is not None:
            self._token_updater(self._tokens)
        return self._tokens
