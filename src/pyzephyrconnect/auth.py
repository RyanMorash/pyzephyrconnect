"""Cognito authentication and AWS IoT policy attachment.

pycognito and boto3 are synchronous. Every blocking call here is wrapped in
asyncio.to_thread so callers get a purely async surface. Auth runs roughly
once an hour, so the thread hop costs nothing.
"""

from __future__ import annotations

import asyncio
import logging
import math
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

    Attributes:
        username: Username the tokens were minted under. Not decoration:
            Cognito's SECRET_HASH is HMAC-SHA256(client_secret,
            username + client_id), and pycognito recomputes it on every
            REFRESH_TOKEN_AUTH call. Tokens without it cannot be
            refreshed.
        id_token: Cognito ID token, presented in the Logins map of the
            identity exchange.
        refresh_token: Long-lived token used to renew the ID token
            without a fresh SRP login.
        identity_id: The full "us-west-2:uuid" string. The region prefix
            is load-bearing - it is what the IoT policy's
            ${cognito-identity.amazonaws.com:sub} resolves to, and it is
            the basis of the MQTT client ID. Never strip it.
        expires_at: POSIX timestamp of token expiry; `expired` applies
            the refresh margin against it.
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
        """Whether the tokens are inside the refresh margin.

        Deliberately pessimistic for the same reason Credentials.expired is:
        rebuilding the MQTT socket takes time.
        """
        return time.time() >= (self.expires_at - const.REFRESH_MARGIN_SECONDS)

    def as_dict(self) -> dict[str, str | float]:
        """Returns the JSON-serializable form for the consumer to persist."""
        return {
            "username": self.username,
            "id_token": self.id_token,
            "refresh_token": self.refresh_token,
            "identity_id": self.identity_id,
            "expires_at": self.expires_at,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ZephyrTokens:
        """Rebuilds from restored storage, validating rather than coercing.

        str() coercion was worse than no validation: a corrupted None
        became the literal "None", which is a perfectly usable string that
        survives every check here and fails much later and far away - as a
        SECRET_HASH Cognito rejects, or as an MQTT client ID whose messages
        AWS IoT silently drops. Corruption has to fail here, at the
        boundary the README tells consumers to call.

        The four string fields are checked as-is, never converted.
        `expires_at` alone is converted: anything float() accepts,
        including a numeric string, is taken, and the result must be
        finite.

        Args:
            data: Mapping previously produced by as_dict and restored
                from the consumer's storage.

        Returns:
            The validated tokens.

        Raises:
            ZephyrDataError: If a string field is missing, empty, or not
                a str, or if expires_at is missing, cannot be converted
                to float, or converts to a non-finite value.
        """
        try:
            values: dict[str, str] = {}
            for key in ("username", "id_token", "refresh_token", "identity_id"):
                value = data[key]
                if not isinstance(value, str) or not value:
                    # The field NAME only - the value may be a token.
                    raise ValueError(key)
                values[key] = value
            try:
                # Only the CONVERSION is guarded. A missing key raises
                # KeyError, which this except does not name, so it falls
                # through to the outer handler exactly as before.
                #
                # The re-raise below carries the field NAME alone, and
                # `from None`: float("<garbage>") puts the raw value into its
                # own message, and the outer `from err` would then thread
                # that value through the ZephyrDataError's chained traceback
                # - persisted token material printed in full by any consumer
                # that logs the exception.
                expires_at = float(data["expires_at"])
            except (TypeError, ValueError, OverflowError):
                # OverflowError: a persisted expires_at can be an
                # arbitrarily large int (e.g. corrupted storage), and
                # float() on an int too large to represent raises
                # OverflowError rather than ValueError. `from None` still
                # applies - the huge value must not enter the message.
                raise ValueError("expires_at") from None
            if not math.isfinite(expires_at):
                # NaN compares False against everything, so `expired` would
                # be permanently False and the tokens never refreshed -
                # the socket then dies on credentials nothing renews.
                raise ValueError("expires_at")
            return cls(expires_at=expires_at, **values)
        except (KeyError, TypeError, ValueError) as err:
            raise ZephyrDataError("persisted tokens are malformed") from err


class AbstractAuth(ABC):
    """Supplies valid Zephyr cloud tokens - and everything derived from them.

    Implement `async_get_tokens()` and nothing else: the identity exchange,
    the AWS credential cache, the MQTT client ID and the IoT policy attach
    are all concrete here, built on the one abstract method. That is what
    makes the class implementable by a consumer - ZephyrClient consumes
    async_get_credentials, async_get_presign_credentials,
    credentials_expired, credentials_generation, mqtt_client_id and
    async_attach_policy, so if those lived only on CredentialsAuth, a
    custom subclass would satisfy the type checker and AttributeError at
    runtime.

    Only the ID token crosses the abstract boundary. The AWS credentials
    derived from it last an hour and are bound to a live socket; nothing
    about them is worth delegating or persisting.

    CredentialsAuth is the built-in implementation for the simple case.

    Attributes:
        session: The aiohttp client session, owned by the consumer.
        endpoints: Cloud endpoint set every Cognito and IoT call runs
            against.
        credentials_generation: Monotonic counter identifying the current
            AWS credentials, incremented at every site that installs a
            fresh set. A socket presigned under an older generation
            carries a SigV4 signature that dies at the old expiry, no
            matter how fresh the cache looks now.
    """

    def __init__(
        self,
        session: aiohttp.ClientSession,
        endpoints: Endpoints = DEFAULT_ENDPOINTS,
    ) -> None:
        """Stores the session and endpoints; all derived state starts empty.

        Args:
            session: aiohttp client session, owned by the consumer.
            endpoints: Cloud endpoint set to authenticate against.
        """
        self.session = session
        self.endpoints = endpoints
        self._credentials: Credentials | None = None
        # Monotonic counter identifying the CURRENT AWS credentials.
        # Incremented at every site that assigns a fresh self._credentials,
        # and read by the refresh supervisor: a socket presigned under an
        # older generation carries a SigV4 signature that dies at the OLD
        # expiry, no matter how fresh the cache looks now. Expiry alone
        # cannot express that - ZephyrApi calls async_get_tokens() on every
        # REST request and CredentialsAuth._acquire replaces the cached
        # credentials as a side effect, so a REST call can refresh them
        # without any socket being re-presigned.
        self.credentials_generation: int = 0
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
        """Returns valid, unexpired tokens, refreshing if necessary.

        Called on every REST request and by the credential supervisor, so
        implementations should return a cached value while it is fresh.
        """

    @property
    def identity_id(self) -> str:
        """The Cognito identity ID, the full region-prefixed string.

        Stable per account: the identity pool keys this on the user pool's
        immutable `sub` claim, so it survives password and email changes and
        is idempotent across calls - the natural unique key for a consumer
        that needs to identify this account.

        Available after the first async_get_credentials(), which
        ZephyrClient.async_setup() performs (and CredentialsAuth also makes
        it available after async_get_tokens()).

        Raises:
            ZephyrAuthError: If no tokens have been acquired yet.
        """
        if self._identity_override is not None:
            return self._identity_override
        if self._seen_tokens is None:
            raise ZephyrAuthError("no tokens acquired yet")
        return self._seen_tokens.identity_id

    @property
    def mqtt_client_id(self) -> str:
        """The identity ID plus a stable suffix.

        The IoT policy pins the client ID to the identity. Using the bare
        identity ID makes this library and the phone app evict each other.
        Derived from identity_id, never the other way around.

        Raises:
            ZephyrAuthError: If no tokens have been acquired yet (via
                identity_id).
        """
        return f"{self.identity_id}{const.CLIENT_ID_SUFFIX}"

    @property
    def credentials_expired(self) -> bool:
        """Whether the cached AWS credentials need renewing.

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
        """Returns AWS credentials for SigV4-presigning the MQTT WebSocket URL.

        Derived from the ID token rather than persisted: they last an hour
        and are bound to a live socket, so there is nothing worth storing.

        Returns:
            The cached credentials while fresh and minted for the current
            identity; otherwise a freshly exchanged set.

        Raises:
            ZephyrAuthError: If the cloud rejects the credentials
                terminally.
            ZephyrTransportError: If the exchange fails for a retryable
                infrastructure reason.
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
                #
                # from None, deliberately: the classified error carries the
                # type name and AWS code; chaining the original would render
                # its message - which can embed request parameters and
                # identifiers - in supervisor ERROR tracebacks that users
                # paste into public issues. (Same reasoning at every
                # classification site in this module.)
                raise self._classify(err) from None
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
            # Every socket presigned before this line is now a generation
            # behind and still signed against the credentials just replaced.
            self.credentials_generation += 1
            return self._credentials

    async def async_get_presign_credentials(self) -> tuple[Credentials, int]:
        """Returns the current credentials and the generation they belong to.

        Read as a consistent pair: the two attribute reads below are
        consecutive sync statements on the event loop, atomic with respect
        to any concurrent coroutine - unlike reading the generation after
        an await, which can pair a newer counter with older credentials
        and leave a socket the supervisor believes is current dying at the
        older credentials' expiry.

        Returns:
            The credentials and the generation counter value they were
            installed under, guaranteed consistent with each other.

        Raises:
            ZephyrAuthError: If the cloud rejects the credentials
                terminally.
            ZephyrTransportError: If the exchange fails for a retryable
                infrastructure reason.
        """
        while True:
            creds = await self.async_get_credentials()
            if self._credentials is creds:
                return creds, self.credentials_generation
            # Replaced mid-flight by a concurrent refresh; loop converges
            # on the newer pair immediately.

    async def async_attach_policy(self) -> None:
        """Binds the IoT policy to this identity.

        MUST run before connecting. An open MQTT connection does not pick up
        newly attached permissions.

        Raises:
            ZephyrPolicyError: If IoT refuses the attach itself.
            ZephyrAuthError: If the cloud rejects the credentials
                terminally.
            ZephyrTransportError: If a retryable infrastructure failure
                interrupts the exchange or the attach.
        """
        credentials = await self.async_get_credentials()
        await asyncio.to_thread(self._attach, self.identity_id, credentials)

    def _on_identity_refetched(self, identity_id: str) -> None:
        """Hook called when a stored identity_id was stale and got replaced.

        Default no-op. CredentialsAuth overrides it to write the corrected
        value back into its persisted tokens. ZephyrClient also re-attaches
        the IoT policy for the new identity - see _ensure_policy.

        Args:
            identity_id: The freshly fetched replacement identity ID.
        """

    @staticmethod
    def _classify(err: Exception) -> ZephyrError:
        """Classifies a failure as terminal rejection or retryable noise.

        The supervisor keys terminal-vs-retry on the exception TYPE, so
        wrapping everything in ZephyrAuthError turns a DNS blip or a Cognito
        TooManyRequestsException at the hourly refresh into a permanent stop
        and a reauth prompt. Only genuine rejections may become auth errors.

        Args:
            err: The exception a pycognito or botocore call raised.

        Returns:
            ZephyrAuthError for a genuine credential rejection,
            ZephyrTransportError for everything else.
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
        """Builds an unsigned cognito-identity client for the exchange.

        UNSIGNED because get_id and get_credentials_for_identity
        authenticate through the Logins token map, not SigV4 - there are no
        AWS credentials to sign with until this exchange produces them.
        """
        return boto3.client(
            "cognito-identity",
            region_name=self.endpoints.region,
            config=Config(signature_version=UNSIGNED),
        )

    def _exchange(
        self, id_token: str, identity_id: str | None
    ) -> tuple[str, Credentials]:
        """Trades an ID token for AWS credentials.

        A persisted identity_id is replayed when we have one, but it can be
        stale - and unlike an in-memory value, a bad one survives restarts.
        Only a failure that actually means "this identity is wrong"
        discards it and refetches once; everything else propagates to
        _classify.

        Args:
            id_token: Cognito ID token to present in the Logins map.
            identity_id: Previously stored identity ID to replay, or None
                to have Cognito resolve one.

        Returns:
            The resolved identity ID and the freshly minted credentials.
        """
        client = self._identity_client()
        logins = {self.endpoints.provider: id_token}

        def fetch(iid: str | None) -> tuple[str, dict]:
            """Resolves `iid` if None, then mints raw credentials for it."""
            resolved = (
                iid
                or client.get_id(
                    IdentityPoolId=self.endpoints.identity_pool, Logins=logins
                )["IdentityId"]
            )
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
            if err.response.get("Error", {}).get("Code", "") not in {
                # The only two codes that mean the STORED IDENTITY is the
                # problem: it was deleted, or it is no longer bound to this
                # login. Every other code is about the request, not the
                # identity - and TooManyRequestsException is the one that
                # made this actively harmful, because an immediate get_id
                # DOUBLES the request count against the very throttle
                # _classify deliberately treats as retryable.
                "ResourceNotFoundException",
                "NotAuthorizedException",
            }:
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
        """Binds the policy, classifying the failure rather than assuming one.

        Only a genuine authorization/policy refusal is terminal. Every other
        failure - a throttled or unreachable IoT endpoint during a
        supervisor rebuild, a rejected credential - goes through _classify,
        because a blanket ZephyrPolicyError here keys the supervisor's
        terminal-vs-retry decision to "stop" and permanently kills every
        hood over what is usually a transient blip.

        Args:
            identity_id: Identity to attach the policy to.
            creds: AWS credentials that sign the IoT calls.

        Raises:
            ZephyrPolicyError: If IoT refused the attach itself - the
                caller may not attach, or the policy does not exist.
            ZephyrAuthError: If the credentials were rejected terminally.
            ZephyrTransportError: If the attach failed for a retryable
                infrastructure reason.
        """
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
            client.attach_policy(policyName=const.POLICY_NAME, target=identity_id)
        except Exception as err:  # noqa: BLE001
            code = ""
            if isinstance(err, ClientError):
                code = err.response.get("Error", {}).get("Code", "")
            if code not in {
                # The only codes that mean the ATTACH ITSELF was refused:
                # the caller may not attach, or the policy is not there.
                # Those are terminal - retrying cannot grant a permission
                # the identity does not have. Everything else (throttling,
                # socket, DNS, a rejected credential) is about the request,
                # not the authorization, and must stay retryable.
                "AccessDeniedException",
                "UnauthorizedException",
                "ResourceNotFoundException",
            }:
                # from None - see async_get_credentials.
                raise self._classify(err) from None
            # No identity ID in the message: it is a stable account
            # identifier, and exception text reaches ERROR logs users paste
            # into public issues.
            # from None - see async_get_credentials. The scrubbing above is
            # the whole point of this branch; chaining would undo it.
            raise ZephyrPolicyError(
                f"Could not attach {const.POLICY_NAME} to this identity. "
                "Without it the MQTT connection succeeds but every message is "
                "silently dropped."
            ) from None


@dataclass(frozen=True, slots=True)
class Credentials:
    """Hour-lived AWS credentials minted by the Cognito identity exchange.

    These SigV4-sign the presigned MQTT WebSocket URL and the IoT policy
    attach. Deliberately never persisted - see AbstractAuth.

    Attributes:
        access_key: AWS access key ID.
        secret_key: AWS secret access key.
        session_token: AWS session token for the temporary credentials.
        expiration: Expiry reported by the identity exchange.
    """

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
        """Whether the credentials are inside the refresh margin.

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
        """Sets up SRP login as `username`, optionally resuming stored tokens.

        Args:
            username: Cognito username to log in as.
            password: Password for the SRP login.
            session: aiohttp client session, owned by the consumer.
            tokens: Previously persisted tokens; lets the first
                acquisition try the stored refresh token before burning a
                rate-limited SRP login.
            token_updater: Called with every new ZephyrTokens so the
                consumer can persist them.
            endpoints: Cloud endpoint set to authenticate against.
        """
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
        """Persists a corrected identity into the stored tokens.

        The base class already routes mqtt_client_id through its override;
        this makes the correction survive a restart instead of being
        rediscovered by a failed exchange every time.

        Args:
            identity_id: The freshly fetched replacement identity ID.
        """
        if self._tokens is not None:
            self._tokens = replace(self._tokens, identity_id=identity_id)
            if self._token_updater is not None:
                self._token_updater(self._tokens)

    # -- blocking bodies, run in a worker thread ----------------------

    def _cognito(
        self, *, username: str | None = None, refresh_token: str | None = None
    ) -> Cognito:
        """Builds a pycognito handle for the configured pool/client/secret.

        Args:
            username: Username to bind the handle to; defaults to the
                constructor username. The refresh path passes the stored
                username, which minted the refresh token.
            refresh_token: Stored refresh token to seed the handle with,
                for the REFRESH_TOKEN_AUTH path.
        """
        return Cognito(
            self.endpoints.user_pool,
            self.endpoints.client_id,
            client_secret=self.endpoints.client_secret,
            username=username or self._username,
            refresh_token=refresh_token,
            # Must be explicit; otherwise pycognito reads ambient AWS config
            # and raises a confusing ResourceNotFoundException.
            user_pool_region=self.endpoints.region,
        )

    def _srp_login(self) -> Cognito:
        """Logs in with the password over SRP, minting fresh tokens.

        The expensive, rate-limited path (PROTOCOL.md section 3.1) - taken
        only when there is no stored refresh token or Cognito rejected it.

        Returns:
            An authenticated pycognito handle carrying the fresh tokens.
        """
        user = self._cognito()
        user.authenticate(password=self._password)
        return user

    def _refresh(self, stored: ZephyrTokens) -> Cognito:
        """Renews from a stored refresh token, under ITS username.

        stored.username, not self._username: SECRET_HASH is
        HMAC-SHA256(client_secret, username + client_id) and pycognito
        recomputes it on every REFRESH_TOKEN_AUTH call, so it has to use
        the username that MINTED this refresh token. That is the documented
        reason ZephyrTokens carries a username at all - reading it from the
        constructor argument instead makes the field decorative, and a
        consumer that rebuilds this object with a differently spelled
        username (a changed email, different casing) while restoring the
        same tokens sends a hash Cognito rejects.

        Args:
            stored: The persisted tokens whose refresh token - and the
                username that minted it - drive the renewal.

        Returns:
            A pycognito handle carrying the renewed tokens.
        """
        user = self._cognito(
            username=stored.username, refresh_token=stored.refresh_token
        )
        user.renew_access_token()
        return user

    # _identity_client, _exchange and _attach are inherited from
    # AbstractAuth: they operate on tokens and endpoints, nothing
    # Cognito-login-specific, and hoisting them is what makes AbstractAuth
    # implementable by consumers.

    # -- async surface -------------------------------------------------

    async def async_get_tokens(self) -> ZephyrTokens:
        """Serves cached tokens while fresh; refreshes or logs in otherwise.

        The unlocked fast path keeps this cheap for ZephyrApi, which calls
        it on every REST request.

        Returns:
            Valid, unexpired tokens.

        Raises:
            ZephyrAuthError: If Cognito rejects the credentials
                terminally.
            ZephyrTransportError: If refresh, login or the identity
                exchange fails for a retryable infrastructure reason.
        """
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
        """Refreshes or logs in, minting fresh tokens.

        The caller must hold self._lock.

        Returns:
            The freshly acquired tokens, persisted through the token
            updater when one is configured.

        Raises:
            ZephyrAuthError: If Cognito rejects the login or the identity
                exchange rejects the credentials terminally.
            ZephyrTransportError: If a retryable infrastructure failure
                interrupts the refresh, the login or the exchange.
        """
        stored = self._tokens
        user: Cognito | None = None
        # Which username the tokens minted below belong to. The REFRESH
        # path keeps the stored one, because the refresh token it renewed
        # is bound to that username through SECRET_HASH and the NEXT
        # refresh has to reproduce the same hash. An SRP login mints fresh
        # tokens under the username this object was constructed with.
        token_username = self._username

        if stored is not None:
            try:
                user = await asyncio.to_thread(self._refresh, stored)
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
                    # from None - see async_get_credentials.
                    raise classified from None
            else:
                token_username = stored.username

        if user is None:
            try:
                user = await asyncio.to_thread(self._srp_login)
            except Exception as err:  # noqa: BLE001
                # Classify - a DNS failure or pool throttling here must NOT
                # become ZephyrAuthError, which the supervisor treats as
                # terminal and the consumer maps to a reauth prompt.
                # from None - see async_get_credentials.
                raise self._classify(err) from None

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
            # from None - see async_get_credentials.
            raise self._classify(err) from None

        self._credentials = credentials
        self._credentials_for = identity_id
        # This is the site that makes expiry alone a lie: ZephyrApi calls
        # async_get_tokens() on every REST request, so an ordinary poll can
        # land here and replace the credentials while the live MQTT sockets
        # keep the signatures of the ones just discarded.
        self.credentials_generation += 1
        # The tokens built two lines below carry the authoritative identity
        # from THIS exchange, so any older override is stale. Keeping it
        # lets identity_id/mqtt_client_id diverge from the tokens after two
        # successive stale-identity events - the PROTOCOL.md section 3.3
        # silent-drop failure.
        self._identity_override = None
        self._tokens = ZephyrTokens(
            username=token_username,
            id_token=user.id_token,
            refresh_token=user.refresh_token
            or (stored.refresh_token if stored else ""),
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
