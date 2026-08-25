"""SigV4 presigning for AWS IoT Core WebSocket connections.

Pure and stdlib-only by design: no network, no clock of its own, no
credentials provider. `now` is a parameter so the tests are deterministic.

The one non-obvious rule: X-Amz-Security-Token is appended AFTER the
signature is computed and is NOT part of the canonical query string. Signing
over it yields a signature the broker rejects with an opaque handshake
error.
"""

from __future__ import annotations

import hashlib
import hmac
from datetime import datetime
from urllib.parse import quote

from .const import IOT_SERVICE as SERVICE

ALGORITHM = "AWS4-HMAC-SHA256"
CANONICAL_URI = "/mqtt"
SIGNED_HEADERS = "host"
# SHA-256 of the empty string; a presigned GET has no body.
EMPTY_PAYLOAD_HASH = (
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)
# RFC 3986 unreserved characters. urllib's default safe set is "/", which is
# wrong for canonical query encoding.
_SAFE = "-_.~"


def _hmac(key: bytes, msg: str) -> bytes:
    """Computes HMAC-SHA256 of `msg` under `key` as raw digest bytes."""
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _signing_key(secret_key: str, datestamp: str, region: str, service: str = SERVICE) -> bytes:
    """Derives the SigV4 signing key via the date/region/service chain.

    Args:
        secret_key: AWS secret access key.
        datestamp: Signing date as YYYYMMDD.
        region: AWS region being signed for.
        service: AWS service name; defaults to the IoT service.

    Returns:
        The raw HMAC signing key bytes.
    """
    k_date = _hmac(f"AWS4{secret_key}".encode("utf-8"), datestamp)
    k_region = _hmac(k_date, region)
    k_service = _hmac(k_region, service)
    return _hmac(k_service, "aws4_request")


def _credential_scope(datestamp: str, region: str) -> str:
    """Formats the SigV4 credential scope string."""
    return f"{datestamp}/{region}/{SERVICE}/aws4_request"


def _query_params(access_key: str, region: str, now: datetime) -> dict[str, str]:
    """Builds the auth query parameters the signature is computed over.

    Deliberately excludes X-Amz-Signature and X-Amz-Security-Token; both
    are appended to the URL only after signing.

    Args:
        access_key: AWS access key ID.
        region: AWS region being signed for.
        now: Current UTC time, used for X-Amz-Date and the credential
            scope.

    Returns:
        The unencoded X-Amz-* parameters, keyed by parameter name.
    """
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    datestamp = now.strftime("%Y%m%d")
    scope = _credential_scope(datestamp, region)
    return {
        "X-Amz-Algorithm": ALGORITHM,
        "X-Amz-Credential": f"{access_key}/{scope}",
        "X-Amz-Date": amz_date,
        "X-Amz-SignedHeaders": SIGNED_HEADERS,
    }


def _canonical_query(params: dict[str, str]) -> str:
    """Encodes `params` as a key-sorted RFC 3986 canonical query string."""
    return "&".join(
        f"{quote(k, safe=_SAFE)}={quote(v, safe=_SAFE)}"
        for k, v in sorted(params.items())
    )


def canonical_request(
    *, access_key: str, endpoint: str, region: str, now: datetime
) -> str:
    """Builds the SigV4 canonical request.

    Exposed for testing.

    Args:
        access_key: AWS access key ID.
        endpoint: AWS IoT endpoint hostname.
        region: AWS region being signed for.
        now: Current UTC time the request is signed at.

    Returns:
        The newline-joined canonical request string.
    """
    return "\n".join(
        [
            "GET",
            CANONICAL_URI,
            _canonical_query(_query_params(access_key, region, now)),
            f"host:{endpoint}\n",
            SIGNED_HEADERS,
            EMPTY_PAYLOAD_HASH,
        ]
    )


def build_presigned_url(
    access_key: str,
    secret_key: str,
    session_token: str | None,
    *,
    endpoint: str,
    region: str,
    now: datetime,
) -> str:
    """Builds a presigned `wss://` URL for an MQTT connection to AWS IoT.

    Args:
        access_key: AWS access key ID.
        secret_key: AWS secret access key paired with `access_key`.
        session_token: STS session token for temporary credentials, or
            None for long-lived keys. Appended to the URL only after the
            signature is computed, never signed over - see the module
            docstring.
        endpoint: AWS IoT endpoint hostname.
        region: AWS region of the endpoint.
        now: Current UTC time; a parameter so tests are deterministic.

    Returns:
        The presigned WebSocket URL.
    """
    datestamp = now.strftime("%Y%m%d")
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    scope = _credential_scope(datestamp, region)

    params = _query_params(access_key, region, now)
    query = _canonical_query(params)

    string_to_sign = "\n".join(
        [
            ALGORITHM,
            amz_date,
            scope,
            hashlib.sha256(
                canonical_request(
                    access_key=access_key, endpoint=endpoint,
                    region=region, now=now,
                ).encode("utf-8")
            ).hexdigest(),
        ]
    )

    signature = hmac.new(
        _signing_key(secret_key, datestamp, region),
        string_to_sign.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    query = f"{query}&X-Amz-Signature={signature}"
    if session_token:
        # Appended after signing - see module docstring.
        query = f"{query}&X-Amz-Security-Token={quote(session_token, safe=_SAFE)}"

    return f"wss://{endpoint}{CANONICAL_URI}?{query}"
