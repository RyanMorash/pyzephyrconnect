"""Exception hierarchy.

Each error names the operator action that resolves it. A generic error here
costs hours of debugging, because most failure modes in this protocol are
silent - see PROTOCOL.md section 6.
"""


class ZephyrError(Exception):
    """Base for all library errors."""


class ZephyrAuthError(ZephyrError):
    """Cognito authentication failed. Credentials are wrong or expired."""


class ZephyrCertificateError(ZephyrError):
    """TLS verification failed against system trust plus the TWCA anchors.

    The vendor's intermediate omits the Subject Key Identifier extension, so
    plain system trust rejects it. The library adds its own TWCA CA bundle
    as supplementary trust anchors on top of the system store - this is not
    certificate pinning. If this fires, the chain is untrusted by both the
    system CAs and the TWCA additions, which usually means the vendor
    changed its certificate chain again.
    """


class ZephyrPolicyError(ZephyrError):
    """The IoT policy is not attached to this Cognito identity.

    Symptom: connect, subscribe and publish all succeed and every message is
    silently dropped. Call attach_policy() BEFORE connecting - an open
    connection does not pick up newly attached permissions.
    """


class ZephyrTransportError(ZephyrError):
    """A network, timeout or throttling failure. Retryable.

    Deliberately distinct from ZephyrAuthError: the supervisor treats auth
    errors as terminal (they need the user), while transport errors are
    retried on the next tick. Wrapping a DNS blip in ZephyrAuthError turns
    a Wi-Fi hiccup into a reauth prompt.
    """


class ZephyrNotConnectedError(ZephyrError):
    """A publish-path operation had no live shadow connection.

    Writes, and the shadow GET behind them. Reads never raise this: state()
    returns the cached value or None, and async_poll() goes over HTTPS and
    works whether or not MQTT is up.

    Raised when the hood was never started, was stopped, or a rebuild failed
    - and when the socket is found dead at the moment of publishing, in which
    case the connection is torn down so the refused write cannot be delivered
    later by paho's own reconnect. Call Hood.async_start(), or wait for
    `connected`, and retry.
    """


class ZephyrWriteError(ZephyrError):
    """A shadow write was refused before it left the process.

    Either the field is not in WRITABLE_FIELDS, or the value is outside the
    range the device's own capabilities declare. Nothing was published.
    """


class ZephyrDataError(ZephyrError):
    """A payload field was present but could not be parsed.

    Distinct from an absent field, which is not an error - other Zephyr
    models legitimately omit keys this one returns.
    """
