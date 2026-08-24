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
    """MQTT connect, subscribe or publish failed."""
