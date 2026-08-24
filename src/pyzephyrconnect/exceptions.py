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
    """TLS verification failed against the bundled TWCA CA set.

    The vendor's intermediate omits the Subject Key Identifier extension, so
    system trust stores reject it. The library ships its own CA bundle. If
    this fires, the vendor rotated to a chain the bundle does not cover.
    """


class ZephyrPolicyError(ZephyrError):
    """The IoT policy is not attached to this Cognito identity.

    Symptom: connect, subscribe and publish all succeed and every message is
    silently dropped. Call attach_policy() BEFORE connecting - an open
    connection does not pick up newly attached permissions.
    """


class ZephyrTransportError(ZephyrError):
    """MQTT connect, subscribe or publish failed."""
