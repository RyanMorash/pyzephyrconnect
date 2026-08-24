"""Python client for Zephyr/Gemtek range hoods."""

from .exceptions import (
    ZephyrAuthError,
    ZephyrCertificateError,
    ZephyrError,
    ZephyrPolicyError,
    ZephyrTransportError,
)

__version__ = "0.1.0"

__all__ = [
    "ZephyrError",
    "ZephyrAuthError",
    "ZephyrCertificateError",
    "ZephyrPolicyError",
    "ZephyrTransportError",
    "__version__",
]
