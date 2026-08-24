"""Python client for Zephyr/Gemtek range hoods."""

from .client import ZephyrClient
from .exceptions import (
    ZephyrAuthError,
    ZephyrCertificateError,
    ZephyrError,
    ZephyrPolicyError,
    ZephyrTransportError,
)
from .models import HoodCapabilities, HoodState

__version__ = "0.1.0"

__all__ = [
    "ZephyrClient",
    "ZephyrError",
    "ZephyrAuthError",
    "ZephyrCertificateError",
    "ZephyrPolicyError",
    "ZephyrTransportError",
    "HoodCapabilities",
    "HoodState",
    "__version__",
]
