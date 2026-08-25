"""Python client for Zephyr/Gemtek range hoods."""

from .client import ZephyrClient
from .exceptions import (
    ZephyrAuthError,
    ZephyrCertificateError,
    ZephyrDataError,
    ZephyrError,
    ZephyrNotConnectedError,
    ZephyrPolicyError,
    ZephyrTransportError,
    ZephyrWriteError,
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
    "ZephyrNotConnectedError",
    "ZephyrWriteError",
    "ZephyrDataError",
    "HoodCapabilities",
    "HoodState",
    "__version__",
]
