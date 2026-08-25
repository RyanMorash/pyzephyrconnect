"""Python client for Zephyr/Gemtek range hoods."""

from .auth import AbstractAuth, CredentialsAuth, ZephyrTokens
from .client import ZephyrClient
from .const import DEFAULT_ENDPOINTS, Endpoints
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
    "DEFAULT_ENDPOINTS",
    "AbstractAuth",
    "CredentialsAuth",
    "Endpoints",
    "ZephyrClient",
    "ZephyrTokens",
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
