"""Constants for the Zephyr/Gemtek cloud.

All values reverse-engineered from the vendor iOS app. See PROTOCOL.md.
"""
from dataclasses import dataclass, field

REGION = "us-west-2"
USER_POOL = "us-west-2_McuoKpkna"
CLIENT_ID = "5a2qiskdvvu7gre1jvbjnunu20"
# Ships inside the iOS app bundle; provides no security boundary, but SRP
# fails without it because it is needed for SECRET_HASH.
CLIENT_SECRET = "3b085l2fkgph4kt734k5e26tirb9hjasgb4rn8sjpp4mheo5kga"
IDENTITY_POOL = "us-west-2:fb4c1b66-12c2-414b-83a1-a1902f7d98e3"
PROVIDER = f"cognito-idp.{REGION}.amazonaws.com/{USER_POOL}"

IOT_ENDPOINT = "a1nqxu0hki9zw3-ats.iot.us-west-2.amazonaws.com"
IOT_SERVICE = "iotdevicegateway"
POLICY_NAME = "RangeHoodPolicy"

DEVICE_API_BASE = "https://zephyr-prod-app.gemteks.com/prod"
DEVICE_API_LIST = f"{DEVICE_API_BASE}/getowndevices"
DEVICE_API_DISCOVER = f"{DEVICE_API_BASE}/discoverdevice"


@dataclass(frozen=True, slots=True)
class Endpoints:
    """Where the vendor cloud lives.

    Defaults reproduce the production Zephyr/Gemtek deployment. They are
    overridable so the library can be pointed at a staging host, exercised
    in tests without monkeypatching module globals, and survive a vendor
    host change without needing a release.
    """

    region: str = REGION
    user_pool: str = USER_POOL
    client_id: str = CLIENT_ID
    # repr=False: it is already public (ships in the iOS bundle), but there
    # is no reason to print it in logs or tracebacks.
    client_secret: str = field(default=CLIENT_SECRET, repr=False)
    identity_pool: str = IDENTITY_POOL
    iot_endpoint: str = IOT_ENDPOINT
    device_api_base: str = DEVICE_API_BASE

    @property
    def provider(self) -> str:
        """Cognito login-provider key for the identity-pool exchange."""
        return f"cognito-idp.{self.region}.amazonaws.com/{self.user_pool}"

    @property
    def device_api_list(self) -> str:
        return f"{self.device_api_base}/getowndevices"

    @property
    def device_api_discover(self) -> str:
        return f"{self.device_api_base}/discoverdevice"


DEFAULT_ENDPOINTS = Endpoints()

# Suffix appended to the Cognito identity ID to form the MQTT client ID, so
# the library can coexist with the phone app instead of evicting it.
CLIENT_ID_SUFFIX = "-ha"

# Credentials last 1 hour. Refresh early enough to rebuild the socket.
REFRESH_MARGIN_SECONDS = 600

# Fields the probe CLI is permitted to write. Everything else in the shadow
# is a counter, an alarm, or device-reported telemetry. Note: delaytimer is
# device-reported only; the device derives and decrements it from setdelaytimer,
# so writing delaytimer is unnecessary.
WRITABLE_FIELDS = frozenset({
    "power",
    "light",
    "fan",
    "setdelaytimer",
    "setcleanairfunction",
    "setrecirculating",
    "resetgreasefilter",
})

# Writes that are destructive or change device configuration. The probe
# requires an extra confirmation for these.
DANGEROUS_FIELDS = frozenset({
    "resetgreasefilter",   # zeroes an unrecoverable usage counter
    "setrecirculating",    # changes filter accounting
})
