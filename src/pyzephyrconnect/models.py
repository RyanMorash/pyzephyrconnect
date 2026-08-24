"""Typed views over the vendor's untyped JSON.

Both models keep the original payload in `raw`. Field semantics are only
partially understood, so discarding unmodelled keys would destroy the
evidence needed to characterise them later.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any

_URL_KEYS = (
    "CharcoalFilterVideoURL",
    "CharcoalFilterWebstoreURL",
    "GreaseFilterVideoURL",
    "GreaseFilterWebstoreURL",
    "HoodCleanVideoURL",
    "ProductPhotoURL",
    "UserManualURL",
    "ContactURL",
    "FAQURL",
    "WarranyRegistrationURL",
)


@dataclass(frozen=True, slots=True)
class HoodCapabilities:
    """What a specific hood can do, from the discoverdevice endpoint.

    Entity creation is gated on these rather than on the model string, so
    the library generalises to Zephyr hoods we have never seen.
    """

    thing_name: str
    serial: str
    model: str
    mac: str
    manufacturer: str
    max_fan_speed: int
    max_light_level: int
    supports_recirculating: bool
    supports_tru_hue: bool
    max_grease_filter_hours: int
    max_charcoal_filter_hours: int
    labor_warranty: str
    parts_warranty: str
    urls: dict[str, str] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_discover(cls, payload: dict[str, Any]) -> HoodCapabilities:
        return cls(
            thing_name=str(payload.get("thingName", "")),
            serial=str(payload.get("SN", "")),
            model=str(payload.get("modelName", "")),
            mac=str(payload.get("MAC", "")),
            manufacturer=str(payload.get("companyName", "")),
            max_fan_speed=int(payload.get("maxFanSpeed", 0)),
            max_light_level=int(payload.get("maxLightLevel", 0)),
            supports_recirculating=bool(payload.get("Recirculating", 0)),
            supports_tru_hue=bool(payload.get("truHueSupport", 0)),
            max_grease_filter_hours=int(payload.get("maxGreasefilterTimer", 0)),
            max_charcoal_filter_hours=int(
                payload.get("maxCharcoalfilterTimer", 0)
            ),
            labor_warranty=str(payload.get("laborWarranty", "")),
            parts_warranty=str(payload.get("partsWarranty", "")),
            urls={k: payload[k] for k in _URL_KEYS if payload.get(k)},
            raw=dict(payload),
        )


@dataclass(frozen=True, slots=True)
class HoodState:
    """Current shadow state.

    Field semantics are documented where known. `act` and the exact units of
    the use*time counters are unverified - see PROTOCOL.md section 7.
    """

    power: int = 0
    light: int = 0
    fan: int = 0
    act: str = ""
    delay_timer: int = 0
    set_delay_timer: int = 0
    set_recirculating: int = 0
    set_clean_air_function: int = 0
    clean_grease_filters: int = 0
    clean_charcoal_filters: int = 0
    use_grease_filter_time: int = 0
    use_charcoal_filter_time: int = 0
    use_light_time: int = 0
    use_fan_time: int = 0
    fan_warning: int = 0
    alarm_fan: int = 0
    alarm_fault_code: int = 0
    alarm_grease_filter: int = 0
    is_online: bool = False
    fault_codes: list[Any] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_reported(cls, reported: dict[str, Any]) -> HoodState:
        def as_int(key: str) -> int:
            try:
                return int(reported.get(key, 0) or 0)
            except (TypeError, ValueError):
                return 0

        return cls(
            power=as_int("power"),
            light=as_int("light"),
            fan=as_int("fan"),
            act=str(reported.get("act", "")),
            delay_timer=as_int("delaytimer"),
            set_delay_timer=as_int("setdelaytimer"),
            set_recirculating=as_int("setrecirculating"),
            set_clean_air_function=as_int("setcleanairfunction"),
            clean_grease_filters=as_int("cleangreasefilters"),
            clean_charcoal_filters=as_int("cleancharcoalfilters"),
            use_grease_filter_time=as_int("usegreasefiltertime"),
            use_charcoal_filter_time=as_int("usecharcoalfiltertime"),
            use_light_time=as_int("uselighttime"),
            use_fan_time=as_int("usefantime"),
            fan_warning=as_int("fanwarning"),
            alarm_fan=as_int("alarmfan"),
            alarm_fault_code=as_int("alarmfaultcode"),
            alarm_grease_filter=as_int("alarmgreasefilter"),
            is_online=bool(as_int("isOnline")),
            fault_codes=list(reported.get("faultCode") or []),
            raw=dict(reported),
        )

    def merge(self, delta: dict[str, Any]) -> HoodState:
        """Return a new state with `delta` applied over the raw payload.

        update/delta and update/accepted carry only changed keys, so a
        replace-the-whole-object approach would silently zero everything the
        device did not mention.
        """
        merged_raw = {**self.raw, **delta}
        return replace(HoodState.from_reported(merged_raw))
