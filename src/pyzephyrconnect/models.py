"""Typed views over the vendor's untyped JSON.

Both models keep the original payload in `raw`. Field semantics are only
partially understood, so discarding unmodelled keys would destroy the
evidence needed to characterise them later.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from .exceptions import ZephyrDataError

_LOGGER = logging.getLogger(__name__)

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

    Attributes:
        thing_name: AWS IoT thing name identifying the hood.
        serial: Device serial number.
        model: Vendor model name.
        mac: Device MAC address.
        manufacturer: Company name reported by the vendor.
        max_fan_speed: Highest fan speed, or None when not reported.
        max_light_level: Highest light level, or None when not reported.
        supports_recirculating: Whether recirculating mode is supported.
        supports_tru_hue: Whether Tru-Hue lighting is supported.
        max_grease_filter_hours: Grease filter service interval, or None
            when not reported.
        max_charcoal_filter_hours: Charcoal filter service interval, or
            None when not reported.
        labor_warranty: Labor warranty terms as reported.
        parts_warranty: Parts warranty terms as reported.
        urls: Non-empty documentation and support URLs from the payload,
            keyed by their original payload key.
        raw: The complete original payload. Unmodelled keys are kept as
            evidence for characterising field semantics later.
    """

    thing_name: str
    serial: str
    model: str
    mac: str
    manufacturer: str
    max_fan_speed: int | None
    max_light_level: int | None
    supports_recirculating: bool
    supports_tru_hue: bool
    max_grease_filter_hours: int | None
    max_charcoal_filter_hours: int | None
    labor_warranty: str
    parts_warranty: str
    urls: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))
    raw: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))

    @classmethod
    def from_discover(cls, payload: dict[str, Any]) -> HoodCapabilities:
        """Builds capabilities from the discoverdevice payload.

        Absent and malformed are different failures here. Absent is normal:
        other Zephyr models omit keys this one returns, and entity creation
        is gated on capabilities precisely so the library generalises to
        hoods nobody has tested. Malformed is a real error, and this runs
        once at setup, so it fails loudly.

        Args:
            payload: Decoded discoverdevice response body.

        Returns:
            A HoodCapabilities built from the payload, with the payload
            itself preserved in `raw`.

        Raises:
            ZephyrDataError: If a numeric capability is present but
                malformed.
        """

        def as_int(key: str) -> int | None:
            """Coerces the capability at `key` to an int.

            Args:
                key: Payload key to read.

            Returns:
                The integer value, or None when the key is absent or
                its value is empty.

            Raises:
                ZephyrDataError: If the value is present but malformed.
            """
            if (value := payload.get(key)) is None or value == "":
                return None
            # int() would take both of these silently: a JSON true becomes
            # 1 (a hood with "one fan speed"), and 6.5 truncates to 6. Both
            # are present-but-malformed, which this parser is contracted to
            # raise on rather than turn into a plausible-looking wrong
            # capability that gates entity creation for the life of the
            # config entry. Integral floats (6.0) and numeric strings ("6")
            # remain accepted - those are the same fact in another shape.
            if isinstance(value, bool) or (
                isinstance(value, float) and not value.is_integer()
            ):
                raise ZephyrDataError(
                    f"capability {key!r} was present but unparseable: {value!r}"
                )
            try:
                return int(value)
            except (TypeError, ValueError, OverflowError) as err:
                # OverflowError is defense-in-depth: json.loads accepts
                # Infinity/NaN by default, and the is_integer() guard above
                # already rejects a float Infinity/NaN before int() ever
                # sees it. Nothing currently reaches int() able to trigger
                # it, but the contract is "malformed input raises
                # ZephyrDataError", full stop - this must not depend on the
                # guard above staying in that exact order.
                raise ZephyrDataError(
                    f"capability {key!r} was present but unparseable: {value!r}"
                ) from err

        return cls(
            thing_name=str(payload.get("thingName", "")),
            serial=str(payload.get("SN", "")),
            model=str(payload.get("modelName", "")),
            mac=str(payload.get("MAC", "")),
            manufacturer=str(payload.get("companyName", "")),
            max_fan_speed=as_int("maxFanSpeed"),
            max_light_level=as_int("maxLightLevel"),
            supports_recirculating=bool(payload.get("Recirculating", 0)),
            supports_tru_hue=bool(payload.get("truHueSupport", 0)),
            max_grease_filter_hours=as_int("maxGreasefilterTimer"),
            max_charcoal_filter_hours=as_int("maxCharcoalfilterTimer"),
            labor_warranty=str(payload.get("laborWarranty", "")),
            parts_warranty=str(payload.get("partsWarranty", "")),
            urls=MappingProxyType(
                {k: payload[k] for k in _URL_KEYS if payload.get(k)}
            ),
            raw=MappingProxyType(dict(payload)),
        )


@dataclass(frozen=True, slots=True)
class HoodState:
    """Current shadow state.

    Field semantics are documented where known. `act` and the exact units
    of the use*time counters are unverified - see PROTOCOL.md section 7.

    Attributes:
        power: Power state, or None when unknown.
        light: Light level, or None when unknown.
        fan: Fan speed, or None when unknown.
        act: `act` value as a string, or None when unknown; semantics
            unverified.
        delay_timer: `delaytimer` value, or None when unknown.
        set_delay_timer: `setdelaytimer` value, or None when unknown.
        set_recirculating: `setrecirculating` value, or None when
            unknown.
        set_clean_air_function: `setcleanairfunction` value, or None
            when unknown.
        clean_grease_filters: `cleangreasefilters` value, or None when
            unknown.
        clean_charcoal_filters: `cleancharcoalfilters` value, or None
            when unknown.
        use_grease_filter_time: Grease filter usage counter; 0 when
            unreported.
        use_charcoal_filter_time: Charcoal filter usage counter; 0 when
            unreported.
        use_light_time: Light usage counter; 0 when unreported.
        use_fan_time: Fan usage counter; 0 when unreported.
        fan_warning: `fanwarning` value, or None when unknown.
        alarm_fan: `alarmfan` value, or None when unknown.
        alarm_fault_code: `alarmfaultcode` value, or None when unknown.
        alarm_grease_filter: `alarmgreasefilter` value, or None when
            unknown.
        is_online: Whether the device is online, or None when unknown.
        fault_codes: Reported fault codes, or None when unknown.
        raw: The complete `reported` payload this state was parsed from.
    """

    power: int | None = None
    light: int | None = None
    fan: int | None = None
    act: str | None = None
    delay_timer: int | None = None
    set_delay_timer: int | None = None
    set_recirculating: int | None = None
    set_clean_air_function: int | None = None
    clean_grease_filters: int | None = None
    clean_charcoal_filters: int | None = None
    use_grease_filter_time: int = 0
    use_charcoal_filter_time: int = 0
    use_light_time: int = 0
    use_fan_time: int = 0
    fan_warning: int | None = None
    alarm_fan: int | None = None
    alarm_fault_code: int | None = None
    alarm_grease_filter: int | None = None
    is_online: bool | None = None
    fault_codes: tuple[Any, ...] | None = None
    raw: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}))

    @classmethod
    def from_reported(cls, reported: dict[str, Any]) -> HoodState:
        """Builds state from a shadow `reported` block.

        Absent and malformed both yield None, which is not the same fact as
        zero: a missing `alarmfaultcode` is "unknown", not "no fault". The
        consumer decides how to present unknown. Malformed values are still
        logged, because a payload the device changed shape on is worth
        knowing about.

        The four usage counters are the exception - zero is their genuine
        starting value, and the filter-life percentage needs a number.

        Args:
            reported: Decoded `reported` block from a shadow document.

        Returns:
            A HoodState with the block preserved in `raw`.
        """

        def as_int(key: str) -> int | None:
            """Coerces `key` to an int, or None when absent or malformed."""
            if (value := reported.get(key)) is None or value == "":
                return None
            try:
                return int(value)
            except (TypeError, ValueError, OverflowError):
                # OverflowError: json.loads accepts Infinity/NaN by default,
                # and int(float("inf")) raises OverflowError rather than
                # ValueError. This parser runs on every shadow push and must
                # degrade a bad value to None, not let it drop the whole
                # state update.
                _LOGGER.warning(
                    "Could not coerce %r value %r to int; treating as unknown",
                    key,
                    value,
                )
                return None

        def as_counter(key: str) -> int:
            """Coerces `key` to an int, treating absent or malformed as 0."""
            return as_int(key) or 0

        def as_bool(key: str) -> bool | None:
            """Coerces `key` to a bool via as_int, keeping None for unknown."""
            value = as_int(key)
            return None if value is None else bool(value)

        act = reported.get("act")
        codes = reported.get("faultCode")
        if codes is not None and not isinstance(codes, (list, tuple)):
            # Guard the tuple() below: a scalar faultCode would raise
            # TypeError out of a hot push path.
            _LOGGER.warning("faultCode was not a list; treating as unknown")
            codes = None

        return cls(
            power=as_int("power"),
            light=as_int("light"),
            fan=as_int("fan"),
            act=None if act is None else str(act),
            delay_timer=as_int("delaytimer"),
            set_delay_timer=as_int("setdelaytimer"),
            set_recirculating=as_int("setrecirculating"),
            set_clean_air_function=as_int("setcleanairfunction"),
            clean_grease_filters=as_int("cleangreasefilters"),
            clean_charcoal_filters=as_int("cleancharcoalfilters"),
            use_grease_filter_time=as_counter("usegreasefiltertime"),
            use_charcoal_filter_time=as_counter("usecharcoalfiltertime"),
            use_light_time=as_counter("uselighttime"),
            use_fan_time=as_counter("usefantime"),
            fan_warning=as_int("fanwarning"),
            alarm_fan=as_int("alarmfan"),
            alarm_fault_code=as_int("alarmfaultcode"),
            alarm_grease_filter=as_int("alarmgreasefilter"),
            is_online=as_bool("isOnline"),
            fault_codes=None if codes is None else tuple(codes),
            raw=MappingProxyType(dict(reported)),
        )

    def merge(self, delta: dict[str, Any]) -> HoodState:
        """Builds a new state with `delta` applied over the raw payload.

        update/delta and update/accepted carry only changed keys, so a
        replace-the-whole-object approach would silently zero everything
        the device did not mention.

        Args:
            delta: Changed keys from an update/delta or update/accepted
                message.

        Returns:
            A new HoodState reparsed from the merged raw payload.
        """
        merged_raw = {**self.raw, **delta}
        return HoodState.from_reported(merged_raw)
