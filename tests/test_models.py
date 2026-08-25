import json
from pathlib import Path

import pytest

from pyzephyrconnect.exceptions import ZephyrDataError
from pyzephyrconnect.models import HoodCapabilities, HoodState

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def discover() -> dict:
    return json.loads((FIXTURES / "discoverdevice.json").read_text())


@pytest.fixture
def shadow() -> dict:
    return json.loads((FIXTURES / "shadow_get_accepted.json").read_text())


def test_capabilities_parse_the_reference_device(discover):
    caps = HoodCapabilities.from_discover(discover)
    assert caps.max_fan_speed == 6
    assert caps.max_light_level == 3
    assert caps.supports_recirculating is True
    assert caps.supports_tru_hue is False
    assert caps.model == "AK7400AS"
    assert caps.manufacturer == "ZEPHYR"
    assert caps.max_grease_filter_hours == 60
    assert caps.max_charcoal_filter_hours == 200


def test_capabilities_collect_vendor_urls(discover):
    caps = HoodCapabilities.from_discover(discover)
    assert caps.urls["GreaseFilterWebstoreURL"].startswith("https://")
    assert "FAQURL" in caps.urls


def test_capabilities_tolerate_a_missing_optional_field(discover):
    """Other Zephyr models will not return every key. Absent capability
    must degrade to a safe default, not raise."""
    del discover["truHueSupport"]
    del discover["maxCharcoalfilterTimer"]
    caps = HoodCapabilities.from_discover(discover)
    assert caps.supports_tru_hue is False
    assert caps.max_charcoal_filter_hours is None


def test_state_parses_reported_block(shadow):
    state = HoodState.from_reported(shadow["state"]["reported"])
    assert state.power == 0
    assert state.fan == 0
    assert state.act == "Disabled"
    assert state.use_grease_filter_time == 642
    assert state.is_online is True
    assert state.fault_codes == ()


def test_state_merge_applies_a_partial_delta(shadow):
    """update/delta carries only changed keys. Merging must preserve the rest."""
    state = HoodState.from_reported(shadow["state"]["reported"])
    merged = state.merge({"fan": 3, "power": 1})
    assert merged.fan == 3
    assert merged.power == 1
    assert merged.use_grease_filter_time == 642, "unchanged keys must survive"
    assert state.fan == 0, "merge must not mutate the original"


def test_state_keeps_unknown_keys_in_raw(shadow):
    """A model we have never seen may report fields we do not model. They
    must survive into raw so diagnostics can surface them."""
    reported = dict(shadow["state"]["reported"])
    reported["somethingNew"] = 42
    state = HoodState.from_reported(reported)
    assert state.raw["somethingNew"] == 42


def test_state_logs_a_warning_on_malformed_int_field(shadow, caplog):
    """A malformed alarm value must not silently read as 'no fault' - the
    coercion failure must be surfaced via a WARNING log naming the key."""
    reported = dict(shadow["state"]["reported"])
    reported["alarmfaultcode"] = "not-a-number"
    with caplog.at_level("WARNING"):
        state = HoodState.from_reported(reported)
    assert state.alarm_fault_code is None
    warnings = [r for r in caplog.records if r.levelname == "WARNING"]
    assert len(warnings) == 1
    assert "alarmfaultcode" in warnings[0].message
    assert "not-a-number" in warnings[0].message


def test_state_raw_rejects_in_place_mutation(shadow):
    """`raw` must be read-only so a cached HoodState handed to multiple
    listeners cannot be corrupted by one of them mutating it."""
    state = HoodState.from_reported(shadow["state"]["reported"])
    with pytest.raises(TypeError):
        state.raw["fan"] = 99


def test_capabilities_urls_rejects_in_place_mutation(discover):
    """`urls` must be read-only for the same reason as HoodState.raw."""
    caps = HoodCapabilities.from_discover(discover)
    with pytest.raises(TypeError):
        caps.urls["FAQURL"] = "https://example.com"


def test_state_merge_works_with_read_only_raw(shadow):
    """merge() must keep working now that `raw` is a Mapping rather than a
    plain dict: a partial delta applies and unchanged keys survive."""
    state = HoodState.from_reported(shadow["state"]["reported"])
    merged = state.merge({"fan": 5})
    assert merged.fan == 5
    assert merged.use_grease_filter_time == 642, "unchanged keys must survive"
    assert merged.raw["fan"] == 5


def test_absent_state_fields_are_none_not_zero():
    """A missing alarm must not read as 'no alarm', and a missing power must
    not read as 'off'. Those are different facts and the consumer decides."""
    state = HoodState.from_reported({})
    assert state.power is None
    assert state.alarm_fault_code is None
    assert state.is_online is None
    assert state.fault_codes is None


def test_absent_usage_counters_stay_zero():
    """Zero is the genuine starting value for a new filter, and the
    filter-life percentage needs a number."""
    state = HoodState.from_reported({})
    assert state.use_fan_time == 0
    assert state.use_grease_filter_time == 0


def test_malformed_state_field_degrades_to_none_and_warns(caplog):
    """State arrives continuously; one bad payload must not crash the
    integration, but it must not read as a valid zero either."""
    state = HoodState.from_reported({"power": "nonsense"})
    assert state.power is None
    assert "power" in caplog.text


def test_present_zero_is_preserved(shadow):
    state = HoodState.from_reported(shadow["state"]["reported"])
    assert state.power == 0


def test_capabilities_absent_numeric_is_none_not_zero():
    """Entity creation is gated on capabilities, so a hood that omits a key
    must set up without that feature - not fail setup."""
    caps = HoodCapabilities.from_discover({"thingName": "t"})
    assert caps.max_fan_speed is None
    assert caps.max_charcoal_filter_hours is None


def test_capabilities_malformed_numeric_raises():
    """Present-but-garbage is a real error: it runs once at setup, so it
    should fail loudly rather than produce a wrong capability set."""
    with pytest.raises(ZephyrDataError):
        HoodCapabilities.from_discover({"maxFanSpeed": "six"})


def test_scalar_fault_code_degrades_to_none_and_warns(caplog):
    """A non-list faultCode must not raise from the hot push path - tuple(5)
    would TypeError inside _handle_message and the state update would be
    silently dropped into an ERROR log."""
    state = HoodState.from_reported({"faultCode": 5})
    assert state.fault_codes is None
    assert "faultCode" in caplog.text


def test_empty_string_int_field_reads_as_absent():
    state = HoodState.from_reported({"power": ""})
    assert state.power is None


def test_malformed_counter_degrades_to_zero_and_warns(caplog):
    """Counters must stay numeric for the filter-life percentage even when
    the payload is garbage."""
    state = HoodState.from_reported({"usefantime": "garbage"})
    assert state.use_fan_time == 0
    assert "usefantime" in caplog.text
