import json
from pathlib import Path

import pytest

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
    assert caps.max_charcoal_filter_hours == 0


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
    assert state.alarm_fault_code == 0
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
