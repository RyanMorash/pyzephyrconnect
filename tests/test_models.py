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
