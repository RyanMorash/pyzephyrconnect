"""Constants must stay pinned - these are reverse-engineered values."""

import dataclasses

import pytest

from pyzephyrconnect import const
from pyzephyrconnect.const import DEFAULT_ENDPOINTS, Endpoints


def test_aws_constants_are_pinned():
    """Tests that the pinned AWS constants keep their values."""
    assert const.REGION == "us-west-2"
    assert const.USER_POOL == "us-west-2_McuoKpkna"
    assert const.IOT_ENDPOINT.endswith(".iot.us-west-2.amazonaws.com")
    assert const.IOT_SERVICE == "iotdevicegateway"
    assert const.POLICY_NAME == "RangeHoodPolicy"


def test_the_default_client_id_suffix_is_the_neutral_one():
    """Tests that the shipped default client-ID suffix stays "-py".

    Not a reverse-engineered value - a library default consumers inherit.
    It has to be non-empty (an empty suffix leaves the bare identity ID,
    which is what the phone app connects as, and the two evict each other)
    and it has to stay neutral: a consumer-specific default would collide
    with the consumer that overrode it to the same string.
    """
    assert const.CLIENT_ID_SUFFIX == "-py"


def test_alarm_and_counter_fields_are_not_writable():
    """Tests that alarm and counter fields stay out of WRITABLE_FIELDS.

    The probe allowlist is the only thing preventing a write to a
    read-only alarm field. Guard it with a test.
    """
    forbidden = {
        "alarmfan",
        "alarmfaultcode",
        "alarmgreasefilter",
        "faultCode",
        "fanwarning",
        "usegreasefiltertime",
        "usecharcoalfiltertime",
        "uselighttime",
        "usefantime",
        "isOnline",
    }
    assert forbidden.isdisjoint(const.WRITABLE_FIELDS)


def test_writable_fields_cover_the_validation_sequence():
    """Tests that WRITABLE_FIELDS covers the controls but not delaytimer."""
    for field in (
        "light",
        "power",
        "fan",
        "setdelaytimer",
        "setcleanairfunction",
        "setrecirculating",
        "resetgreasefilter",
    ):
        assert field in const.WRITABLE_FIELDS
    # delaytimer is device-managed: writing setdelaytimer=300 alone caused the
    # device to set delaytimer to 300 and count it down in 60-second intervals,
    # so delaytimer must not be in the write allowlist.
    assert "delaytimer" not in const.WRITABLE_FIELDS


def test_defaults_reproduce_the_current_constants():
    """Tests that DEFAULT_ENDPOINTS reproduces the pinned production URLs."""
    e = DEFAULT_ENDPOINTS
    assert e.region == "us-west-2"
    assert e.iot_endpoint == "a1nqxu0hki9zw3-ats.iot.us-west-2.amazonaws.com"
    assert e.device_api_list == "https://zephyr-prod-app.gemteks.com/prod/getowndevices"
    assert (
        e.device_api_discover
        == "https://zephyr-prod-app.gemteks.com/prod/discoverdevice"
    )
    assert e.provider == "cognito-idp.us-west-2.amazonaws.com/us-west-2_McuoKpkna"


def test_overriding_the_base_moves_both_rest_urls():
    """Tests that overriding device_api_base moves both REST URLs.

    Developers must be able to specify API locations - a staging host, or
    a vendor host change, should not require a release.
    """
    e = Endpoints(device_api_base="https://staging.example.com/prod")
    assert e.device_api_list == "https://staging.example.com/prod/getowndevices"
    assert e.device_api_discover == "https://staging.example.com/prod/discoverdevice"


def test_endpoints_are_frozen():
    """Tests that Endpoints instances refuse attribute assignment."""
    with pytest.raises(dataclasses.FrozenInstanceError):
        DEFAULT_ENDPOINTS.region = "eu-west-1"
