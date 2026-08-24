"""Constants must stay pinned - these are reverse-engineered values."""
from pyzephyrconnect import const


def test_aws_constants_are_pinned():
    assert const.REGION == "us-west-2"
    assert const.USER_POOL == "us-west-2_McuoKpkna"
    assert const.IOT_ENDPOINT.endswith(".iot.us-west-2.amazonaws.com")
    assert const.IOT_SERVICE == "iotdevicegateway"
    assert const.POLICY_NAME == "RangeHoodPolicy"


def test_alarm_and_counter_fields_are_not_writable():
    """The probe allowlist is the only thing preventing a write to a
    read-only alarm field. Guard it with a test."""
    forbidden = {
        "alarmfan", "alarmfaultcode", "alarmgreasefilter", "faultCode",
        "fanwarning", "usegreasefiltertime", "usecharcoalfiltertime",
        "uselighttime", "usefantime", "isOnline",
    }
    assert forbidden.isdisjoint(const.WRITABLE_FIELDS)


def test_writable_fields_cover_the_validation_sequence():
    for field in ("light", "power", "fan", "setdelaytimer",
                  "setcleanairfunction", "setrecirculating",
                  "resetgreasefilter"):
        assert field in const.WRITABLE_FIELDS
