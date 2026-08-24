from contextlib import nullcontext

import pytest

from pyzephyrconnect.probe import diff_states, parse_assignment, validate_write


@pytest.mark.parametrize(
    ("text", "expected"),
    [("fan=3", ("fan", 3)), ("light=0", ("light", 0)), ("power=1", ("power", 1))],
)
def test_parse_assignment(text, expected):
    assert parse_assignment(text) == expected


@pytest.mark.parametrize("text", ["fan", "fan=", "=3", "fan=high", "fan=3=4"])
def test_parse_assignment_rejects_malformed_input(text):
    with pytest.raises(ValueError):
        parse_assignment(text)


def test_write_requires_confirmation():
    """--confirm is the deliberate speed bump before actuating hardware."""
    with pytest.raises(PermissionError, match="--confirm"):
        validate_write("light", confirmed=False, forced=False)


def test_readonly_fields_are_refused_even_with_confirm():
    """Counters and alarms are device-reported. Writing them is meaningless
    at best and confusing at worst."""
    for field in ("usegreasefiltertime", "alarmfan", "isOnline", "faultCode"):
        with pytest.raises(PermissionError, match="not writable"):
            validate_write(field, confirmed=True, forced=True)


def test_unknown_fields_are_refused():
    with pytest.raises(PermissionError, match="not writable"):
        validate_write("madeUpField", confirmed=True, forced=True)


def test_dangerous_fields_need_force_as_well_as_confirm():
    """resetgreasefilter zeroes an unrecoverable counter; setrecirculating
    changes filter accounting. --confirm alone must not be enough."""
    for field in ("resetgreasefilter", "setrecirculating"):
        with pytest.raises(PermissionError, match="--force"):
            validate_write(field, confirmed=True, forced=False)


@pytest.mark.parametrize("field", ["light", "fan", "power", "setdelaytimer"])
def test_ordinary_writes_pass_with_confirm_alone(field):
    with nullcontext():
        validate_write(field, confirmed=True, forced=False)


@pytest.mark.parametrize("field", ["resetgreasefilter", "setrecirculating"])
def test_dangerous_writes_pass_with_both_flags(field):
    with nullcontext():
        validate_write(field, confirmed=True, forced=True)


def test_diff_reports_only_changed_keys():
    before = {"fan": 0, "light": 0, "usefantime": 1979}
    after = {"fan": 3, "light": 0, "usefantime": 1979}
    assert diff_states(before, after) == {"fan": (0, 3)}


def test_diff_reports_newly_appearing_keys():
    """A field the device only reports once set is exactly what the
    validation sequence is hunting for."""
    assert diff_states({"fan": 0}, {"fan": 0, "newField": 7}) == {
        "newField": (None, 7)
    }


def test_diff_of_identical_states_is_empty():
    assert diff_states({"fan": 1}, {"fan": 1}) == {}
