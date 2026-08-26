"""Tests for pyzephyrconnect.probe."""

import json
from contextlib import nullcontext

import pytest

from pyzephyrconnect.probe import (
    _REDACT,
    _range,
    _redacted,
    diff_states,
    parse_assignment,
    validate_write,
)


@pytest.mark.parametrize(
    ("text", "expected"),
    [("fan=3", ("fan", 3)), ("light=0", ("light", 0)), ("power=1", ("power", 1))],
)
def test_parse_assignment(text, expected):
    """Tests that field=value parses into a (field, int) tuple."""
    assert parse_assignment(text) == expected


@pytest.mark.parametrize("text", ["fan", "fan=", "=3", "fan=high", "fan=3=4"])
def test_parse_assignment_rejects_malformed_input(text):
    """Tests that a malformed assignment raises ValueError."""
    with pytest.raises(ValueError):
        parse_assignment(text)


def test_write_requires_confirmation():
    """--confirm is the deliberate speed bump before actuating hardware."""
    with pytest.raises(PermissionError, match="--confirm"):
        validate_write("light", confirmed=False, forced=False)


def test_readonly_fields_are_refused_even_with_confirm():
    """Tests that device-reported fields are refused even when forced.

    Counters and alarms are device-reported. Writing them is meaningless
    at best and confusing at worst.
    """
    for field in ("usegreasefiltertime", "alarmfan", "isOnline", "faultCode"):
        with pytest.raises(PermissionError, match="not writable"):
            validate_write(field, confirmed=True, forced=True)


def test_unknown_fields_are_refused():
    """Tests that an unknown field is refused as not writable."""
    with pytest.raises(PermissionError, match="not writable"):
        validate_write("madeUpField", confirmed=True, forced=True)


def test_dangerous_fields_need_force_as_well_as_confirm():
    """Tests that dangerous fields need --force on top of --confirm.

    resetgreasefilter zeroes an unrecoverable counter; setrecirculating
    changes filter accounting. --confirm alone must not be enough.
    """
    for field in ("resetgreasefilter", "setrecirculating"):
        with pytest.raises(PermissionError, match="--force"):
            validate_write(field, confirmed=True, forced=False)


@pytest.mark.parametrize("field", ["light", "fan", "power", "setdelaytimer"])
def test_ordinary_writes_pass_with_confirm_alone(field):
    """Tests that ordinary fields validate with --confirm alone."""
    with nullcontext():
        validate_write(field, confirmed=True, forced=False)


@pytest.mark.parametrize("field", ["resetgreasefilter", "setrecirculating"])
def test_dangerous_writes_pass_with_both_flags(field):
    """Tests that dangerous fields validate with --confirm and --force."""
    with nullcontext():
        validate_write(field, confirmed=True, forced=True)


@pytest.mark.parametrize(("maximum", "expected"), [(6, "0-6"), (3, "0-3"), (0, "0-0")])
def test_range_formats_an_advertised_maximum(maximum, expected):
    """Tests that an advertised maximum renders as the 0-N device banner form."""
    assert _range(maximum) == expected


def test_range_names_an_unadvertised_maximum_unknown():
    """Tests that a missing maximum renders as 'range unknown', never '0-None'.

    A hood we have never seen may not advertise maxFanSpeed or
    maxLightLevel; the device banner must say so instead of printing the
    literal '0-None'.
    """
    assert _range(None) == "range unknown"
    assert "None" not in _range(None)


def test_diff_reports_only_changed_keys():
    """Tests that diff_states reports only keys whose values changed."""
    before = {"fan": 0, "light": 0, "usefantime": 1979}
    after = {"fan": 3, "light": 0, "usefantime": 1979}
    assert diff_states(before, after) == {"fan": (0, 3)}


def test_diff_reports_newly_appearing_keys():
    """Tests that a newly appearing key is reported as (None, value).

    A field the device only reports once set is exactly what the
    validation sequence is hunting for.
    """
    assert diff_states({"fan": 0}, {"fan": 0, "newField": 7}) == {"newField": (None, 7)}


def test_diff_of_identical_states_is_empty():
    """Tests that diff_states of identical states is empty."""
    assert diff_states({"fan": 1}, {"fan": 1}) == {}


def test_redacted_diff_never_exposes_an_identifier_that_starts_reporting():
    """Tests that a redacted key appearing anew shows the placeholder.

    Every print path must run diff_states on redacted snapshots. When a
    _REDACT key (e.g. location) goes from absent to present - the shape
    diff_states can actually express as a "change" once both snapshots are
    pre-redacted - the reported old/new must be None / the redaction
    placeholder, never the real coordinates.
    """
    before = {"fan": 1}
    after = {"location": "41.0,-106.0", "fan": 1}

    changes = diff_states(_redacted(before), _redacted(after))

    assert changes == {"location": (None, "<redacted>")}
    assert "41.0" not in repr(changes) and "-106.0" not in repr(changes)


def test_redacted_diff_drops_a_changed_identifier_present_on_both_sides():
    """Tests that a changed redacted key drops out of the diff.

    When a _REDACT key is present before and after but its value
    changes, redacting before diffing collapses both sides to the same
    placeholder, so diff_states (equality-based) treats it as unchanged and
    the key drops out entirely - the strongest form of "never leaks",
    since nothing about the key's real value is reported at all.
    """
    before = {"location": "40.0,-105.0", "fan": 1}
    after = {"location": "41.0,-106.0", "fan": 1}

    changes = diff_states(_redacted(before), _redacted(after))

    assert "location" not in changes
    assert "40.0" not in repr(changes) and "41.0" not in repr(changes)
    assert "-105.0" not in repr(changes) and "-106.0" not in repr(changes)


def test_redacted_diff_still_shows_real_values_for_ordinary_keys():
    """Tests that ordinary keys keep real values through redaction.

    Redaction must not over-blank: a change in a non-_REDACT key still
    reports its real before/after values through the same redacted-diff
    path used by watch mode and post-write reporting.
    """
    before = {"location": "40.0,-105.0", "fan": 0}
    after = {"location": "40.0,-105.0", "fan": 3}

    changes = diff_states(_redacted(before), _redacted(after))

    assert changes == {"fan": (0, 3)}
    assert "location" not in _REDACT or "location" not in changes


async def test_async_stop_runs_even_when_a_post_start_step_raises(monkeypatch):
    """Tests that the shadow disconnects when a post-start step raises.

    main() must disconnect the shadow client on every path once
    hood.async_start() has begun, not only on happy-path returns. Here
    shadow.request_state() (invoked inside Hood._start()) raises, so the
    failure surfaces before probe ever prints state - this also covers the
    harder case where the shadow was already registered on the hood before
    the exception, not just a clean failure to start.
    """
    from datetime import UTC, datetime, timedelta
    from pathlib import Path
    from unittest.mock import AsyncMock, MagicMock

    from pyzephyrconnect import client as client_module
    from pyzephyrconnect import probe
    from pyzephyrconnect.auth import Credentials
    from pyzephyrconnect.const import DEFAULT_ENDPOINTS

    fixtures = Path(__file__).parent / "fixtures"
    discover = json.loads((fixtures / "discoverdevice.json").read_text())
    thing = discover["thingName"]

    # A double for the AbstractAuth surface ZephyrClient now drives -
    # CredentialsAuth was replaced with token-based auth in Tasks 6 and 10,
    # so the pre-refactor authenticate()/attach_policy()/id_token surface no
    # longer exists.
    auth = MagicMock()
    auth.endpoints = DEFAULT_ENDPOINTS
    auth.identity_id = "us-west-2:abc"
    auth.mqtt_client_id = "us-west-2:abc-py"
    auth.credentials_expired = False
    auth.async_get_tokens = AsyncMock()
    auth.async_get_credentials = AsyncMock(
        return_value=Credentials("k", "s", "t", datetime.now(UTC) + timedelta(hours=1))
    )
    auth.async_attach_policy = AsyncMock()

    api = MagicMock()
    api.get_own_devices = AsyncMock(return_value=[{"thingName": thing}])
    api.discover_device = AsyncMock(return_value=discover)

    shadow = MagicMock()
    shadow.connect = AsyncMock()
    shadow.disconnect = AsyncMock()
    shadow.request_state = AsyncMock(side_effect=RuntimeError("boom"))

    # from_credentials() constructs a CredentialsAuth internally; patching
    # the class is how the double gets injected without touching probe.py's
    # call site.
    monkeypatch.setattr(client_module, "CredentialsAuth", MagicMock(return_value=auth))
    monkeypatch.setattr(client_module, "ZephyrApi", MagicMock(return_value=api))
    monkeypatch.setattr(client_module, "ShadowClient", MagicMock(return_value=shadow))
    monkeypatch.setenv("ZEPHYR_USER", "user@example.com")
    monkeypatch.setenv("ZEPHYR_PASS", "hunter2")

    with pytest.raises(RuntimeError, match="boom"):
        await probe.main([])

    # client.async_stop() (called in probe's finally) cancels and awaits
    # the refresh supervisor _make_shadow started, so no stray task is left
    # behind for this test to reap.
    shadow.disconnect.assert_awaited_once()


async def test_thing_mismatch_exits_2_without_touching_the_device(monkeypatch):
    """Tests that a --thing mismatch exits 2 without device writes.

    An operator typo in --thing must fail closed rather than silently
    fall back to actuating whichever hood happens to be first on the
    account - that fallback is exactly what let a `--thing` typo write to
    the wrong physical hardware.
    """
    from datetime import UTC, datetime, timedelta
    from pathlib import Path
    from unittest.mock import AsyncMock, MagicMock

    from pyzephyrconnect import client as client_module
    from pyzephyrconnect import probe
    from pyzephyrconnect.auth import Credentials
    from pyzephyrconnect.const import DEFAULT_ENDPOINTS

    fixtures = Path(__file__).parent / "fixtures"
    discover = json.loads((fixtures / "discoverdevice.json").read_text())
    thing = discover["thingName"]

    auth = MagicMock()
    auth.endpoints = DEFAULT_ENDPOINTS
    auth.identity_id = "us-west-2:abc"
    auth.mqtt_client_id = "us-west-2:abc-py"
    auth.credentials_expired = False
    auth.async_get_tokens = AsyncMock()
    auth.async_get_credentials = AsyncMock(
        return_value=Credentials("k", "s", "t", datetime.now(UTC) + timedelta(hours=1))
    )
    auth.async_attach_policy = AsyncMock()

    api = MagicMock()
    api.get_own_devices = AsyncMock(return_value=[{"thingName": thing}])
    api.discover_device = AsyncMock(return_value=discover)

    shadow = MagicMock()
    shadow.connect = AsyncMock()
    shadow.disconnect = AsyncMock()
    shadow.request_state = AsyncMock()
    shadow.publish_state = AsyncMock()

    monkeypatch.setattr(client_module, "CredentialsAuth", MagicMock(return_value=auth))
    monkeypatch.setattr(client_module, "ZephyrApi", MagicMock(return_value=api))
    monkeypatch.setattr(client_module, "ShadowClient", MagicMock(return_value=shadow))
    monkeypatch.setenv("ZEPHYR_USER", "user@example.com")
    monkeypatch.setenv("ZEPHYR_PASS", "hunter2")

    exit_code = await probe.main(
        ["--thing", "does-not-match-anything", "--set", "light=1", "--confirm"]
    )

    assert exit_code == 2
    shadow.connect.assert_not_awaited()
    shadow.publish_state.assert_not_awaited()
