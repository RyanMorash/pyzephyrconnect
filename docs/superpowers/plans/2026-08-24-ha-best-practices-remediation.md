# HA Best-Practices Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bring `pyzephyrconnect` into line with the three Home Assistant library documentation pages by replacing credential-holding auth with an abstract token surface, making endpoints injectable, moving writes onto a typed `Hood` object, and distinguishing absent data from zero.

**Architecture:** `AbstractAuth` yields persistable `ZephyrTokens`; `CredentialsAuth` is the built-in SRP implementation. `Endpoints` replaces hardcoded module constants. `ZephyrClient.async_setup()` returns `Hood` objects that own both state and controls. `ZephyrClient` runs a supervisor task that keeps AWS credentials fresh and rebuilds MQTT sockets before they expire, because a presigned WebSocket URL cannot outlive its signature.

**Tech Stack:** Python 3.12+, aiohttp, pycognito, boto3, paho-mqtt 2.x, pytest with `asyncio_mode = auto`.

**Spec:** `docs/superpowers/specs/2026-08-24-ha-best-practices-remediation-design.md`

## Global Constraints

- Nothing is released. There are no tags and PyPI 404s. **No backward compatibility is required or wanted.** Do not add deprecation shims.
- No test may touch the network. `tests/conftest.py` fakes aiohttp; pycognito and boto3 are replaced with `MagicMock` via `monkeypatch`. Preserve this.
- `pytest` runs with `asyncio_mode = auto`. Async tests need **no** `@pytest.mark.asyncio` decorator.
- Ruff 0.14.14 must pass: `ruff check`. Line length and import style follow the existing files.
- The vendor REST API takes a **bare ID token** in `Authorization` — no `Bearer ` prefix. Never add one.
- `getowndevices` is POSTed with a **zero-length body** (`data=b""`), not `{}`.
- The MQTT client ID is `identity_id + "-ha"`. The `us-west-2:` region prefix is **never** stripped.
- Shadow writes go to `state.reported`, never `state.desired`. The device silently ignores `desired`.
- `update/delta` messages stay ignored (debug-logged only).
- `HoodState.raw` and `HoodCapabilities.raw` keep their current shape and contents. Do not change them.
- TLS: `verify_mode` stays `CERT_REQUIRED`, hostname checking stays on, TWCA certs stay **supplementary** anchors on the system store. Never pin, never disable verification.
- Every new exception subclasses `ZephyrError`.
- Commit after every task.

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `src/pyzephyrconnect/const.py` | Raw protocol constants + `Endpoints` dataclass | Modify |
| `src/pyzephyrconnect/exceptions.py` | Exception hierarchy | Modify |
| `src/pyzephyrconnect/models.py` | `HoodCapabilities`, `HoodState` | Modify |
| `src/pyzephyrconnect/auth.py` | `ZephyrTokens`, `AbstractAuth`, `CredentialsAuth`, `Credentials` | Rewrite |
| `src/pyzephyrconnect/api.py` | Vendor REST, now auth-driven | Modify |
| `src/pyzephyrconnect/shadow.py` | MQTT transport, now provider-driven | Modify |
| `src/pyzephyrconnect/hood.py` | `Hood` — state + controls | **Create** |
| `src/pyzephyrconnect/client.py` | Lifecycle facade + refresh supervisor | Rewrite |
| `src/pyzephyrconnect/probe.py` | Diagnostic CLI | Modify |
| `src/pyzephyrconnect/py.typed` | PEP 561 marker | **Create** |
| `tests/test_hood.py` | `Hood` controls and validation | **Create** |
| `tests/test_tokens.py` | `ZephyrTokens` round-trip | **Create** |

---

### Task 1: Packaging and repository metadata

**Files:**
- Modify: `pyproject.toml`
- Create: `src/pyzephyrconnect/py.typed`
- Create: `.github/ISSUE_TEMPLATE/config.yml`
- Create: `.github/ISSUE_TEMPLATE/bug_report.yml`

**Interfaces:**
- Consumes: nothing.
- Produces: `boto3` as a declared dependency; a `py.typed` marker shipped in the wheel.

- [ ] **Step 1: Declare boto3 and modernise metadata**

`boto3` is imported directly at `auth.py:15` but resolves today only because `pycognito` requires it. Replace the `[project]` block's `license`, `dependencies` and `urls` sections:

```toml
license = "GPL-3.0-or-later"
license-files = ["LICENSE"]
authors = [{ name = "Ryan Morash" }]
classifiers = [
    "Development Status :: 3 - Alpha",
    "Intended Audience :: Developers",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.12",
    "Programming Language :: Python :: 3.13",
    "Programming Language :: Python :: 3.14",
    "Topic :: Home Automation",
    "Typing :: Typed",
]
dependencies = [
    "aiohttp>=3.9",
    "boto3>=1.34",
    "pycognito>=2024.5.1",
    "paho-mqtt>=2.1.0",
]

[project.urls]
Homepage = "https://github.com/RyanMorash/pyzephyrconnect"
"Bug Tracker" = "https://github.com/RyanMorash/pyzephyrconnect/issues"
```

Delete the old `license = { text = "GPL-3.0-or-later" }` line.

- [ ] **Step 2: Add the PEP 561 marker**

```bash
touch src/pyzephyrconnect/py.typed
```

`[tool.hatch.build.targets.wheel] packages = ["src/pyzephyrconnect"]` already walks the whole tree, so no force-include is needed — the same reasoning as the `certs/twca.pem` comment already in `pyproject.toml`. Do **not** add a force-include; it caused a duplicate-path build error before.

- [ ] **Step 3: Add the issue template picker**

`.github/ISSUE_TEMPLATE/config.yml`:

```yaml
blank_issues_enabled: false
contact_links:
  - name: Home Assistant integration issue
    url: https://github.com/home-assistant/core/issues
    about: >-
      If the problem is with the Home Assistant integration rather than this
      library's protocol handling, report it against Home Assistant Core.
  - name: Zephyr Connect integration issue
    url: https://github.com/RyanMorash/ha_zephyr/issues
    about: Problems with entities, config flow or setup belong here.
```

`.github/ISSUE_TEMPLATE/bug_report.yml`:

```yaml
name: Bug report
description: A protocol or library defect in pyzephyrconnect
labels: ["bug"]
body:
  - type: input
    id: version
    attributes:
      label: pyzephyrconnect version
    validations:
      required: true
  - type: input
    id: model
    attributes:
      label: Hood model
      description: From the vendor app, or the modelName field in diagnostics.
    validations:
      required: true
  - type: textarea
    id: what
    attributes:
      label: What happened
    validations:
      required: true
  - type: textarea
    id: logs
    attributes:
      label: Logs
      description: >-
        Redact thingName, SN, MAC and location before pasting — they identify
        your home.
      render: text
```

- [ ] **Step 4: Verify the build still produces both distributions**

Run: `python -m build && python -m twine check --strict dist/*`
Expected: `PASSED` for both the sdist and the wheel.

Run: `python -c "import zipfile,glob; w,=glob.glob('dist/*.whl'); n=zipfile.ZipFile(w).namelist(); assert 'pyzephyrconnect/py.typed' in n; assert n.count('pyzephyrconnect/certs/twca.pem')==1; print('ok')"`
Expected: `ok`

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml src/pyzephyrconnect/py.typed .github/ISSUE_TEMPLATE
git commit -m "build: declare boto3, ship py.typed, modernise metadata"
```

---

### Task 2: Exception hierarchy

**Files:**
- Modify: `src/pyzephyrconnect/exceptions.py`
- Modify: `src/pyzephyrconnect/__init__.py`
- Test: `tests/test_exceptions.py` (create)

**Interfaces:**
- Consumes: existing `ZephyrError`.
- Produces: `ZephyrNotConnectedError`, `ZephyrWriteError`, `ZephyrDataError` — all subclasses of `ZephyrError`, all exported from the package root.

- [ ] **Step 1: Write the failing test**

`tests/test_exceptions.py`:

```python
import pyzephyrconnect
from pyzephyrconnect.exceptions import (
    ZephyrDataError,
    ZephyrError,
    ZephyrNotConnectedError,
    ZephyrWriteError,
)


def test_new_errors_are_catchable_as_the_base():
    """A consumer catching ZephyrError must catch everything the library
    raises. Bare RuntimeError/ValueError previously escaped that net."""
    for cls in (ZephyrNotConnectedError, ZephyrWriteError, ZephyrDataError):
        assert issubclass(cls, ZephyrError)


def test_new_errors_are_exported_from_the_package_root():
    for name in (
        "ZephyrNotConnectedError",
        "ZephyrWriteError",
        "ZephyrDataError",
    ):
        assert name in pyzephyrconnect.__all__
        assert hasattr(pyzephyrconnect, name)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_exceptions.py -v`
Expected: FAIL with `ImportError: cannot import name 'ZephyrDataError'`

- [ ] **Step 3: Add the exceptions**

Append to `src/pyzephyrconnect/exceptions.py`:

```python
class ZephyrNotConnectedError(ZephyrError):
    """An operation needed a live shadow connection and there was none.

    Call Hood.async_start() before reading push state or writing.
    """


class ZephyrWriteError(ZephyrError):
    """A shadow write was refused before it left the process.

    Either the field is not in WRITABLE_FIELDS, or the value is outside the
    range the device's own capabilities declare. Nothing was published.
    """


class ZephyrDataError(ZephyrError):
    """A payload field was present but could not be parsed.

    Distinct from an absent field, which is not an error - other Zephyr
    models legitimately omit keys this one returns.
    """
```

In `src/pyzephyrconnect/__init__.py`, add the three names to both the `from .exceptions import (...)` block and `__all__`.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_exceptions.py -v`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add src/pyzephyrconnect/exceptions.py src/pyzephyrconnect/__init__.py tests/test_exceptions.py
git commit -m "feat: add not-connected, write and data errors to the hierarchy"
```

---

### Task 3: Injectable endpoints

**Files:**
- Modify: `src/pyzephyrconnect/const.py`
- Modify: `src/pyzephyrconnect/__init__.py`
- Test: `tests/test_const.py`

**Interfaces:**
- Consumes: the existing module-level constants.
- Produces: `Endpoints` (frozen dataclass) and `DEFAULT_ENDPOINTS`, both exported from the package root. Fields: `region`, `user_pool`, `client_id`, `client_secret`, `identity_pool`, `iot_endpoint`, `device_api_base`. Properties: `provider`, `device_api_list`, `device_api_discover`.

- [ ] **Step 1: Write the failing test**

Append to `tests/test_const.py`:

```python
from pyzephyrconnect.const import DEFAULT_ENDPOINTS, Endpoints


def test_defaults_reproduce_the_current_constants():
    e = DEFAULT_ENDPOINTS
    assert e.region == "us-west-2"
    assert e.iot_endpoint.endswith("-ats.iot.us-west-2.amazonaws.com")
    assert e.device_api_list.endswith("/getowndevices")
    assert e.device_api_discover.endswith("/discoverdevice")
    assert e.provider == "cognito-idp.us-west-2.amazonaws.com/us-west-2_McuoKpkna"


def test_overriding_the_base_moves_both_rest_urls():
    """Developers must be able to specify API locations - a staging host, or
    a vendor host change, should not require a release."""
    e = Endpoints(device_api_base="https://staging.example.com/prod")
    assert e.device_api_list == "https://staging.example.com/prod/getowndevices"
    assert e.device_api_discover == "https://staging.example.com/prod/discoverdevice"


def test_endpoints_are_frozen():
    with pytest.raises(Exception):
        DEFAULT_ENDPOINTS.region = "eu-west-1"
```

Add `import pytest` to the top of the file if it is not already there.

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_const.py -v`
Expected: FAIL with `ImportError: cannot import name 'Endpoints'`

- [ ] **Step 3: Add the dataclass**

Add to `src/pyzephyrconnect/const.py`, after the existing constants and before `CLIENT_ID_SUFFIX`:

```python
from dataclasses import dataclass


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
    client_secret: str = CLIENT_SECRET
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
```

Keep the existing bare constants — they are the defaults, and `probe.py` reads `WRITABLE_FIELDS`/`DANGEROUS_FIELDS` from this module.

Export `Endpoints` and `DEFAULT_ENDPOINTS` from `src/pyzephyrconnect/__init__.py` (`from .const import DEFAULT_ENDPOINTS, Endpoints`, plus both names in `__all__`).

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_const.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/pyzephyrconnect/const.py src/pyzephyrconnect/__init__.py tests/test_const.py
git commit -m "feat: make service endpoints injectable via an Endpoints dataclass"
```

---

### Task 4: Absent is not zero

**Files:**
- Modify: `src/pyzephyrconnect/models.py`
- Test: `tests/test_models.py`

**Interfaces:**
- Consumes: `ZephyrDataError` from Task 2.
- Produces: `HoodState` with `| None` on every field except the four usage counters; `HoodCapabilities` with `int | None` numeric fields, absent → `None`, malformed → `ZephyrDataError`.

Exact `HoodState` field types after this task:

```
power, light, fan                                        int | None = None
act                                                      str | None = None
delay_timer, set_delay_timer                             int | None = None
set_recirculating, set_clean_air_function                int | None = None
clean_grease_filters, clean_charcoal_filters             int | None = None
alarm_fan, alarm_fault_code, alarm_grease_filter         int | None = None
fan_warning                                              int | None = None
is_online                                                bool | None = None
fault_codes                                              tuple[Any, ...] | None = None
use_grease_filter_time, use_charcoal_filter_time         int = 0
use_light_time, use_fan_time                             int = 0
raw                                                      Mapping[str, Any]  (unchanged)
```

`HoodCapabilities` numeric fields (`max_fan_speed`, `max_light_level`, `max_grease_filter_hours`, `max_charcoal_filter_hours`) become `int | None`. String fields keep `str` with `""` defaults. `supports_*` booleans keep `bool` with `False` defaults — absent means "not advertised", which is the correct reading for a feature flag.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_models.py`:

```python
from pyzephyrconnect.exceptions import ZephyrDataError


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
    assert state.power == 0 or state.power is not None


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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_models.py -v`
Expected: FAIL — `assert 0 is None` on the absent-field tests, and `DID NOT RAISE` on the capabilities test.

- [ ] **Step 3: Implement**

In `HoodState.from_reported`, replace the `as_int` helper and the field defaults:

```python
    @classmethod
    def from_reported(cls, reported: dict[str, Any]) -> HoodState:
        """Build state from a shadow `reported` block.

        Absent and malformed both yield None, which is not the same fact as
        zero: a missing `alarmfaultcode` is "unknown", not "no fault". The
        consumer decides how to present unknown. Malformed values are still
        logged, because a payload the device changed shape on is worth
        knowing about.

        The four usage counters are the exception - zero is their genuine
        starting value, and the filter-life percentage needs a number.
        """

        def as_int(key: str) -> int | None:
            if (value := reported.get(key)) is None or value == "":
                return None
            try:
                return int(value)
            except (TypeError, ValueError):
                _LOGGER.warning(
                    "Could not coerce %r value %r to int; treating as unknown",
                    key,
                    value,
                )
                return None

        def as_counter(key: str) -> int:
            return as_int(key) or 0

        def as_bool(key: str) -> bool | None:
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
```

Update the dataclass field declarations to the types in the Interfaces table above.

For `HoodCapabilities.from_discover`, replace the bare `int()` calls:

```python
    @classmethod
    def from_discover(cls, payload: dict[str, Any]) -> HoodCapabilities:
        """Build capabilities from the discoverdevice payload.

        Absent and malformed are different failures here. Absent is normal:
        other Zephyr models omit keys this one returns, and entity creation
        is gated on capabilities precisely so the library generalises to
        hoods nobody has tested. Malformed is a real error, and this runs
        once at setup, so it fails loudly.
        """

        def as_int(key: str) -> int | None:
            if (value := payload.get(key)) is None or value == "":
                return None
            try:
                return int(value)
            except (TypeError, ValueError) as err:
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
```

Import `ZephyrDataError` at the top of `models.py`.

- [ ] **Step 4: Run the full suite**

Run: `pytest tests/test_models.py -v`
Expected: PASS

Run: `pytest -q`
Expected: failures in `tests/test_client.py` only, from `HoodState` fields that are now `None`. Those are fixed in Task 10. Note which ones; do not fix them here.

- [ ] **Step 5: Commit**

```bash
git add src/pyzephyrconnect/models.py tests/test_models.py
git commit -m "feat: distinguish absent from zero in HoodState and HoodCapabilities"
```

---

### Task 5: `ZephyrTokens` and `AbstractAuth`

**Files:**
- Modify: `src/pyzephyrconnect/auth.py`
- Modify: `src/pyzephyrconnect/__init__.py`
- Test: `tests/test_tokens.py` (create)

**Interfaces:**
- Consumes: `Endpoints`/`DEFAULT_ENDPOINTS` from Task 3, `ZephyrAuthError`.
- Produces:
  - `ZephyrTokens(username: str, id_token: str, refresh_token: str, identity_id: str, expires_at: float)`, frozen, with `as_dict() -> dict[str, str | float]`, `from_dict(Mapping) -> ZephyrTokens`, and `expired: bool`.
  - `AbstractAuth(session, endpoints=DEFAULT_ENDPOINTS)` with abstract `async_get_tokens() -> ZephyrTokens`.
  - Existing `Credentials` dataclass is unchanged.

`ZephyrTokens.username` exists because Cognito's `SECRET_HASH` is `HMAC-SHA256(client_secret, username + client_id)` and pycognito recomputes it from `self.username` on every `REFRESH_TOKEN_AUTH` call. Tokens without a username cannot drive a refresh.

`expires_at` is epoch seconds so the dataclass stays JSON-serializable, per the auth documentation's "dictionaries with primitive types".

- [ ] **Step 1: Write the failing test**

`tests/test_tokens.py`:

```python
import time

import pytest

from pyzephyrconnect.auth import AbstractAuth, ZephyrTokens


def _tokens(**overrides):
    base = {
        "username": "user@example.com",
        "id_token": "ID",
        "refresh_token": "REFRESH",
        "identity_id": "us-west-2:00000000-1111-2222-3333-444455556666",
        "expires_at": time.time() + 3600,
    }
    return ZephyrTokens(**{**base, **overrides})


def test_tokens_round_trip_through_primitives():
    """The auth docs require JSON-serializable auth data so the consumer can
    persist it. json.dumps must work without a custom encoder."""
    import json

    original = _tokens()
    restored = ZephyrTokens.from_dict(json.loads(json.dumps(original.as_dict())))
    assert restored == original


def test_tokens_carry_the_username():
    """SECRET_HASH is HMAC(client_secret, username + client_id); pycognito
    recomputes it on every refresh. Tokens without a username are inert."""
    assert _tokens().username == "user@example.com"


def test_expired_is_true_inside_the_refresh_margin():
    assert _tokens(expires_at=time.time() + 60).expired is True
    assert _tokens(expires_at=time.time() + 3600).expired is False


def test_abstract_auth_cannot_be_instantiated():
    with pytest.raises(TypeError):
        AbstractAuth(session=None)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_tokens.py -v`
Expected: FAIL with `ImportError: cannot import name 'ZephyrTokens'`

- [ ] **Step 3: Implement**

Add to `src/pyzephyrconnect/auth.py`, above the existing `Credentials` class:

```python
import time
from abc import ABC, abstractmethod
from collections.abc import Mapping
from typing import Any

import aiohttp

from .const import DEFAULT_ENDPOINTS, Endpoints


The existing `Credentials` dataclass gets the same treatment in this task —
`secret_key` and `session_token` become `field(repr=False)` for the same
reason. `Endpoints.client_secret` too: it is already public (it ships in the
iOS bundle) but there is no reason to print it.

```python
@dataclass(frozen=True, slots=True)
class ZephyrTokens:
    """Consumer-persistable auth state.

    Primitives only - the auth documentation asks for JSON-serializable
    data so the consumer, not the library, owns storage.

    `username` is not decoration: Cognito's SECRET_HASH is
    HMAC-SHA256(client_secret, username + client_id), and pycognito
    recomputes it on every REFRESH_TOKEN_AUTH call. Tokens without it
    cannot be refreshed.

    `identity_id` is the full "us-west-2:uuid" string. The region prefix is
    load-bearing - it is what the IoT policy's
    ${cognito-identity.amazonaws.com:sub} resolves to, and it is the basis
    of the MQTT client ID. Never strip it.
    """

    username: str
    # repr=False on both: a refresh token is valid for ~30 days and is on its
    # own enough to take over the account. The default dataclass repr would
    # put it in any log line or traceback that captures this object, and
    # Home Assistant users paste logs into public issues.
    id_token: str = field(repr=False)
    refresh_token: str = field(repr=False)
    identity_id: str
    expires_at: float

    @property
    def expired(self) -> bool:
        """True once inside the refresh margin.

        Deliberately pessimistic for the same reason Credentials.expired is:
        rebuilding the MQTT socket takes time.
        """
        return time.time() >= (self.expires_at - const.REFRESH_MARGIN_SECONDS)

    def as_dict(self) -> dict[str, str | float]:
        return {
            "username": self.username,
            "id_token": self.id_token,
            "refresh_token": self.refresh_token,
            "identity_id": self.identity_id,
            "expires_at": self.expires_at,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ZephyrTokens:
        return cls(
            username=str(data["username"]),
            id_token=str(data["id_token"]),
            refresh_token=str(data["refresh_token"]),
            identity_id=str(data["identity_id"]),
            expires_at=float(data["expires_at"]),
        )


class AbstractAuth(ABC):
    """Supplies valid Zephyr cloud tokens.

    Implement this to keep credentials out of the library entirely: the
    consumer owns storage and refresh policy, and the library only ever
    asks for a token that works right now.

    CredentialsAuth is the built-in implementation for the simple case.
    """

    def __init__(
        self,
        session: aiohttp.ClientSession,
        endpoints: Endpoints = DEFAULT_ENDPOINTS,
    ) -> None:
        self.session = session
        self.endpoints = endpoints

    @abstractmethod
    async def async_get_tokens(self) -> ZephyrTokens:
        """Return valid, unexpired tokens, refreshing if necessary."""

    @property
    def identity_id(self) -> str:
        """Cognito identity ID from the most recent tokens.

        Consumers use this as a stable per-account key. Implementations that
        cache tokens differently should override this; the default reads the
        `_tokens` attribute an implementation is expected to maintain.
        """
        tokens = getattr(self, "_tokens", None)
        if tokens is None:
            raise ZephyrAuthError("async_get_tokens() has not been called")
        return tokens.identity_id
```

Export `AbstractAuth` and `ZephyrTokens` from `src/pyzephyrconnect/__init__.py`.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_tokens.py -v`
Expected: PASS (4 passed)

- [ ] **Step 5: Commit**

```bash
git add src/pyzephyrconnect/auth.py src/pyzephyrconnect/__init__.py tests/test_tokens.py
git commit -m "feat: add ZephyrTokens and the AbstractAuth surface"
```

---

### Task 6: `CredentialsAuth`

**Files:**
- Modify: `src/pyzephyrconnect/auth.py`
- Test: `tests/test_auth.py`

**Interfaces:**
- Consumes: `ZephyrTokens`, `AbstractAuth`, `Endpoints`, `Credentials`.
- Produces: `CredentialsAuth(username, password, session, *, tokens=None, token_updater=None, endpoints=DEFAULT_ENDPOINTS)` implementing `async_get_tokens()`, plus `async_get_credentials() -> Credentials`, `async_attach_policy() -> None`, and the `mqtt_client_id` property. `ZephyrAuth` is deleted and replaced by this class.

Behaviour contract:

| Situation | Action |
|---|---|
| No tokens supplied | Full SRP login |
| Tokens supplied, not expired | Return as-is, no network |
| Tokens supplied, expired | `renew_access_token()`, then re-exchange |
| Refresh raises `NotAuthorizedException` | Fall back to full SRP login |
| Any successful acquisition | Invoke `token_updater(tokens)` |
| `get_credentials_for_identity` fails with a stored `identity_id` | Discard it, `get_id()` again, retry once, then raise |

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_auth.py`:

```python
import time
from unittest.mock import AsyncMock

from botocore.exceptions import ClientError

from pyzephyrconnect.auth import CredentialsAuth, ZephyrTokens


def _not_authorized():
    return ClientError(
        {"Error": {"Code": "NotAuthorizedException", "Message": "expired"}},
        "InitiateAuth",
    )


def _stored_tokens(expires_in=-1):
    return ZephyrTokens(
        username="user@example.com",
        id_token="OLD-ID",
        refresh_token="REFRESH",
        identity_id=IDENTITY,
        expires_at=time.time() + expires_in,
    )


async def test_srp_runs_when_no_tokens_are_supplied(fake_aws):
    auth = CredentialsAuth("user@example.com", "pw", MagicMock())
    tokens = await auth.async_get_tokens()

    fake_aws["cognito"].authenticate.assert_called_once_with(password="pw")
    assert tokens.id_token == "ID-TOKEN"
    assert tokens.username == "user@example.com"


async def test_unexpired_stored_tokens_skip_the_network_entirely(fake_aws):
    """The whole point of persistence: a restart must not re-run SRP."""
    auth = CredentialsAuth(
        "user@example.com", "pw", MagicMock(), tokens=_stored_tokens(3600)
    )
    tokens = await auth.async_get_tokens()

    assert tokens.id_token == "OLD-ID"
    fake_aws["cognito"].authenticate.assert_not_called()


async def test_expired_stored_tokens_refresh_instead_of_full_srp(fake_aws):
    auth = CredentialsAuth(
        "user@example.com", "pw", MagicMock(), tokens=_stored_tokens()
    )
    await auth.async_get_tokens()

    fake_aws["cognito"].renew_access_token.assert_called_once()
    fake_aws["cognito"].authenticate.assert_not_called()


async def test_rejected_refresh_token_falls_back_to_srp(fake_aws):
    """Cognito refresh tokens expire (30 days by default) and can be
    revoked. That must reauthenticate, not surface an error."""
    fake_aws["cognito"].renew_access_token.side_effect = _not_authorized()
    auth = CredentialsAuth(
        "user@example.com", "pw", MagicMock(), tokens=_stored_tokens()
    )
    tokens = await auth.async_get_tokens()

    fake_aws["cognito"].authenticate.assert_called_once_with(password="pw")
    assert tokens.id_token == "ID-TOKEN"


async def test_token_updater_fires_so_the_consumer_can_persist(fake_aws):
    seen = []
    auth = CredentialsAuth(
        "user@example.com", "pw", MagicMock(), token_updater=seen.append
    )
    await auth.async_get_tokens()

    assert len(seen) == 1
    assert seen[0].refresh_token


async def test_stale_identity_id_is_discarded_and_refetched_once(fake_aws):
    """A persisted identity_id survives restarts, so a wrong one becomes
    permanent. It decides the MQTT client ID and the IoT policy principal."""
    identity = fake_aws["identity"]
    identity.get_credentials_for_identity.side_effect = [
        _not_authorized(),
        _creds_response(),
    ]
    auth = CredentialsAuth(
        "user@example.com", "pw", MagicMock(), tokens=_stored_tokens(3600)
    )
    await auth.async_get_credentials()

    assert identity.get_id.call_count == 1
    assert identity.get_credentials_for_identity.call_count == 2


async def test_identity_id_is_read_not_reconstructed(fake_aws):
    """Consumers use this as a config entry's permanent unique ID, so it must
    come from the tokens rather than by stripping a suffix off a value
    derived from it."""
    auth = CredentialsAuth("user@example.com", "pw", MagicMock())
    await auth.async_get_tokens()

    assert auth.identity_id == IDENTITY
    assert auth.mqtt_client_id == f"{auth.identity_id}-ha"


async def test_identity_id_survives_a_refresh(fake_aws):
    """Password changes and token refreshes must not change the account key -
    the identity pool keys this on the user pool's immutable sub claim."""
    auth = CredentialsAuth(
        "user@example.com", "pw", MagicMock(), tokens=_stored_tokens()
    )
    first = (await auth.async_get_tokens()).identity_id
    auth._tokens = _stored_tokens()          # force another refresh
    assert (await auth.async_get_tokens()).identity_id == first


async def test_mqtt_client_id_keeps_the_region_prefix_and_suffix(fake_aws):
    """The policy pins client ID to identity; the suffix is what lets this
    coexist with the phone app instead of evicting it."""
    auth = CredentialsAuth("user@example.com", "pw", MagicMock())
    await auth.async_get_tokens()

    assert auth.mqtt_client_id == f"{IDENTITY}-ha"
    assert auth.mqtt_client_id.startswith("us-west-2:")
```

Extend the `fake_aws` fixture so the Cognito double carries refresh state:

```python
    cognito.id_token = "ID-TOKEN"
    cognito.refresh_token = "REFRESH-TOKEN"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_auth.py -v`
Expected: FAIL with `ImportError: cannot import name 'CredentialsAuth'`

- [ ] **Step 3: Implement**

Replace the `ZephyrAuth` class in `src/pyzephyrconnect/auth.py` with:

```python
class CredentialsAuth(AbstractAuth):
    """Built-in auth: SRP login, with refresh-token reuse.

    pycognito and boto3 are synchronous. Every blocking call is wrapped in
    asyncio.to_thread so callers get a purely async surface. renew_access_token
    also performs JWKS verification, which is a network call - it must stay
    in the worker thread.
    """

    def __init__(
        self,
        username: str,
        password: str,
        session: aiohttp.ClientSession,
        *,
        tokens: ZephyrTokens | None = None,
        token_updater: Callable[[ZephyrTokens], None] | None = None,
        endpoints: Endpoints = DEFAULT_ENDPOINTS,
    ) -> None:
        super().__init__(session, endpoints)
        self._username = username
        self._password = password
        self._tokens = tokens
        self._token_updater = token_updater
        self._user: Cognito | None = None
        self._credentials: Credentials | None = None

    @property
    def identity_id(self) -> str:
        """Cognito identity ID, the full "us-west-2:uuid" string.

        Stable per account: the identity pool keys this on the user pool's
        immutable `sub` claim, so it survives password and email changes and
        is idempotent across calls. That makes it the natural unique key for
        a consumer that needs to identify this account - for example a Home
        Assistant config entry's unique ID.

        Raises ZephyrAuthError if async_get_tokens() has not run yet.
        """
        if self._tokens is None:
            raise ZephyrAuthError("async_get_tokens() has not been called")
        return self._tokens.identity_id

    @property
    def mqtt_client_id(self) -> str:
        """Identity ID plus a stable suffix.

        The IoT policy pins the client ID to the identity. Using the bare
        identity ID makes this library and the phone app evict each other.

        Derived from identity_id, never the other way around.
        """
        return f"{self.identity_id}{const.CLIENT_ID_SUFFIX}"

    # -- blocking bodies, run in a worker thread ----------------------

    def _cognito(self, *, refresh_token: str | None = None) -> Cognito:
        return Cognito(
            self.endpoints.user_pool,
            self.endpoints.client_id,
            client_secret=self.endpoints.client_secret,
            username=self._username,
            refresh_token=refresh_token,
            # Must be explicit; otherwise pycognito reads ambient AWS config
            # and raises a confusing ResourceNotFoundException.
            user_pool_region=self.endpoints.region,
        )

    def _srp_login(self) -> Cognito:
        user = self._cognito()
        user.authenticate(password=self._password)
        return user

    def _refresh(self, refresh_token: str) -> Cognito:
        user = self._cognito(refresh_token=refresh_token)
        user.renew_access_token()
        return user

    def _identity_client(self):
        return boto3.client(
            "cognito-identity",
            region_name=self.endpoints.region,
            config=Config(signature_version=UNSIGNED),
        )

    def _exchange(
        self, id_token: str, identity_id: str | None
    ) -> tuple[str, Credentials]:
        """Trade an ID token for AWS credentials.

        A persisted identity_id is replayed when we have one, but it can be
        stale - and unlike an in-memory value, a bad one survives restarts.
        On failure it is discarded and refetched once before giving up.
        """
        client = self._identity_client()
        logins = {self.endpoints.provider: id_token}

        def fetch(iid: str | None) -> tuple[str, dict]:
            resolved = iid or client.get_id(
                IdentityPoolId=self.endpoints.identity_pool, Logins=logins
            )["IdentityId"]
            raw = client.get_credentials_for_identity(
                IdentityId=resolved, Logins=logins
            )["Credentials"]
            return resolved, raw

        try:
            resolved, raw = fetch(identity_id)
        except Exception:
            if identity_id is None:
                raise
            _LOGGER.debug("stored identity ID rejected; refetching")
            resolved, raw = fetch(None)

        return resolved, Credentials(
            access_key=raw["AccessKeyId"],
            # "SecretKey", not "SecretAccessKey" - differs from STS.
            secret_key=raw["SecretKey"],
            session_token=raw["SessionToken"],
            expiration=raw["Expiration"],
        )

    def _attach(self, identity_id: str, creds: Credentials) -> None:
        client = boto3.client(
            "iot",
            region_name=self.endpoints.region,
            aws_access_key_id=creds.access_key,
            aws_secret_access_key=creds.secret_key,
            aws_session_token=creds.session_token,
        )
        try:
            attached = client.list_attached_policies(target=identity_id)
            names = [p["policyName"] for p in attached.get("policies", [])]
            if const.POLICY_NAME in names:
                return
        except Exception:  # noqa: BLE001 - listing is best-effort
            _LOGGER.debug("list_attached_policies failed; attaching anyway")

        try:
            client.attach_policy(
                policyName=const.POLICY_NAME, target=identity_id
            )
        except Exception as err:  # noqa: BLE001
            raise ZephyrPolicyError(
                f"Could not attach {const.POLICY_NAME} to {identity_id}. "
                "Without it the MQTT connection succeeds but every message is "
                "silently dropped."
            ) from err

    # -- async surface -------------------------------------------------

    async def async_get_tokens(self) -> ZephyrTokens:
        if self._tokens is not None and not self._tokens.expired:
            return self._tokens

        stored = self._tokens
        user: Cognito | None = None

        if stored is not None:
            try:
                user = await asyncio.to_thread(self._refresh, stored.refresh_token)
            except Exception as err:  # noqa: BLE001
                # Refresh tokens expire (30 days by default) and can be
                # revoked. Reauthenticate rather than surfacing an error.
                _LOGGER.debug("refresh rejected (%s); falling back to SRP", err)

        if user is None:
            try:
                user = await asyncio.to_thread(self._srp_login)
            except Exception as err:  # noqa: BLE001
                raise ZephyrAuthError(
                    f"Cognito authentication failed: {err}"
                ) from err

        self._user = user
        try:
            identity_id, credentials = await asyncio.to_thread(
                self._exchange,
                user.id_token,
                stored.identity_id if stored is not None else None,
            )
        except Exception as err:  # noqa: BLE001
            raise ZephyrAuthError(f"Identity exchange failed: {err}") from err

        self._credentials = credentials
        self._tokens = ZephyrTokens(
            username=self._username,
            id_token=user.id_token,
            refresh_token=user.refresh_token or (
                stored.refresh_token if stored else ""
            ),
            identity_id=identity_id,
            expires_at=credentials.expiration.timestamp(),
        )
        if self._token_updater is not None:
            self._token_updater(self._tokens)
        return self._tokens

    async def async_get_credentials(self) -> Credentials:
        """AWS credentials for SigV4-presigning the MQTT WebSocket URL.

        Derived from the ID token rather than persisted: they last an hour
        and are bound to a live socket, so there is nothing worth storing.
        """
        await self.async_get_tokens()
        if self._credentials is None or self._credentials.expired:
            tokens = self._tokens
            assert tokens is not None
            identity_id, credentials = await asyncio.to_thread(
                self._exchange, tokens.id_token, tokens.identity_id
            )
            if identity_id != tokens.identity_id:
                # The stored identity was stale and _exchange refetched it.
                # This MUST be written back: mqtt_client_id is derived from
                # it, and an MQTT client ID built on a dead identity gets a
                # connection where subscribe and publish succeed and every
                # message is silently dropped (PROTOCOL.md section 3.3).
                self._tokens = replace(tokens, identity_id=identity_id)
                if self._token_updater is not None:
                    self._token_updater(self._tokens)
            self._credentials = credentials
        return self._credentials

    @property
    def credentials_expired(self) -> bool:
        """True when the cached AWS credentials need renewing.

        A plain property on purpose. The supervisor must be able to ask "do
        these need replacing?" without async_get_credentials() renewing them
        as a side effect, which would make the answer always False and the
        socket never get rebuilt.
        """
        return self._credentials is None or self._credentials.expired

    async def async_attach_policy(self) -> None:
        """Bind the IoT policy to this identity.

        MUST run before connecting. An open MQTT connection does not pick up
        newly attached permissions.
        """
        tokens = await self.async_get_tokens()
        credentials = await self.async_get_credentials()
        await asyncio.to_thread(self._attach, tokens.identity_id, credentials)
```

Add `from collections.abc import Callable` to the imports. Delete the old `ZephyrAuth` class entirely.

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_auth.py tests/test_tokens.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/pyzephyrconnect/auth.py tests/test_auth.py
git commit -m "feat: replace ZephyrAuth with token-based CredentialsAuth"
```

---

### Task 7: `ZephyrApi` drives itself from auth

**Files:**
- Modify: `src/pyzephyrconnect/api.py`
- Test: `tests/test_api.py`

**Interfaces:**
- Consumes: `AbstractAuth`, `Endpoints`.
- Produces: `ZephyrApi(auth: AbstractAuth, *, ssl_context=None)` with `get_own_devices() -> list[dict]` and `discover_device(thing_name) -> dict` — both now taking **no** `id_token` argument. `build_ssl_context()` is unchanged.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_api.py`:

```python
async def test_authorization_header_is_a_bare_token():
    """PROTOCOL.md section 4: the API rejects a 'Bearer ' prefix. This is
    trivially easy to break while refactoring onto AbstractAuth."""
    session = FakeSession(FakeResponse({"devices": []}))
    api = ZephyrApi(_fake_auth(session))
    await api.get_own_devices()

    assert session.calls[0]["headers"]["Authorization"] == "ID-TOKEN"
    assert not session.calls[0]["headers"]["Authorization"].startswith("Bearer")


async def test_getowndevices_sends_a_zero_length_body():
    """PROTOCOL.md section 4: Content-Length 0, not '{}'."""
    session = FakeSession(FakeResponse({"devices": []}))
    api = ZephyrApi(_fake_auth(session))
    await api.get_own_devices()

    assert session.calls[0]["data"] == b""


async def test_every_request_asks_auth_for_a_current_token():
    """Refresh lives in the request path now, so a token that went stale
    between calls is renewed without the consumer doing anything."""
    session = FakeSession(
        FakeResponse({"devices": []}), FakeResponse({"thingName": "t"})
    )
    auth = _fake_auth(session)
    api = ZephyrApi(auth)
    await api.get_own_devices()
    await api.discover_device("t")

    assert auth.async_get_tokens.await_count == 2


async def test_endpoint_override_reaches_the_url_requested():
    session = FakeSession(FakeResponse({"devices": []}))
    auth = _fake_auth(
        session, endpoints=Endpoints(device_api_base="https://staging.example/prod")
    )
    await ZephyrApi(auth).get_own_devices()

    assert session.calls[0]["url"] == "https://staging.example/prod/getowndevices"
```

Add this helper near the top of `tests/test_api.py`:

```python
from unittest.mock import AsyncMock, MagicMock

from pyzephyrconnect.auth import ZephyrTokens
from pyzephyrconnect.const import DEFAULT_ENDPOINTS, Endpoints


def _fake_auth(session, endpoints=DEFAULT_ENDPOINTS):
    auth = MagicMock()
    auth.session = session
    auth.endpoints = endpoints
    auth.async_get_tokens = AsyncMock(
        return_value=ZephyrTokens(
            username="u@example.com",
            id_token="ID-TOKEN",
            refresh_token="R",
            identity_id="us-west-2:abc",
            expires_at=time.time() + 3600,
        )
    )
    return auth
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_api.py -v`
Expected: FAIL — `ZephyrApi.__init__` still expects a session, and the methods still require an `id_token` argument.

- [ ] **Step 3: Implement**

In `src/pyzephyrconnect/api.py`, replace the class body:

```python
class ZephyrApi:
    """Client for the vendor's two REST endpoints.

    The auth object owns the session and the token, so this class is
    agnostic to how credentials are obtained - which is what lets a consumer
    supply its own AbstractAuth. The SSL context (system trust plus the TWCA
    workaround anchors) is applied per request, so a shared session needs no
    special construction.
    """

    def __init__(
        self,
        auth: AbstractAuth,
        *,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        self._auth = auth
        # Deliberately NOT built here. build_ssl_context() calls
        # SSLContext.load_default_certs and load_verify_locations, both of
        # which Home Assistant instruments as blocking calls and reports when
        # they run on the event loop - and this constructor runs on the loop
        # inside async_setup_entry. Built lazily in a worker thread instead.
        self._ssl = ssl_context

    async def _get_ssl(self) -> ssl.SSLContext:
        """The SSL context, built off the event loop on first use."""
        if self._ssl is None:
            self._ssl = await asyncio.to_thread(build_ssl_context)
        return self._ssl

    def _headers(self, id_token: str) -> dict[str, str]:
        # Bare token, no "Bearer " prefix - the API rejects the prefixed form.
        return {
            "Authorization": id_token,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    async def _post(self, url: str, **kwargs: Any) -> Any:
        tokens = await self._auth.async_get_tokens()
        ssl_context = await self._get_ssl()
        try:
            async with self._auth.session.post(
                url,
                headers=self._headers(tokens.id_token),
                ssl=ssl_context,
                **kwargs,
            ) as response:
                if response.status == 403:
                    raise ZephyrAuthError(
                        f"{url} returned 403 - the ID token is rejected or expired"
                    )
                if response.status >= 400:
                    raise ZephyrError(f"{url} returned HTTP {response.status}")
                # The API sends text/plain for some responses.
                return await response.json(content_type=None)
        except aiohttp.ClientConnectorCertificateError as err:
            raise ZephyrCertificateError(
                f"TLS verification failed for {url}. The presented chain is "
                f"trusted by neither the system CA store nor the bundled "
                f"TWCA anchors ({CERT_BUNDLE}) added to work around the "
                "vendor's SKI-less intermediate. The vendor likely changed "
                "its certificate chain again - recapture it and update the "
                "TWCA bundle if needed. Do not disable verification."
            ) from err

    async def get_own_devices(self) -> list[dict[str, Any]]:
        """Return the caller's devices.

        Note: the response includes precise device coordinates. Treat the
        payload as personal data and never log it.
        """
        # Empty body, not "{}" - matches the captured request exactly.
        payload = await self._post(self._auth.endpoints.device_api_list, data=b"")
        devices = payload.get("devices") or []
        _LOGGER.debug("getowndevices returned %d device(s)", len(devices))
        return devices

    async def discover_device(self, thing_name: str) -> dict[str, Any]:
        """Return capabilities merged with current state for one thing."""
        return await self._post(
            self._auth.endpoints.device_api_discover,
            json={"thingName": thing_name},
        )
```

Import `AbstractAuth` from `.auth`, and add `import asyncio` to the module imports.

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_api.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/pyzephyrconnect/api.py tests/test_api.py
git commit -m "refactor: drive ZephyrApi from AbstractAuth instead of a token argument"
```

---

### Task 8: `ShadowClient` re-presigns on every connect

**Files:**
- Modify: `src/pyzephyrconnect/shadow.py`
- Test: `tests/test_shadow.py`

**Interfaces:**
- Consumes: `Credentials`, `Endpoints`, `ZephyrWriteError` from Task 2.
- Produces: `ShadowClient(thing_name, client_id, on_message, on_connection_change, credentials_provider, *, endpoints=DEFAULT_ENDPOINTS)` where `credentials_provider: Callable[[], Awaitable[Credentials]]`. `connect(timeout=15.0)` takes no credentials argument. `publish_state` raises `ZephyrWriteError` instead of `ValueError`.

This is the change that keeps push alive past one hour. The presigned URL embeds a SigV4 signature over credentials that expire; AWS IoT drops the session at expiry, and paho's automatic reconnect would otherwise retry the same dead URL forever.

- [ ] **Step 1: Write the failing tests**

Append to `tests/test_shadow.py`:

```python
async def test_connect_asks_the_provider_for_fresh_credentials(monkeypatch):
    """A presigned URL cannot outlive its signature. Every connect attempt
    must re-presign, or a reconnect after expiry retries a dead URL."""
    calls = []

    async def provider():
        calls.append(1)
        return Credentials("k", "s", "t", datetime.now(UTC) + timedelta(hours=1))

    shadow = _shadow(credentials_provider=provider)
    await _connect(shadow)
    await shadow.disconnect()
    await _connect(shadow)

    assert len(calls) == 2


async def test_publish_empty_state_raises_a_library_error():
    """ValueError escapes a consumer catching ZephyrError."""
    shadow = _shadow()
    await _connect(shadow)
    with pytest.raises(ZephyrWriteError):
        await shadow.publish_state({})
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_shadow.py -v`
Expected: FAIL — `connect()` still takes a `Credentials` positional argument, and `publish_state` raises `ValueError`.

- [ ] **Step 3: Implement**

In `src/pyzephyrconnect/shadow.py`, change the constructor and `connect`:

```python
    def __init__(
        self,
        thing_name: str,
        client_id: str,
        on_message: Callable[[str, dict[str, Any]], None],
        on_connection_change: Callable[[bool], None],
        credentials_provider: Callable[[], Awaitable[Credentials]],
        *,
        endpoints: Endpoints = DEFAULT_ENDPOINTS,
    ) -> None:
        self.topics = ShadowTopics(thing_name)
        self._client_id = client_id
        self._on_message_cb = on_message
        self._on_connection_cb = on_connection_change
        self._credentials_provider = credentials_provider
        self._endpoints = endpoints
        self._client: mqtt.Client | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._connected = asyncio.Event()
        self._subscribed = asyncio.Event()
        self._subscribe_error: ZephyrPolicyError | None = None
        self._pending_subscribes = 0

    async def connect(self, timeout: float = 15.0) -> None:
        """Open the WebSocket and subscribe to the shadow topics.

        Credentials are fetched from the provider on every attempt rather
        than captured once: the presigned URL embeds a SigV4 signature that
        expires with them, so a reconnect must re-presign or it will retry a
        URL AWS IoT has already stopped accepting.
        """
        self._loop = asyncio.get_running_loop()
        credentials = await self._credentials_provider()
        url = build_presigned_url(
            credentials.access_key,
            credentials.secret_key,
            credentials.session_token,
            endpoint=self._endpoints.iot_endpoint,
            region=self._endpoints.region,
            now=datetime.now(UTC),
        )
        parts = urlsplit(url)
        ...
```

Replace the remaining `const.IOT_ENDPOINT` and `const.REGION` references in the method body with `self._endpoints.iot_endpoint` and `self._endpoints.region`.

Fix the disconnect ordering, which now runs on a ~50-minute reconnect cycle
rather than once at shutdown:

```python
    async def disconnect(self) -> None:
        if self._client is None:
            return
        # disconnect() BEFORE loop_stop(). The network thread is what writes
        # the DISCONNECT packet; stopping it first means the packet is queued
        # and never sent, and the broker only notices via keepalive timeout.
        self._client.disconnect()
        self._client.loop_stop()
        self._client = None
        self._connected.clear()
        self._subscribed.clear()
```

In `publish_state`, change the guard:

```python
        if not fields:
            raise ZephyrWriteError("refusing to publish an empty reported state")
```

Add `from collections.abc import Awaitable, Callable` and import `DEFAULT_ENDPOINTS`, `Endpoints`, `ZephyrWriteError`.

Leave `_on_connect`, `_on_subscribe`, `_record_subscribe_result` and the delta handling untouched. Denied subscribes must keep raising `ZephyrPolicyError`, because Task 10's supervisor treats it as terminal.

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_shadow.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/pyzephyrconnect/shadow.py tests/test_shadow.py
git commit -m "feat: re-presign the shadow WebSocket URL on every connect"
```

---

### Task 9: The `Hood` object

**Files:**
- Create: `src/pyzephyrconnect/hood.py`
- Modify: `src/pyzephyrconnect/__init__.py`
- Test: `tests/test_hood.py` (create)

**Interfaces:**
- Consumes: `HoodCapabilities`, `HoodState`, `ShadowClient`, `ZephyrWriteError`, `ZephyrNotConnectedError`, `const.WRITABLE_FIELDS`, `const.DANGEROUS_FIELDS`.
- Produces: `Hood`, constructed by `ZephyrClient` in Task 10 as `Hood(capabilities, shadow_factory, poll)` where `shadow_factory: Callable[[Hood], ShadowClient]` and `poll: Callable[[str], Awaitable[HoodState]]`.

Public surface:

```
thing_name -> str
capabilities -> HoodCapabilities
state -> HoodState | None
async_start() -> None
async_stop() -> None
async_poll() -> HoodState
add_listener(cb: Callable[[HoodState], None]) -> Callable[[], None]
async_set_power(on: bool) -> None
async_set_light(level: int) -> None
async_set_fan(speed: int) -> None
async_set_clean_air(on: bool) -> None
async_set_delay_timer(seconds: int) -> None
async_set_recirculating(on: bool) -> None      # destructive
async_reset_grease_filter() -> None            # destructive
async_set_fields(fields: dict[str, int]) -> None   # raw, allowlist-enforced
```

`async_set_fields` is the single enforcement chokepoint; every typed method delegates to it. It exists because the probe CLI's `--set field=value` writes *arbitrary* allowlisted fields in order to map unknown semantics — a fixed method surface cannot express that, and mapping those fields is the probe's entire purpose. It is documented as the diagnostic path, not the normal one.

- [ ] **Step 1: Write the failing tests**

`tests/test_hood.py`:

```python
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from pyzephyrconnect.exceptions import ZephyrNotConnectedError, ZephyrWriteError
from pyzephyrconnect.hood import Hood
from pyzephyrconnect.models import HoodCapabilities, HoodState

FIXTURES = Path(__file__).parent / "fixtures"
THING = "aaaaaaaabbbbbbbbccccccccddddddddeeeeeeee"


def _caps(**overrides) -> HoodCapabilities:
    payload = json.loads((FIXTURES / "discoverdevice.json").read_text())
    payload.update(overrides)
    return HoodCapabilities.from_discover(payload)


def _hood(caps=None):
    shadow = MagicMock()
    shadow.connect = AsyncMock()
    shadow.disconnect = AsyncMock()
    shadow.request_state = AsyncMock()
    shadow.publish_state = AsyncMock()
    hood = Hood(
        caps or _caps(),
        shadow_factory=lambda _hood: shadow,
        poll=AsyncMock(return_value=HoodState.from_reported({"power": 1})),
    )
    return hood, shadow


async def test_typed_methods_publish_the_vendor_field_names():
    hood, shadow = _hood()
    await hood.async_start()

    await hood.async_set_light(2)
    shadow.publish_state.assert_awaited_with({"light": 2})

    await hood.async_set_clean_air(True)
    shadow.publish_state.assert_awaited_with({"setcleanairfunction": 1})

    await hood.async_reset_grease_filter()
    shadow.publish_state.assert_awaited_with({"resetgreasefilter": 1})


async def test_out_of_range_is_refused_before_anything_is_published():
    """The device advertises its own limits. Catching this locally beats a
    silent no-op on hardware."""
    hood, shadow = _hood()
    await hood.async_start()

    with pytest.raises(ZephyrWriteError):
        await hood.async_set_fan(7)          # reference hood maxes at 6
    shadow.publish_state.assert_not_awaited()


async def test_absent_capability_maximum_permits_the_write():
    """Hoods we have never seen omit capability keys. A missing maximum must
    not become a blanket refusal to write."""
    hood, shadow = _hood(_caps(maxFanSpeed=None))
    await hood.async_start()

    await hood.async_set_fan(9)
    shadow.publish_state.assert_awaited_with({"fan": 9})


async def test_negative_values_are_always_refused():
    hood, _ = _hood()
    await hood.async_start()
    with pytest.raises(ZephyrWriteError):
        await hood.async_set_light(-1)


async def test_raw_writes_enforce_the_allowlist():
    """The allowlist used to live only in the probe CLI, so any other caller
    could write anything."""
    hood, shadow = _hood()
    await hood.async_start()

    with pytest.raises(ZephyrWriteError):
        await hood.async_set_fields({"usefantime": 0})
    shadow.publish_state.assert_not_awaited()


async def test_writing_before_start_raises_a_library_error():
    """Previously a bare RuntimeError, which escaped ZephyrError."""
    hood, _ = _hood()
    with pytest.raises(ZephyrNotConnectedError):
        await hood.async_set_light(1)


async def test_listeners_are_notified_and_removable():
    hood, _ = _hood()
    seen = []
    remove = hood.add_listener(seen.append)
    hood.handle_state(HoodState.from_reported({"power": 1}))
    remove()
    hood.handle_state(HoodState.from_reported({"power": 0}))

    assert len(seen) == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_hood.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'pyzephyrconnect.hood'`

- [ ] **Step 3: Implement**

Create `src/pyzephyrconnect/hood.py`:

```python
"""One range hood: its capabilities, its state, and its controls.

The data-models guidance puts control methods on the model object rather
than on a generic client, so a consumer writes hood.async_set_fan(2) and
never learns the vendor's field spellings. That also makes the write
allowlist structural: only these methods exist.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import Any

from . import const
from .exceptions import ZephyrNotConnectedError, ZephyrWriteError
from .models import HoodCapabilities, HoodState
from .shadow import ShadowClient

_LOGGER = logging.getLogger(__name__)

StateListener = Callable[[HoodState], None]


class Hood:
    """A single hood on the account."""

    def __init__(
        self,
        capabilities: HoodCapabilities,
        shadow_factory: Callable[[Hood], ShadowClient],
        poll: Callable[[str], Awaitable[HoodState]],
    ) -> None:
        self._capabilities = capabilities
        self._shadow_factory = shadow_factory
        self._poll = poll
        self._shadow: ShadowClient | None = None
        self._state: HoodState | None = None
        self._listeners: list[StateListener] = []

    @property
    def thing_name(self) -> str:
        return self._capabilities.thing_name

    @property
    def capabilities(self) -> HoodCapabilities:
        return self._capabilities

    @property
    def state(self) -> HoodState | None:
        """Latest known state, or None before the first report."""
        return self._state

    # -- lifecycle -----------------------------------------------------

    async def async_start(self) -> None:
        """Open this hood's shadow connection and request current state."""
        shadow = self._shadow_factory(self)
        await shadow.connect()
        self._shadow = shadow
        await shadow.request_state()

    async def async_stop(self) -> None:
        if self._shadow is not None:
            await self._shadow.disconnect()
            self._shadow = None

    async def async_reconnect(self) -> None:
        """Rebuild the socket after a credential refresh.

        The presigned URL is derived from credentials that expire, so a
        refresh without a reconnect leaves a socket AWS IoT will drop.
        """
        await self.async_stop()
        await self.async_start()

    async def async_poll(self) -> HoodState:
        """Read state over HTTPS. Used at setup and while push is down.

        This is also how a terminal supervisor failure reaches the consumer:
        the supervisor stops on an auth or policy error and flips `connected`
        to False, which drives the consumer to poll, and this call re-raises
        the stored error so it can become a reauth prompt rather than a hood
        that quietly stops updating.
        """
        state = await self._poll(self.thing_name)
        self.handle_state(state)
        return state

    # -- state ---------------------------------------------------------

    def handle_state(self, state: HoodState) -> None:
        """Record new state and notify listeners. Called by ZephyrClient."""
        self._state = state
        for callback in list(self._listeners):
            try:
                callback(state)
            except Exception:  # noqa: BLE001
                # One bad consumer must not stop the others from updating.
                _LOGGER.exception("state listener raised")

    def add_listener(self, callback: StateListener) -> Callable[[], None]:
        self._listeners.append(callback)

        def remove() -> None:
            try:
                self._listeners.remove(callback)
            except ValueError:
                pass

        return remove

    # -- writes: ACTUATE HARDWARE --------------------------------------

    def _check_range(self, name: str, value: int, maximum: int | None) -> None:
        if value < 0:
            raise ZephyrWriteError(f"{name} cannot be negative, got {value}")
        # A hood we have never seen may not advertise a maximum. Absent must
        # not become a blanket refusal to write.
        if isinstance(maximum, int) and maximum > 0 and value > maximum:
            raise ZephyrWriteError(
                f"{name} must be between 0 and {maximum} on this hood, "
                f"got {value}"
            )

    async def async_set_fields(self, fields: dict[str, int]) -> None:
        """WRITE PATH - actuates hardware. Diagnostic surface.

        The typed async_set_* methods below are the normal way to write.
        This exists for the probe CLI, which writes arbitrary allowlisted
        fields in order to map semantics that are not yet established -
        something a fixed method surface cannot express.

        Publishes state.reported, not state.desired: that is what this
        device acts on. state.desired writes are accepted by AWS IoT and
        silently ignored by the hardware.
        """
        if self._shadow is None:
            raise ZephyrNotConnectedError(
                f"async_start() has not been called for {self.thing_name}"
            )
        if not fields:
            raise ZephyrWriteError("refusing to publish an empty reported state")
        if forbidden := set(fields) - const.WRITABLE_FIELDS:
            raise ZephyrWriteError(
                f"not writable: {', '.join(sorted(forbidden))}. Allowed: "
                f"{', '.join(sorted(const.WRITABLE_FIELDS))}"
            )
        if destructive := set(fields) & const.DANGEROUS_FIELDS:
            _LOGGER.warning(
                "destructive write to %s - this changes device configuration "
                "or zeroes a counter that cannot be reconstructed",
                ", ".join(sorted(destructive)),
            )
        await self._shadow.publish_state(dict(fields))

    async def async_set_power(self, on: bool) -> None:
        await self.async_set_fields({"power": int(bool(on))})

    async def async_set_light(self, level: int) -> None:
        self._check_range("light", level, self._capabilities.max_light_level)
        await self.async_set_fields({"light": level})

    async def async_set_fan(self, speed: int) -> None:
        self._check_range("fan", speed, self._capabilities.max_fan_speed)
        await self.async_set_fields({"fan": speed})

    async def async_set_clean_air(self, on: bool) -> None:
        await self.async_set_fields({"setcleanairfunction": int(bool(on))})

    async def async_set_delay_timer(self, seconds: int) -> None:
        """Arm the delay-off timer. Non-zero values start the fan.

        The device derives and decrements `delaytimer` from this itself, so
        only `setdelaytimer` is written.
        """
        self._check_range("delay timer", seconds, None)
        await self.async_set_fields({"setdelaytimer": seconds})

    async def async_set_recirculating(self, on: bool) -> None:
        """DESTRUCTIVE: changes filter accounting for this hood."""
        await self.async_set_fields({"setrecirculating": int(bool(on))})

    async def async_reset_grease_filter(self) -> None:
        """DESTRUCTIVE: zeroes a usage counter that cannot be reconstructed."""
        await self.async_set_fields({"resetgreasefilter": 1})
```

Export `Hood` from `src/pyzephyrconnect/__init__.py`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_hood.py -v`
Expected: PASS (7 passed)

- [ ] **Step 5: Commit**

```bash
git add src/pyzephyrconnect/hood.py src/pyzephyrconnect/__init__.py tests/test_hood.py
git commit -m "feat: add the Hood object and make the write allowlist structural"
```

---

### Task 10: `ZephyrClient` rewire and the refresh supervisor

**Files:**
- Modify: `src/pyzephyrconnect/client.py`
- Test: `tests/test_client.py`

**Interfaces:**
- Consumes: everything from Tasks 3, 5, 6, 7, 8, 9.
- Produces:
  - `ZephyrClient(auth: AbstractAuth, *, endpoints=DEFAULT_ENDPOINTS)`
  - `ZephyrClient.from_credentials(username, password, session, *, tokens=None, token_updater=None, endpoints=DEFAULT_ENDPOINTS) -> ZephyrClient`
  - `async_setup() -> list[Hood]`
  - `async_stop() -> None`
  - `connected -> bool`
  - `identity_id -> str`
  - Removed: `async_set_state`, `async_start(thing_name)`, `async_poll(thing_name)`, `state(thing_name)`, `capabilities(thing_name)`, `add_listener(thing_name, cb)`, `async_refresh_if_needed()`.

The supervisor is the reason `async_refresh_if_needed()` can be deleted. It runs while any hood is started, renews credentials inside `REFRESH_MARGIN_SECONDS` of expiry, and reconnects each hood. It does **not** re-attach the IoT policy: per `PROTOCOL.md` §3.3 the binding persists on the identity.

- [ ] **Step 1: Write the failing tests**

Rewrite `tests/test_client.py`'s fixture and add:

```python
async def test_setup_returns_hood_objects(wired):
    hoods = await _client().async_setup()
    assert len(hoods) == 1
    assert hoods[0].thing_name == THING
    assert hoods[0].capabilities.max_fan_speed == 6


async def test_policy_is_attached_before_the_socket_opens(wired):
    """Ordering is load-bearing: an already-open connection does not pick up
    newly attached permissions, and the failure is silent."""
    hoods = await _client().async_setup()
    await hoods[0].async_start()

    order = wired["order"]
    assert order.index("attach_policy") < order.index("connect")


async def test_get_accepted_replaces_and_update_accepted_merges(wired):
    """get/accepted carries a full document; update/accepted carries only
    what changed, so replacing on it would zero everything unmentioned."""
    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()

    client._handle_message(
        hoods[0], f"$aws/things/{THING}/shadow/get/accepted",
        {"state": {"reported": {"power": 1, "fan": 3}}},
    )
    client._handle_message(
        hoods[0], f"$aws/things/{THING}/shadow/update/accepted",
        {"state": {"reported": {"fan": 5}}},
    )

    assert hoods[0].state.power == 1
    assert hoods[0].state.fan == 5


async def test_update_delta_is_ignored(wired):
    """Nothing writes state.desired here, so a delta can only be stale or
    foreign. Merging one produces a phantom change."""
    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()
    client._handle_message(
        hoods[0], f"$aws/things/{THING}/shadow/get/accepted",
        {"state": {"reported": {"fan": 1}}},
    )
    client._handle_message(
        hoods[0], f"$aws/things/{THING}/shadow/update/delta",
        {"state": {"fan": 6}},
    )

    assert hoods[0].state.fan == 1


async def test_supervisor_rebuilds_the_socket_before_credentials_expire(wired):
    """A presigned URL cannot outlive its signature. Without this, push dies
    after an hour and paho retries a dead URL forever."""
    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()

    wired["auth"].async_get_credentials = AsyncMock(
        return_value=Credentials("k", "s", "t", datetime.now(UTC) + timedelta(seconds=1))
    )
    await client._refresh_once()

    assert wired["shadow"].disconnect.await_count >= 1
    assert wired["shadow"].connect.await_count >= 2
    assert wired["shadow"].request_state.await_count >= 2


async def test_refresh_does_not_ask_a_method_that_renews_as_a_side_effect(wired):
    """async_get_credentials() renews when expired, so testing ITS result
    always reports "not expired" and the socket never gets rebuilt. The
    supervisor must ask the non-mutating property instead."""
    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()

    wired["auth"].credentials_expired = False
    assert await client._refresh_once() is False
    assert wired["shadow"].connect.await_count == 1      # no rebuild

    wired["auth"].credentials_expired = True
    assert await client._refresh_once() is True
    assert wired["shadow"].connect.await_count == 2      # rebuilt


async def test_a_transient_failure_does_not_end_supervision(wired):
    """The failure mode this guards against is not a logged error - it is
    push dying silently an hour later."""
    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()

    calls = []

    async def flaky():
        calls.append(1)
        if len(calls) == 1:
            raise OSError("transient DNS failure")
        return False

    client._refresh_once = flaky
    monkeypatch_interval(client, 0)          # see helper in this module
    await _run_supervisor_ticks(client, 2)

    assert len(calls) == 2                   # kept going after the OSError


async def test_supervisor_stops_on_a_policy_error(wired):
    """A denied subscribe closes the whole connection (PROTOCOL.md section 6).
    Retrying that forever is a hot loop that can never succeed."""
    client = _client()
    hoods = await client.async_setup()
    await hoods[0].async_start()

    async def denied():
        raise ZephyrPolicyError("denied")

    client._refresh_once = denied
    monkeypatch_interval(client, 0)
    await _run_supervisor_ticks(client, 3)

    assert isinstance(client._supervisor_error, ZephyrPolicyError)
    assert client.connected is False


async def test_a_terminal_error_reaches_the_consumer_via_poll(wired):
    """The supervisor runs detached, so its failure has to surface somewhere
    the consumer already looks - otherwise the hood just stops updating."""
    client = _client()
    hoods = await client.async_setup()
    client._supervisor_error = ZephyrAuthError("refresh token revoked")

    with pytest.raises(ZephyrAuthError):
        await hoods[0].async_poll()


async def test_a_refetched_identity_is_written_back(wired):
    """mqtt_client_id is derived from identity_id. Keeping a dead one gets a
    connection where subscribe and publish succeed and every message is
    silently dropped."""
    auth = wired["auth"]
    auth.identity_id = "us-west-2:new"
    client = _client()
    await client.async_setup()

    assert client.identity_id == "us-west-2:new"
```

Add these two helpers to `tests/test_client.py`; the supervisor is a detached
task, so tests drive it deterministically rather than sleeping:

```python
def monkeypatch_interval(client, seconds: float) -> None:
    client._supervisor_interval = seconds


async def _run_supervisor_ticks(client, ticks: int) -> None:
    """Run the supervisor body `ticks` times, then cancel it."""
    task = asyncio.create_task(client._supervise())
    for _ in range(ticks + 1):
        await asyncio.sleep(0)
    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task
```

This requires `_supervise()` to read `self._supervisor_interval` (defaulting
to `const.SUPERVISOR_INTERVAL_SECONDS`) rather than the constant directly, so
tests do not have to wait a real minute.

Update the fixture: `wired["auth"]` is now a `CredentialsAuth` double with `async_get_tokens`, `async_get_credentials`, `async_attach_policy` as `AsyncMock`s and a `mqtt_client_id` attribute. `_client()` becomes:

```python
def _client():
    return ZephyrClient(_auth_double())
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_client.py -v`
Expected: FAIL — `ZephyrClient.__init__` still takes `(username, password, session)`.

- [ ] **Step 3: Implement**

Rewrite `src/pyzephyrconnect/client.py`. Key structure:

```python
class ZephyrClient:
    """One authenticated account and the hoods under it."""

    def __init__(
        self,
        auth: AbstractAuth,
        *,
        endpoints: Endpoints = DEFAULT_ENDPOINTS,
    ) -> None:
        self._auth = auth
        self._endpoints = endpoints
        self._api = ZephyrApi(auth)
        self._hoods: dict[str, Hood] = {}
        self._connected = False
        self._supervisor: asyncio.Task | None = None
        self._supervisor_error: ZephyrError | None = None

    @classmethod
    def from_credentials(
        cls,
        username: str,
        password: str,
        session: aiohttp.ClientSession,
        *,
        tokens: ZephyrTokens | None = None,
        token_updater: Callable[[ZephyrTokens], None] | None = None,
        endpoints: Endpoints = DEFAULT_ENDPOINTS,
        ssl_context: ssl.SSLContext | None = None,
    ) -> ZephyrClient:
        """Convenience path: build a CredentialsAuth and a client from it.

        Supply `tokens` from a previous session and `token_updater` to
        persist new ones, and a restart will skip the SRP login entirely.
        """
        return cls(
            CredentialsAuth(
                username,
                password,
                session,
                tokens=tokens,
                token_updater=token_updater,
                endpoints=endpoints,
            ),
            endpoints=endpoints,
        )

    @property
    def connected(self) -> bool:
        return self._connected

    @property
    def identity_id(self) -> str:
        """Cognito identity ID. Stable per account; a natural unique key.

        Reads the identity straight off the auth object. Do not reconstruct
        it by stripping the suffix off mqtt_client_id - that derives a source
        from its own derivative and returns a wrong value the day
        CLIENT_ID_SUFFIX changes.
        """
        return self._auth.identity_id

    async def async_setup(self) -> list[Hood]:
        """Authenticate and discover every hood on the account."""
        await self._auth.async_get_tokens()
        devices = await self._api.get_own_devices()
        for device in devices:
            if not (thing_name := device.get("thingName")):
                # A KeyError here would escape ZephyrError and reach the
                # consumer as an unknown crash rather than a setup retry.
                _LOGGER.warning("skipping a device with no thingName")
                continue
            payload = await self._api.discover_device(thing_name)
            caps = HoodCapabilities.from_discover(payload)
            hood = Hood(caps, self._make_shadow, self._poll_state)
            hood.handle_state(self._state_from_discover(payload))
            self._hoods[thing_name] = hood
        return list(self._hoods.values())

    async def async_stop(self) -> None:
        if self._supervisor is not None:
            self._supervisor.cancel()
            self._supervisor = None
        for hood in self._hoods.values():
            await hood.async_stop()
        self._connected = False
```

`_make_shadow(hood)` builds a `ShadowClient` wired to this client's message handler, the auth's `mqtt_client_id`, and `self._auth.async_get_credentials` as the provider, then starts the supervisor if it is not already running.

`_poll_state(thing_name)` re-raises a stored terminal supervisor error before
doing anything else, so an auth failure that stopped the supervisor becomes a
`ConfigEntryAuthFailed` on the consumer's next tick rather than a hood that
quietly stops updating:

```python
    async def _poll_state(self, thing_name: str) -> HoodState:
        if self._supervisor_error is not None:
            raise self._supervisor_error
        payload = await self._api.discover_device(thing_name)
        return self._state_from_discover(payload)
```

`_state_from_discover(payload)` keeps the existing `_PERSONAL_DATA_KEYS` filter verbatim — `discoverdevice` returns a flat dict mixing shadow fields with identifiers, and those must never enter `HoodState.raw`.

`_handle_message(hood, topic, payload)` is the existing `_handle_message` with `thing_name` replaced by the `Hood`, calling `hood.handle_state(...)` instead of writing a dict. Keep every guard: the non-dict shape check, the leaf-only logging, the rejected branch that never logs the payload, the ignored delta, and the broad `except` backstop.

The supervisor:

```python
    async def _supervise(self) -> None:
        """Keep credentials fresh and sockets alive.

        The presigned WebSocket URL embeds a SigV4 signature over
        credentials that expire in an hour. AWS IoT drops the session at
        expiry and paho reconnects to the same dead URL indefinitely, so
        push must be rebuilt from this side before that happens.
        """
        while True:
            # The try is INSIDE the loop deliberately. A transient failure -
            # a DNS blip during one refresh cycle - must not end supervision,
            # because the consequence is not a logged error, it is push dying
            # silently an hour later.
            try:
                await asyncio.sleep(const.SUPERVISOR_INTERVAL_SECONDS)
                await self._refresh_once()
            except asyncio.CancelledError:
                raise
            except (ZephyrPolicyError, ZephyrAuthError) as err:
                # Neither of these fixes itself by retrying. A denied
                # subscribe closes the whole connection and needs the IoT
                # policy attached; a rejected credential needs the user.
                # Stop, and leave the error where async_poll() will surface
                # it - see _supervisor_error below.
                self._supervisor_error = err
                self._connected = False
                _LOGGER.error("refresh supervisor stopping: %s", err)
                return
            except Exception:  # noqa: BLE001
                _LOGGER.exception("refresh cycle failed; retrying next tick")

    async def _refresh_once(self) -> bool:
        """Renew credentials and rebuild sockets if inside the margin.

        Asks `credentials_expired` rather than calling
        async_get_credentials() first: that method renews as a side effect,
        so testing its result would always report "not expired" and the
        socket would never be rebuilt.
        """
        if not self._auth.credentials_expired:
            return False
        _LOGGER.debug("credentials near expiry; refreshing and reconnecting")
        # Renews the Cognito tokens and re-exchanges for AWS credentials.
        await self._auth.async_get_credentials()
        for hood in self._hoods.values():
            await hood.async_reconnect()
        return True
```

Add `SUPERVISOR_INTERVAL_SECONDS = 60` to `const.py`.

- [ ] **Step 4: Run the full suite**

Run: `pytest -q`
Expected: PASS, all tests.

Run: `ruff check`
Expected: `All checks passed!`

- [ ] **Step 5: Commit**

```bash
git add src/pyzephyrconnect/client.py src/pyzephyrconnect/const.py tests/test_client.py
git commit -m "feat: return Hood objects and supervise credential refresh"
```

---

### Task 11: Probe CLI, docs and release preparation

**Files:**
- Modify: `src/pyzephyrconnect/probe.py`
- Modify: `README.md`
- Modify: `VALIDATION.md`
- Test: `tests/test_probe.py`

**Interfaces:**
- Consumes: `ZephyrClient.from_credentials`, `Hood.async_set_fields`.
- Produces: no library API; the CLI's behaviour is unchanged from the user's side.

- [ ] **Step 1: Update the probe's library calls**

In `src/pyzephyrconnect/probe.py`'s `main()`, replace the client block:

```python
    async with aiohttp.ClientSession() as session:
        client = ZephyrClient.from_credentials(username, password, session)
        hoods = await client.async_setup()
        if not hoods:
            print("no devices on this account", file=sys.stderr)
            return 1

        hood = next(
            (h for h in hoods if h.thing_name == args.thing),
            hoods[0],
        )
        caps = hood.capabilities
        print(f"device: {caps.model} (fan 0-{caps.max_fan_speed}, "
              f"light 0-{caps.max_light_level})")

        try:
            await hood.async_start()
            await asyncio.sleep(2)

            before = dict(hood.state.raw)
            print("current state:")
            print(json.dumps(_redacted(before), indent=2, sort_keys=True))

            if field is None:
                if args.watch:
                    print(f"watching for {args.seconds}s (ctrl-c to stop)")
                    try:
                        await asyncio.sleep(args.seconds)
                    except asyncio.CancelledError:
                        pass
                    after = dict(hood.state.raw)
                    _report(diff_states(_redacted(before), _redacted(after)))
                return 0

            print(f"\nWRITING {field}={value} to a physical appliance.")
            await hood.async_set_fields({field: value})

            await asyncio.sleep(5)
            after = dict(hood.state.raw)
            _report(diff_states(_redacted(before), _redacted(after)))
            return 0
        finally:
            await client.async_stop()
```

`validate_write()` stays exactly as it is. The CLI's `--confirm`/`--force` gate is a *user-interaction* control and is separate from the library's allowlist; both should hold.

- [ ] **Step 2: Run the probe's tests**

Run: `pytest tests/test_probe.py -v`
Expected: PASS. If a test asserts on `client.async_set_state`, update it to `hood.async_set_fields`.

- [ ] **Step 3: Update the README**

Replace the "Read state" example:

```python
import aiohttp
from pyzephyrconnect import ZephyrClient

async with aiohttp.ClientSession() as session:
    client = ZephyrClient.from_credentials("you@example.com", "password", session)
    for hood in await client.async_setup():
        print(hood.capabilities.model, hood.capabilities.max_fan_speed)
        await hood.async_start()
        print(hood.state)
        await hood.async_set_light(1)
```

Add a section after it:

```markdown
## Persisting tokens

The library never stores credentials. Supply tokens from a previous
session and a callback to save new ones, and a restart skips the SRP
login entirely:

```python
client = ZephyrClient.from_credentials(
    username, password, session,
    tokens=ZephyrTokens.from_dict(saved) if saved else None,
    token_updater=lambda t: save(t.as_dict()),
)
```

To keep the password out of the library completely, subclass `AbstractAuth`
and implement `async_get_tokens()`.
```

- [ ] **Step 4: Update VALIDATION.md's command surface**

The runbook's commands are unchanged (`python -m pyzephyrconnect --set light=1 --confirm`), but the troubleshooting section references token refresh. Replace the `ZephyrAuthError` entry:

```markdown
**`ZephyrAuthError`.** Credentials wrong, or both the refresh token and a
fresh SRP login failed. Tokens last one hour; the library refreshes them in
the request path and rebuilds the MQTT socket before they expire.
```

- [ ] **Step 5: Run everything and commit**

Run: `pytest -q && ruff check && python -m build && twine check --strict dist/*`
Expected: all pass.

```bash
git add src/pyzephyrconnect/probe.py README.md VALIDATION.md tests/test_probe.py
git commit -m "refactor: move the probe CLI onto Hood, update docs"
```

- [ ] **Step 6: Tag the first release**

Only after the whole plan is green:

```bash
git tag v0.1.0
git push origin main --tags
```

The release workflow verifies the tag against `pyproject.toml` and `__init__.py` before uploading anything, then publishes to PyPI via trusted publishing.

---

## Self-Review

**Spec coverage:**

| Spec section | Task |
|---|---|
| §1 `ZephyrTokens` / `AbstractAuth` | 5 |
| §1 `CredentialsAuth`, SRP fallback, `token_updater` | 6 |
| §1 identity-ID invalidation | 6 |
| §1 refresh in the request path | 7 |
| §1 credentials provider + supervisor | 8, 10 |
| §2 `Endpoints` | 3 |
| §3 `Hood`, structural allowlist, range guards | 9 |
| §4 `HoodState` absent-vs-zero | 4 |
| §4 `HoodCapabilities` absent → None, malformed → raise | 4 |
| §5 boto3, py.typed, PEP 639, issue templates | 1 |
| §5 exception hierarchy | 2 |
| Release | 11 |

**Amendment against the spec:** the spec says `async_set_state` is removed outright. Task 9 keeps one raw entry point, `Hood.async_set_fields`, because the probe CLI writes arbitrary allowlisted fields to map unknown semantics and a fixed method surface cannot express that. It is allowlist-enforcing and is the chokepoint every typed method delegates through, so the spec's intent — no caller can write a non-writable field — holds.

**Type consistency:** `Hood.async_set_fields` is used by Tasks 9 and 11. `Hood.handle_state` is used by Tasks 9 and 10. `CredentialsAuth.async_get_credentials` is used by Tasks 6, 8 and 10. `Endpoints.device_api_list` / `.device_api_discover` are used by Tasks 3 and 7. `ZephyrTokens.expired` is used by Tasks 5 and 6.

**Ordering:** Tasks 1–4 are independent of each other. Task 4 leaves `tests/test_client.py` failing; Task 10 fixes it. Tasks 5→6→7→8→9→10 are strictly sequential.
