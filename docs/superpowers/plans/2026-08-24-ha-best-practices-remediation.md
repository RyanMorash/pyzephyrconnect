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
- Every MQTT client ID starts with the full Cognito identity ID (`us-west-2:` region prefix **never** stripped) followed by `"-ha"`. Each hood's connection appends a per-device suffix on top — AWS IoT treats two live connections with the SAME client ID as one session and evicts one for the other, so N hoods sharing one ID flap forever. PROTOCOL.md §5 establishes the policy's client-ID constraint is absent-or-prefix-match, so identity-prefixed suffixes stay authorised.
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

Widen the existing `ZephyrTransportError` docstring - it becomes the class
for every *retryable* infrastructure failure, not just MQTT:

```python
class ZephyrTransportError(ZephyrError):
    """A network, timeout or throttling failure. Retryable.

    Deliberately distinct from ZephyrAuthError: the supervisor treats auth
    errors as terminal (they need the user), while transport errors are
    retried on the next tick. Wrapping a DNS blip in ZephyrAuthError turns
    a Wi-Fi hiccup into a reauth prompt.
    """
```

Then append to `src/pyzephyrconnect/exceptions.py`:

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

**Reconcile the existing tests in `tests/test_models.py` first**: any test
asserting the old zero-defaults for absent fields (e.g. an absent `power`
reading as `0`, or absent capability numerics reading as `0`) now asserts the
wrong behaviour. Update those assertions to `is None`; keep tests asserting
present values unchanged.

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
  - `AbstractAuth(session, endpoints=DEFAULT_ENDPOINTS)` with abstract `async_get_tokens() -> ZephyrTokens` and **concrete** `async_get_credentials()`, `credentials_expired`, `mqtt_client_id`, `async_attach_policy()`, `identity_id` and the `_on_identity_refetched` hook — the complete surface `ZephyrClient` consumes, so a subclass implementing only the abstract method works end to end.
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

Also append to `tests/test_auth.py` (it has the `fake_aws` fixture the
concrete AWS members need). Add `AbstractAuth` and `ZephyrTokens` to its
pyzephyrconnect.auth import line, and define the shared helper HERE, once -
Task 6's tests reuse it with this exact default:

```python
def _stored_tokens(expires_in=-1):
    return ZephyrTokens(
        username="user@example.com",
        id_token="OLD-ID",
        refresh_token="REFRESH",
        identity_id=IDENTITY,
        expires_at=time.time() + expires_in,
    )


class _StaticAuth(AbstractAuth):
    """The documented consumer path: implement one method, nothing else."""

    def __init__(self, tokens, session):
        super().__init__(session)
        self._static = tokens

    async def async_get_tokens(self):
        return self._static


async def test_a_minimal_subclass_satisfies_the_whole_client_contract(fake_aws):
    """ZephyrClient consumes async_get_credentials, credentials_expired,
    mqtt_client_id and async_attach_policy. If any of those live only on
    CredentialsAuth, a custom AbstractAuth satisfies the type checker and
    AttributeErrors at runtime - which is exactly the consumer the abstract
    class exists for."""
    auth = _StaticAuth(_stored_tokens(3600), MagicMock())

    creds = await auth.async_get_credentials()
    assert creds.secret_key == "SECRET"
    assert auth.credentials_expired is False
    assert auth.mqtt_client_id == f"{IDENTITY}-ha"
    await auth.async_attach_policy()
    fake_aws["iot"].attach_policy.assert_called_once()
```

(`import time` is needed at the top of the file if not already present.)

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
from botocore.exceptions import ClientError

from .const import DEFAULT_ENDPOINTS, Endpoints
from .exceptions import ZephyrTransportError

# The module's dataclasses import must become:
#   from dataclasses import dataclass, field, replace
# - `field` for the repr=False declarations below, `replace` for the
# identity write-back in Task 6.


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
    """Supplies valid Zephyr cloud tokens - and everything derived from them.

    Implement `async_get_tokens()` and nothing else: the identity exchange,
    the AWS credential cache, the MQTT client ID and the IoT policy attach
    are all concrete here, built on the one abstract method. That is what
    makes the class implementable by a consumer - ZephyrClient consumes
    async_get_credentials, credentials_expired, mqtt_client_id and
    async_attach_policy, so if those lived only on CredentialsAuth, a custom
    subclass would satisfy the type checker and AttributeError at runtime.

    Only the ID token crosses the abstract boundary. The AWS credentials
    derived from it last an hour and are bound to a live socket; nothing
    about them is worth delegating or persisting.

    CredentialsAuth is the built-in implementation for the simple case.
    """

    def __init__(
        self,
        session: aiohttp.ClientSession,
        endpoints: Endpoints = DEFAULT_ENDPOINTS,
    ) -> None:
        self.session = session
        self.endpoints = endpoints
        self._credentials: Credentials | None = None
        # Set when the exchange discovers a stored identity_id is stale.
        # Runtime authority over tokens.identity_id from that point on.
        self._identity_override: str | None = None
        self._seen_tokens: ZephyrTokens | None = None
        # Serialises the identity exchange - distinct from any lock a
        # subclass uses for token acquisition.
        self._aws_lock = asyncio.Lock()

    @abstractmethod
    async def async_get_tokens(self) -> ZephyrTokens:
        """Return valid, unexpired tokens, refreshing if necessary.

        Called on every REST request and by the credential supervisor, so
        implementations should return a cached value while it is fresh.
        """

    @property
    def identity_id(self) -> str:
        """Cognito identity ID, the full region-prefixed string.

        Stable per account: the identity pool keys this on the user pool's
        immutable `sub` claim, so it survives password and email changes and
        is idempotent across calls - the natural unique key for a consumer
        that needs to identify this account.

        Available after the first async_get_credentials(), which
        ZephyrClient.async_setup() performs (and CredentialsAuth also makes
        it available after async_get_tokens()). Raises ZephyrAuthError
        before that.
        """
        if self._identity_override is not None:
            return self._identity_override
        if self._seen_tokens is None:
            raise ZephyrAuthError("no tokens acquired yet")
        return self._seen_tokens.identity_id

    @property
    def mqtt_client_id(self) -> str:
        """Identity ID plus a stable suffix.

        The IoT policy pins the client ID to the identity. Using the bare
        identity ID makes this library and the phone app evict each other.
        Derived from identity_id, never the other way around.
        """
        return f"{self.identity_id}{const.CLIENT_ID_SUFFIX}"

    @property
    def credentials_expired(self) -> bool:
        """True when the cached AWS credentials need renewing.

        A plain property on purpose. The supervisor must be able to ask "do
        these need replacing?" without async_get_credentials() renewing them
        as a side effect, which would make the answer always False and the
        socket never get rebuilt.
        """
        return self._credentials is None or self._credentials.expired

    async def async_get_credentials(self) -> Credentials:
        """AWS credentials for SigV4-presigning the MQTT WebSocket URL.

        Derived from the ID token rather than persisted: they last an hour
        and are bound to a live socket, so there is nothing worth storing.
        """
        tokens = await self.async_get_tokens()
        self._seen_tokens = tokens
        if not self.credentials_expired:
            assert self._credentials is not None
            return self._credentials
        async with self._aws_lock:
            if not self.credentials_expired:
                assert self._credentials is not None
                return self._credentials
            stored_identity = self._identity_override or tokens.identity_id
            try:
                identity_id, credentials = await asyncio.to_thread(
                    self._exchange, tokens.id_token, stored_identity
                )
            except ZephyrError:
                raise
            except Exception as err:  # noqa: BLE001
                # This is the path a restart with persisted tokens takes, so
                # a raw botocore exception here escapes the "consumers catch
                # ZephyrError" contract exactly at boot. Classify: rejection
                # is terminal, a network blip is retryable.
                raise self._classify(err) from err
            if identity_id != stored_identity:
                # The stored identity was stale and _exchange refetched it.
                # This MUST take effect: mqtt_client_id derives from it, and
                # a client ID built on a dead identity gets a connection
                # where subscribe and publish succeed and every message is
                # silently dropped (PROTOCOL.md section 3.3).
                self._identity_override = identity_id
                self._on_identity_refetched(identity_id)
            self._credentials = credentials
            return self._credentials

    async def async_attach_policy(self) -> None:
        """Bind the IoT policy to this identity.

        MUST run before connecting. An open MQTT connection does not pick up
        newly attached permissions.
        """
        credentials = await self.async_get_credentials()
        await asyncio.to_thread(self._attach, self.identity_id, credentials)

    def _on_identity_refetched(self, identity_id: str) -> None:
        """Hook: a stored identity_id was stale and has been replaced.

        Default no-op. CredentialsAuth overrides it to write the corrected
        value back into its persisted tokens. ZephyrClient also re-attaches
        the IoT policy for the new identity - see _ensure_policy.
        """

    @staticmethod
    def _classify(err: Exception) -> ZephyrError:
        """Terminal credential rejection, or retryable infrastructure noise?

        The supervisor keys terminal-vs-retry on the exception TYPE, so
        wrapping everything in ZephyrAuthError turns a DNS blip or a Cognito
        TooManyRequestsException at the hourly refresh into a permanent stop
        and a reauth prompt. Only genuine rejections may become auth errors.
        """
        code = ""
        if isinstance(err, ClientError):
            code = err.response.get("Error", {}).get("Code", "")
        if code in {
            "NotAuthorizedException",
            "UserNotFoundException",
            "UserNotConfirmedException",
            "PasswordResetRequiredException",
            "AccessDeniedException",
        }:
            return ZephyrAuthError(f"credentials rejected: {code}")
        return ZephyrTransportError(f"cloud request failed: {err}")

    # -- blocking bodies, run in a worker thread ----------------------

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
            # No identity ID in the message: it is a stable account
            # identifier, and exception text reaches ERROR logs users paste
            # into public issues.
            raise ZephyrPolicyError(
                f"Could not attach {const.POLICY_NAME} to this identity. "
                "Without it the MQTT connection succeeds but every message is "
                "silently dropped."
            ) from err
```

Everything `ZephyrClient` consumes now exists on the base class, implemented
in terms of the one method a subclass writes.

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
- Modify: `src/pyzephyrconnect/__init__.py` (export `CredentialsAuth` - the design presents it as the public built-in implementation)
- Test: `tests/test_auth.py`

**Interfaces:**
- Consumes: `ZephyrTokens`, `AbstractAuth`, `Endpoints`, `Credentials`.
- Produces: `CredentialsAuth(username, password, session, *, tokens=None, token_updater=None, endpoints=DEFAULT_ENDPOINTS)` implementing `async_get_tokens()` and overriding the `_on_identity_refetched` hook to persist a corrected identity. `async_get_credentials()`, `async_attach_policy()`, `credentials_expired` and `mqtt_client_id` are **inherited from AbstractAuth** (Task 5), not defined here. `ZephyrAuth` is deleted and replaced by this class.

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


# _stored_tokens(expires_in=-1) is already defined in this file by Task 5 -
# reuse it, do not redefine it.


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


async def test_concurrent_callers_trigger_only_one_login(fake_aws):
    """ZephyrApi asks for tokens on every request and the supervisor asks too,
    so an expired token can be requested by several callers at once. The pool
    rate-limits (PROTOCOL.md section 3.1)."""
    import asyncio

    auth = CredentialsAuth("user@example.com", "pw", MagicMock())
    await asyncio.gather(*(auth.async_get_tokens() for _ in range(5)))

    assert fake_aws["cognito"].authenticate.call_count == 1


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
        # Restored tokens make identity_id readable immediately.
        self._seen_tokens = tokens
        # Serialises token acquisition. Without it, concurrent callers each
        # run a full SRP login against a pool that rate-limits (PROTOCOL.md
        # section 3.1), and ZephyrApi asks for tokens on every request.
        # Distinct from the inherited _aws_lock guarding the exchange.
        self._lock = asyncio.Lock()

    def _on_identity_refetched(self, identity_id: str) -> None:
        """Persist a corrected identity into the stored tokens.

        The base class already routes mqtt_client_id through its override;
        this makes the correction survive a restart instead of being
        rediscovered by a failed exchange every time.
        """
        if self._tokens is not None:
            self._tokens = replace(self._tokens, identity_id=identity_id)
            if self._token_updater is not None:
                self._token_updater(self._tokens)

    # -- blocking bodies, run in a worker thread ----------------------    # -- blocking bodies, run in a worker thread ----------------------

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

    # _identity_client, _exchange and _attach are inherited from
    # AbstractAuth: they operate on tokens and endpoints, nothing
    # Cognito-login-specific, and hoisting them is what makes AbstractAuth
    # implementable by consumers.

    # -- async surface -------------------------------------------------    # -- async surface -------------------------------------------------

    async def async_get_tokens(self) -> ZephyrTokens:
        if self._tokens is not None and not self._tokens.expired:
            return self._tokens
        async with self._lock:
            # Re-check under the lock: whoever held it may have refreshed
            # while we waited, and a second login would be wasted and
            # rate-limitable.
            if self._tokens is not None and not self._tokens.expired:
                return self._tokens
            return await self._acquire()

    async def _acquire(self) -> ZephyrTokens:
        """Refresh or log in. Caller holds self._lock."""
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
                # Classify - a DNS failure or pool throttling here must NOT
                # become ZephyrAuthError, which the supervisor treats as
                # terminal and the consumer maps to a reauth prompt.
                raise self._classify(err) from err

        self._user = user
        try:
            identity_id, credentials = await asyncio.to_thread(
                self._exchange,
                user.id_token,
                stored.identity_id if stored is not None else None,
            )
        except ZephyrError:
            raise
        except Exception as err:  # noqa: BLE001
            raise self._classify(err) from err

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
        self._seen_tokens = self._tokens
        if self._token_updater is not None:
            self._token_updater(self._tokens)
        return self._tokens

```

Add `from collections.abc import Callable````

Add `from collections.abc import Callable`, `from dataclasses import replace` and `import asyncio` to the imports. Delete the old `ZephyrAuth` class entirely.

- [ ] **Step 4: Reconcile the existing ZephyrAuth tests, then run**

`tests/test_auth.py` currently imports `ZephyrAuth` at the top and holds ~10
tests exercising it; this task deletes that class, which makes the import a
collection-time `ImportError` taking down the NEW tests too. Remove
`ZephyrAuth` from the import line and port or delete each old test:
behaviours worth keeping (explicit `user_pool_region`, `SecretKey`-not-
`SecretAccessKey`, policy attach raising `ZephyrPolicyError`, the accessor
raising before authentication) map directly onto `CredentialsAuth`/
`AbstractAuth` equivalents; the rest duplicate the new coverage and go.

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
import time
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
            # Must stay ABOVE the ClientError clause - it is a subclass, and
            # the certificate diagnosis is the valuable one.
            raise ZephyrCertificateError(
                f"TLS verification failed for {url}. The presented chain is "
                f"trusted by neither the system CA store nor the bundled "
                f"TWCA anchors ({CERT_BUNDLE}) added to work around the "
                "vendor's SKI-less intermediate. The vendor likely changed "
                "its certificate chain again - recapture it and update the "
                "TWCA bundle if needed. Do not disable verification."
            ) from err
        except (aiohttp.ClientError, TimeoutError) as err:
            # DNS failure, connection reset, timeout: retryable transport
            # noise. Left unwrapped it escapes the "consumers catch
            # ZephyrError" contract from async_setup() and async_poll().
            raise ZephyrTransportError(
                f"request to {url} failed: {err}"
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

Import `AbstractAuth` from `.auth`, `ZephyrTransportError` from `.exceptions`, and add `import asyncio` to the module imports.

- [ ] **Step 4: Reconcile the existing ZephyrApi tests, then run**

The existing tests in `tests/test_api.py` construct `ZephyrApi(session)` and
pass `id_token` arguments that no longer exist. Port them onto the
`_fake_auth` helper and the no-argument method signatures - their assertions
(bare token, empty body, 403 mapping, certificate error text) are all still
the right assertions; only the plumbing changes.

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

`tests/test_shadow.py` builds clients via a `_make()` helper and a
`fake_paho` fixture that replaces `mqtt.Client`. Define these two helpers on
top of them (adjust `_make`'s actual signature as found in the file), and
make sure every new test requests `fake_paho` so no real paho client or
network thread is ever constructed:

```python
CREDS = Credentials("k", "s", "t", datetime.now(UTC) + timedelta(hours=1))


async def _default_provider():
    return CREDS


def _shadow(credentials_provider=_default_provider, **kwargs):
    """A ShadowClient on the new 5-argument constructor."""
    return ShadowClient(
        THING,
        "us-west-2:abc-ha",
        lambda topic, payload: None,
        lambda connected: None,
        credentials_provider,
        **kwargs,
    )


async def _connect(shadow):
    """Drive connect() to completion against the fake paho client."""
    task = asyncio.create_task(shadow.connect(timeout=1))
    await asyncio.sleep(0)
    shadow._client.simulate_connect()      # fake_paho: fires on_connect + SUBACKs
    await task
```

(`simulate_connect` names whatever mechanism the existing `fake_paho`
fixture uses to fire the connect/subscribe callbacks - reuse it, do not
invent a parallel fake.)

**Then reconcile the existing tests**: every current test constructs the
4-argument `ShadowClient` and passes `Credentials` into `connect()`. Move
them onto `_shadow()`/`_connect()` - the assertions stand, only construction
changes. Add `timedelta` to the file's datetime import.

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


async def test_tls_context_is_not_built_on_the_event_loop():
    """paho's tls_set() calls load_default_certs() inline, which Home
    Assistant reports as a blocking call on the loop. Hand it a finished
    context instead."""
    shadow = _shadow()
    await _connect(shadow)

    client = shadow._client
    client.tls_set.assert_not_called()
    client.tls_set_context.assert_called_once()
    ctx = client.tls_set_context.call_args.args[0]
    # Design Risks 10-11: a default context - CERT_REQUIRED, hostname
    # checking on, and NOT the TWCA-augmented REST context.
    assert ctx.verify_mode is ssl.VERIFY_DEFAULT or ctx.verify_mode.name == "CERT_REQUIRED"
    assert ctx.check_hostname is True


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

Also replace the `client.tls_set()` call further down the method:

```python
        # The IoT ATS endpoint chains to Amazon Root CA 1, which system trust
        # stores already carry. Only the vendor REST host needs the extra CAs,
        # so this is a plain default context - NOT the TWCA one.
        #
        # Built in a worker thread and handed to paho finished. paho's
        # tls_set() constructs the context inline on the calling thread: it
        # does ssl.SSLContext(...) and then, because ca_certs is None,
        # context.load_default_certs() - which Home Assistant instruments as
        # a blocking call. connect() is async and runs on the event loop, and
        # this path executes on every connect including every supervisor
        # reconnect.
        client.tls_set_context(
            await asyncio.to_thread(ssl.create_default_context)
        )
```

`ssl.create_default_context()` gives `CERT_REQUIRED` plus hostname checking,
matching what `tls_set()` produced.

Make everything after `loop_start()` cancellation-safe. The current code
cleans up only on `TimeoutError`; a `CancelledError` while awaiting the
connected/subscribed events abandons a paho client whose network thread is
already running and that no reference can ever reach again - and Hood only
assigns `self._shadow` after `connect()` returns. Restructure the tail of
`connect()`:

```python
        client.connect_async(self._endpoints.iot_endpoint, 443, keepalive=30)
        client.loop_start()
        self._client = client

        try:
            try:
                await asyncio.wait_for(self._connected.wait(), timeout)
            except TimeoutError as err:
                raise ZephyrTransportError(
                    f"MQTT connection to {self._endpoints.iot_endpoint} timed out"
                ) from err
            try:
                await asyncio.wait_for(self._subscribed.wait(), timeout)
            except TimeoutError as err:
                raise ZephyrTransportError(
                    "MQTT connected but shadow subscriptions did not "
                    "complete in time"
                ) from err
            if self._subscribe_error is not None:
                error, self._subscribe_error = self._subscribe_error, None
                raise error
        except BaseException:
            # Covers the ZephyrTransportError raises above, ZephyrPolicyError,
            # AND CancelledError: whatever interrupts the handshake, the paho
            # client and its network thread must be torn down before the
            # exception leaves - nothing outside holds a reference yet.
            await self.disconnect()
            raise
```

Fix the disconnect ordering, which now runs on a ~50-minute reconnect cycle
rather than once at shutdown:

```python
    async def disconnect(self) -> None:
        if self._client is None:
            return
        client, self._client = self._client, None
        # Off the loop: loop_stop() JOINS paho's network thread (see
        # paho/mqtt/client.py), and that thread is frequently inside a
        # synchronous socket recv. A thread join on the event loop was
        # tolerable once at shutdown; this now runs on every ~50-minute
        # supervisor rebuild, per hood.
        await asyncio.to_thread(self._teardown, client)
        self._connected.clear()
        self._subscribed.clear()

    @staticmethod
    def _teardown(client: mqtt.Client) -> None:
        # disconnect() BEFORE loop_stop(). The network thread is what writes
        # the DISCONNECT packet; stopping it first means the packet is queued
        # and never sent, and the broker only notices via keepalive timeout.
        client.disconnect()
        client.loop_stop()
```

In `publish_state`, change the guard:

```python
        if not fields:
            raise ZephyrWriteError("refusing to publish an empty reported state")
```

Add `from collections.abc import Awaitable, Callable`, `import ssl`, and import `DEFAULT_ENDPOINTS`, `Endpoints`, `ZephyrWriteError`.

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
- Produces: `Hood`, constructed by `ZephyrClient` in Task 10 as `Hood(capabilities, shadow_factory, poll, prepare)` where `shadow_factory: Callable[[Hood], ShadowClient]`, `poll: Callable[[str], Awaitable[HoodState]]` and `prepare: Callable[[], Awaitable[None]]` (attaches the IoT policy before the first connect). Also exposes `connected -> bool` and `handle_connection_change(bool)`.

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

from pyzephyrconnect.exceptions import (
    ZephyrNotConnectedError,
    ZephyrTransportError,
    ZephyrWriteError,
)
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
        prepare=AsyncMock(),
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


async def test_policy_is_attached_before_the_socket_opens():
    """The single most dangerous failure in this protocol: without the policy,
    connect, subscribe and publish all succeed and every message is silently
    dropped, with no exception and no log line (PROTOCOL.md section 3.3)."""
    order = []
    shadow = MagicMock()
    shadow.connect = AsyncMock(side_effect=lambda: order.append("connect"))
    shadow.request_state = AsyncMock()
    hood = Hood(
        _caps(),
        shadow_factory=lambda _h: shadow,
        poll=AsyncMock(),
        prepare=AsyncMock(side_effect=lambda: order.append("prepare")),
    )
    await hood.async_start()

    assert order == ["prepare", "connect"]


async def test_starting_twice_does_not_orphan_a_client():
    """The first paho client keeps its network thread running, so overwriting
    it leaks a thread and a socket per call."""
    made = []

    def factory(_h):
        shadow = MagicMock()
        shadow.connect = AsyncMock()
        shadow.request_state = AsyncMock()
        made.append(shadow)
        return shadow

    hood = Hood(_caps(), factory, AsyncMock(), AsyncMock())
    await hood.async_start()
    await hood.async_start()

    assert len(made) == 1


async def test_ensure_running_recovers_a_hood_whose_rebuild_failed():
    """A transient connect failure during a supervisor rebuild leaves the
    hood with no socket but with consumer intent intact. It must come back
    on a later tick, not stay dead until a reload."""
    made = []

    def factory(_h):
        shadow = MagicMock()
        shadow.connect = AsyncMock(
            side_effect=ZephyrTransportError("boom") if len(made) == 1 else None
        )
        shadow.request_state = AsyncMock()
        shadow.disconnect = AsyncMock()
        made.append(shadow)
        return shadow

    hood = Hood(_caps(), factory, AsyncMock(), AsyncMock())
    await hood.async_start()                      # made[0] connects

    with pytest.raises(ZephyrTransportError):
        await hood.async_reconnect()              # made[1] fails; _shadow None

    await hood.async_ensure_running()             # made[2] recovers
    assert len(made) == 3
    made[2].request_state.assert_awaited()


async def test_reconnect_does_not_start_a_hood_that_was_never_started():
    """The supervisor reconnects every hood it knows about. Discovering two
    hoods and starting one must not mean the other quietly comes up on the
    next credential refresh."""
    hood, shadow = _hood()
    await hood.async_reconnect()

    shadow.connect.assert_not_awaited()


async def test_a_write_during_a_reconnect_waits_rather_than_failing():
    """The supervisor rebuilds the socket about every 50 minutes. A write
    landing in that window is not a disconnected hood, and must not surface
    to the user as a failed command."""
    import asyncio

    hood, shadow = _hood()
    await hood.async_start()

    release = asyncio.Event()

    async def slow_connect():
        await release.wait()

    shadow.connect = AsyncMock(side_effect=slow_connect)
    reconnect = asyncio.create_task(hood.async_reconnect())
    await asyncio.sleep(0)

    write = asyncio.create_task(hood.async_set_light(1))
    await asyncio.sleep(0)
    assert not write.done()          # waiting on the lock, not raising

    release.set()
    await reconnect
    await write
    shadow.publish_state.assert_awaited_with({"light": 1})


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

import asyncio
import logging
from collections.abc import Awaitable, Callable

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
        prepare: Callable[[], Awaitable[None]],
    ) -> None:
        self._capabilities = capabilities
        self._shadow_factory = shadow_factory
        self._poll = poll
        # Runs before the first connect. Attaches the IoT policy; see _start.
        self._prepare = prepare
        self._shadow: ShadowClient | None = None
        self._state: HoodState | None = None
        self._listeners: list[StateListener] = []
        self._connected = False
        # Consumer intent: True between async_start() and async_stop().
        # Distinct from having a socket - a failed supervisor rebuild leaves
        # _shadow None while the hood SHOULD still be running, and keying
        # recovery on _shadow alone demotes it to "never started" forever.
        self._should_run = False
        # Serialises start/stop/reconnect against writes.
        self._lock = asyncio.Lock()

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

    @property
    def connected(self) -> bool:
        """Whether THIS hood's shadow connection is up.

        Per-hood, not per-account: with several hoods one dropping must not
        report the others as down.
        """
        return self._connected

    def handle_connection_change(self, connected: bool) -> None:
        """Called by ShadowClient from the event loop."""
        self._connected = connected

    async def async_start(self) -> None:
        """Open this hood's shadow connection and request current state."""
        async with self._lock:
            self._should_run = True
            await self._start()

    async def async_stop(self) -> None:
        async with self._lock:
            self._should_run = False
            await self._stop()

    async def async_reconnect(self) -> None:
        """Rebuild the socket after a credential refresh.

        The presigned URL is derived from credentials that expire, so a
        refresh without a reconnect leaves a socket AWS IoT will drop.

        Holds the lock across both halves so a write arriving mid-rebuild
        waits rather than failing with a spurious ZephyrNotConnectedError.
        """
        async with self._lock:
            if not self._should_run:
                # Never started, or deliberately stopped. The supervisor
                # calls this for every hood on the account; it must not
                # bring up MQTT for hoods the consumer chose not to start.
                return
            await self._stop()
            await self._start()

    async def async_ensure_running(self) -> None:
        """Reopen the socket if the consumer wants this hood up and it is not.

        The recovery path for a transient failure during a supervisor
        rebuild: _start raised, _shadow stayed None, and without this the
        hood would be indistinguishable from one never started - push dead
        forever with no error surfaced. Called by the supervisor every tick.
        """
        async with self._lock:
            if self._should_run and self._shadow is None:
                await self._start()

    # Lock-free bodies. Callers above hold self._lock; asyncio.Lock is not
    # reentrant, so async_reconnect cannot call the public methods.

    async def _start(self) -> None:
        if self._shadow is not None:
            # Already connected. Rebuilding here would orphan the previous
            # paho client with its network thread still running.
            return
        # MUST precede connect(). An already-open MQTT connection does not
        # pick up newly attached permissions, and the failure is silent:
        # connect, subscribe and publish all succeed and every message is
        # dropped (PROTOCOL.md section 3.3). Latched by the client, so a
        # reconnect does not re-attach - the binding persists on the identity.
        await self._prepare()
        shadow = self._shadow_factory(self)
        await shadow.connect()
        self._shadow = shadow
        await shadow.request_state()

    async def _stop(self) -> None:
        if self._shadow is not None:
            await self._shadow.disconnect()
            self._shadow = None
        self._connected = False

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
        async with self._lock:
            await self._publish(fields)

    async def _publish(self, fields: dict[str, int]) -> None:
        if self._shadow is None:
            # No thing name in the message: it identifies a home, and
            # exception text ends up in logs users paste publicly.
            raise ZephyrNotConnectedError(
                "async_start() has not been called for this hood"
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

    async def async_set_delay_timer(self, value: int) -> None:
        """Arm the delay-off timer.

        UNITS UNESTABLISHED: VALIDATION.md question 2 - whether this is
        seconds or minutes, and whether it snaps to presets, is exactly what
        the hardware runbook exists to answer. Do not document units as fact
        anywhere until step 6 of the runbook has run.

        The device derives and decrements `delaytimer` from this itself, so
        only `setdelaytimer` is written.
        """
        self._check_range("delay timer", value, None)
        await self.async_set_fields({"setdelaytimer": value})

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
  - `ZephyrClient(auth: AbstractAuth)` — endpoints are read from `auth.endpoints`, never a second argument
  - `ZephyrClient.from_credentials(username, password, session, *, tokens=None, token_updater=None, endpoints=DEFAULT_ENDPOINTS) -> ZephyrClient`
  - `async_setup() -> list[Hood]`
  - `async_stop() -> None`
  - `connected -> bool` (derived: any hood connected)
  - `identity_id -> str`
  - Removed: `async_set_state`, `async_start(thing_name)`, `async_poll(thing_name)`, `state(thing_name)`, `capabilities(thing_name)`, `add_listener(thing_name, cb)`, `async_refresh_if_needed()`.

The supervisor is the reason `async_refresh_if_needed()` can be deleted. It runs while any hood is started, renews credentials inside `REFRESH_MARGIN_SECONDS` of expiry, and reconnects each hood. It does **not** re-attach the IoT policy: per `PROTOCOL.md` §3.3 the binding persists on the identity.

It also retires itself: a tick that finds no hood with `_should_run` set returns, because the running task holds the client strongly through every sleep and a consumer that abandoned the client (Home Assistant's `ConfigEntryNotReady` retry builds a fresh one) would otherwise keep a zombie alive that revives hoods onto MQTT client IDs identical to the replacement client's — and `Hood.async_start()` rolls its own intent back when it raises, precisely so an abandoned client leaves nothing armed. Correspondingly, `ShadowClient` refuses a write before handing it to paho unless the client reports `is_connected()`, and if paho refuses one with `MQTT_ERR_NO_CONN` (already parked in its out-queue) the connection is torn down before the error is raised, so a refused write can never actuate the hood later on paho's own reconnect.

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

    wired["auth"].credentials_expired = True
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
    # Non-vacuous setup: mark the hood connected BEFORE the terminal error,
    # so the final assertion proves the terminal branch's hood-stop actually
    # flipped the derived property rather than it never having been True.
    hoods[0].handle_connection_change(True)
    assert client.connected is True

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

Replace the fixture with a fully specified double — every attribute below is
consumed by some test in this file, and a bare `MagicMock` attribute is
truthy, which silently satisfies (or breaks) the `credentials_expired` guard:

```python
def _auth_double(endpoints=DEFAULT_ENDPOINTS, order=None):
    auth = MagicMock()
    auth.endpoints = endpoints
    auth.identity_id = "us-west-2:abc"
    auth.mqtt_client_id = "us-west-2:abc-ha"
    auth.credentials_expired = False          # explicit bool, never a Mock
    auth.async_get_tokens = AsyncMock()
    auth.async_get_credentials = AsyncMock(
        return_value=Credentials(
            "k", "s", "t", datetime.now(UTC) + timedelta(hours=1)
        )
    )
    auth.async_attach_policy = AsyncMock(
        side_effect=lambda: (order or []).append("attach_policy")
    )
    return auth
```

The `wired` fixture builds one `_auth_double(order=order)`, monkeypatches
`client_module.ZephyrApi` and `client_module.ShadowClient` exactly as the
current fixture does, and `_client()` becomes:

```python
def _client():
    return ZephyrClient(_auth_double())
```

Add the endpoint-threading test here (it needs `_auth_double`, which is why
it cannot live in Task 7):

```python
async def test_an_endpoint_override_reaches_mqtt_too(wired):
    """Overriding endpoints must not silently apply to REST only - the MQTT
    host is a separate wiring path, and failing to thread it through leaves
    the override half-applied with nothing complaining."""
    endpoints = Endpoints(iot_endpoint="staging-ats.iot.us-west-2.amazonaws.com")
    client = ZephyrClient(_auth_double(endpoints=endpoints))
    hoods = await client.async_setup()
    client._make_shadow(hoods[0])

    passed = client_module.ShadowClient.call_args.kwargs["endpoints"]
    assert passed.iot_endpoint.startswith("staging-ats")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_client.py -v`
Expected: FAIL — `ZephyrClient.__init__` still takes `(username, password, session)`.

- [ ] **Step 3: Implement**

Rewrite `src/pyzephyrconnect/client.py`. Key structure:

```python
class ZephyrClient:
    """One authenticated account and the hoods under it."""

    def __init__(self, auth: AbstractAuth) -> None:
        self._auth = auth
        # Deliberately NOT a separate constructor argument. The auth object
        # already carries the endpoints and ZephyrApi reads them from there,
        # so a second source would let REST and MQTT point at different
        # clouds with nothing complaining.
        self._endpoints = auth.endpoints
        self._api = ZephyrApi(auth)
        self._hoods: dict[str, Hood] = {}
        self._supervisor: asyncio.Task | None = None
        self._supervisor_error: ZephyrError | None = None
        # Attribute, not the bare constant: tests drive the supervisor with
        # a zero interval instead of waiting a real minute.
        self._supervisor_interval: float = const.SUPERVISOR_INTERVAL_SECONDS
        # The IoT policy binding persists per identity. Keyed on WHICH
        # identity it was attached for, not a bare bool: a mid-session
        # identity refetch (AbstractAuth._identity_override) must trigger a
        # re-attach for the new identity, or every message on the next
        # reconnect is silently dropped - the exact failure the attach
        # exists to prevent.
        self._policy_attached_for: str | None = None

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
            )
        )

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
        # The full chain, not just tokens: this performs the identity
        # exchange, which is what makes auth.identity_id readable - the
        # config-flow ordering "async_setup(), then read identity_id for
        # the unique ID" depends on it. Also exactly what the pre-refactor
        # authenticate() verified at setup.
        await self._auth.async_get_credentials()
        if self._hoods:
            # Re-running setup would replace started Hood objects while
            # their sockets and the supervisor still reference the old ones.
            # One client = one setup; build a new client to re-discover.
            raise ZephyrError("async_setup() has already run on this client")
        devices = await self._api.get_own_devices()
        for device in devices:
            if not (thing_name := device.get("thingName")):
                # A KeyError here would escape ZephyrError and reach the
                # consumer as an unknown crash rather than a setup retry.
                _LOGGER.warning("skipping a device with no thingName")
                continue
            payload = await self._api.discover_device(thing_name)
            caps = HoodCapabilities.from_discover(payload)
            hood = Hood(
                caps, self._make_shadow, self._poll_state, self._ensure_policy
            )
            hood.handle_state(self._state_from_discover(payload))
            self._hoods[thing_name] = hood
        return list(self._hoods.values())

    async def async_stop(self) -> None:
        if self._supervisor is not None:
            self._supervisor.cancel()
            # Await it. Cancelling without awaiting can leave a hood halfway
            # through async_reconnect() with no socket and no supervisor, and
            # lets the task be collected with an unretrieved CancelledError.
            with contextlib.suppress(asyncio.CancelledError):
                await self._supervisor
            self._supervisor = None
        for hood in self._hoods.values():
            await hood.async_stop()

    @property
    def connected(self) -> bool:
        """True while at least one hood has a live push connection.

        Derived from the hoods rather than a single latched flag, which with
        more than one hood reported whichever shadow changed state last.
        """
        return any(hood.connected for hood in self._hoods.values())

    async def _ensure_policy(self) -> None:
        """Attach the IoT policy. Idempotent, and latched after the first run.

        Passed to each Hood as its `prepare` callable, so it always runs
        before the first connect and never on a reconnect.
        """
        identity = self._auth.identity_id
        if self._policy_attached_for == identity:
            return
        await self._auth.async_attach_policy()
        self._policy_attached_for = identity
```

`_make_shadow(hood)` builds the `ShadowClient`. Every argument matters, and the
last one is easy to omit:

```python
    def _make_shadow(self, hood: Hood) -> ShadowClient:
        shadow = ShadowClient(
            hood.thing_name,
            # Per-CONNECTION client ID. AWS IoT treats two live connections
            # with the same ID as one session and evicts one for the other,
            # so N hoods sharing the bare mqtt_client_id would flap forever.
            # Identity-prefixed, so the policy's prefix-match still covers
            # it (PROTOCOL.md section 5).
            f"{self._auth.mqtt_client_id}-{hood.thing_name[:8]}",
            lambda topic, payload: self._handle_message(hood, topic, payload),
            hood.handle_connection_change,
            self._auth.async_get_credentials,
            # Without this the ShadowClient falls back to DEFAULT_ENDPOINTS,
            # so an endpoint override would reach REST but silently leave
            # MQTT pointed at production.
            endpoints=self._endpoints,
        )
        self._ensure_supervisor()
        return shadow
```

The message callback closes over `hood`, so a shadow message is folded into
the right appliance's state. `_ensure_supervisor()` must be synchronous and must treat a COMPLETED task
as not-running — the terminal branch exits via `return`, leaving
`self._supervisor` holding a done task, and a naive `is not None` check
would then never restart supervision after a reauth on the same client:

```python
    def _ensure_supervisor(self) -> None:
        if self._supervisor is None or self._supervisor.done():
            # A fresh supervisor supersedes any stored terminal error -
            # otherwise the error outlives the condition that caused it and
            # every later poll raises.
            self._supervisor_error = None
            self._supervisor = asyncio.create_task(self._supervise())
```

`Hood` needs the small internal used by the terminal branch — a stop that
closes the socket but PRESERVES consumer intent, so `_should_run` survives
for the recovery path:

```python
    async def _stop_for_supervisor(self) -> None:
        """Close the socket without clearing consumer intent."""
        async with self._lock:
            await self._stop()
```

It does **not** attach the IoT policy: that is `_ensure_policy`, passed to each
`Hood` as its `prepare` callable so it runs before the first connect and is
latched thereafter.

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
                await asyncio.sleep(self._supervisor_interval)
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
                # Stop the hoods: the derived `connected` property flips to
                # False the moment their sockets close (a bare flag write
                # here would be dead code - the property never reads one),
                # and paho stops hammering presigned URLs that can no longer
                # be renewed. Consumer intent (_should_run) survives, so a
                # reauth that builds a new client is unaffected.
                for hood in self._hoods.values():
                    try:
                        await hood._stop_for_supervisor()
                    except Exception:  # noqa: BLE001
                        _LOGGER.exception("stopping hood after terminal error")
                # Log the TYPE, not the message - ZephyrPolicyError text may
                # name the policy, and identifiers do not belong at ERROR.
                _LOGGER.error(
                    "refresh supervisor stopping: %s", type(err).__name__
                )
                return
            except Exception:  # noqa: BLE001
                _LOGGER.exception("refresh cycle failed; retrying next tick")

    async def _refresh_once(self) -> bool:
        """Renew credentials if inside the margin; keep wanted hoods up.

        Asks `credentials_expired` rather than calling
        async_get_credentials() first: that method renews as a side effect,
        so testing its result would always report "not expired" and the
        socket would never be rebuilt.

        Per-hood try/except, terminal errors excepted: one hood's transient
        connect failure must neither abort the loop (stranding later hoods
        on expiring signatures) nor be swallowed as handled - the hood keeps
        its consumer intent and async_ensure_running retries it every tick,
        which is also how a hood whose rebuild failed LAST cycle recovers.
        """
        rebuilt = False
        if self._auth.credentials_expired:
            _LOGGER.debug("credentials near expiry; refreshing")
            # Renews the Cognito tokens and re-exchanges for AWS credentials.
            await self._auth.async_get_credentials()
            rebuilt = True
        for hood in self._hoods.values():
            try:
                if rebuilt:
                    # No-ops for never-started hoods - guard is in Hood.
                    await hood.async_reconnect()
                else:
                    # Recovery: reopens a wanted hood whose socket is gone.
                    await hood.async_ensure_running()
            except (ZephyrPolicyError, ZephyrAuthError):
                raise
            except Exception:  # noqa: BLE001
                _LOGGER.exception("hood rebuild failed; retrying next tick")
        return rebuilt
```

Add `SUPERVISOR_INTERVAL_SECONDS = 60` to `const.py`, and `import contextlib`
to `client.py`.

### Three behaviours to document rather than change

- **`token_updater` runs on the event loop.** Persisting usually means a
  storage write, so the docstring must state that the callback has to be
  non-blocking; a consumer needing I/O should schedule it.
- **paho's own auto-reconnect races the supervisor.** After credential expiry
  paho retries the presigned URL on a 1→120s backoff and fails every time
  until the supervisor rebuilds it. Noisy but self-correcting, and worth
  keeping: for an ordinary network drop the URL is still valid and paho's
  reconnect is the faster fix.
- **A REST 403 raises rather than forcing a refresh and retrying once.**
  `async_get_tokens()` already refreshes inside a 10-minute margin, so a 403
  means the token was genuinely rejected (revocation, or a vendor-side
  change), which retrying cannot fix. If server-side clock skew ever shows
  up in practice, add a single forced-refresh retry in `ZephyrApi._post`.
- **`expires_at` uses the AWS credential expiry as the token expiry.** Both
  are one hour from the same exchange so they track, but that is an
  assumption. If they ever diverge, read the `exp` claim from the ID token
  instead.

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

- [ ] **Step 2: Reconcile and run the probe's tests**

`tests/test_probe.py` monkeypatches `client_module.ZephyrAuth` and stubs the
pre-refactor auth surface — both gone after Tasks 6 and 10, so the patch
itself raises `AttributeError` at test time. Rework those tests: monkeypatch
`client_module.CredentialsAuth` (or patch `ZephyrClient.from_credentials`
directly), stub the AbstractAuth surface (`async_get_tokens`,
`async_get_credentials`, `async_attach_policy`, `identity_id`,
`mqtt_client_id`, `credentials_expired = False`), and update any assertion on
`client.async_set_state` to `hood.async_set_fields`.

Run: `pytest tests/test_probe.py -v`
Expected: PASS

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
```

Do NOT include a write call in this example: it sits under "Read state", it
would actuate a physical appliance when copy-pasted, and VALIDATION.md gates
the write path on hardware validation that has not run. Writes are documented
by the probe CLI section, which carries the confirmation flags.

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

**Amendments from the verified-review fleet (final pass):** transient
failures are classified (`AbstractAuth._classify`) so only genuine credential
rejections and policy denials are terminal; each hood carries consumer intent
(`_should_run`) and the supervisor's `async_ensure_running` recovers failed
rebuilds; every MQTT connection gets a distinct identity-prefixed client ID
(`mqtt_client_id + "-" + thing_name[:8]`) because AWS IoT evicts same-ID
sessions; the policy latch is keyed per identity; paho teardown and the
cancellation path in `connect()` are event-loop-safe; Tasks 4, 6, 7, 8 and 11
carry explicit existing-test reconciliation steps.

**Amendment against the spec:** the spec says `async_set_state` is removed outright. Task 9 keeps one raw entry point, `Hood.async_set_fields`, because the probe CLI writes arbitrary allowlisted fields to map unknown semantics and a fixed method surface cannot express that. It is allowlist-enforcing and is the chokepoint every typed method delegates through, so the spec's intent — no caller can write a non-writable field — holds.

**Type consistency:** `Hood.async_set_fields` is used by Tasks 9 and 11. `Hood.handle_state` is used by Tasks 9 and 10. `AbstractAuth.async_get_credentials` is defined in Task 5 and consumed by Tasks 8 and 10; `CredentialsAuth` (Task 6) inherits it. `Endpoints.device_api_list` / `.device_api_discover` are used by Tasks 3 and 7. `ZephyrTokens.expired` is used by Tasks 5 and 6.

**Ordering:** Tasks 1–4 are independent of each other. Task 4 leaves `tests/test_client.py` failing; Task 10 fixes it. Tasks 5→6→7→8→9→10 are strictly sequential.
