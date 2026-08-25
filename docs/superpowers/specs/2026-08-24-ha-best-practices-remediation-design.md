# Design: align pyzephyrconnect with Home Assistant library best practices

Date: 2026-08-24
Status: approved, amended after three protocol/consumer review passes

## Context

A review against the three Home Assistant library documentation pages
(`api_lib_index`, `api_lib_auth`, `api_lib_data_models`) found the packaging
and release engineering already compliant, and the architecture divergent in
four ways that matter. This document specifies the corrections.

Nothing has been released: there are no git tags and PyPI returns 404 for
`pyzephyrconnect`. There is therefore no compatibility obligation. The API
gets to be correct rather than compatible, and this work lands as the
initial `0.1.0` rather than as a breaking `0.2.0`.

Sections 1, 3 and 4 were amended after a protocol-communication review; the
findings that forced each change are recorded under Risks.

## Scope

In scope:

1. Authentication restructured around an abstract auth surface with
   serializable, consumer-owned tokens.
2. Service endpoints made injectable instead of hardcoded module constants.
3. A `Hood` object that owns the write path, replacing raw-dict writes.
4. `HoodState` distinguishing "absent" from "zero".
5. Mechanical packaging and exception-hierarchy fixes.

Out of scope:

- The `VALIDATION.md` contradiction. That runbook forbids any consumer from
  writing to the shadow until hardware validation of the write path is
  complete, while this library exposes a write path today. That is a product
  decision, unrelated to these docs, and is tracked separately.
- Any change to `HoodState.raw` / `HoodCapabilities.raw`. They stay exactly
  as they are: they are the evidence channel for characterising unmodelled
  fields on hoods we have never seen, and the consumer's diagnostics output
  depends on them.
- Analysis or modification of the downstream Home Assistant integration. A
  separate agent owns that work; this repository's obligation is to describe
  the delta accurately.

## 1. Authentication

### Problem

`ZephyrAuth` holds the username and password for the process lifetime
(`auth.py:47`) and `ZephyrClient` takes them as constructor arguments
(`client.py:39`). The auth documentation says never to store authentication
data in the library. There is no seam for a consumer to supply or persist
tokens, so every process start performs a full SRP login. Refresh is a
separate consumer-driven call (`client.py:127`) rather than happening inside
the request path, and it is gated on the AWS credential expiry while the
REST path sends the Cognito ID token unchecked (`client.py:118`).

### Design

The protocol needs two credentials with different lifecycles:

- The Cognito **ID token**, sent bare (no `Bearer` prefix) to the vendor REST
  API. Refreshable from a Cognito refresh token. Worth persisting.
- The derived **AWS credentials**, used to SigV4-presign the MQTT WebSocket
  URL. Cheap to re-derive from a valid ID token, and bound to a live socket.
  Not worth persisting.

Only the first crosses the abstract boundary.

```python
@dataclass(frozen=True, slots=True)
class ZephyrTokens:
    """Consumer-persistable auth state. JSON-serializable primitives only."""

    username: str              # required: SECRET_HASH is derived from it
    id_token: str
    refresh_token: str
    identity_id: str
    expires_at: float          # epoch seconds, UTC

    def as_dict(self) -> dict[str, str | float]: ...

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ZephyrTokens: ...


class AbstractAuth(ABC):
    """Abstract class to supply valid Zephyr cloud tokens."""

    def __init__(self, session: aiohttp.ClientSession,
                 endpoints: Endpoints = DEFAULT_ENDPOINTS) -> None: ...

    @abstractmethod
    async def async_get_tokens(self) -> ZephyrTokens:
        """Return valid, unexpired tokens, refreshing if necessary."""


class CredentialsAuth(AbstractAuth):
    """Built-in implementation: SRP login, with refresh-token reuse."""

    def __init__(
        self,
        username: str,
        password: str,
        session: aiohttp.ClientSession,
        *,
        tokens: ZephyrTokens | None = None,
        token_updater: Callable[[ZephyrTokens], None] | None = None,
        endpoints: Endpoints = DEFAULT_ENDPOINTS,
    ) -> None: ...
```

`ZephyrTokens` carries `username` because Cognito's `SECRET_HASH` is
`HMAC-SHA256(client_secret, username + client_id)` — pycognito recomputes it
on every `REFRESH_TOKEN_AUTH` call, so tokens alone cannot drive a refresh.

`CredentialsAuth` performs a full SRP login only when it has no usable
refresh token. When `tokens` are supplied it reconstructs a `Cognito` object
via `Cognito(..., username=..., refresh_token=...)` and calls
`renew_access_token()`. A `NotAuthorizedException` from that call means the
refresh token has expired or been revoked; `CredentialsAuth` falls back to a
full SRP login rather than surfacing an error. Every successful refresh
invokes `token_updater` so the consumer can persist the new state.

`renew_access_token()` performs JWKS verification, which is a blocking
network call — it stays wrapped in `asyncio.to_thread`, as today.

Refresh is serialised by an `asyncio.Lock` with a re-check inside it. Token
freshness is checked on every REST request and by the supervisor, so an
expired token can be demanded by several callers at once, and the user pool
rate-limits repeated logins (`PROTOCOL.md` §3.1).

`credentials_expired` is a plain non-mutating property. The supervisor needs
to ask whether credentials want replacing without `async_get_credentials()`
renewing them as a side effect and making the answer always "no".

A consumer that does not want the library to see a password subclasses
`AbstractAuth` directly and implements `async_get_tokens()` however it likes.

### Identity ID restore

`identity_id` is persisted because it is the basis of the MQTT client ID and
the principal the IoT policy is attached to. It must be stored and replayed
verbatim, region prefix included.

A persisted `identity_id` that is stale or wrong makes
`get_credentials_for_identity` fail. On any such failure the cached value is
discarded, `get_id` is called again, and the exchange is retried once. Only a
second failure raises `ZephyrAuthError`.

A refetched identity is written back into the stored tokens and pushed to
`token_updater`. `mqtt_client_id` derives from it, so keeping the dead value
would pin the MQTT client ID to an identity the IoT policy does not cover —
the silent-drop failure, arrived at from the recovery path meant to prevent it.

### Refresh and the MQTT socket

Token freshness moves inside the REST request path: `ZephyrApi` calls
`await auth.async_get_tokens()` per request rather than receiving an
`id_token` argument, matching the documented `AbstractAuth.request()` shape.
The bare-token `Authorization` header and the zero-length request body for
`getowndevices` are unchanged.

That alone is **not sufficient** for the MQTT transport, which is authorised
by a SigV4 signature baked into the WebSocket URL at connect time. AWS IoT
drops a WebSocket session when its signing credentials expire, and paho would
then reconnect to the same now-invalid presigned URL indefinitely. The
library therefore owns the transport lifecycle rather than delegating it:

- `ShadowClient` takes a `credentials_provider: Callable[[], Awaitable[
  Credentials]]` instead of a one-shot `Credentials`, and re-presigns on
  every connect attempt.
- `ZephyrClient` runs a supervisor task that renews credentials and rebuilds
  each shadow socket inside `REFRESH_MARGIN_SECONDS` of expiry, then re-issues
  `request_state()`. Started by the first `Hood.async_start()`, cancelled and
  **awaited** by `ZephyrClient.async_stop()` — cancelling without awaiting can
  strand a hood halfway through a reconnect.
- Its retry boundary is inside the loop, not around it. A transient failure
  must not end supervision, because the consequence is not a logged error but
  push dying silently an hour later. Auth and policy errors are terminal, are
  stored, and are re-raised from the next `async_poll()` so they can reach a
  reauth flow.
- The supervisor distinguishes recoverable from terminal failures. A
  `ZephyrPolicyError` — a denied subscribe, meaning the IoT policy is not
  attached — is terminal: it is surfaced to the consumer and the supervisor
  stops rather than reconnecting forever. Transport errors back off and retry.
- Reconnects do not re-attach the IoT policy. Per `PROTOCOL.md` §3.3 the
  binding persists on the identity, so re-attaching is redundant work on a
  path that already has a latency budget.

`async_refresh_if_needed()` is deleted. There is no released version to keep
compatible, and the consumer should not have to remember to call it.

## 2. Injectable endpoints

Every host, pool and region is currently a module constant referenced
directly at call sites. The auth documentation requires that developers be
able to specify API locations.

```python
@dataclass(frozen=True, slots=True)
class Endpoints:
    region: str = REGION
    user_pool: str = USER_POOL
    client_id: str = CLIENT_ID
    client_secret: str = CLIENT_SECRET
    identity_pool: str = IDENTITY_POOL
    iot_endpoint: str = IOT_ENDPOINT
    device_api_base: str = DEVICE_API_BASE

    @property
    def provider(self) -> str: ...
    @property
    def device_api_list(self) -> str: ...
    @property
    def device_api_discover(self) -> str: ...


DEFAULT_ENDPOINTS = Endpoints()
```

`const.py` retains the raw values as the dataclass defaults. `Endpoints` lives
on the auth object and is read from there by everything else — `ZephyrClient`
takes no separate `endpoints` argument. A second source would let REST and
MQTT address different clouds with nothing complaining.

`ZephyrClient` must pass its endpoints explicitly when constructing each
`ShadowClient`. Omitting it falls back to `DEFAULT_ENDPOINTS`, which applies
an override to REST while silently leaving MQTT on production.

The TWCA supplementary trust anchors are unaffected: they are added on top of
the system trust store, so overriding `device_api_base` to a host with a
mainstream chain still verifies normally.

## 3. The `Hood` object

### Problem

Writes go through `client.async_set_state(thing_name, fields)` using raw
vendor field spellings, and the write allowlist (`const.WRITABLE_FIELDS`)
is enforced only in the probe CLI. The data-models documentation puts
control methods on the model object.

### Design

```python
class Hood:
    """One range hood: its capabilities, its state, and its controls."""

    @property
    def thing_name(self) -> str: ...
    @property
    def capabilities(self) -> HoodCapabilities: ...
    @property
    def state(self) -> HoodState | None: ...

    async def async_start(self) -> None: ...
    async def async_poll(self) -> HoodState: ...
    def add_listener(self, callback) -> Callable[[], None]: ...

    async def async_set_power(self, on: bool) -> None: ...
    async def async_set_light(self, level: int) -> None: ...
    async def async_set_fan(self, speed: int) -> None: ...
    async def async_set_clean_air(self, on: bool) -> None: ...
    async def async_set_delay_timer(self, seconds: int) -> None: ...

    # Destructive. Documented as such; logged at WARNING.
    async def async_set_recirculating(self, on: bool) -> None: ...
    async def async_reset_grease_filter(self) -> None: ...
```

The allowlist becomes structural: only these methods exist, so no caller can
write a field that is not writable. `WRITABLE_FIELDS` and `DANGEROUS_FIELDS`
remain in `const.py` for the probe CLI and as documentation of intent.

`async_set_light` and `async_set_fan` validate their argument against
`capabilities.max_light_level` / `max_fan_speed` and raise `ZephyrWriteError`
when out of range — but **only when the capability is a positive integer**.
Capabilities are absent on hoods we have not seen, and a missing maximum must
not become a blanket refusal to write. A negative argument is always
rejected.

The two destructive methods get no additional confirmation gate. The
consumer owns its own confirmation UX, and a second library-level gate would
be friction without safety.

One raw entry point survives: `Hood.async_set_fields(fields)` enforces
`WRITABLE_FIELDS` and is the chokepoint every typed method delegates through.
It exists because the probe CLI writes *arbitrary* allowlisted fields in order
to map semantics that are not yet established, which a fixed method surface
cannot express. The spec's intent holds — no caller can write a non-writable
field — while the diagnostic path keeps working.

Lifecycle and writes share a per-hood `asyncio.Lock`. The supervisor's rebuild
briefly has no socket, and a write landing in that window is not a
disconnected hood; it waits rather than raising. `async_start()` is idempotent
under the same lock, since overwriting a live `ShadowClient` orphans a paho
network thread.

The IoT policy is attached through a `prepare` callable each `Hood` runs
before its first connect, latched once per client. It cannot live in
`async_start()` unlatched: that now runs on every reconnect, and the binding
persists on the identity (`PROTOCOL.md` §3.3). It cannot be omitted at all —
without it every message is silently dropped.

`connected` is per-hood, derived rather than latched on the client. A single
flag reported whichever shadow changed state last.

`ZephyrClient.async_setup()` returns `list[Hood]` instead of
`list[HoodCapabilities]`. `ZephyrClient.async_set_state`,
`async_start(thing_name)`, `async_poll(thing_name)`, `state(thing_name)`,
`capabilities(thing_name)` and `add_listener(thing_name, cb)` are removed;
their behaviour moves onto `Hood`.

## 4. `HoodState`: absent is not zero

Every field currently defaults to `0`, and `as_int` coerces unparseable
values to `0` with a warning. A missing `alarmfaultcode` therefore reads as
"no fault" and a missing `power` reads as "off".

The rule: a field is `None` unless zero is a genuine reading.

`| None`: `power`, `light`, `fan`, `is_online`, `act`, `delay_timer`,
`set_delay_timer`, `set_recirculating`, `set_clean_air_function`,
`clean_grease_filters`, `clean_charcoal_filters`, `alarm_fan`,
`alarm_fault_code`, `alarm_grease_filter`, `fan_warning`, `fault_codes`.

Unchanged at `int = 0`: `use_grease_filter_time`, `use_charcoal_filter_time`,
`use_light_time`, `use_fan_time`. Zero is the real starting value for a new
filter, and the filter-life percentage requires a number.

Coercion failures continue to log at WARNING but now yield `None` rather
than `0`.

`merge()` is unaffected: it rebuilds from `{**self.raw, **delta}`, and `raw`
is unchanged.

### Capabilities

`HoodCapabilities.from_discover` distinguishes the two failure modes its
docstring already claims to distinguish:

- **Absent** field → `None`. Numeric capability fields become `int | None`.
- **Present but malformed** field → raise `ZephyrDataError`.

Absent must not raise. The class exists so that entity creation is gated on
capabilities rather than on a model string, which is what lets the library
generalise to hoods nobody has tested. A hood that omits
`maxCharcoalfilterTimer` must set up fine with no charcoal-filter feature,
not fail setup outright.

## 5. Mechanical fixes

- Declare `boto3` in `[project.dependencies]`. It is imported directly
  (`auth.py:15`) but resolves today only because `pycognito` requires it.
- Add `src/pyzephyrconnect/py.typed` and include it in the wheel.
- New exceptions: `ZephyrNotConnectedError` replaces the bare `RuntimeError`
  at `client.py:160`; `ZephyrWriteError` replaces the `ValueError` at
  `shadow.py:283` and carries allowlist and range violations;
  `ZephyrDataError` for capability parse failures. All subclass `ZephyrError`.
- PEP 639 license form (`license = "GPL-3.0-or-later"` plus `license-files`),
  plus `Programming Language` classifiers and a `Bug Tracker` project URL.
- `.github/ISSUE_TEMPLATE/` with a picker linking to Home Assistant Core, as
  the index page encourages.

## Testing

The existing suite fakes `aiohttp` in `tests/conftest.py` and touches no
network. That property is preserved.

New coverage:

- `ZephyrTokens` round-trips through `as_dict()`/`from_dict()`.
- `CredentialsAuth` performs SRP when given no tokens, refreshes when given
  valid ones, and falls back to SRP when refresh raises
  `NotAuthorizedException`.
- `token_updater` fires on every successful refresh.
- A stale `identity_id` is discarded and re-fetched once, then raises.
- `Endpoints` overrides reach the URL actually requested.
- The REST `Authorization` header stays a bare token with no `Bearer` prefix,
  and `getowndevices` still sends a zero-length body.
- The refresh supervisor rebuilds a shadow socket before expiry and re-issues
  `request_state()`.
- A `ZephyrPolicyError` stops the supervisor instead of looping.
- Each `Hood.async_set_*` publishes the expected shadow field; out-of-range
  values raise `ZephyrWriteError` before any publish; an absent capability
  maximum permits the write.
- `HoodState` yields `None` for absent and malformed fields, and `0` for the
  four counters.
- `HoodCapabilities` yields `None` for absent fields and raises
  `ZephyrDataError` for malformed ones.
- `AbstractAuth` cannot be instantiated directly.

## Release

Land the work, then tag `v0.1.0` as the first release. The consumer switches
its requirement pin from a moving `git+…@main` to the tag.

## Risks

Findings from the protocol-communication review of this design. The first
four changed the design above; the rest are constraints implementation must
respect.

1. **Deleting `async_refresh_if_needed()` would have broken push after one
   hour.** The presigned WebSocket URL embeds a SigV4 signature over
   credentials that expire in 1 hour. AWS IoT drops the session at expiry and
   paho retries the same stale URL forever, so push would die silently and
   never recover. Moving refresh into the REST request path does not touch
   this. Resolved by the library-owned supervisor and the
   `credentials_provider` callable in §1.
2. **`ZephyrTokens` could not have driven a refresh.** Cognito's
   `SECRET_HASH` is `HMAC-SHA256(client_secret, username + client_id)`, and
   pycognito recomputes it on every `REFRESH_TOKEN_AUTH` call from
   `self.username`. Tokens without a username are unusable. Resolved by
   adding `username` to `ZephyrTokens`.
3. **A persisted `identity_id` is a new failure surface.** It survives
   restarts, so a wrong value becomes permanent rather than transient, and it
   determines both the MQTT client ID and the IoT policy principal. Resolved
   by the discard-and-refetch fallback in §1.
4. **Raising on absent capability fields would break unseen hoods.**
   `from_discover` raising on a missing `maxCharcoalfilterTimer` would fail
   setup for any model that omits it, defeating the reason the class exists.
   Resolved by absent → `None`, malformed → raise, in §4.
5. **A denied subscribe closes the whole connection.** Per `PROTOCOL.md` §6,
   AWS IoT closes the connection on a refused subscribe, so subsequent
   subscribes on that socket time out rather than failing individually. Any
   automatic reconnect must treat `ZephyrPolicyError` as terminal — this is
   why the supervisor stops on it.
6. **The MQTT client ID must remain `identity_id + "-ha"`.** The policy pins
   the client ID to the identity, and the suffix is what lets the library
   coexist with the phone app instead of evicting it. The region prefix must
   never be stripped.
7. **The write path stays `state.reported`.** This is backwards from the AWS
   shadow convention but is what the hardware acts on; `state.desired` writes
   are accepted by AWS and silently ignored by the device. `Hood.async_set_*`
   must route through the existing `ShadowClient.publish_state`.
8. **`update/delta` stays ignored.** Nothing writes `state.desired`, so any
   delta is stale or foreign and merging one produces a phantom state change.
9. **The REST contract is exact.** Bare ID token with no `Bearer` prefix, and
   a zero-length body for `getowndevices` — not `{}`. Both are easy to break
   while refactoring `ZephyrApi` onto `AbstractAuth`.
10. **Every SSL context must be built off the event loop.** Home Assistant
    instruments `SSLContext.load_default_certs` and `load_verify_locations`
    and reports them when they run on the loop. Two paths hit this: the
    library's own `build_ssl_context()`, and paho's `tls_set()`, which
    constructs a context inline on the calling thread. Both build in a worker
    thread; the MQTT path uses `tls_set_context()` with a finished context.
11. **The MQTT path uses plain system trust, not the TWCA bundle.** The IoT
    ATS endpoint chains to Amazon Root CA 1. Only the vendor REST host needs
    the supplementary anchors.
12. **Endpoint overrides do not weaken TLS.** The TWCA certificates are
    supplementary anchors on top of the system store, so a redirected host
    verifies against normal system trust. `verify_mode` stays `CERT_REQUIRED`.
