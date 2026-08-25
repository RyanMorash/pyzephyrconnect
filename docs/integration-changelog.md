# pyzephyrconnect API changes — for the Home Assistant integration

**Audience:** the agent maintaining `ha_zephyr` (`custom_components/zephyr_connect`).

**Status of the library:** `pyzephyrconnect` has never been released. There are
no tags and PyPI 404s. These changes therefore land as the initial `0.1.0`,
not as a breaking `0.2.0` — there is no previous version to fall back to, no
version gate to write, and no compatibility shim to detect. Every change below
is unconditional.

**First step:** the integration currently requires
`pyzephyrconnect @ git+https://github.com/RyanMorash/pyzephyrconnect@main`.
Once this work lands and `v0.1.0` is tagged, pin the tag rather than tracking
a moving branch:

```json
"requirements": ["pyzephyrconnect @ git+https://github.com/RyanMorash/pyzephyrconnect@v0.1.0"]
```

---

## Why this changed

The library was reviewed against Home Assistant's three library-authoring
pages (`api_lib_index`, `api_lib_auth`, `api_lib_data_models`). Packaging and
release engineering already complied. Four architectural things did not:

1. The library held the username and password for the process lifetime and
   re-ran a full SRP login on every restart. The auth page says never to store
   auth data in the library.
2. Every endpoint was a hardcoded module constant. The auth page requires that
   developers be able to specify API locations.
3. Writes went through a raw dict of vendor field names, with the write
   allowlist enforced only in a CLI. The data-models page puts control methods
   on the model object.
4. Every state field defaulted to `0`, so a missing alarm read as "no alarm"
   and a missing power reading read as "off".

---

## 1. Client construction

`ZephyrClient` no longer takes credentials directly.

```python
# before
client = ZephyrClient(username, password, session)

# after
client = ZephyrClient.from_credentials(username, password, session)
```

### Token persistence (new capability)

The library no longer persists credentials itself (the built-in
`CredentialsAuth` still holds them in memory for the refresh fallback;
subclass `AbstractAuth` to keep the password out of the library entirely),
and it can now skip the SRP login entirely on restart if you hand it tokens
from a previous session:

```python
from pyzephyrconnect import ZephyrClient, ZephyrTokens

client = ZephyrClient.from_credentials(
    username,
    password,
    session,
    tokens=ZephyrTokens.from_dict(saved) if saved else None,
    token_updater=save,          # called with a ZephyrTokens on every refresh
)
```

`saved` is whatever `as_dict()` produced last time, and `save` is however you
choose to persist it. Where that lives is your call — see the warning below
before deciding.

`ZephyrTokens.as_dict()` returns JSON-serializable primitives only, so it is
safe to store in a config entry. It carries `username`, `id_token`,
`refresh_token`, `identity_id` and `expires_at` (epoch seconds).

Notes:

- The `username` field is not optional. Cognito's `SECRET_HASH` is
  `HMAC-SHA256(client_secret, username + client_id)`, recomputed on every
  refresh — tokens without it cannot be refreshed.
- A rejected or expired refresh token falls back to a full SRP login
  automatically. It does not raise.
- **`ZephyrTokens.from_dict()` raises `ZephyrDataError` on malformed stored
  data** — a missing field, a non-string field, an empty string, or an
  expiry that is not a finite number. It validates rather than coercing,
  because a corrupted value that survives here fails much later and far
  away: as a `SECRET_HASH` Cognito rejects, or as an MQTT client ID whose
  messages AWS IoT silently drops. The correct response is to discard the
  stored record and pass `tokens=None`, which falls back to a full SRP
  login — not to abort setup:

  ```python
  from pyzephyrconnect import ZephyrDataError

  try:
      tokens = ZephyrTokens.from_dict(saved) if saved else None
  except ZephyrDataError:
      tokens = None          # discard the record; a fresh login rebuilds it
  ```
- If you would rather the library never saw the password at all, subclass
  `AbstractAuth`, implement `async_get_tokens()`, and pass the instance to
  `ZephyrClient(auth)` directly.

> ### Redact the tokens in diagnostics before shipping persistence
>
> `ZephyrTokens.as_dict()` contains `id_token` and `refresh_token`. A Cognito
> refresh token is valid for around 30 days by default and is on its own
> sufficient to take over the account.
>
> Two things to know:
>
> - `async_redact_data` matches on **key names, at every depth**. It recurses
>   into nested mappings and into lists of them, so naming `id_token` and
>   `refresh_token` in the redaction set reaches them however deeply they are
>   stored, and naming the container key redacts the whole sub-dict. What it
>   cannot do is recognise a token by its *value*: anything stored under a key
>   name that is not in the set — a renamed field, or a bare string in a list —
>   passes through in full. It also returns a redacted **copy**, so the return
>   value is what must be emitted.
> - Config entries are stored as plain JSON in `.storage/core.config_entries`.
>
> So wherever these tokens are persisted, the redaction list needs to name the
> keys they are actually stored under — the individual keys (`id_token`,
> `refresh_token`) or their container. Diagnostics output is meant to be safe
> to paste into a public issue, so this belongs in the same change that
> introduces persistence, not a follow-up.
>
> `identity_id` is worth redacting too. It is not a credential, but it is a
> stable account identifier in the same category as a serial number or MAC.
>
> Persistence is optional. `from_credentials` works without `tokens` and
> `token_updater` and simply re-runs the SRP login on each restart, which
> avoids introducing a second live credential entirely.

### `identity_id` is unchanged, and is the right config entry unique ID

`client.identity_id` still returns the full `us-west-2:uuid` string.

It is a sound permanent unique ID for the account's config entry. Cognito
Identity Pools key an identity on the *provider's* user identifier, which for
a User Pool provider is the immutable `sub` claim — not the email, not the
password. So it survives a password change, survives an email change, is
idempotent across `get_id` calls, and does not change on token refresh. It is
also the right granularity for an account-level entry: one account can own
several hoods, so `thingName` identifies a device rather than the account, and
the email address is both mutable and personal data.

The one theoretical failure is the vendor recreating their identity pool,
which would reissue every user's ID. Not worth designing around: the IoT
policy attachments are keyed on identity IDs too, so that event breaks the
integration outright and a churned unique ID is the least of it.

`identity_id` is now read directly off the auth object rather than
reconstructed by stripping the `-ha` suffix off the MQTT client ID. Availability
is unchanged — it raises `ZephyrAuthError` until tokens have been acquired, and
`async_setup()` acquires them, so the existing config-flow ordering still works.

---

## 2. `async_setup()` returns `Hood` objects

```python
# before
capabilities: list[HoodCapabilities] = await client.async_setup()

# after
hoods: list[Hood] = await client.async_setup()
```

`Hood` bundles capabilities, state, lifecycle and controls for one appliance.
`hood.capabilities` is the same `HoodCapabilities` object you had before.

### Per-thing client methods moved onto `Hood`

Every method that took a `thing_name` is gone; the `Hood` knows its own.

| Removed from `ZephyrClient` | Replacement |
|---|---|
| `client.async_start(thing_name)` | `hood.async_start()` |
| `client.async_poll(thing_name)` | `hood.async_poll()` |
| `client.state(thing_name)` | `hood.state` |
| `client.capabilities(thing_name)` | `hood.capabilities` |
| `client.add_listener(thing_name, cb)` | `hood.add_listener(cb)` |
| `client.async_set_state(thing_name, fields)` | typed methods — see §3 |

`hood.add_listener(cb)` still returns an unsubscribe callable, and the
callback still receives a `HoodState` on the event loop (never from paho's
network thread).

New: `hood.connected` — whether **this** hood's push connection is up. Use it
for per-device availability. `client.connected` still exists but is now
derived: `True` while at least one hood's connection is up, so on a
multi-hood account it is an aggregate, not a per-device signal.

Unchanged on `ZephyrClient`: `async_setup()`, `async_stop()`, `identity_id`.
(`connected` remains but with derived semantics — see above. `async_setup()`
may only run once per client; build a new client to re-discover.)

---

## 3. Writes are typed methods now

`async_set_state` is gone. Vendor field spellings no longer appear in consumer
code.

| Before | After |
|---|---|
| `async_set_state(thing, {"power": 1})` | `await hood.async_set_power(True)` |
| `async_set_state(thing, {"power": 0})` | `await hood.async_set_power(False)` |
| `async_set_state(thing, {"light": n})` | `await hood.async_set_light(n)` |
| `async_set_state(thing, {"fan": n})` | `await hood.async_set_fan(n)` |
| `async_set_state(thing, {"setcleanairfunction": 1})` | `await hood.async_set_clean_air(True)` |
| `async_set_state(thing, {"setcleanairfunction": 0})` | `await hood.async_set_clean_air(False)` |
| `async_set_state(thing, {"setdelaytimer": n})` | `await hood.async_set_delay_timer(n)` |
| `async_set_state(thing, {"resetgreasefilter": 1})` | `await hood.async_reset_grease_filter()` |
| `async_set_state(thing, {"setrecirculating": n})` | `await hood.async_set_recirculating(bool)` |

`async_set_delay_timer` passes its value straight through to `setdelaytimer`.
**The field's units are not established** — whether the device reads seconds
or minutes, and whether it snaps to presets, is an open hardware-validation
question (the library's `VALIDATION.md`, question 2). Do not present a
unit to users until that validation has run.

### New: range validation

`async_set_light` and `async_set_fan` now validate against the hood's own
advertised maximums and raise `ZephyrWriteError` **before publishing**
anything. Negative values are always rejected. If a hood does not advertise a
maximum (some models omit the key), the write is permitted rather than
blanket-refused.

This means a bad value now surfaces as an exception instead of a silent no-op
on hardware.

### Escape hatch

`hood.async_set_fields({field: value})` writes arbitrary fields from
`const.WRITABLE_FIELDS` and raises `ZephyrWriteError` for anything else. It
exists for the diagnostic probe CLI, which maps unknown field semantics. The
integration should use the typed methods.

---

## 4. `async_refresh_if_needed()` is gone — do not replace it

The library now supervises its own credential lifecycle. Delete the call; do
not substitute anything for it.

Why this mattered: the MQTT connection is a WebSocket whose URL embeds a SigV4
signature over credentials that expire in one hour. AWS IoT drops the session
at expiry, and paho then reconnects to the same now-invalid URL indefinitely.
Keeping that alive was previously the consumer's job via
`async_refresh_if_needed()`. It is now a supervisor task inside `ZephyrClient`
that renews credentials and rebuilds each hood's socket before expiry, started
by the first `hood.async_start()` **attempt** and cancelled by
`client.async_stop()`.

Its lifecycle is self-correcting at both ends. A `hood.async_start()` that
raises rolls that hood's intent back, so it leaves nothing armed behind it,
and a supervisor that finds no started hoods on a tick retires itself rather
than holding the client alive and refreshing credentials for nobody. A later
`hood.async_start()` arms a fresh one. Still wire the teardown up before you
start any hood — `entry.async_on_unload(client.async_stop)` or equivalent —
as belt and braces: it is the only thing that reliably retires a supervisor
mid-tick, and it stops every hood in one call.

**What this means for you:** keeping credentials alive is no longer a reason
for a consumer to poll on a timer. If a periodic tick is still wanted for
other reasons — a safety-net re-read after push has been briefly unhealthy, or
degraded HTTPS reads while MQTT is down — `hood.async_poll()` and
`client.connected` both still exist for that.

A terminal failure inside the supervisor stops it, disconnects the hoods
(flipping `connected` to `False`), and re-raises from the next
`hood.async_poll()` — the intended path to a reauth flow, so a consumer that
never polls will not learn about it. **Only genuine credential rejections
(`ZephyrAuthError`) and a missing IoT policy (`ZephyrPolicyError`) are
terminal.** Transient failures — DNS, timeouts, Cognito throttling — surface
as the retryable `ZephyrTransportError` and the supervisor keeps going, so
mapping `ZephyrAuthError` to a reauth prompt is safe: it will not fire for a
Wi-Fi blip. The supervisor also self-heals: a hood whose reconnect failed
transiently is retried every tick until it comes back.

---

## 5. Absent is no longer zero

This is the change most likely to alter entity behaviour.

### `HoodState`

These fields are now `| None`, and are `None` when the device did not report
them or reported something unparseable:

`power`, `light`, `fan`, `is_online`, `act`, `delay_timer`, `set_delay_timer`,
`set_recirculating`, `set_clean_air_function`, `clean_grease_filters`,
`clean_charcoal_filters`, `alarm_fan`, `alarm_fault_code`,
`alarm_grease_filter`, `fan_warning`, `fault_codes`.

These four are **unchanged** and still default to `0`, because zero is their
genuine starting value and the filter-life percentage needs a number:

`use_grease_filter_time`, `use_charcoal_filter_time`, `use_light_time`,
`use_fan_time`.

**Watch for boolean coercion.** `bool(None)` is `False`, so any
`bool(state.alarm_fault_code)` or `state.alarm_fan or state.fan_warning`
expression will silently continue to report "no problem" for a field that is
actually unknown. That is the exact failure this change exists to eliminate,
so those need to become explicit — returning `None` from an `is_on` property
makes Home Assistant show the entity as unknown, which is usually what you
want for a fault sensor with no data.

### `HoodCapabilities`

The numeric capability fields are now `int | None`:
`max_fan_speed`, `max_light_level`, `max_grease_filter_hours`,
`max_charcoal_filter_hours`.

- **Absent** → `None`. Not an error. Other Zephyr models legitimately omit
  keys the reference device returns, and gating entity creation on
  capabilities is what lets this work on untested hoods.
- **Present but malformed** → raises the new `ZephyrDataError`. This runs once
  at setup, so it fails loudly rather than producing a wrong capability set.

Any comparison against these values needs a `None` check first —
`None > 0` raises `TypeError` rather than evaluating falsy.

String fields (`model`, `serial`, `mac`, `manufacturer`, warranties) still
default to `""`, and the `supports_*` booleans still default to `False` —
absent means "not advertised", which is the correct reading for a feature flag.

### `raw` is unchanged

`HoodState.raw` and `HoodCapabilities.raw` keep exactly their current shape and
contents. Anything reading them needs no change.

---

## 6. New exceptions

All three subclass `ZephyrError`, so a handler catching `ZephyrError` catches
them.

| Exception | Raised when |
|---|---|
| `ZephyrNotConnectedError` | A write (or any other publish-path operation) was attempted without a live shadow connection |
| `ZephyrWriteError` | A field is not writable, a value is out of range, or the payload is empty |
| `ZephyrDataError` | A capability field was present but unparseable, or `ZephyrTokens.from_dict()` was handed a malformed record |

**Note the first one.** `client.async_set_state` previously raised a bare
`RuntimeError` when called before the shadow connection for that thing was
open. `RuntimeError` is not a `ZephyrError`, so any handler catching
`ZephyrError` around a write would have let it escape. It is now
`ZephyrNotConnectedError` and is caught by a `ZephyrError` handler.

It is a **write-path** error, not a read one: reads never raise it. `hood.state`
returns the cached state or `None`, and `hood.async_poll()` reads over HTTPS and
works whether or not MQTT is up. A write raises it when the hood was never
started, was stopped, or a rebuild failed — and now also when the connection is
found dead at the moment of publishing, in which case the library tears the
connection down so the refused write cannot be delivered later by paho's own
reconnect. Treat it as "try again once `hood.connected` is `True`".

Unchanged: `ZephyrError`, `ZephyrAuthError`, `ZephyrCertificateError`,
`ZephyrPolicyError`, `ZephyrTransportError`.

---

## 7. Smaller things

- **`py.typed` is now shipped.** The library was already fully annotated but
  was invisible to type checkers under PEP 561. mypy will now actually check
  integration code against these signatures — expect it to surface the `None`
  handling from §5 for you.
- **`boto3` is now a declared dependency.** It was always imported directly
  and resolved only transitively through `pycognito`. No action needed.
- **Endpoints are injectable.** `ZephyrClient.from_credentials(...,
  endpoints=Endpoints(device_api_base="https://staging.example/prod"))`. The
  defaults are the current production values, so omitting it changes nothing.
  Useful for tests that would otherwise monkeypatch module globals.

---

## Protocol invariants — unchanged, and load-bearing

None of these changed, but they are easy to break accidentally and each one
fails silently rather than loudly:

- Shadow writes go to `state.reported`, never `state.desired`. AWS accepts a
  `desired` write and the hardware ignores it.
- `update/delta` messages are ignored by the library. Nothing writes
  `desired`, so any delta is stale or foreign, and merging one produces a
  phantom state change.
- Every MQTT client ID starts with `identity_id + "-ha"` (region prefix
  included) — that prefix is what lets this coexist with the vendor phone app
  instead of evicting it — and each hood's connection appends a per-device
  suffix, because AWS IoT evicts concurrent same-ID sessions.
- The IoT policy is attached before connecting. An open connection does not
  pick up newly attached permissions; without it, connect/subscribe/publish
  all succeed and every message is silently dropped.
- The vendor REST API takes a bare ID token with no `Bearer ` prefix.
- `thingName`, `SN`, `MAC` and `location` are personal data — `location`
  carries precise coordinates. Keep them redacted in diagnostics and out of
  logs.

## Still open, unrelated to this change

The library's own `VALIDATION.md` runbook states that the shadow write path is
unverified and that no consumer should write to it until hardware validation
is complete. That validation has not happened yet.

The write API described in §3 exists and works, but the *semantics* of several
fields are still unestablished — `PROTOCOL.md` §7 lists what remains. Notably,
whether `power` gates the light and fan, whether `setdelaytimer` accepts
arbitrary values or snaps to presets, and the units of the `use*time` counters.
Those three answers materially affect what entities should exist.

This is a product decision rather than an API one and is out of scope for this
changelog, but it is worth resolving deliberately rather than by default.
