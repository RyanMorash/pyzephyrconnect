# pyzephyrconnect 0.1.0 — API notes

**Audience:** anyone writing against the library.

`pyzephyrconnect` has never been released. There are no earlier tags and PyPI
404s, so `0.1.0` is the initial public API rather than a break from a previous
one — there is no version to fall back to, no version gate to write, and no
compatibility shim to detect. If you tracked the `main` branch before the tag,
read the sections below as the deltas from that shape. If you are starting at
`0.1.0`, read them as a description of what the API does and why.

Pin the tag rather than tracking a moving branch:

```
pyzephyrconnect @ git+https://github.com/RyanMorash/pyzephyrconnect@v0.1.0
```

---

## Why the API looks like this

Four rules shaped it, each replacing something the pre-tag shape did:

1. **The library does not store credentials.** It used to hold the username
   and password for the process lifetime and re-run a full SRP login on every
   restart. Auth now sits behind an abstract token surface, and where tokens
   live is the consumer's decision.
2. **Endpoints are injectable.** Every endpoint used to be a hardcoded module
   constant, which put staging and test targets out of reach without
   monkeypatching module globals.
3. **Controls are typed methods on the model object.** Writes used to go
   through a raw dict of vendor field names, with the write allowlist enforced
   only in the CLI.
4. **Absent is not zero.** Every state field used to default to `0`, so a
   missing alarm read as "no alarm" and a missing power reading read as "off".

These are general library-design rules, not house style for any one consumer;
they came out of a review against Home Assistant's library-authoring guidance,
which is where the library's first consumer lives.

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

`ZephyrTokens.as_dict()` returns JSON-serializable primitives only, so it will
survive any ordinary JSON store. It carries `username`, `id_token`,
`refresh_token`, `identity_id` and `expires_at` (epoch seconds).

Notes:

- The `username` field is not optional. Cognito's `SECRET_HASH` is
  `HMAC-SHA256(client_secret, username + client_id)`, recomputed on every
  refresh — tokens without it cannot be refreshed.
- A rejected or expired refresh token falls back to a full SRP login
  automatically. It does not raise.
- `token_updater` runs on the event loop, so it must not block. A consumer
  that needs real I/O to persist should schedule it rather than perform it
  inline.
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

> ### Treat persisted tokens as credentials
>
> `ZephyrTokens.as_dict()` contains `id_token` and `refresh_token`. A Cognito
> refresh token is valid for around 30 days by default and is on its own
> sufficient to take over the account.
>
> Two consequences worth planning for:
>
> - Whatever you persist that record into becomes a credential store, whether
>   or not it was designed as one. Most application state stores are plain
>   files readable by anything running as the same user.
> - Anything that exports or copies that record — a diagnostic dump, a bug
>   report attachment, a debug log — carries the tokens with it unless it
>   strips them by key name. `identity_id` is worth stripping too: not a
>   credential, but a stable account identifier in the same category as a
>   serial number or MAC.
>
> The library keeps them out of its own output: `ZephyrTokens` sets
> `repr=False` on both token fields, so they do not land in tracebacks or log
> lines that happen to capture the object. That protects the library's
> surface, not yours.
>
> Persistence is optional. `from_credentials` works without `tokens` and
> `token_updater` and simply re-runs the SRP login on each restart, which
> avoids introducing a second long-lived credential entirely.

### `identity_id` is unchanged, and is a stable account identifier

`client.identity_id` still returns the full `us-west-2:uuid` string.

It is durable enough to key an account on permanently. Cognito Identity Pools
key an identity on the *provider's* user identifier, which for a User Pool
provider is the immutable `sub` claim — not the email, not the password. So it
survives a password change, survives an email change, is idempotent across
`get_id` calls, and does not change on token refresh. It is also
account-level rather than device-level: one account can own several hoods, so
`thingName` identifies a device while `identity_id` identifies the account,
and the email address is both mutable and personal data.

The one theoretical failure is the vendor recreating their identity pool,
which would reissue every user's ID. Not worth designing around: the IoT
policy attachments are keyed on identity IDs too, so that event breaks every
client outright and a churned identifier is the least of it.

`identity_id` is now read directly off the auth object rather than
reconstructed by stripping the suffix off the MQTT client ID. Availability is
unchanged — it raises `ZephyrAuthError` until tokens have been acquired, and
`async_setup()` acquires them.

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

New: `hood.connected` — whether **this** hood's push connection is up, which
is the per-device signal. `client.connected` still exists but is now derived:
`True` while at least one hood's connection is up, so on a multi-hood account
it is an aggregate rather than a per-device answer.

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
**The units are seconds**, established against the reference hood and recorded
in `PROTOCOL.md` §5. Values off the vendor app's two presets are accepted,
proven up to 3600 seconds; past that the device's own ceiling is unprobed
(`PROTOCOL.md` §7), so a larger value may be clamped or rejected by the
hardware rather than by this method. A caller working in minutes multiplies
by 60.

`power` is a master switch with memory rather than a precondition: `fan` and
`light` write through while `power` reads `0`, and the device raises `power`
itself. So `async_set_fan` and `async_set_light` deliberately do not write
`power` alongside the level.

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
exists for the diagnostic probe CLI, which maps unknown field semantics.
Prefer the typed methods everywhere else.

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
`hood.async_start()` arms a fresh one. Still wire teardown up before you start
any hood, so that `client.async_stop()` runs however the consumer shuts down:
it is the only thing that reliably retires a supervisor mid-tick, and it stops
every hood in one call.

**What this means for you:** keeping credentials alive is no longer a reason
to poll on a timer. If a periodic tick is still wanted for other reasons — a
safety-net re-read after push has been briefly unhealthy, or degraded HTTPS
reads while MQTT is down — `hood.async_poll()` and `client.connected` both
still exist for that.

A terminal failure inside the supervisor stops it, disconnects the hoods
(flipping `connected` to `False`), and re-raises from the next
`hood.async_poll()` — the intended path for surfacing a re-authentication
requirement, so a consumer that never polls will not learn about it. **Only
genuine credential rejections (`ZephyrAuthError`) and a missing IoT policy
(`ZephyrPolicyError`) are terminal.** Transient failures — DNS, timeouts,
Cognito throttling — surface as the retryable `ZephyrTransportError` and the
supervisor keeps going, so treating `ZephyrAuthError` as "this account must
log in again" is safe: it will not fire for a Wi-Fi blip. The supervisor also
self-heals: a hood whose reconnect failed transiently is retried every tick
until it comes back.

---

## 5. Absent is no longer zero

This is the change most likely to alter observable behaviour.

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

**Watch for boolean coercion.** `bool(None)` is `False`, so
`bool(state.alarm_fault_code)` or `state.alarm_fan or state.fan_warning`
silently keeps reporting "no problem" for a field that is actually unknown.
That is the exact failure this change exists to eliminate, so those tests need
to become explicit. What you then do with "unknown" — surface it, or fold it
back into a default — is your call; the library's job is to keep the
distinction available rather than to decide it for you.

### `HoodCapabilities`

The numeric capability fields are now `int | None`:
`max_fan_speed`, `max_light_level`, `max_grease_filter_hours`,
`max_charcoal_filter_hours`.

- **Absent** → `None`. Not an error. Other Zephyr models legitimately omit
  keys the reference device returns, and gating on capabilities rather than
  assuming them is what lets a consumer work on untested hoods.
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
  was invisible to type checkers under PEP 561. A type checker will now
  actually check calling code against these signatures — expect it to surface
  the `None` handling from §5 for you.
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
- Every MQTT client ID starts with `identity_id + const.CLIENT_ID_SUFFIX`
  (region prefix included) — a suffix on the bare identity ID is what lets
  this coexist with the vendor phone app instead of evicting it — and each
  hood's connection appends a per-device suffix on top, because AWS IoT
  evicts concurrent same-ID sessions.
- The IoT policy is attached before connecting. An open connection does not
  pick up newly attached permissions; without it, connect/subscribe/publish
  all succeed and every message is silently dropped.
- The vendor REST API takes a bare ID token with no `Bearer ` prefix.
- `thingName`, `SN`, `MAC` and `location` are personal data — `location`
  carries precise coordinates. Keep them out of logs and out of anything you
  export.

## Still open

The `VALIDATION.md` runbook has since been run against the reference hood
(`AK7400AS`), so the questions that used to sit here are answered: `power`
does not gate the light and fan, `setdelaytimer` takes seconds and is not
preset-snapped, the filter counters are minutes against a maximum in hours,
and `usefantime` / `uselighttime` are hours. All of it is recorded in
`PROTOCOL.md` §5.

What is genuinely still unknown is listed in `PROTOCOL.md` §7 — the
`setdelaytimer` ceiling, `act` values beyond `"Disabled"`, whether a
charcoal-filter reset exists at all, and what distinguishes `fanwarning` from
`alarmfan`. None of it changes the API described here, but each one bounds
what a consumer can honestly present.

Writes actuate hardware throughout. `resetgreasefilter` in particular zeroes a
counter that cannot be reconstructed, and ships untested by design.
