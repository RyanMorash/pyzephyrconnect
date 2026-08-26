# Zephyr / Gemtek range hood — protocol notes

Reverse-engineered from the iOS app (running on macOS), its bundled
`awsconfiguration.json`, Mach-O string dump, and Proxyman capture.
Verified working end to end against a real device (model `AK7400AS`).

All device identifiers in this document (thing name, serial, MAC,
coordinates, identity ID) are placeholders, not real values.

Both the read and write paths are covered; the write path actuates
hardware and is marked as such where it appears (§5, §7).

---

## 1. Architecture

The device does not expose a local API. All communication is cloud
round-trip through AWS IoT Core:

```
client ──SRP──> Cognito User Pool      (identity)
       ──────> Cognito Identity Pool  (temporary AWS credentials)
       ──────> iot:AttachPolicy       (grant MQTT topic access)
       ──────> vendor REST API        (thing name lookup)
       ──wss──> AWS IoT Core          (device shadow get / subscribe)
                     └──> device
```

Device state lives entirely in the **AWS IoT classic device shadow**.
There are no custom telemetry or command topics — a string dump of the
app binary produced only `$aws/things/%@/shadow/*` formats. Reads and
writes are both shadow operations.

## 2. Constants

| Key | Value |
|---|---|
| Region | `us-west-2` |
| User Pool ID | `us-west-2_McuoKpkna` |
| App Client ID | `5a2qiskdvvu7gre1jvbjnunu20` |
| App Client Secret | *(in `awsconfiguration.json`; mirrored in `const.py`, required for SRP)* |
| Identity Pool ID | `us-west-2:fb4c1b66-12c2-414b-83a1-a1902f7d98e3` |
| IoT ATS endpoint | `a1nqxu0hki9zw3-ats.iot.us-west-2.amazonaws.com` |
| IoT policy name | `RangeHoodPolicy` |
| Device API | `https://zephyr-prod-app.gemteks.com/prod/getowndevices` |
| Vendor AWS account | `527656002764` |
| Assumed role | `Cognito_ZephyrAuth_Role` |

The app client has a **secret**, which is unusual for a public client —
Amplify emitted it because the vendor ticked "generate client secret".
It ships inside the app bundle, so it is not a secret in any meaningful
sense, but SRP will fail without it (it is needed for `SECRET_HASH`).

These vendor constants are committed deliberately — they ship in the app
bundle and gate nothing. What must never be committed is the account side:
your email, password, Cognito tokens, `identityId`, or any real
`thingName`/`SN`/`MAC`/`location` from §4.

## 3. Auth chain

### 3.1 User Pool — SRP

`USER_PASSWORD_AUTH` is not enabled on this app client; SRP is required.
`pycognito` handles both SRP and the secret hash:

```python
u = Cognito(USER_POOL, CLIENT_ID, client_secret=SECRET,
            username=EMAIL, user_pool_region=REGION)
u.authenticate(password=PASSWORD)
id_token = u.id_token
```

Pass `user_pool_region` explicitly — pycognito otherwise falls back to
ambient AWS config and throws a confusing `ResourceNotFoundException`.

Tokens are valid **1 hour**. Keep the `Cognito` object and call
`renew_access_token()` rather than re-running SRP (multiple round trips,
and the pool may rate-limit).

The ID token contains **no device information** — no `custom:` claims,
access token scope is the stock `aws.cognito.signin.user.admin`. Thing
names must come from the REST API (§4).

### 3.2 Identity Pool — AWS credentials

Both calls are unsigned (`signature_version=UNSIGNED`):

```python
logins = {f"cognito-idp.{REGION}.amazonaws.com/{USER_POOL}": id_token}
iid   = ci.get_id(IdentityPoolId=ID_POOL, Logins=logins)["IdentityId"]
creds = ci.get_credentials_for_identity(IdentityId=iid, Logins=logins)["Credentials"]
```

Gotchas:
- The response key is **`SecretKey`**, not `SecretAccessKey` (differs
  from STS).
- Credentials expire in **1 hour**, in step with the Cognito tokens.
- `IdentityId` is the full `us-west-2:uuid` string, region prefix
  included. This is what `${cognito-identity.amazonaws.com:sub}`
  resolves to in the IoT policy, and it is the correct MQTT client ID.
  Do **not** strip the region prefix.

### 3.3 AttachPolicy — the step that is easy to miss

**This is mandatory and has no error path if skipped.**

The IAM role governs whether you can connect and publish. Delivery of
subscribed messages is evaluated against an **AWS IoT policy attached to
the Cognito identity principal**, which is a separate object. With no
policy attached:

- CONNECT succeeds (CONNACK 0)
- SUBSCRIBE succeeds (SUBACK, granted QoS 1)
- PUBLISH succeeds (PUBACK returns)
- **every message is silently dropped at delivery**

No exception, no disconnect, no log line. It presents as a working
connection that receives nothing.

The app does this on every launch. Captured as:

```
PUT /target-policies/RangeHoodPolicy HTTP/1.1
Host: iot.us-west-2.amazonaws.com
{"target":"us-west-2:00000000-0000-0000-0000-000000000000"}
```

signed SigV4 with the Cognito session credentials. Equivalent:

```python
iot = boto3.client("iot", ...)          # with the Cognito creds
iot.attach_policy(policyName="RangeHoodPolicy", target=identity_id)
```

Idempotent, and the Cognito role is permitted to call it.

**Ordering matters**: an already-open MQTT connection does not pick up
newly attached permissions. Attach, then connect. On reconnect after a
credential refresh, re-attach is harmless but unnecessary — the binding
persists on the identity.

Use `iot.list_attached_policies(target=identity_id)` to check first.

## 4. Device list

The Amplify config has no API section — the endpoint is a vendor-owned
domain fronting API Gateway, found only in the Proxyman capture.

```
POST https://zephyr-prod-app.gemteks.com/prod/getowndevices
Authorization: <raw ID token>          # bare, NO "Bearer " prefix
Content-Type: application/json
Content-Length: 0                      # empty body, not "{}"
```

No SigV4 — the token alone authorizes. The app also sends `X-Amz-Date`,
which appears to be vestigial SDK behaviour and is ignored.

Response:

```json
{"message":"Success","devices":[{
  "thingName":"aaaaaaaabbbbbbbbccccccccddddddddeeeeeeee",
  "SN":"1234567XYZ",
  "modelName":"AK7400AS",
  "MAC":"00:00:5e:00:53:00",
  "location":{"lng":"-XX.XXXXXX","lat":"YY.YYYYYY"}
}]}
```

`thingName` is 40 hex chars (SHA-1 shaped) but is **not** a plain SHA-1
of the MAC or serial in any obvious form — tested `mac`, `mac` without
colons, both cases, and the serial. Treat it as opaque and always fetch
it from this endpoint. Do not attempt to derive or guess it.

Note the response includes precise device coordinates. Anything built on
this should treat the payload as containing personal location data.

### discoverdevice — capabilities and state over HTTPS

A second endpoint on the same host returns one device's declared
capabilities merged with its current reported state:

```
POST https://zephyr-prod-app.gemteks.com/prod/discoverdevice
Authorization: <raw ID token>          # bare, same rules as above
Content-Type: application/json

{"thingName":"aaaaaaaabbbbbbbbccccccccddddddddeeeeeeee"}
```

The response is **flat** — no `state`/`reported` nesting — and is a superset
of the shadow's `reported` block: the same runtime keys plus `modelName`,
`SN`, `MAC`, warranty dates, support URLs, and the capability maxima
(`maxFanSpeed`, `maxLightLevel`, `maxGreasefilterTimer`,
`maxCharcoalfilterTimer`).

Those maxima appear **only here**. The device shadow does not carry them, so
capability discovery cannot be done over MQTT — compare
`tests/fixtures/discoverdevice.json` against
`tests/fixtures/shadow_get_accepted.json`.

This is the library's HTTPS read path. It backs `hood.async_poll()` and works
whether or not MQTT is up, which is what makes a degraded read possible while
the shadow connection is down.

### TLS caveat

`zephyr-prod-app.gemteks.com` presents a chain (TWCA → GEMTEK wildcard)
that **fails OpenSSL 3.x verification** with
`CERTIFICATE_VERIFY_FAILED: Missing Subject Key Identifier`. The
intermediate omits the SKI extension. Apple's Security framework is
lenient about this, so the iOS app is unaffected; Python is not.

Do **not** use `verify=False`, and do not pin the vendor's leaf
certificate. `pyzephyrconnect` ships the three TWCA certificate-authority
certs — `TWCA Root Certification Authority`, `TWCA Global Root CA`, and
`TWCA Secure SSL Certification Authority` — as package data at
`certs/twca.pem`, and **adds them to the system trust store as
supplementary anchors** rather than replacing or narrowing it. This is
purely to cover the vendor intermediate's missing SKI extension, which
OpenSSL 3.x rejects but Apple's stack accepts.

This is explicitly **not certificate pinning**: the full system trust
store stays intact, nothing is restricted to a fixed leaf or a fixed CA
set, and the library keeps working if the vendor rotates to a mainstream
CA (the extra anchors simply go unused). Pinning the leaf, by contrast,
would break it outright on that rotation. All three bundled TWCA certs are
valid through **2030**, well past the current leaf's 2026-10-15 expiry, so
there is no pin-refresh cliff to plan around.

## 5. MQTT / shadow

WebSocket, SigV4-signed, port 443. The library uses **paho-mqtt** with a
hand-rolled presigner (`presign.py`), not the AWS IoT SDK's awscrt
connection builder that earlier drafts of this document assumed:

```python
url = build_presigned_url(
    creds.access_key, creds.secret_key, creds.session_token,
    endpoint=IOT_ENDPOINT, region=REGION, now=datetime.now(UTC))
parts = urlsplit(url)

client = mqtt.Client(
    callback_api_version=mqtt.CallbackAPIVersion.VERSION2,
    client_id=client_id,          # see "Client ID" below
    transport="websockets", protocol=mqtt.MQTTv311)
client.ws_set_options(path=f"{parts.path}?{parts.query}")
# Off-thread: building the context on the event loop blocks. See below.
client.tls_set_context(await asyncio.to_thread(ssl.create_default_context))
client.connect_async(IOT_ENDPOINT, 443, keepalive=30)
```

The presigned URL embeds a signature over credentials that expire in an
hour, so **every reconnect must re-presign**. Reusing the URL retries a
signature AWS IoT has already stopped accepting — and paho's own
auto-reconnect will do exactly that, indefinitely, unless something
rebuilds the socket. Credentials last an hour (§3.2), so the library runs a
supervisor that re-presigns and rebuilds each hood's socket ahead of
expiry; anything reimplementing this transport needs the equivalent.

### Topics

Base: `$aws/things/<thingName>/shadow`

| Topic | Direction | Purpose |
|---|---|---|
| `.../get` | pub | request current shadow (empty `{}` payload) |
| `.../get/accepted` | sub | full shadow document |
| `.../get/rejected` | sub | errors (404 = no shadow exists) |
| `.../update/accepted` | sub | confirmed state changes |
| `.../update/rejected` | sub | rejected writes |
| `.../update/delta` | sub | `desired` ≠ `reported` — subscribed but ignored, see below |
| `.../update/documents` | sub | before/after pairs |
| `.../update` | pub | **WRITE PATH — actuates hardware** |

Read flow: subscribe first, then publish `{}` to `.../get`. The document
arrives on `get/accepted` within a second.

Control (implemented): publish `{"state":{"reported":{...}}}` to
`.../update`. The device applies it and echoes back on
`update/accepted` with `state.reported` updated.

Writing `reported` is backwards from the usual AWS IoT shadow
convention — `reported` is normally device-authored and clients write
`desired` — but it is demonstrably how this product works. Live MQTT
captures of the vendor iOS app's own traffic show it publishing
`state.reported` when the user taps a control, and a direct experiment
confirmed a `state.reported` write physically actuates the hood.
Writing `state.desired` instead is accepted by AWS IoT — the publish
succeeds and nothing complains — but this device silently ignores it.

Consequently `update/delta` never carries device state. It is still
subscribed, but its payload is deliberately ignored (debug-logged
only): a delta is a `desired`-vs-`reported` difference, and since
nothing in this system ever writes `desired`, any delta arriving here
can only come from a stale or foreign `desired` write. Merging one
into cached state produces a phantom "change" — that exact bug
disguised the desired/reported root cause for a full debugging cycle.

The write path is covered by `tests/test_shadow.py` and
`tests/test_client.py`.

### Field semantics

Established against the real hood by the `VALIDATION.md` runbook. Each of
these was an open question in earlier revisions of this document.

**`power` — a master switch with memory, not a precondition.**
Writing `0` turns everything off. Writing `1` restores the levels that were
running before (observed restoring fan 6 and light 1 together). It does
**not** gate the other controls: `fan` and `light` can be written directly
while `power` reads `0`, and the device raises `power` itself in response.
`power` is therefore an independent field rather than a prerequisite, and
bundling it into a fan or light write is redundant — the device raises it
on its own.

**`setdelaytimer` — seconds, not preset-snapped.**
Not minutes. The vendor app offers two presets, but that is a UI choice
rather than a device constraint: values off the presets are accepted. The
proven domain is non-negative seconds up to 3600. Beyond that the ceiling
is unprobed (§7) — do not describe the field as unbounded. The device
derives `delaytimer` from it and counts down itself in 60-second steps,
reporting roughly once a minute, so `delaytimer` is device-authored and
writing it is unnecessary.

The countdown has been watched to zero: when `delaytimer` reaches 0 the
hood shuts off. So this is a real device-side delay-off function, not a
display counter a client is expected to act on — nothing needs to watch
for zero and issue its own `power` write.

**Filter counters — counter in minutes, capability maximum in hours.**
`usegreasefiltertime` / `usecharcoalfiltertime` count **minutes**, while
`maxGreasefilterTimer` / `maxCharcoalfilterTimer` are **hours**. Conflating
them is wrong by 60x. Cross-checked against the vendor app's own display:
643 minutes against a 60-hour life is 82.1%, and the app shows 82%. So

```
remaining = 1 - used_minutes / (life_hours * 60)
```

**`usefantime` / `uselighttime` — hours.**
Lifetime run-time counters, and a *different unit from the filter counters
above* — those are minutes, these are hours. Getting this backwards is the
same 60x error in the other direction.

Two independent lines of evidence. Both counters held flat across five
minutes of fan runtime while `usegreasefiltertime` moved, which rules out
minutes outright. And the readings (`usefantime` 1979, `uselighttime` 2833)
reconcile with the hood's approximate age and usage on hours, where the
finer-grained alternatives do not.

Note the basis: this is an estimate against known usage, not a timed
measurement. It is sound for the 60x question that matters, and the
remaining doubt is narrow. If a fan-runtime figure ever surfaces in the
vendor app, it is worth a confirming glance — the same cross-check that
settled the filter formula.

**`setcleanairfunction` — an operating mode, not a setting.**
Enabling it starts the fan at speed 1.

### Client ID

AWS IoT evicts concurrent sessions sharing a client ID, so the phone app and
a script using the bare identity ID mutually evict each other in a reconnect
loop. Appending a suffix avoids it, which means the policy's client ID
constraint is either absent or a prefix match.

Settled shape, one connection per hood:

```
<identity_id>-ha-<thingName>          # e.g. us-west-2:uuid-ha-aaaa...eeee
```

What matters is that *some* suffix is present, so this client and the
vendor app do not evict each other, and that it then varies per thing, so
two hoods on one account do not evict each other either. The suffix string
itself is arbitrary: `-ha` is simply the value this library ships, as
`const.CLIENT_ID_SUFFIX`, and any stable non-empty string works. Keep the
region prefix on the identity ID (§3.2).

### Transport gotchas

- **A refused subscribe still looks like a success.** paho fires
  `on_subscribe` even when the broker denied the topic. Granted QoS `128`
  means denied — check `reason_code_list` explicitly. This is the same trap
  as the missing-policy case in §3.3 and usually has the same cause.
- **Callbacks run on paho's network thread, and must never raise.** paho
  re-raises callback exceptions into the thread runner, which has no
  handler, so one exception silently kills the network thread and updates
  simply stop arriving. Marshal onto the event loop
  (`call_soon_threadsafe`) and swallow exceptions at the boundary.
- **`X-Amz-Security-Token` is appended *after* signing** and is not part of
  the canonical query string. Signing over it produces a signature the
  broker rejects with an opaque handshake error. See `presign.py`.
- **Use `tls_set_context()`, not `tls_set()`.** paho's `tls_set()` builds
  the SSL context inline on the calling thread and, with `ca_certs=None`,
  calls `load_default_certs()` — file I/O that blocks the event loop it is
  called on. Build the context in a worker thread and hand it over
  finished.
- **The IoT endpoint needs the plain default trust store.** It chains to
  Amazon Root CA 1. Only the vendor REST host (§4) needs the TWCA anchors;
  do not reuse that context here.
- **Cap the reconnect backoff.** paho retries indefinitely at a fixed short
  interval by default, which turns an expired credential into a hot loop —
  `reconnect_delay_set(min_delay=1, max_delay=120)`.

## 6. Failure modes seen, and what they meant

| Symptom | Cause |
|---|---|
| `ForbiddenException` from `get_thing_shadow` (HTTPS) | Policy grants MQTT topic actions, not `iot:GetThingShadow`. The **AWS IoT** REST data plane is unusable — read the shadow over MQTT, or the vendor's own `discoverdevice` endpoint (§4). |
| Connect OK, subscribe OK, publish OK, no messages | No IoT policy attached to the identity (§3.3). |
| Subscribe "succeeds" but topic is dead | Granted QoS 128 — check it explicitly. |
| Second and third subscribes time out after first denial | IoT closes the connection on a refused subscribe. Sequential probing on one connection is invalid; reconnect per probe. |
| `AccessDeniedException` on `iot:ListThings` | Expected and correct — the role has no control-plane enumeration. |
| `CERTIFICATE_VERIFY_FAILED: Missing Subject Key Identifier` | Vendor's broken intermediate (§4). |

## 7. Open items

The `VALIDATION.md` runbook has been run against the reference hood
(`AK7400AS`), except step 9. What it established is folded into §5 —
`power` semantics, `setdelaytimer` units, the filter-life formula, the
run-time counter units, and `setcleanairfunction`. Credential refresh, reconnect handling and the
polling/push decision, listed as open in earlier revisions, are implemented
in the library. What follows is what is genuinely still unknown.

1. **The `setdelaytimer` ceiling.** Off-preset values are accepted (§5),
   but the maximum is unprobed and the domain is validated at exactly one
   point: 3600 seconds worked. One write above an hour establishes whether
   a larger value is accepted, clamped, or rejected.
2. **`act` beyond `"Disabled"`.** The field is understood as a mode string
   but no other value has ever been observed. Treat it as free-form; do not
   build an enum on one sample.
3. **Charcoal filter reset.** There is no `resetcharcoalfilter` field in the
   shadow. If the vendor app offers a charcoal reset, watch
   `update/accepted` while pressing it — it may reuse `resetgreasefilter`,
   or be app-side only. Until this is known, a recirculating hood gets a
   charcoal-life figure with no way to reset it.
4. **`fanwarning` vs `alarmfan`.** Neither has ever fired, so what
   distinguishes them is unknown. Record both if either ever trips.
5. **`resetgreasefilter` (runbook step 9) — deliberately deferred.** It
   zeroes `usegreasefiltertime`, which cannot be reconstructed. Do not run
   it until the grease filter is actually being cleaned.

Writes remain hardware-actuating: validate field names against observed
`reported` values before writing, and test with the device attended.

## 8. Security notes

Findings so far, for a possible disclosure to Gemtek:

- **Broken TLS chain** on `zephyr-prod-app.gemteks.com` (missing SKI on
  the intermediate). Breaks every non-Apple client. Low severity, easy
  fix, worth reporting regardless.
- **App client secret shipped in the app bundle.** Anti-pattern rather
  than a vulnerability by itself, but it means the client secret
  provides no security boundary.
- **Any authenticated customer can call `iot:AttachPolicy`** to bind
  `RangeHoodPolicy` to their own identity. That is how the app works, so
  it is by design — which makes the contents of `RangeHoodPolicy` the
  only thing separating one customer's device from another's.

**Not yet checked:** the `RangeHoodPolicy` document itself. Run
`iot.get_policy(policyName="RangeHoodPolicy")` — likely denied, but if
readable it answers the question. If the topic ARNs are templated with
`${cognito-identity.amazonaws.com:sub}` or
`${iot:Connection.Thing.ThingName}`, the design is sound. If they are
wildcards over `$aws/things/*/shadow/*`, every customer can read and
write every other customer's device.

Given `getowndevices` returns precise home coordinates and the shadow
carries usage state, a wildcard policy would be a serious finding.

**If it turns out permissive: note it and stop.** Do not test against a
thing name that is not yours, and do not enumerate. Write it up and send
it to Gemtek (Taiwan HQ; try `security@gemtek.com.tw`, or their support
channel) along with the TLS issue.
