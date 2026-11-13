# Zephyr / Gemtek range hood — protocol notes

Reverse-engineered from the iOS app (running on macOS), its bundled
`awsconfiguration.json`, Mach-O string dump, and Proxyman capture.
Verified working end to end against a real device (model `AK7400AS`).

A second source is a static decompilation of the Android app
`com.gemteks.rangehood` v1.1.16 (versionCode 32). That pass did not
contact vendor servers. The report itself is `docs/android-findings.md`;
this document keeps the protocol conclusions. Where Android only shows
a REST call the library does not make, the call is listed as a candidate.

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
iOS binary produced only `$aws/things/%@/shadow/*` formats, and the
Android package contains only the same classic shadow topics (§5).
Reads and writes are both shadow operations.

There is no local LAN or HTTP API on the hood. Android confirms that:
provisioning, Wi-Fi changes, and the one-time readout of thing name,
firmware version, and MAC are BLE (§9). Runtime control stays on this
cloud path.

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

### Production match (Android 1.1.16)

The Android release APK's production region, user pool, app client,
identity pool, IoT ATS endpoint, IoT policy name, and device API base
are the same values as the table above. Source:
`res/raw/awsconfiguration.json`, plus `DeviceManager`'s
`CUSTOMER_SPECIFIC_ENDPOINT` and `POLICY_NAME`. The side-by-side table
is in `docs/android-findings.md` §2.

Three production values are new relative to `const.py` and do not
conflict with it:

| Key | Value | Role |
|---|---|---|
| Cognito Hosted UI domain | `rangehoodprod.auth.us-west-2.amazoncognito.com` | Alexa and Google account linking. Not the username/password SRP path the app itself uses. |
| OAuth scopes | `phone`, `email`, `openid`, `profile`, `aws.cognito.signin.user.admin` | Hosted UI only. |
| Leftover policy constant | `AwsIotDemo` | Declared and unused. `attachPolicy` uses `RangeHoodPolicy`. |

Android's MQTT client ID is `{thingName}` plus a UUID, with no
separator. The identity ID is logged and then not used for the client
ID. That is a different shape from this library's
`<identity_id><suffix>-<thingName>` (§5), not a disagreement about the
constants above. The library's shape is the one exercised against
hardware. Android keepalive is 5 seconds, and both subscribe and
publish use QoS 0. The shadow GET payload is an empty string; this
library sends `{}`. IoT accepts both. Android subscribes to
`get/accepted`, `update/accepted`, and `update/rejected` only. It
defines `$aws/things/%s/shadow/+` and never subscribes to it.

### Dev bundle (not used by the release APK)

`res/raw/awsconfiguration_dev.json` is a second Amplify config. Nothing
in the release code loads it. The REST client and the IoT endpoint are
hardcoded to production, so loading that file would still leave REST
and MQTT on prod.

| Key | Dev value |
|---|---|
| User Pool | `us-west-2_GieFqJhLq` |
| App Client ID | `30gtpd7g0rooa11tlvnf3hnhj8` |
| Identity Pool | `us-west-2:5af68ebd-5259-4409-8666-ec5884318852` |
| OAuth WebDomain | `rangehood.auth.us-west-2.amazoncognito.com` |

The dev app client secret ships in the APK the same way the production
secret does. It is recorded in `docs/android-findings.md` and is not
copied into `const.py`, which tracks production only. No dev REST host
and no dev IoT endpoint appear in the APK.

### Other hosts

None of these is on the hood-control path. The APK has no second Gemtek
REST host, no `execute-api` hostname, and no `/dev` or `/stage` API
Gateway stage.

| Host / ARN | Role |
|---|---|
| `https://sns.us-west-2.amazonaws.com` | Dead-code SNS registration. No caller. |
| `arn:aws:sns:us-west-2:008768393459:app/GCM/Rangehood` | SNS platform application for that dead path. AWS account `008768393459`, distinct from the vendor account `527656002764` above. |
| Cognito identity pool `us-west-2:1677020c-000e-458a-b5a9-67c54d120221` | Unauthenticated provider for the dead SNS path. Not the main identity pool. |
| Firebase project `rangehoodprod` | FCM and analytics. Sender id `721873133313`. Database `https://rangehoodprod.firebaseio.com`. Storage `rangehoodprod.appspot.com`. |
| `https://zephyronline.com/privacy-policy/` | Privacy-policy link. |
| `https://store.zephyronline.com/en/productregistration` | Warranty registration. Per-device warranty and support URLs also come back from `discoverdevice`. |

The in-app upgrade dialog points at Play Store package
`com.zephyr.rangehood`, a different package from
`com.gemteks.rangehood`. Alexa linking opens `com.amazon.dee.app`;
Google Home linking opens `com.google.android.apps.chromecast.app`.
Neither is a Gemtek API (§7).

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

Android signs in the same way: `AWSMobileClient.signIn` (SRP).
`USER_PASSWORD_AUTH` is not used. Password change and forgot-password
are Cognito calls (`changePassword`, `forgotPassword` /
`confirmForgotPassword`). The password-length string in the APK says
six or more characters. There is no vendor REST account API, no
delete-account screen, and no `deleteUser` call. Sign-out also calls
`POST /delmobiletoken` (§4).

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

Idempotent, and the Cognito role is permitted to call it. Android
calls the same `attachPolicy(policyName="RangeHoodPolicy",
target=identityId)` on every MQTT init.

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
Android types `lat` and `lng` as numbers; the iOS capture had them as
strings. Treat either shape as the same coordinate pair.

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

Android's `discoverdevice` model does not declare `act`, `fanwarning`,
`alarmfan`, `resetgreasefilter`, `resetcharcoalfilter`,
`alarmfaultcode`, `alarmgreasefilter`, or `truHueSupport`. Those keys
can still be on the wire — the iOS fixture carries several of them —
and this app ignores them on that endpoint. The shadow `Reported`
model does carry `act`, `fanwarning`, `alarmfan`, and
`resetcharcoalfilter`. `alarmfaultcode` and `alarmgreasefilter` are in
the iOS-captured shadow and absent from the Android `Reported` class.

### Other REST endpoints — candidates, not implemented

Android's `RangeHoodAPPClient` is an AWS API Gateway client
(`@Service` / `@Operation`), not Retrofit. Retrofit is in the APK as a
transitive dependency and has no interface under `com.gemteks`. Every
call is POST to `https://zephyr-prod-app.gemteks.com/prod`. Auth on
every call is `Authorization: <raw Cognito ID token>` with no `Bearer `
prefix, and a JSON body. A typical success body is
`{"message":"Success"}`. The client is built with
`credentialsProvider(null)` — no SigV4, matching §4 above.

The library implements `getowndevices` and `discoverdevice` only. The
calls below are candidates, with the request and response shapes the
APK models imply. They are not client methods.

Server error strings the app switches on: `"This device was already
been bound"`, `"Need input token"`, `"No binding device"`, `"This
device is not yours"`, `"You have already bound other device"`, `"The
user already bound other device"`, `"Incorrect model name"`, `"SN and
modelName exist"`, `"Please check the input Serial No. or Model No."`,
`"Internal server error"`, `"Invalid command"`, `"Non-engineer only"`.
Several of those imply **one hood per customer account**.

| Path | Request body | Response | Role |
|---|---|---|---|
| `/checkmodel` | `{modelName, SN}` | `{message, Recirculating, setrecirculating, thingName, registeredFirstDate, url}` | Validate a model and serial before bind or first registration. Returns the thing name and a warranty URL. |
| `/uploadinfo` | `{SN, modelName, thingName, MAC, OS, IdentityId, location:{lat,lng}, setrecirculating, version, registeredFirstDate}` | `{message}` | First registration of a new hood. `OS` is `"Android "` plus the OS release. `version` is the firmware string read over BLE. `IdentityId` is the Cognito identity ID. `setrecirculating` is 0 or 1. |
| `/uploadbindinfo` | `{SN, modelName, thingName, OS, IdentityId, location:{lat,lng}, setrecirculating}` | `{message}` | Bind an already-registered hood to this account. No `MAC`, `version`, or `registeredFirstDate`. |
| `/unbinddevice` | `{thingName}` | `{message}` | Remove the hood from this account ("Remove Hood"). `"This device is not yours"` is the not-owned error. This is the only ownership-transfer call. There is no share, transfer, or invite endpoint. |
| `/updaterecirculating` | `{thingName, SN, modelName, setrecirculating}` | `{message}` | Cloud-side recirculating flag. The app also writes `setrecirculating` to the shadow. The library performs the shadow write only. |
| `/updatemobiletoken` | `{service, token}` | `{message}` | Register the FCM token. `service` is hardcoded `"GCM"`. `"Non-engineer only"` is treated as success (engineer accounts skip push). |
| `/delmobiletoken` | `{token}` | `{message}` | Unregister FCM on logout. Skipped for engineer accounts. |
| `/getswitchnotify` | none (auth header only) | `{message, uid, notification}` | Read the account push switch. `notification` is 0 or 1. |
| `/setswitchnotify` | `{notification}` | `{message}` | Enable or disable push for this account. |
| `/getfaultcodedesc` | `{faultCode: [string]}` | `{message, info:[{faultCode, description}]}` | Human-readable text for shadow `faultCode` values. The list key is `"info"`. |

`/updatemobiletoken` is the live push-registration path. Incoming
messages use Amazon Pinpoint keys (`pinpoint.notification.title`,
`pinpoint.notification.body`, `pinpoint.jsonBody`). `pinpoint.jsonBody`
is `{"type": ...}` and `type` is one of `"fanwarning"` (open Home),
`"filters"` (My Hood), or `"faultcode"` (Support). A second path would
`CreatePlatformEndpoint` against the SNS ARN in §2 using the other
identity pool. That method has no callers.

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

Android confirms the reported-only write from a second codebase. Its
shadow document model has a `reported` field and no `desired` class.
Every real control (`power`, `fan`, `light`, `setdelaytimer`,
`setcleanairfunction`, `setrecirculating`, `resetgreasefilter`,
`resetcharcoalfilter`) publishes
`{"state":{"reported":{"%s":%d}}}` to `.../update`. An engineer debug
screen can also publish `isOnline` as 0 or 1; that is not a consumer
control. `SetResetToDefault` publishes the raw string
`"ResetToDefault"` rather than a shadow document, and it has no
callers. Do not implement it.

Policy attach matches §3.3: `RangeHoodPolicy` on the identity, on every
MQTT init. No `$aws/events`, jobs, or vendor-specific topic strings
appear under `com.gemteks`.

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
Not minutes. The Android delay-off enum is `MIN_0`, `MIN_5`, and
`MIN_10`, and `toInt` is `ordinal() * 300`, so that UI writes only 0,
300, or 600 seconds. Display snaps `value / 300`, rounded up, and caps
the result at 10 minutes — a device reporting 3600 would *display* as
10 minutes. That is a UI choice rather than a device constraint: values
off the presets are accepted. The proven domain is non-negative seconds
up to 3600. Beyond that the ceiling is unprobed (§7) — do not describe
the field as unbounded. The Android code does not probe or enforce a
device maximum. The device derives `delaytimer` from it and counts down
itself in 60-second steps, reporting roughly once a minute, so
`delaytimer` is device-authored and writing it is unnecessary.

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

**`resetgreasefilter` / `resetcharcoalfilter` — write `1` to reported.**
Both are commands, not counters. Android publishes

```json
{"state":{"reported":{"resetgreasefilter":1}}}
{"state":{"reported":{"resetcharcoalfilter":1}}}
```

from dedicated My Hood buttons (`ResetGreasefilter`,
`ResetCharcoalfilter`). Each uses the same command format as every
other control, `{"state":{"reported":{"%s":%d}}}`. The charcoal field
is the one the iOS capture never showed; it is a real shadow write, not
a reuse of `resetgreasefilter` and not an app-side-only reset. Each is
intended to zero the matching usage counter
(`usegreasefiltertime`, `usecharcoalfiltertime`). That effect has not
been run on hardware (§7): both counters are unrecoverable. The library
accepts both fields and gates them with the destructive confirmation
(`DANGEROUS_FIELDS`). Android also warns to replace a filter when the
used fraction is at least 0.85, which is the formula above with 15%
remaining (`FILTER_USAGE_REPLACE_WARNING = 0.15`).

**`act` — Airflow Control Technology.**
An installer-configured make-up-air mode. The My Hood screen shows a
row labelled ACT and displays the raw shadow string. The help text
says it may have been enabled by the installer to meet local make-up
air codes, and that Disabled means the hood is on the factory setting.
`"Disabled"` is that factory default. The app never compares the
string, never writes `act`, and has no enum. Any other value would be
whatever the device reports, and no other value is in the APK. Treat
it as a free-form status string. That is enough to name the field. It
is not enough to build a closed enum (§7).

**Light level, and the absence of Tru-Hue in this Android build.**
`light` is an integer 0–10 (`LightingLevelConverter`: OFF through TEN).
The device maximum comes from `maxLightLevel`. Android 1.1.16 has no
color, Kelvin, RGB, or `truHue` field, command, or screen. The library
still parses `truHueSupport` from `discoverdevice` because the iOS
fixture carries it. Android's discover model simply does not declare
that key. A later hood that supports Tru-Hue cannot be color-controlled
from this Android build.

**`fanwarning` and `alarmfan` — shadow integers still unread.**
Both are integers on the Android `Reported` model, with getters, and
neither is read by UI or business logic. Separately, `"fanwarning"` is
a Pinpoint push `type` that opens the Home screen. There is no push
type named `"alarmfan"`. What the shadow integers mean when they
become non-zero, and how they differ, is still unknown (§7).

Android's `Reported` model defaults every integer to `-1` for "not
present". The library keeps the stronger rule already in force: absent
is `None`, not zero and not `-1`, except the four usage counters.

### Client ID

AWS IoT evicts concurrent sessions sharing a client ID, so the phone app and
a script using the bare identity ID mutually evict each other in a reconnect
loop. Appending a suffix avoids it, which means the policy's client ID
constraint is either absent or a prefix match.

Settled shape, one connection per hood:

```
<identity_id><suffix>-<thingName>     # e.g. us-west-2:uuid-py-aaaa...eeee
```

What matters is that *some* suffix is present, so this client and the
vendor app do not evict each other, and that it then varies per thing, so
two hoods on one account do not evict each other either. The suffix string
itself is arbitrary: `-py` is simply the default this library ships, as
`const.CLIENT_ID_SUFFIX`, and any stable non-empty string works. Consumers
set their own — a Home Assistant integration would pass `-ha` — through
`AbstractAuth`'s `client_id_suffix` argument, which is what keeps two
*consumers* on one account from evicting each other as well. Keep the
region prefix on the identity ID (§3.2), and keep the suffix short: AWS IoT
caps the whole client ID at 128 characters, and the per-thing part is
appended after it.

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
run-time counter units, and `setcleanairfunction`. Credential refresh,
reconnect handling, and the polling/push decision, listed as open in
earlier revisions, are implemented in the library.

Android 1.1.16 static analysis (`docs/android-findings.md`) closed a
second set of gaps that the iOS capture could not. Status below is
against that report plus the attended run. Writes remain
hardware-actuating: validate field names against observed `reported`
values before writing, and test with the device attended.

### Resolved

**Charcoal filter reset — the field and the write.** The field is
`resetcharcoalfilter`. The My Hood screen has its own button and
publishes `{"state":{"reported":{"resetcharcoalfilter":1}}}`. It does
not reuse `resetgreasefilter`, and it is not app-side only. The library
accepts the field and gates it the same way as `resetgreasefilter`
(§5). The live effect on `usecharcoalfiltertime` is still deferred,
with the grease reset, below.

**`act` — what the field is.** Airflow Control Technology, an
installer-configured make-up-air mode. `"Disabled"` is the factory
default (ACT off). The apps display the raw string and never write it.
Other values are still unenumerated; that remainder is under partially
resolved.

**Desired versus reported.** Android writes only `state.reported`.
Confirms §5 from a second codebase. There is no `desired` model.

**Tru-Hue / light color, for this app.** None. Lighting is an integer
level 0–10. No color, Kelvin, RGB, or `truHue` control exists in
v1.1.16. `truHueSupport` on `discoverdevice` remains a key the library
parses from the iOS fixture; Android's discover model does not declare
it.

**Push registration.** `POST /updatemobiletoken` with
`{"service":"GCM","token":"<fcm token>"}` and the raw ID token.
Unregister is `POST /delmobiletoken` with `{"token":"..."}`. Account
on/off is `/getswitchnotify` and `/setswitchnotify`. Shapes are in §4.
The SNS `CreatePlatformEndpoint` path has no callers.

**Alexa / Google linking.** No Gemtek REST endpoint. The in-app flow is
tutorial UI that opens the Alexa or Google Home app. Login is Cognito
Hosted UI on `rangehoodprod.auth.us-west-2.amazoncognito.com` (§2).
After linking, voice control is Amazon or Google talking to the same
Cognito-authenticated backend.

**Share, transfer, unbind.** Only `POST /unbinddevice` with
`{thingName}`. No share, transfer, or invite UI or endpoint. Error copy
(`"You have already bound other device"`, `"The user already bound
other device"`) indicates one hood per account: move a hood by
unbinding it and binding it on the other account (`/uploadbindinfo`),
after `/checkmodel`.

**Firmware / OTA.** No device firmware-update endpoint and no firmware
MQTT topic. The version is read once over BLE during provision (§9)
and uploaded as `version` on `/uploadinfo`. In-app upgrade dialogs are
for the Android app itself.

**Account delete and password.** Password change and forgot-password
are Cognito (§3.1). There is no account-delete flow.

**Local API and other MQTT topics.** No LAN/HTTP API. BLE is
provisioning only (§9). No MQTT topics beyond classic
`$aws/things/{thing}/shadow/*`.

### Partially resolved

**`setdelaytimer` ceiling.** The Android app's write maximum is known:
it publishes only 0, 300, or 600 seconds, and its display would show
3600 as 10 minutes (§5). The device-side ceiling is not. 3600 is
accepted off-preset. What happens above 3600 is still one attended
write: accepted, clamped, or rejected.

**`act` values other than `"Disabled"`.** The meaning and the factory
default are known. The APK has no other sample and no enum. Record any
other string the device reports. Do not build an enum on
`"Disabled"` alone.

**`fanwarning` versus `alarmfan`.** The push category `"fanwarning"`
means "open the Home / fan screen". Neither shadow integer is read by
the Android UI. What those integers mean when non-zero, and how they
differ, is still unknown. Record both if either trips.

### Still open

**`resetgreasefilter` and `resetcharcoalfilter` live effect — deliberately
deferred.** Runbook step 9. Each write is `1` to `state.reported` (§5).
Each is intended to zero a usage counter that cannot be reconstructed.
Do not run either until that filter is actually being cleaned or
replaced. The charcoal write is now a supported library field; support
is not the same thing as having watched the counter hit zero.

### REST candidates

The endpoints in §4 under "candidates, not implemented" are a product
decision, not a protocol gap. Shapes are recorded. The library does not
call them.

## 8. Security notes

Findings so far, for a possible disclosure to Gemtek:

- **Broken TLS chain** on `zephyr-prod-app.gemteks.com` (missing SKI on
  the intermediate). Breaks every non-Apple client. Low severity, easy
  fix, worth reporting regardless.
- **App client secret shipped in the app bundle.** Anti-pattern rather
  than a vulnerability by itself, but it means the client secret
  provides no security boundary. The Android APK ships the same
  production secret, plus a dev-pool secret in an unused
  `awsconfiguration_dev.json` (§2).
- **Dead SNS registration uses a different AWS account and identity
  pool** (`008768393459`, pool
  `us-west-2:1677020c-000e-458a-b5a9-67c54d120221`). The method has no
  callers. The live push path is the vendor REST endpoint in §4. Do
  not exercise the dead path.
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

## 9. BLE provisioning

There is no local control API (§1). Android provisions a new hood, and
changes Wi-Fi later, over BLE only. Advertising name prefix is
`ZEPHYR`. The scan filters on the transparent-UART service UUID below.
The consumer flow does not join the hood to Wi-Fi by writing the
connect characteristic; it writes credentials, watches connect-status
notifications, then asks the hood for its thing name.

### GATT

ISSC / Microchip Transparent UART, the well-known `49535343-…` UUIDs:

| Role | UUID |
|---|---|
| Service `SERVICE_TRANSPARENT` | `49535343-fe7d-4ae5-8fa9-9fafd205e455` |
| Write | `49535343-8841-43f4-a8d4-ecbe34729bb3` |
| Read / notify | `49535343-1e4d-4bd9-ba61-23c647249616` |
| Alternate notify | `49535343-4c8a-39b3-2f49-511cff073b7e` |
| CCCD | `00002902-0000-1000-8000-00805f9b34fb` |

Wi-Fi scan service:

| Role | UUID |
|---|---|
| Service | `fb8c0001-d224-11e4-85a1-0002a5d5c51b` |
| Scan mode | `fb8c0002-d224-11e4-85a1-0002a5d5c51b` |
| AP count | `fb8c0003-d224-11e4-85a1-0002a5d5c51b` |
| AP detail slots 1–15 | `fb8c0100-d224-11e4-85a1-0002a5d5c51b` through `fb8c010e-…` |

Write `0x01` to scan mode to start. Notifications are 0 = init, 1 =
scanning, 2 = done. On done, read the AP count, then each detail slot.

Wi-Fi connect / credential. The app has no service UUID for this one;
it matches characteristics:

| Role | UUID |
|---|---|
| Connect status | `77880002-d229-11e4-8689-0002a5d5c51b` |
| AP parameter | `77880003-d229-11e4-8689-0002a5d5c51b` |

Connect status values: 0 = disconnected, 1 = connecting, 2 = connected.
The 98-byte credential blob is written to the AP parameter
characteristic. That characteristic also notifies "set wifi done".

### Transparent-UART frame

```
[0]      0xFE     header
[1]      action
[2]      N        length of values
[3..3+N) values   omitted when N is 0
[3+N]    checksum (action + N + sum(values)) & 0xFF
[3+N+1]  0xFF     end
```

A request with no values is `{0xFE, action, 0x00, action, 0xFF}`.

| Action | Name | Direction |
|---|---|---|
| `0xA2` | Request thing name and device version | app → device |
| `0xA1` | Setting Wi-Fi (`changeToProvisionCmd`) | app → device; engineer screen, not the consumer bind flow |
| `0xB2` | Thing-name response | device → app |
| `0xB3` | Device-version response | nested inside the `0xB2` frame |
| `0xB5` | Device-MAC response | nested inside the `0xB2` frame |
| `0xB1` | Setting-Wi-Fi response | device → app; logged only |
| `0xB4` | Keep-alive | device → app; logged only |

`CMD_CHANGE_TO_PROVISION = "S"` is defined and never sent.
`changeToProvisionCmd` sends a `0xA1` frame instead.

The `0xB2` buffer, after the `0xFE` header:

```
0xB2, thingNameLen, thingName bytes,
0xB3, versionLen, version bytes,
0xB5, macLen, mac bytes
```

The app renders the thing name as lowercase hex, the version as
`XX.XX.XX`, and the MAC as lowercase colon-separated bytes. Those three
are what `/uploadinfo` later uploads (§4). They are device identifiers.
Do not log them.

### Wi-Fi credential blob

98 bytes, written to the AP parameter characteristic:

```
[0]      security    1 = open, 2 = WPA, 3 = WEP
[1]      ssidLen     min(length, 32)
[2..33]  ssid        UTF-8, zero-padded
[34]     keyLen      min(length, 63)
[35..97] key         UTF-8, zero-padded
```

WEP keys of length 5 or 13 are hex-expanded first. Length 10 or 26 is
used as-is.

An AP scan record, from a detail characteristic:

```
[0] security  [1] rssi (7-bit)  [2] ssidLen  [3..] ssid
```

### Consumer flow

1. Scan for the transparent service and the `ZEPHYR` name prefix.
   Connect, optionally bond, discover GATT, enable notifications.
2. Start a Wi-Fi scan (write `0x01` to scan mode). On done, read the AP
   count and each detail characteristic.
3. The user picks an SSID and enters a password.
4. Write the 98-byte blob. Wait for the "set wifi done" notify and for
   connect-status notifications. The consumer flow does not write
   `0x01` to the connect-status characteristic. That write exists on
   the engineer screen only.
5. Send `0xA2` on the write characteristic and parse the `0xB2`
   compound response.
6. Cloud: `/checkmodel`, then `/uploadinfo` for a first registration or
   `/uploadbindinfo` to bind a hood that is already registered (§4).

The library does not speak BLE. This section is the protocol, for a
later decision about whether a provisioner belongs here.
