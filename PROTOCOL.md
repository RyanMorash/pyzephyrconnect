# Zephyr / Gemtek range hood — protocol notes

Reverse-engineered from the iOS app (running on macOS), its bundled
`awsconfiguration.json`, Mach-O string dump, and Proxyman capture.
Verified working end to end against a real device (model `AK7400AS`).

All device identifiers in this document (thing name, serial, MAC,
coordinates, identity ID) are placeholders, not real values.

Target use: a Home Assistant integration. Everything below is read path
unless explicitly marked otherwise.

---

## 1. Architecture

The device does not expose a local API. All communication is cloud
round-trip through AWS IoT Core:

```
HA / client ──SRP──> Cognito User Pool      (identity)
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
| App Client Secret | *(in `awsconfiguration.json`; required for SRP)* |
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

Do not commit these to a public repo alongside real credentials.

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
set, and the integration keeps working if the vendor rotates to a
mainstream CA (the extra anchors simply go unused). Pinning the leaf, by
contrast, would break the integration outright on that rotation. All
three bundled TWCA certs are valid through **2030**, well past the
current leaf's 2026-10-15 expiry, so there is no pin-refresh cliff to
plan around.

## 5. MQTT / shadow

WebSocket, SigV4-signed, port 443:

```python
mqtt_connection_builder.websockets_with_default_aws_signing(
    endpoint=ENDPOINT, region=REGION,
    credentials_provider=auth.AwsCredentialsProvider.new_static(
        creds["AccessKeyId"], creds["SecretKey"], creds["SessionToken"]),
    client_id=identity_id,      # full "us-west-2:uuid"
    clean_session=True, keep_alive_secs=30)
```

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
`tests/test_client.py`. **Field semantics are only partly mapped** —
see §7.

### Client ID collision

The IoT policy pins the client ID to the identity ID. Running the phone
app and a script with the same client ID causes mutual session takeover
(each evicts the other, reconnect loop). Append a suffix
(`identity_id + "-ha"`) to coexist — this works, so the policy's client
ID constraint is either absent or a prefix match. Worth using a stable
distinct suffix for the HA integration.

### awscrt API gotchas

- `subscribe()` and `publish()` return `(future, packet_id)` tuples.
  Index `[0]` before `.result()`.
- `subscribe()` **resolves its future even when the broker denies that
  topic**. Check the granted QoS in the result dict: `0`/`1` is a real
  subscription, `128` or `None` means denied. Not checking this makes
  denied subscribes look successful.
- Message callbacks run on a CRT background thread. The main thread must
  stay alive (event wait or sleep) or the process exits before delivery.
- `awscrt.io.init_logging(io.LogLevel.Debug, "stderr")` exposes protocol
  detail that `AwsCrtError` swallows. Useful when something fails
  opaquely.

## 6. Failure modes seen, and what they meant

| Symptom | Cause |
|---|---|
| `ForbiddenException` from `get_thing_shadow` (HTTPS) | Policy grants MQTT topic actions, not `iot:GetThingShadow`. The REST data plane is not usable here — use MQTT. |
| Connect OK, subscribe OK, publish OK, no messages | No IoT policy attached to the identity (§3.3). |
| Subscribe "succeeds" but topic is dead | Granted QoS 128 — check it explicitly. |
| Second and third subscribes time out after first denial | IoT closes the connection on a refused subscribe. Sequential probing on one connection is invalid; reconnect per probe. |
| `AccessDeniedException` on `iot:ListThings` | Expected and correct — the role has no control-plane enumeration. |
| `CERTIFICATE_VERIFY_FAILED: Missing Subject Key Identifier` | Vendor's broken intermediate (§4). |

## 7. Open items for the integration

1. **Map shadow fields to functions.** Toggle each control in the app
   while subscribed to `update/accepted`; record which keys change.
   (Not `update/delta` — it never reflects device state here, see §5.)
   Needed before exposing writes beyond the probe CLI.
2. **Write path is implemented; individual fields still need
   validating.** The mechanism is settled and tested — publish
   `{"state":{"reported":{...}}}` to `.../update` (§5). What remains
   unproven is the effect of most individual fields. This is a range
   hood — a wrong payload actuates a fan and possibly heat/light.
   Validate field names against observed `reported` values before
   writing, and test with the device attended.
3. **Credential refresh loop.** Tokens and AWS credentials both expire
   at 1 hour. HA needs a scheduled refresh (`renew_access_token()` →
   re-exchange → rebuild the MQTT connection), or an
   `AwsCredentialsProvider` backed by a callback rather than static
   credentials.
4. **Reconnect handling.** Wire `on_connection_interrupted` /
   `on_connection_resumed`; check `session_present` on resume and
   re-subscribe if false.
5. **Polling vs push.** `update/accepted` gives push updates when the
   device or another client changes state, but a periodic `get` is a
   reasonable safety net for missed messages.

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
