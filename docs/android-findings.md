# Zephyr Connect Android 1.1.16 (versionCode 32) — static analysis

Static decompilation of `com.gemteks.rangehood` v1.1.16. No vendor
network requests and no account login were used. Vendor constants in
this file ship in the APK. It contains no account email, password,
token, thing name, serial, or MAC.

The protocol conclusions live in `PROTOCOL.md`: which §7 gaps this
closed, the REST candidates (not client methods), BLE provisioning, the
host list, and the constants comparison. The `resetcharcoalfilter`
write recommended below is implemented and gated like
`resetgreasefilter`. The candidate REST endpoints are not.

---

Static decompilation of `com.gemteks.rangehood` v1.1.16, produced to
close the open gaps in PROTOCOL.md §7. The §7 text in this report is
the status *before* those conclusions were folded back into
`PROTOCOL.md`.

**APK:** `/workspace/zephyr/xapk/com.gemteks.rangehood.apk` (base, three DEX files, ~27 MB). Splits in the same directory are config-only (`mdpi`, `en`, `fr`, `arm64_v8a`) and add no application code.

**Tooling:** Eclipse Temurin JDK 21.0.13 and jadx 1.5.6, installed under `/workspace/zephyr/tools`. Decompiled to `/workspace/zephyr/jadx-out` (jadx reported 95 errors, typical of Android SDK stubs; application classes under `com.gemteks.rangehood` decompiled cleanly). apktool was not needed — jadx already decoded resources, including `res/raw/awsconfiguration.json`.

Source paths below are relative to `/workspace/zephyr/jadx-out/sources/` unless noted as `/workspace/zephyr/jadx-out/resources/`.

---

## 1. Stack

Native Java Android app (not Flutter, not React Native). Package `com.gemteks.rangehood`, `minSdk` 26, `targetSdk` 35, `BUILD_TYPE=release`, `DEBUG=false` (`com/gemteks/rangehood/BuildConfig.java`).

| Layer | What the APK actually uses |
|---|---|
| Auth / identity | **AWS Mobile Client** (`AWSMobileClient`) reading Amplify-CLI-generated `res/raw/awsconfiguration.json` (`UserAgent: aws-amplify-cli/0.1.0`). Cognito User Pool SRP + Identity Pool. Not the newer Amplify Android library. |
| Vendor REST | **AWS API Gateway Android client**, interface `RangeHoodAPPClient`, annotations `@Service` / `@Operation`. **Not Retrofit.** Retrofit 2 and OkHttp 3 are present in the APK as transitive/SDK dependencies; no Retrofit interface exists under `com.gemteks`. Built with `new ApiClientFactory().credentialsProvider(null)` — **no SigV4**. Auth is the Cognito **ID token in the `Authorization` header, bare, no `Bearer ` prefix**. Matches the iOS/library behavior. |
| MQTT / shadow | **AWS IoT Android SDK** `AWSIotMqttManager` (Paho underneath; `org.eclipse.paho` is packaged). Endpoint and policy are hardcoded in `DeviceManager`. |
| Push | **Firebase Cloud Messaging** + Amazon Pinpoint-shaped data keys. Token is registered with the vendor REST API (`/updatemobiletoken`). A second path talks to **AWS SNS** but has **no callers** (dead code). Firebase Analytics is packaged. |
| Local persistence | Room, SharedPreferences. |
| Other | RxJava 2, Data Binding, ButterKnife, Lottie, Timber, EasyPermissions, Play Services (location, auth, measurement). |

`AWSMobileClient.getInstance().initialize(application, …)` in `AuthRepository.initClient` (line 84) loads the default raw resource `awsconfiguration.json`. A sibling `awsconfiguration_dev.json` is bundled but **never referenced from Java** in this release build (only listed in `public.xml`).

---

## 2. Constants comparison vs `pyzephyrconnect/const.py`

Production Cognito / IoT constants **match the library exactly**. The Android `awsconfiguration.json` is the same shape as the iOS bundle the library was taken from, including the app client secret (already public in `const.py`; it provides no security boundary, but SRP needs it for `SECRET_HASH`).

### 2.1 Production — matches

| Key | Library (`const.py`) | Android production | Source |
|---|---|---|---|
| Region | `us-west-2` | `us-west-2` | `res/raw/awsconfiguration.json` |
| User Pool | `us-west-2_McuoKpkna` | **same** | same |
| App Client ID | `5a2qiskdvvu7gre1jvbjnunu20` | **same** | same |
| App Client Secret | `3b085l2fkgph4kt734k5e26tirb9hjasgb4rn8sjpp4mheo5kga` | **same** | same |
| Identity Pool | `us-west-2:fb4c1b66-12c2-414b-83a1-a1902f7d98e3` | **same** | same |
| IoT ATS endpoint | `a1nqxu0hki9zw3-ats.iot.us-west-2.amazonaws.com` | **same** | `DeviceManager.java:40` `CUSTOMER_SPECIFIC_ENDPOINT` |
| IoT policy | `RangeHoodPolicy` | **same** | `DeviceManager.java:42` `POLICY_NAME` (this is what `attachPolicy` uses) |
| Device API base | `https://zephyr-prod-app.gemteks.com/prod` | **same** | `RangeHoodAPPClient.java:26` `@Service(endpoint=…)` |

### 2.2 Production — additions (not in `const.py`, no conflict)

| Key | Android value | Source / notes |
|---|---|---|
| Cognito Hosted UI domain | `rangehoodprod.auth.us-west-2.amazoncognito.com` | `awsconfiguration.json` `Auth.Default.OAuth.WebDomain`. Used for Alexa/Google account linking (login with the Zephyr Connect account), not for the app's own username/password SRP path. |
| OAuth scopes | `phone`, `email`, `openid`, `profile`, `aws.cognito.signin.user.admin` | same file |
| Leftover policy constant | `AwsIotDemo` | `DeviceManager.java:39` `AWS_IOT_POLICY_NAME`. **Unused.** `policyName` defaults to `RangeHoodPolicy`. |
| MQTT client ID | `{thingName}{UUID}` with no separator | `DeviceManager.java:175`. Different *shape* from the library's `{identity_id}{suffix}-{thingName}`, but not a constant mismatch. Android logs the identity ID and then ignores it for the client ID. |
| MQTT keepalive | 5 seconds | `DeviceManager.java:221` |
| MQTT QoS | 0 | subscribe and publish |
| Shadow GET payload | empty string `""` | `Hood.java:209` — library sends `{}`; both are fine for IoT. |
| Subscribe set | `get/accepted`, `update/accepted`, `update/rejected` only | `Hood.java:408`. Library also subscribes to `update/delta` and `update/documents` (and ignores delta). Android does not. |
| Wildcard topic constant | `$aws/things/%s/shadow/+` | `DeviceManager.java:43` / `Hood.java:178`. Assigned to `HOOD_TOPIC_THING` and **never subscribed**. |

### 2.3 Dev / unused bundles (not used by this release APK)

`res/raw/awsconfiguration_dev.json` is a full second Amplify config. Nothing in the release code loads it, and both the REST client and the IoT endpoint are **hardcoded to production**, so flipping this file would still leave REST and MQTT on prod.

| Key | Dev value |
|---|---|
| User Pool | `us-west-2_GieFqJhLq` |
| App Client ID | `30gtpd7g0rooa11tlvnf3hnhj8` |
| App Client Secret | `1j8oeubblpsn2nhuqci4popcmnkamrtsfo90drs4vcopcmnaq045` (same anti-pattern: ships in the APK) |
| Identity Pool | `us-west-2:5af68ebd-5259-4409-8666-ec5884318852` |
| OAuth WebDomain | `rangehood.auth.us-west-2.amazoncognito.com` |
| Dev REST host / IoT endpoint | **not present** in this APK |

### 2.4 Other hosts (not Cognito/IoT of the hood control path)

| Host / ARN | Role |
|---|---|
| `https://sns.us-west-2.amazonaws.com` | Dead-code SNS registration (see §8). |
| SNS platform ARN `arn:aws:sns:us-west-2:008768393459:app/GCM/Rangehood` | AWS account **008768393459**, different from the vendor account `527656002764` in PROTOCOL.md §2. |
| SNS Cognito identity pool `us-west-2:1677020c-000e-458a-b5a9-67c54d120221` | Different pool from the main Identity Pool. Unauthenticated provider for the dead SNS path. |
| Firebase project `rangehoodprod` | `gcm_defaultSenderId` 721873133313; `firebase_database_url` `https://rangehoodprod.firebaseio.com`; storage `rangehoodprod.appspot.com`. FCM / analytics only. |
| `https://zephyronline.com/privacy-policy/` | Privacy policy link (`Define.URL_PRIVACY_LINK`). |
| `https://store.zephyronline.com/en/productregistration` | Warranty registration (`Define.URL_WARRANTY_REGISTRATION`). Per-device warranty/support URLs also come back from `discoverdevice`. |
| Play Store | Alexa `com.amazon.dee.app`, Google Home `com.google.android.apps.chromecast.app`, and an in-app upgrade dialog pointing at `market://details?id=com.zephyr.rangehood` (a **different** package name from `com.gemteks.rangehood`). |

No `execute-api` hostname, no `/dev` or `/stage` API Gateway stage, and no second Gemtek REST host appear in application code.

---

## 3. REST endpoint table

Base: `https://zephyr-prod-app.gemteks.com/prod`

All methods are **POST**. Auth on every call: header `Authorization: <raw Cognito ID token>` (no `Bearer `). Content-Type JSON. Built by `ApiClient.java` wrapping `RangeHoodAPPClient.java`. Typical success body is `{"message":"Success"}` (`GeneralOutput`). Token is obtained via `AWSMobileClient.getInstance().getTokens().getIdToken().getTokenString()` (`ApiClient.java:507–509`).

| Method | Path | Request body | Response (inferable) | Notes |
|---|---|---|---|---|
| POST | `/getowndevices` | **none** (interface takes only the Authorization header; same as iOS empty body) | `{message, devices:[{SN, MAC, thingName, modelName, location:{lat, lng}}]}` | Already in the library. `lat`/`lng` are `BigDecimal` here (iOS capture had them as strings). |
| POST | `/discoverdevice` | `{thingName}` | Flat document: runtime state (`power`, `light`, `fan`, `delaytimer`, `setdelaytimer`, `cleangreasefilters`, `cleancharcoalfilters`, `setrecirculating`, `setcleanairfunction`, `usegreasefiltertime`, `usecharcoalfiltertime`, `uselighttime`, `usefantime`, `faultCode[]`, `isOnline`) plus identity (`SN`, `thingName`, `MAC`, `modelName`) plus maxima (`maxFanSpeed`, `maxLightLevel`, `maxCharcoalfilterTimer`, `maxGreasefilterTimer`) plus warranty/support URLs (`laborWarranty`, `partsWarranty`, `Recirculating`, `GreaseFilterWebstoreURL`, `CharcoalFilterWebstoreURL`, `HoodCleanVideoURL`, `GreaseFilterVideoURL`, `CharcoalFilterVideoURL`, `UserManualURL`, `ProductPhotoURL`, `companyName`, `ContactURL`, `FAQURL`, `WarranyRegistrationURL` [sic]). | Already in the library. Android model does **not** declare `act`, `fanwarning`, `alarmfan`, `resetgreasefilter`, `resetcharcoalfilter`, `alarmfaultcode`, `alarmgreasefilter`, or `truHueSupport` — those may still appear on the wire (the library's iOS fixture has several of them) but this app ignores them on this endpoint. |
| POST | `/checkmodel` | `{modelName, SN}` | `{message, Recirculating, setrecirculating, thingName, registeredFirstDate, url}` | Validates a model/serial before bind or first registration; returns the thing name and a URL (warranty). |
| POST | `/uploadinfo` | `{SN, modelName, thingName, MAC, OS, IdentityId, location:{lat,lng}, setrecirculating, version, registeredFirstDate}` | `{message}` | **First registration** of a new hood. `OS` is `"Android " + Build.VERSION.RELEASE`. `version` is the device firmware string from BLE. `IdentityId` is the Cognito identity ID. `setrecirculating` is 0/1. Called from `ApiClient.registerNewDevice`. |
| POST | `/uploadbindinfo` | `{SN, modelName, thingName, OS, IdentityId, location:{lat,lng}, setrecirculating}` | `{message}` | **Bind an already-registered hood** to this account. No `MAC` / `version` / `registeredFirstDate`. |
| POST | `/unbinddevice` | `{thingName}` | `{message}` | Removes the hood from this account. Error `"This device is not yours"` → `Define.ERROR_UNBIND_NO_OWNED`. |
| POST | `/updaterecirculating` | `{thingName, SN, modelName, setrecirculating}` | `{message}` | Cloud-side recirculating flag (in addition to the shadow write of `setrecirculating`). |
| POST | `/updatemobiletoken` | `{service, token}` | `{message}` | FCM registration. `service` is hardcoded **`"GCM"`**; `token` is the FCM token (`ApiClient.java:408–414`). `"Non-engineer only"` is treated as success (engineers skip push). |
| POST | `/delmobiletoken` | `{token}` | `{message}` | Unregister FCM on logout. Skipped if the user is an engineer (`Zephyr.delFCMToken`). |
| POST | `/getswitchnotify` | none (auth header only) | `{message, uid, notification}` | `notification` is 0/1. |
| POST | `/setswitchnotify` | `{notification}` | `{message}` | Enable/disable push for this account. |
| POST | `/getfaultcodedesc` | `{faultCode: [string]}` | `{message, info:[{faultCode, description}]}` | Looks up human-readable text for shadow `faultCode` values. JSON key for the list is `"info"`. |

Relevant server-side error strings the app switches on (`Define.java`, `ApiClient.handleException`): `"This device was already been bound"`, `"Need input token"`, `"No binding device"`, `"This device is not yours"`, `"You have already bound other device"`, `"The user already bound other device"`, `"Incorrect model name"`, `"SN and modelName exist"`, `"Please check the input Serial No. or Model No."`, `"Internal server error"`, `"Invalid command"`, `"Non-engineer only"`. Several of these imply **one hood per customer account**.

---

## 4. Shadow fields

### 4.1 Writes go to `state.reported` only

This confirms PROTOCOL.md §5 from the Android side.

- `AwsCommand.COMMAND_FORMAT` is exactly `{"state":{"reported":{"%s":%d}}}` (`domain/executors/command/AwsCommand.java:9`).
- Every real control command (`SetPower`, `SetFanSpeed`, `SetLightLevel`, `SetDelayOffTimer`, `SetIsCleanairfunction`, `SetIsRecirculating`, `ResetGreasefilter`, `ResetCharcoalfilter`) uses that format.
- The shadow document model `State` has **only** a `reported` field — there is no `Desired` class (`domain/models/hood/State.java`).
- Commands are published to `$aws/things/{thingName}/shadow/update` (`domain/core/models/device/Command.java:46`).
- An engineer debug screen can also publish `{"state":{"reported":{"isOnline":1}}}` / `{"isOnline":0}` (`EngineerActivity.java:153–157`).

`SetResetToDefault` is the only exception: it publishes the raw string `"ResetToDefault"` (not a JSON shadow document). **It has no callers** and is dead code.

### 4.2 Reported model (Android)

`domain/models/hood/Reported.java` — all integers default to `-1` (“not present”):

| Field | Type | Writable by the app? | Notes |
|---|---|---|---|
| `power` | int | yes (0/1) | |
| `light` | int | yes (0–10 ordinal) | `LightingLevelConverter`: OFF…TEN. No color / Kelvin / truHue field exists anywhere in the Android app. |
| `fan` | int | yes (0–10 ordinal) | `FanSpeedConverter`: OFF…TEN. Device max comes from `maxFanSpeed` via `discoverdevice`. |
| `delaytimer` | int | no | Device-authored countdown. |
| `setdelaytimer` | int | yes | See §13. UI presets only. |
| `isOnline` | int | engineer only | Treated as boolean (`== 1`). |
| `cleangreasefilters` | int | no | Treated as boolean. |
| `cleancharcoalfilters` | int | no | Treated as boolean. |
| `setrecirculating` | int | yes (0/1) | Also synced to REST `/updaterecirculating`. |
| `setcleanairfunction` | int | yes (0/1) | |
| `resetgreasefilter` | int | yes (writes `1`) | |
| **`resetcharcoalfilter`** | int | **yes (writes `1`)** | **New vs the library's `WRITABLE_FIELDS`.** See §13. |
| `usegreasefiltertime` | int | no | Minutes. Filter used-fraction = `used / (maxHours * 60)` (`Hood.java:341`). Replace warning when used-fraction ≥ 0.85 (`Hood.java:376–386`; `Define.FILTER_USAGE_REPLACE_WARNING = 0.15f`). Matches PROTOCOL.md. |
| `usecharcoalfiltertime` | int | no | Same formula. |
| `uselighttime` | int | no | |
| `usefantime` | int | no | |
| `faultCode` | `List<String>` | no | Looked up via `/getfaultcodedesc`. |
| **`act`** | **String** | no | See §13. Displayed raw on the My Hood screen. |
| `fanwarning` | int | no | Getter only; **never read by UI**. See §13. |
| `alarmfan` | int | no | Getter only; **never read by UI**. See §13. |

Fields present in the library's iOS-captured fixtures but **absent from the Android `Reported` model**: `alarmfaultcode`, `alarmgreasefilter`. The Android `discoverdevice` model also lacks `truHueSupport` (the library already parses it from the iOS capture as `supports_tru_hue`).

Recommended library change: add `resetcharcoalfilter` to `WRITABLE_FIELDS` and `DANGEROUS_FIELDS` (it zeroes `usecharcoalfiltertime`, same class of unrecoverable counter as `resetgreasefilter`).

---

## 5. MQTT topics

Only classic device-shadow topics. No custom telemetry or command topics.

```
$aws/things/{thingName}/shadow/get              pub  (payload: empty string)
$aws/things/{thingName}/shadow/get/accepted     sub
$aws/things/{thingName}/shadow/get/rejected     defined, not subscribed
$aws/things/{thingName}/shadow/update           pub  (WRITE PATH)
$aws/things/{thingName}/shadow/update/accepted  sub
$aws/things/{thingName}/shadow/update/rejected  sub
$aws/things/{thingName}/shadow/+                constant only, never subscribed
```

Defined in `DeviceManager.java:43–49`, wired in `Hood.java:178–188, 209, 408`. No `$aws/events`, jobs, or vendor-specific topic strings appear under `com.gemteks`.

Policy attach is the same as the library: `iot.attachPolicy(policyName="RangeHoodPolicy", target=identityId)` on every MQTT init (`DeviceManager.java:149–155`).

---

## 6. BLE provisioning

There is **no local LAN / HTTP API**. Provisioning is BLE only. Device advertising name prefix: `ZEPHYR` (`BLEDefine.DEVICE_NAME_PREFIX`). Scan filters for service UUID `SERVICE_TRANSPARENT`.

### 6.1 GATT services and characteristics

`domain/interactor/bluetooth/utility/BLEDefine.java`, mapped in `BLEManager.displayGattServices` (lines 433–481).

**ISSC / Microchip Transparent UART** (well-known 49535343-… UUIDs):

| Role | UUID |
|---|---|
| Service `SERVICE_TRANSPARENT` | `49535343-fe7d-4ae5-8fa9-9fafd205e455` |
| Write `CHAR_WRITE` (`customWriteStatusChar`) | `49535343-8841-43f4-a8d4-ecbe34729bb3` |
| Read / notify `CHAR_READ` | `49535343-1e4d-4bd9-ba61-23c647249616` |
| Alternate notify `CHAR_NEW` | `49535343-4c8a-39b3-2f49-511cff073b7e` |
| CCCD | `00002902-0000-1000-8000-00805f9b34fb` |
| Generic Access | `00001800-0000-1000-8000-00805f9b34fb` |

**Wi-Fi scan service:**

| Role | UUID |
|---|---|
| Service `SERVICE_WIFI_SCAN` | `fb8c0001-d224-11e4-85a1-0002a5d5c51b` |
| Scan mode (write 0x01 to start; notify 0=INIT, 1=SCANING, 2=DONE) `CHAR_SCAN_MODE` | `fb8c0002-d224-11e4-85a1-0002a5d5c51b` |
| AP count `CHAR_AP_COUNT` | `fb8c0003-d224-11e4-85a1-0002a5d5c51b` |
| AP detail slots `CHAR_AP_DETAIL_1`…`_15` | `fb8c0100-d224-11e4-85a1-0002a5d5c51b` … `fb8c010e-…` |

**Wi-Fi connect / credential (7788-…, no named service UUID in the app — discovered by characteristic UUID):**

| Role | UUID |
|---|---|
| Connect status notify/write `CHAR_CONNECT_STATUS` (0=DISCONNECTED, 1=CONNECTING or DO_CONNECT, 2=CONNECTED) | `77880002-d229-11e4-8689-0002a5d5c51b` |
| AP param (write 98-byte credential blob; read current AP; notify “set wifi done”) `CHAR_AP_PARAM_STATUS` | `77880003-d229-11e4-8689-0002a5d5c51b` |

### 6.2 Transparent-UART frame format

Built by `domain/interactor/bluetooth/data/Command.toByte()`:

```
[0]     0xFE    header  (TRANSPARENT_CMD_HEADER = -2)
[1]     action  (see below)
[2]     N       length of values
[3..3+N)        values (omitted if N=0)
[3+N]   checksum  (action + N + sum(values)) & 0xFF
[3+N+1] 0xFF    end     (TRANSPARENT_CMD_END = -1)
```

Empty-values form (used for requests): `{0xFE, action, 0x00, action, 0xFF}` (checksum equals action when N=0).

| Action (signed / hex) | Name | Direction |
|---|---|---|
| -94 / `0xA2` | `TRANSPARENT_CMD_ACTION_REQUEST_THING_NAME_AND_DEVICE_VERSION` | app → device |
| -95 / `0xA1` | `TRANSPARENT_CMD_ACTION_SETTING_WIFI` | app → device (`changeToProvisionCmd`; used in the engineer screen, not the consumer bind flow) |
| -78 / `0xB2` | `TRANSPARENT_CMD_ACTION_REQUEST_THING_NAME_RESPONSE` | device → app |
| -77 / `0xB3` | `TRANSPARENT_CMD_ACTION_REQUEST_DEVICE_VERSION_RESPONSE` | nested in the 0xB2 frame |
| -75 / `0xB5` | `TRANSPARENT_CMD_ACTION_REQUEST_DEVICE_MAC_RESPONSE` | nested in the 0xB2 frame |
| -79 / `0xB1` | `TRANSPARENT_CMD_ACTION_SETTING_WIFI_RESPONSE` | device → app (logged only) |
| -76 / `0xB4` | `TRANSPARENT_CMD_ACTION_KEEP_ALIVE` | device → app (logged only) |

Constant `CMD_CHANGE_TO_PROVISION = "S"` is defined and **never used**; `changeToProvisionCmd` sends a 0xA1 frame instead.

**Thing-name / version / MAC response** (`BLEManager.parseThingNameAndDeviceVersionAndMacAddress`, lines 399–430), parsed from the full 0xFE-framed buffer when action is 0xB2:

```
[0]=0xFE  [1]=0xB2  [2]=thingNameLen  [3..]=thingName bytes
          then at 3+thingNameLen:  0xB3, versionLen, version bytes
          then:                    0xB5, macLen, mac bytes
```

Thing name is rendered as lowercase hex (`getStringByByte`); version as `XX.XX.XX` (`getVersionByByte`); MAC as lowercase `xx:xx:…` (`getMacAddressByByte`). These three are stored in SharedPreferences and later sent to `/uploadinfo`.

### 6.3 Wi-Fi credential payload

`AccessPointProvData.serialise()` — **98-byte** blob written to `CHAR_AP_PARAM_STATUS`:

```
[0]      security   1=open/NONE, 2=WPA, 3=WEP   (ApSecurityType.ordinal(); WifiItem.Security uses the same numbers)
[1]      ssidLen    min(len, 32)
[2..33]  ssid       UTF-8, padded with zeros
[34]     keyLen     min(len, 63)
[35..97] key        UTF-8, padded with zeros
```

WEP keys of length 5 or 13 are hex-expanded first; length 10 or 26 are used as-is.

AP scan records (`AccessPointScanData` constructor from a detail characteristic):

```
[0] security  [1] rssi (7-bit)  [2] ssidLen  [3..] ssid
```

### 6.4 Consumer provision flow

1. BLE scan for `SERVICE_TRANSPARENT` / name prefix `ZEPHYR`; connect; optionally bond; discover GATT; enable notifications.
2. `startScanWifi()`: write `0x01` to `CHAR_SCAN_MODE`. On notify `DONE` (2), read `CHAR_AP_COUNT`, then each `CHAR_AP_DETAIL_*`.
3. User picks an SSID and enters a password.
4. `setWifiToDevice` → `setWifiBean`: write the 98-byte blob to `CHAR_AP_PARAM_STATUS`. The characteristic notifies “set wifi done”. The production bind flow does **not** call `connectToWifi()` (write `0x01` to `CHAR_CONNECT_STATUS`); that write exists only on the engineer debug screen. The app observes `CHAR_CONNECT_STATUS` notifications (0/1/2) to learn when the hood has joined Wi-Fi.
5. `requestThingNameAndDeviceVersion()`: 0xA2 frame on `CHAR_WRITE`; parse the 0xB2 compound response.
6. Cloud: `checkmodel`, then either `/uploadinfo` (first registration) or `/uploadbindinfo` (bind existing).

---

## 7. Local LAN API

**None.** No `192.168`, `10.0.`, SoftAP HTTP, or device-local `OkHttp`/`HttpURLConnection` calls under `com.gemteks`. This agrees with PROTOCOL.md §1: all runtime control is cloud/MQTT. BLE is used only for Wi-Fi provisioning, thing-name/version/MAC readout, and “change Wi-Fi” from settings.

---

## 8. Push (FCM)

**Live path**

1. `ZephyrFirebaseMessagingService.onNewToken` saves the FCM token and calls `Zephyr.updateFCMToken`.
2. That is `POST /updatemobiletoken` with `{"service":"GCM","token":"<fcm token>"}` and the raw ID token (`ApiClient.java:408–414`, `Zephyr.java:726–728`).
3. Logout calls `POST /delmobiletoken` with `{"token":"…"}` (skipped for engineer accounts).
4. Incoming messages use Amazon Pinpoint keys: `pinpoint.notification.title`, `pinpoint.notification.body`, `pinpoint.jsonBody`.
5. `pinpoint.jsonBody` is `{"type": …}` (`PinpointJson`). The `type` is one of:
   - `"fanwarning"` → open the Home pager (`Define.NotificationPage.HOME`)
   - `"filters"` → My Hood (`MYHOOD`)
   - `"faultcode"` → Support (`SUPPORT`)
6. Account-level on/off is `GET`-style `POST /getswitchnotify` and `POST /setswitchnotify` with `{notification: 0|1}`.

**Dead path (no callers)**

`ZephyrFirebaseMessagingService.sendRegistrationToServer` (line 103) would `CreatePlatformEndpoint` against `arn:aws:sns:us-west-2:008768393459:app/GCM/Rangehood` using a *different* Cognito identity pool (`us-west-2:1677020c-000e-458a-b5a9-67c54d120221`). The method is never called. The live registration path is the vendor REST endpoint above.

---

## 9. Alexa / Google linking

**No Gemtek REST endpoint** for skill linking. The in-app flow is tutorial UI only:

- `Define.ALEXA_PACKAGE_NAME = "com.amazon.dee.app"` and `GOOGLE_HOME_PACKAGE_NAME = "com.google.android.apps.chromecast.app"`, opened via Play Store URLs (`BaseUtility.java:47, 57`).
- Strings (`values/strings.xml`): find the **“Zephyr Connect”** Alexa skill, tap “ENABLE TO USE”, then **“Login with Zephyr Connect App account.”** Google Home is the same idea (add device → log in with the Zephyr account).
- That login is Cognito Hosted UI on `rangehoodprod.auth.us-west-2.amazoncognito.com` (the OAuth block in `awsconfiguration.json`). After linking, voice control is Amazon/Google talking to the same Cognito-authenticated backend; the Android app does not implement a linking API of its own.

---

## 10. Device share / transfer / unbind

- **Unbind:** `POST /unbinddevice` `{thingName}` — used by “Remove Hood” (`UserActivity` / `RemoveHoodDialog` / `Zephyr.unbindHoodDevice`). This is the only ownership-transfer-like call.
- **Share / transfer / invite:** **no endpoints, no UI, no strings.** Error copy (`"You have already bound other device"`, `"The user already bound other device"`) indicates a **one-hood-per-account** policy: to move a hood, unbind it and bind it on the other account (`/uploadbindinfo`), after `checkmodel`.

---

## 11. Firmware / OTA

**No device OTA / firmware-update endpoint and no firmware MQTT topic.** Firmware version is read once over BLE during provision (`0xA2` / nested `0xB3`) and uploaded as `version` on `/uploadinfo`. It is cached as `SpfsCurrentDeviceVersion`.

In-app “upgrade” dialogs are for the **Android app itself**, linking to `market://details?id=com.zephyr.rangehood`.

---

## 12. Account delete / password

All account operations are **Cognito via `AWSMobileClient`**, in `AuthRepository.java`. There is **no vendor REST account API** and **no delete-account UI or `deleteUser` call**.

| Action | Implementation |
|---|---|
| Sign up | `AWSMobileClient.signUp` (email attribute); confirm with a code; resend |
| Sign in | `AWSMobileClient.signIn` (SRP; `USER_PASSWORD_AUTH` is not used, consistent with PROTOCOL.md §3.1) |
| Sign out | `AWSMobileClient.signOut` + `IdentityManager.signOut`; also `/delmobiletoken` |
| Change password | `AWSMobileClient.changePassword(old, new)` — `ChangePasswordActivity`. String `password_length_validation_failed`: “Password should have 6 or more characters.” |
| Forgot password | `AWSMobileClient.forgotPassword` + `confirmForgotPassword(code, newPassword)` — `ForgetPasswordActivity`, `ResetPasswordActivity` |
| Delete account | **not implemented** |

---

## 13. PROTOCOL.md §7 gaps — resolved and unresolved

### Resolved

**3. Charcoal filter reset — resolved.** The field is **`resetcharcoalfilter`**. The app has a dedicated command and a “reset charcoal filter” button on the My Hood screen.

- Write: `{"state":{"reported":{"resetcharcoalfilter":1}}}` (`ResetCharcoalfilter.java:19–22, 27`).
- The field is also on the shadow `Reported` model (`Reported.java:46–47`).
- UI: `MyHoodFragment.java` binds `btnResetCharcoalFilter` → `MyHoodViewModel.resetCharcoalfilter()` (lines 105, 295–306, 344–356).
- Same danger class as `resetgreasefilter`: it is intended to zero `usecharcoalfiltertime`. Do not fire it casually. Add it to `WRITABLE_FIELDS` and `DANGEROUS_FIELDS`.

**2. `act` — meaning resolved; other values still not enumerated.** `act` is **Airflow Control Technology**, an installer-configured make-up-air mode. The My Hood screen shows a row labeled “ACT” and displays the **raw shadow string** in `tv_act_enable` (`LayoutMyHoodBindingImpl.java:315, 523`; layout `layout_my_hood.xml` ids `tv_act`, `tv_act_enable`). Help text (`strings.xml` `information_act_info`):

> Airflow Control Technology may have been enabled by the installer to meet local make-up air codes. If the status is Disabled it means your hood is set to the default factory setting.

So `"Disabled"` is the factory default (ACT off). The app never compares the string, never writes `act`, and has no enum. Other values, if the installer enables it, would appear as whatever the device reports — they are not in this APK. Treat it as a free-form status string; `"Disabled"` is the one documented value. This is enough to document the field; it is not enough to build a closed enum.

**Desired vs reported — resolved (confirms §5).** Android writes **only** `state.reported`. See §4.1.

**truHue / light color — resolved for this app: there are none.** Lighting is an integer level 0–10 (`LightingLevelConverter`). No color, Kelvin, RGB, or `truHue` field, command, or UI exists in v1.1.16. The library already reads `truHueSupport` from `discoverdevice` (iOS fixture); Android's `DiscoverDeviceOutput` simply does not declare that key. If a future hood supports Tru-Hue, this Android build cannot control it.

**Push registration endpoint — resolved.** `POST https://zephyr-prod-app.gemteks.com/prod/updatemobiletoken` with `{service:"GCM", token}` and raw ID token. Unregister: `/delmobiletoken`. See §8.

**Alexa / Google — resolved.** No vendor linking API; Cognito Hosted UI + official Alexa/Google Home apps. See §9.

**Share / transfer / unbind — resolved.** Only `/unbinddevice`. No share/transfer. See §10.

**Firmware / OTA — resolved.** No device OTA. Version is BLE-only, uploaded on `/uploadinfo`. See §11.

**Account delete / password — resolved.** Password change and forgot-password are Cognito; there is no account-delete flow. See §12.

**BLE provisioning and local LAN — resolved.** Full BLE protocol in §6. No LAN API (§7).

**Other MQTT topics — resolved.** None beyond classic `$aws/things/{thing}/shadow/*` (§5).

### Partially resolved

**1. `setdelaytimer` ceiling — app write max known; device ceiling still unprobed.**

`DelayOffTimerConverter.java`: `TIME_PERIOD = 300` seconds. The UI enum is only `MiN_0`, `MIN_5`, `MIN_10`, and `toInt` is `ordinal() * 300`. The Android app therefore **writes only 0, 300, or 600 seconds**. Display snapping: `value/300` rounded up, then capped at `MIN_10` — a device reporting 3600 would *display* as 10 minutes.

This does **not** answer the device-side ceiling. PROTOCOL.md already established that 3600 is accepted off-preset. The Android code does not probe or enforce a device max. The gap “what happens above 3600” remains a live experiment (one attended write).

**4. `fanwarning` vs `alarmfan` — only partially explained.**

Both are `int` fields on `Reported` with getters and a `toString`, and **neither is read by any UI or business logic**. Independently, `"fanwarning"` is a **Pinpoint push `type`** that navigates to the Home page (`Define.NotificationPage.HOME`). There is no push type named `"alarmfan"`. So:

- `fanwarning` as a *notification category* means “go to the Home / fan screen.”
- What the *shadow integers* `fanwarning` and `alarmfan` mean when they become non-zero, and how they differ, is still unknown. Record both if either trips, as PROTOCOL.md already says.

### Unresolved (unchanged)

**5. `resetgreasefilter` live effect** — deliberately deferred (runbook step 9). The Android write is the same as the library already implements: `{"state":{"reported":{"resetgreasefilter":1}}}`.

---

## 14. Other notes useful to the library

- **New REST surface to implement if desired:** `/checkmodel`, `/uploadinfo`, `/uploadbindinfo`, `/unbinddevice`, `/updaterecirculating`, `/updatemobiletoken`, `/delmobiletoken`, `/getswitchnotify`, `/setswitchnotify`, `/getfaultcodedesc`. Auth and host are the same as the two endpoints already in `const.py`. `/updaterecirculating` is the cloud companion to the shadow `setrecirculating` write.
- **Filter math** in `Hood.java` agrees with PROTOCOL.md: used fraction = `usegreasefiltertime / (maxGreasefilterTimer * 60)` (minutes over hours×60). Replace warning at ≥ 85% used.
- **Engineer activities** (`EngineerActivity`, `BLEengineerActivity`) are exported in the manifest and contain debug MQTT `isOnline` writes plus a hardcoded test SSID/password for BLE Wi-Fi. Not part of the consumer path.
- **AWS Android SDK version** (from `fabric/com.amazonaws.aws-android-sdk-core.properties`): 2.22.6.
