# Hardware validation runbook

> **Status: run against the reference hood (`AK7400AS`), except step 9.**
> The answers are recorded in `PROTOCOL.md` §5, and what remains genuinely
> unknown is `PROTOCOL.md` §7. Step 9 (`resetgreasefilter`) is deliberately
> deferred until the grease filter is actually being cleaned — see below.
>
> The write path is no longer unverified, and the earlier blanket rule that
> nothing may write to the shadow is lifted. Publishing to
> `$aws/things/<thing>/shadow/update` still actuates a physical fan and
> light, so writes stay attended and field names stay validated against
> observed `reported` values.
>
> Keep this document. It is the procedure to re-run on another model, and
> the same sequence answers the §7 items that are still open.

This runbook establishes what each field does, one field at a time, with
the hood attended.

## Before you start

```bash
cd ~/Developer/pyzephyrconnect
export ZEPHYR_USER=you@example.com
export ZEPHYR_PASS='...'          # or omit and be prompted
```

Stand where you can see and hear the hood. Have the vendor app closed, or
accept that it may briefly contend (the library uses a distinct MQTT
client ID suffix, so they should coexist).

## Step 0 — read-only smoke test (no writes)

Proves auth, the SigV4 presigned handshake, policy attach, and the shadow
read all work end to end. **This is also the first real-world proof that
`presign.py` is correct** — its unit tests pin structure and the AWS
key-derivation vector, but only a live handshake proves the full
signature.

```bash
python -m pyzephyrconnect --watch --seconds 30
```

Expect: device line (model, fan 0-6, light 0-3), then the current state
dump with identifiers redacted. If the connection is refused or nothing
arrives, stop — see Troubleshooting.

While it watches, press a button on the hood itself. The watch window is
not a live stream — when it ends, the CLI prints a before/after diff, and
your button press should appear in it. That confirms push updates work
before you write anything.

## The sequence

One field per invocation. Record the reported diff each time — the CLI
prints it for you. Most reversible first.

| # | Command | Establishes | Risk |
|---|---|---|---|
| 1 | `--set light=1 --confirm` | Write path works at all; whether `power` gates it | none |
| 2 | `--set light=2 --confirm` then `light=3`, then `light=0` | Level range maps to `maxLightLevel` | none |
| 3 | `--set power=1 --confirm` then `power=0` | Master switch, derived, or standby | low |
| 4 | `--set fan=1 --confirm` | Fan actuates | audible |
| 5 | `--set fan=6 --confirm` then `fan=0` | Range matches `maxFanSpeed` | loud |
| 6 | `--set setdelaytimer=N --confirm` | Units — watch `delaytimer` count down | low |
| 7 | `--set setcleanairfunction=1 --confirm` then `0` | Toggles | low |
| 8 | `--set setrecirculating=1 --confirm --force` | Ducted ↔ recirculating | **changes filter accounting — set it back** |
| 9 | `--set resetgreasefilter=1 --confirm --force` | Reset works | **destructive — see below** |

Destructive fields require `--force` in addition to `--confirm`. That is
deliberate friction, not a bug.

### Step 9 is deferred

`resetgreasefilter` zeroes `usegreasefiltertime`, which is currently 642
and cannot be reconstructed. **Do not run step 9 until you are actually
cleaning the grease filter.** Everything else can proceed without it.

## The three answers that gated the integration — ANSWERED

Full detail in `PROTOCOL.md` §5. Summarised here so the runbook reads as a
record of what happened.

**1. `power` — master switch with memory, not a precondition.**
Writing `0` turns everything off; writing `1` restores the levels that were
running before (observed restoring fan 6 and light 1 together). `fan` and
`light` write through directly while `power` reads `0`, and the device
raises `power` itself.

→ Power gets its own `switch` entity, and the fan and light entities must
**not** write `power` alongside the level.

**2. `setdelaytimer` — seconds, not preset-snapped.**
Not minutes. The vendor app's two presets are a UI choice rather than a
device constraint: values off the presets are accepted, proven up to 3600
seconds. The device derives `delaytimer` and counts it down itself in
60-second steps, reporting about once a minute.

→ HA `number` entity, converting minutes to seconds on write, and carrying
its own maximum — the device's ceiling is unprobed (`PROTOCOL.md` §7), so
the entity bound is a UI cap, not a known device limit.

**3. Filter counters — minutes, against a maximum in hours.**
Confirmed, and cross-checked against the vendor app rather than inferred:
643 minutes against a 60-hour life is 82.1%, and the app displays 82%.

```
remaining = 1 - used_minutes / (life_hours * 60)
```

→ Note the scope. This settles the **filter** counters,
`usegreasefiltertime` and `usecharcoalfiltertime`.

**Bonus answer — the run-time counters are hours.** `usefantime` and
`uselighttime` are separate fields on a different unit. They held flat
across five minutes of running while `usegreasefiltertime` moved (so: not
minutes), and the readings reconcile with the hood's approximate age and
usage on hours rather than on any finer tick. That is an estimate against
known usage rather than a timed measurement — enough for the 60x question,
and worth a confirming glance if the vendor app ever shows a runtime
figure. Recorded in `PROTOCOL.md` §5.

Careful here: filter counters are **minutes**, run-time counters are
**hours**. They sit next to each other in the same payload.

## Also worth noting while you're there

Answered in passing: **`setcleanairfunction` is an operating mode, not a
setting** — enabling it starts the fan at speed 1.

Still open (and see `PROTOCOL.md` §7 for the rest):

- **`act`** currently reads `"Disabled"`. Does it ever change? Watch it
  during steps 3-7 and record any other value you see.
- **Charcoal filter reset:** there is no `resetcharcoalfilter` field in
  the shadow. If your hood has a charcoal reset in the vendor app, watch
  `update/accepted` while pressing it there — it may reuse
  `resetgreasefilter`, or be app-side only.
- **`fanwarning` vs `alarmfan`:** if either ever trips, note what
  distinguishes them.

## Troubleshooting

**Connect succeeds but nothing arrives.** The IoT policy is not attached
to your Cognito identity. The library attaches it before connecting and
raises `ZephyrPolicyError` on a denied subscribe, so you should see a
clear error rather than silence — if you get silence instead, that is a
bug worth reporting.

**`ZephyrAuthError`.** Credentials wrong, or both the refresh token and a
fresh SRP login failed. Tokens last one hour; the library refreshes them in
the request path and rebuilds the MQTT socket before they expire.

**`ZephyrCertificateError`.** The vendor's chain is no longer trusted by
either the system CA store or the bundled TWCA anchors — likely a vendor
CA rotation. Do not disable verification; recapture the chain.

**A write is accepted but nothing physically happens.** Record it. On the
reference hood `power` is *not* a precondition — `fan` and `light` actuate
while `power` reads `0` — so this is more likely a field that is not what we
think it is, or a model that behaves differently. That is exactly what this
exercise is for.

## When you're done

Record answers in `PROTOCOL.md` §5 and strike the corresponding item from
§7. That has been done for the three gating questions above; §7 now lists
only what is still unknown.
