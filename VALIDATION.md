# Hardware validation runbook

The shadow write path is **unverified**. Publishing to
`$aws/things/<thing>/shadow/update` actuates a physical fan and light.
This runbook establishes what each field does, one field at a time, with
the hood attended.

Nothing in the Home Assistant integration may write to the shadow until
this is complete — three of these answers determine the entity design.

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

While it watches, press a button on the hood itself. You should see the
change appear. That confirms push updates work before you write anything.

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

## The three answers that gate the integration

Record these in `PROTOCOL.md` §7, replacing the open items.

**1. `power` semantics (from step 1 and 3).**
- Did `light=1` work on its own, or did nothing happen until `power=1`?
- When you set `power=1` alone, did the fan or light come on by itself?
- When you set `light=1`, did `power` change to 1 in the reported diff?

→ *Master switch* (light/fan need power=1): the HA fan and light entities
write `power` alongside the level, and there is no separate power entity.
→ *Derived* (power reports 1 when anything is on): read-only, not exposed.
→ *Independent standby*: gets its own `switch` entity.

**2. `setdelaytimer` units and domain (step 6).**
Try a value like 5, then 10. Watch whether `delaytimer` starts counting.
- Are the units minutes or something else?
- Does it accept arbitrary values, or snap to presets (e.g. 5/10/15)?

→ Arbitrary → HA `number` entity. Presets → HA `select` entity.

**3. Filter counter units (observable during any fan run).**
`usegreasefiltertime` is 642 against a `maxGreasefilterTimer` of 60. That
only reconciles if the counter is minutes and the max is hours (≈10.7 h
of 60 h). Run the fan for a known number of minutes and see how much
`usefantime` and `usegreasefiltertime` move.

→ Confirms the filter-life percentage formula, or corrects it.

## Also worth noting while you're there

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

**`ZephyrAuthError`.** Credentials wrong or the ID token expired.
Tokens last one hour; the library refreshes at ~50 min.

**`ZephyrCertificateError`.** The vendor's chain is no longer trusted by
either the system CA store or the bundled TWCA anchors — likely a vendor
CA rotation. Do not disable verification; recapture the chain.

**A write is accepted but nothing physically happens.** Record it. It
likely means the field needs `power=1` first, or is not the field we
think it is. That is exactly what this exercise is for.

## When you're done

Update `PROTOCOL.md` §7 with the answers, then the Home Assistant
integration plan can be written against known semantics instead of
assumptions.
