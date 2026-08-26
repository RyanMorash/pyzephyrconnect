# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`pyzephyrconnect` is an async Python client for Zephyr / Gemtek range hoods. The
hoods expose **no local API** — every read and write is a cloud round-trip through
AWS IoT Core device shadows, reached over a SigV4-presigned WebSocket. The whole
protocol was reverse-engineered from the vendor iOS app; `PROTOCOL.md` is the
record of how, and is the reference for any question about vendor behaviour.

## Commands

Requires Python ≥ 3.12 (CI matrixes 3.12 / 3.13 / 3.14).

```bash
python3.12 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

pytest                                  # full suite, ~5s, no network
pytest tests/test_client.py             # one file
pytest tests/test_client.py::test_name  # one test
pytest -k supervisor                    # by name

ruff check                              # lint (D rules on, google convention)
ruff format --check                     # CI enforces formatting too
python -m build && twine check --strict dist/*
```

`ruff` is **exact-pinned to 0.14.14** in the `dev` extra to match the
`ruff-action` pin in `.github/workflows/ci.yml`. Bump both together or local and
CI will disagree. A system-wide `ruff` is likely a different version — use the
one from the dev extra.

CI runs a fourth gate beyond lint/test/build: an inline script asserting that
**every** module, class, function, and nested def in `src/` *and* `tests/` has a
docstring, with none of ruff's private/nested exemptions. New tests need
docstrings too.

`pyproject.toml` sets `asyncio_mode = "auto"` (async tests need no
`@pytest.mark.asyncio`) and `pythonpath = ["tests"]` (tests do
`from conftest import FakeSession`).

## Architecture

Five layers, each of which can be read on its own; the interesting behaviour is
in how `client.py` wires them together.

- `auth.py` — `AbstractAuth` is the extension point: a consumer implements
  `async_get_tokens()` and inherits the Cognito identity exchange, the AWS
  credential cache, `mqtt_client_id`, and `async_attach_policy()`. `ZephyrClient`
  consumes all of those, so anything it needs must live on `AbstractAuth`, not
  on the built-in `CredentialsAuth` (SRP login), or a custom subclass type-checks
  and `AttributeError`s at runtime. pycognito/boto3 are sync and wrapped in
  `asyncio.to_thread`.
- `api.py` — the two vendor REST endpoints (`getowndevices`, `discoverdevice`)
  plus `build_ssl_context()`.
- `presign.py` — pure, stdlib-only SigV4 presigning. `now` is a parameter so
  tests are deterministic.
- `shadow.py` — one paho MQTT client per hood over the presigned WebSocket.
- `hood.py` / `models.py` — `Hood` owns one device's state *and* its controls;
  the typed `async_set_*` methods are the write allowlist made structural.

**Read strategy is hybrid by design.** `discoverdevice` supplies capabilities and
an initial state over HTTPS before MQTT exists, MQTT then carries live push, and
`discoverdevice` stays available as a fallback so a consumer degrades to slow
polling instead of going unavailable.

**The refresh supervisor (`ZephyrClient._supervise`) is the load-bearing piece.**
The presigned URL embeds a signature over credentials that expire in an hour; AWS
IoT drops the session at expiry and paho then reconnects to the same dead URL
forever. The supervisor ticks every 60s and rebuilds sockets first. Two
non-obvious rules govern it:

- Sockets are rebuilt on **credential *generation* mismatch**, never on expiry
  alone. Any REST call refreshes the credential cache as a side effect, so the
  cache can look fresh while every live socket still carries a signature signed
  under the old, soon-dead credentials. `AbstractAuth.credentials_generation` is
  a monotonic counter bumped wherever fresh credentials are installed;
  `Hood.needs_represign()` compares against it.
- `ZephyrAuthError` and `ZephyrPolicyError` are **terminal** — they stop the
  supervisor, stop the hoods, and are stored so the next `Hood.async_poll()`
  re-raises them (as a fresh instance, to avoid unbounded traceback growth).
  Everything else is retried next tick. Wrapping a DNS blip in `ZephyrAuthError`
  turns a Wi-Fi hiccup into a reauth prompt.

`async_setup()` runs **once per client** and is lock-serialised; re-discovering
means building a new client.

## Protocol invariants — do not "fix" these

Most failure modes in this protocol are *silent*: the call succeeds, and nothing
happens. Each of these was paid for once already.

- **Writes go to `state.reported`, never `state.desired`.** Backwards from the
  AWS convention, but it is what this hardware acts on. `desired` writes are
  accepted by AWS and silently ignored by the device.
- **`update/delta` messages are dropped, not merged** (debug-logged only). A
  delta is a wish, never device-authored state.
- **`async_attach_policy()` must precede `connect()`.** An open connection never
  picks up newly attached permissions; without the policy, connect, subscribe and
  publish all succeed and every message is silently dropped (PROTOCOL.md §3.3).
  The latch is keyed on *which* identity it was attached for, not a bool.
- **A denied subscribe still fires `on_subscribe`.** Granted QoS `128` means
  denied — check `reason_code_list` explicitly.
- **MQTT client ID = `<identity_id><suffix>-<thingName>`.** Two live connections
  sharing an ID make AWS IoT evict one for the other, forever. Keep the
  `us-west-2:` region prefix; keep the whole thing under 128 chars. Consumers set
  their own `client_id_suffix` (default `-py`) so they don't evict the phone app
  or each other.
- **`X-Amz-Security-Token` is appended *after* signing** and is not part of the
  canonical query string.
- **REST takes a bare ID token** in `Authorization` — no `Bearer ` prefix — and
  `getowndevices` is POSTed with a zero-length body (`data=b""`), not `{}`.
- **TLS:** the vendor REST host's intermediate omits the Subject Key Identifier,
  so the bundled TWCA certs are added as *supplementary* anchors on top of system
  trust. Never pin, never disable verification, never lower `verify_mode`. The
  IoT endpoint chains to Amazon Root CA 1 and uses a plain default context — do
  not reuse the TWCA one there.
- **paho callbacks run on its network thread and must never raise** — an escaped
  exception kills the thread and updates just stop. Marshal onto the loop with
  `call_soon_threadsafe` and swallow at the boundary. Use `tls_set_context()`
  with a context built in a worker thread, not `tls_set()` (which blocks the
  event loop loading default certs).

## Conventions

**Log hygiene is a hard rule.** `thingName`, `SN`, `MAC` and `location` identify
a home and its owner, and `getowndevices` returns precise coordinates. Never log
a thing name, a full topic, or a raw payload — log the topic's leaf segment
(`accepted`/`delta`/`rejected`) only, and the exception *type* rather than its
message where the text may name a policy. `_PERSONAL_DATA_KEYS` in `client.py`
filters those keys out of any `HoodState.raw` built from `discoverdevice`
(shadow messages arrive already clean).

**Absent is not zero.** `HoodState` fields default to `None` for "unknown"; a
missing `alarmfaultcode` is not "no fault". The four usage counters are the
deliberate exception — zero is their real starting value.

**Units are a 60x trap.** Filter counters (`usegreasefiltertime`,
`usecharcoalfiltertime`) are *minutes*; their capability maxima and
`usefantime`/`uselighttime` are *hours*. See PROTOCOL.md §5 before deriving
anything.

**No test touches the network.** `tests/conftest.py` fakes aiohttp; pycognito and
boto3 are `MagicMock`ed via monkeypatch. The supervisor is driven through
`_run_supervisor_ticks` rather than real sleeps. A CI failure here is always
real, never flaky — preserve that.

**The write path actuates a physical fan and light.** `const.WRITABLE_FIELDS` is
the allowlist and `const.DANGEROUS_FIELDS` the extra speed bump; the probe CLI
(`python -m pyzephyrconnect`) requires `--confirm`, and `--force` on top for
destructive fields. `resetgreasefilter` zeroes a counter that cannot be
reconstructed and ships untested by design.

**Version lives in two places** — `pyproject.toml` and
`src/pyzephyrconnect/__init__.py` — and CI fails the build if they disagree, or
if the release tag doesn't match. The cert bundle must appear in the wheel
exactly once (a duplicate `force-include` is a hard hatchling error).

**Code comments here explain *why*, at length, usually naming the failure that
would occur otherwise.** That density is deliberate — match it when touching this
code rather than trimming it. Commits follow `type: summary`
(`fix:`, `docs:`, `test:`, `ci:`, `refactor:`, `style:`).

## Where the knowledge lives

- `PROTOCOL.md` — the protocol reference: auth chain, topics, field semantics,
  failure modes seen and what they meant (§6), open items (§7), security findings
  (§8, including the standing instruction to *not* probe other customers' things).
- `VALIDATION.md` — the attended-hardware runbook, and the answers it established.
- `docs/api-notes.md` — the 0.1.0 API shape and the rationale behind it.
- Still unestablished: the `act` mode strings and the delay-timer ceiling above
  3600s. Don't document either as known.
