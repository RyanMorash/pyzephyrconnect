# AGENTS.md

This repository uses agent guidance documents to keep automated changes safe and aligned with project behavior.

## What this project is

`pyzephyrconnect` is an async Python client for Zephyr / Gemtek range hoods.
The devices do not expose a local API; all reads/writes are cloud round-trips via AWS IoT Core device shadows over a SigV4-presigned WebSocket.
Protocol behavior is reverse-engineered from the vendor app and documented in `PROTOCOL.md`.

## Local setup and validation

Requires Python >= 3.12.

```bash
python3.12 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

pytest
ruff check
ruff format --check
python -m build && twine check --strict dist/*
```

Notes:
- `ruff` is pinned to `0.14.14` in dev dependencies and CI; bump both together.
- CI enforces docstrings for every module/class/function/nested def in `src/` and `tests/`.
- Tests must not use the network.

## Architecture map

- `auth.py`: auth abstractions, Cognito identity exchange, AWS credential lifecycle, policy attach.
- `api.py`: vendor REST endpoints (`getowndevices`, `discoverdevice`) and vendor TLS context.
- `presign.py`: stdlib-only SigV4 presigning.
- `shadow.py`: per-hood paho MQTT client over presigned WebSocket.
- `hood.py` and `models.py`: device state + typed control/write API.
- `client.py`: orchestration and refresh supervisor.

## Protocol invariants (do not change casually)

- Writes must go to `state.reported` (not `state.desired`).
- Drop MQTT `update/delta` payloads rather than merging into state.
- Always attach IoT policy before establishing MQTT connection.
- Treat subscribe QoS `128` as denied (even if callback fires).
- Preserve MQTT client ID pattern: `<identity_id><suffix>-<thingName>`.
- Append `X-Amz-Security-Token` after signing; it is not part of canonical query.
- REST auth header uses bare ID token (no `Bearer`); `getowndevices` uses `data=b""`.
- Keep TLS verification strict; use TWCA bundle only for vendor REST host, not IoT host.
- Never let paho callbacks raise; marshal to event loop and swallow at thread boundary.

## Conventions and safety

- Protect user/location data in logs; never log thing names, full topics, or raw payloads.
- Preserve unknown state as `None` (absent does not mean zero), except defined counter fields.
- Treat filter time fields carefully (minutes vs hours semantics differ across fields).
- `const.WRITABLE_FIELDS` and `const.DANGEROUS_FIELDS` are intentional control guardrails.
- Keep comments high-signal and explanatory ("why", often with failure mode context).
- Use commit subject format: `type: summary` (`fix:`, `docs:`, `test:`, `ci:`, `refactor:`, `style:`).

## Source-of-truth docs

- `PROTOCOL.md`: protocol and observed behavior reference.
- `VALIDATION.md`: attended hardware validation notes.
- `docs/api-notes.md`: API shape and rationale.
- `CLAUDE.md`: detailed implementation and maintenance guidance used to derive this file.
