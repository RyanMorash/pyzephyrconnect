# Copilot Instructions

Repository instructions for Copilot agents working on `pyzephyrconnect`.

## Scope

- Use this file plus `CLAUDE.md` and `PROTOCOL.md` as the primary behavior references.
- Keep changes minimal, targeted, and consistent with existing design.

## Critical behavior constraints

- Do not replace cloud-shadow behavior with local API assumptions.
- Keep write operations on `state.reported`; do not switch to `state.desired`.
- Do not merge MQTT delta messages into state.
- Ensure IoT policy is attached before MQTT connect/subscription flow.
- Preserve MQTT client ID uniqueness rules and format.
- Do not weaken TLS verification or repurpose vendor REST TLS context for IoT.
- Keep paho callback boundaries exception-safe (never raise out of callback thread).

## Coding conventions

- Match existing style and comment density (comments explain "why", not only "what").
- Preserve privacy-safe logging: avoid thing names, full topics, and raw payload logs.
- Keep unknown state semantics (`None` for unknown, except intentional counter defaults).
- Avoid introducing network access in tests.
- Add/maintain docstrings for all modules/classes/functions/nested defs in `src/` and `tests/`.

## Validation expectations

- Use Python >= 3.12 and dev dependencies.
- Run relevant checks for your change:
  - `pytest`
  - `ruff check`
  - `ruff format --check`
  - `python -m build && twine check --strict dist/*`
- Keep Ruff version aligned with project pin (`0.14.14`) and CI workflow pin.
