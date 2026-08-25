"""Probe CLI for mapping the shadow write path.

The write path is unverified and actuates a physical fan and light. This
tool exists so field semantics can be established one field at a time, with
the device attended, before any of it reaches an automation platform.

    python -m pyzephyrconnect --watch
    python -m pyzephyrconnect --set light=1 --confirm
    python -m pyzephyrconnect --set resetgreasefilter=1 --confirm --force
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import logging
import os
import sys
from typing import Any

import aiohttp

from . import const
from .client import ZephyrClient

_LOGGER = logging.getLogger(__name__)

# Keys never echoed to the terminal - they identify a home and its owner.
_REDACT = {"thingName", "SN", "MAC", "location"}


def parse_assignment(text: str) -> tuple[str, int]:
    """Parse `field=value`. Values are integers; the shadow has no others
    among the writable fields."""
    if text.count("=") != 1:
        raise ValueError(f"expected field=value, got {text!r}")
    field, _, raw = text.partition("=")
    field, raw = field.strip(), raw.strip()
    if not field or not raw:
        raise ValueError(f"expected field=value, got {text!r}")
    try:
        return field, int(raw)
    except ValueError as err:
        raise ValueError(f"value must be an integer, got {raw!r}") from err


def validate_write(field: str, *, confirmed: bool, forced: bool) -> None:
    """Raise unless this write is permitted. Order matters: report an
    unwritable field before complaining about missing flags."""
    if field not in const.WRITABLE_FIELDS:
        raise PermissionError(
            f"{field!r} is not writable. Allowed: "
            f"{', '.join(sorted(const.WRITABLE_FIELDS))}"
        )
    if not confirmed:
        raise PermissionError(
            f"refusing to write {field!r} without --confirm; this actuates "
            "hardware"
        )
    if field in const.DANGEROUS_FIELDS and not forced:
        raise PermissionError(
            f"{field!r} is destructive or changes device configuration; "
            "pass --force as well as --confirm"
        )


def diff_states(
    before: dict[str, Any], after: dict[str, Any]
) -> dict[str, tuple[Any, Any]]:
    """Changed keys as {key: (before, after)}. Absent-before reads as None."""
    return {
        key: (before.get(key), after.get(key))
        for key in set(before) | set(after)
        if before.get(key) != after.get(key)
    }


def _redacted(payload: dict[str, Any]) -> dict[str, Any]:
    return {k: ("<redacted>" if k in _REDACT else v) for k, v in payload.items()}


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pyzephyrconnect",
        description="Read and probe a Zephyr range hood's device shadow.",
    )
    parser.add_argument("--watch", action="store_true",
                        help="stream shadow updates until interrupted")
    parser.add_argument("--seconds", type=int, default=300,
                        help="how long --watch listens (default: 300)")
    parser.add_argument("--set", dest="assignment", metavar="FIELD=VALUE",
                        help="write one field to the shadow")
    parser.add_argument("--confirm", action="store_true",
                        help="required for any write; actuates hardware")
    parser.add_argument("--force", action="store_true",
                        help="additionally required for destructive writes")
    parser.add_argument("--thing", help="thing name (default: first device)")
    parser.add_argument("--verbose", action="store_true")
    return parser


async def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s",
    )

    field = value = None
    if args.assignment:
        try:
            field, value = parse_assignment(args.assignment)
            validate_write(field, confirmed=args.confirm, forced=args.force)
        except (ValueError, PermissionError) as err:
            print(f"error: {err}", file=sys.stderr)
            return 2

    username = os.environ.get("ZEPHYR_USER") or input("email: ")
    password = os.environ.get("ZEPHYR_PASS") or getpass.getpass("password: ")

    async with aiohttp.ClientSession() as session:
        client = ZephyrClient.from_credentials(username, password, session)
        hoods = await client.async_setup()
        if not hoods:
            print("no devices on this account", file=sys.stderr)
            return 1

        if args.thing:
            hood = next((h for h in hoods if h.thing_name == args.thing), None)
            if hood is None:
                # Do not echo the available thing names here - they are
                # device identifiers.
                print("error: no device matches --thing", file=sys.stderr)
                return 2
        else:
            hood = hoods[0]
        caps = hood.capabilities
        print(f"device: {caps.model} (fan 0-{caps.max_fan_speed}, "
              f"light 0-{caps.max_light_level})")

        try:
            await hood.async_start()
            await asyncio.sleep(2)

            before = dict(hood.state.raw)
            print("current state:")
            print(json.dumps(_redacted(before), indent=2, sort_keys=True))

            if field is None:
                if args.watch:
                    print(f"watching for {args.seconds}s (ctrl-c to stop)")
                    try:
                        await asyncio.sleep(args.seconds)
                    except asyncio.CancelledError:
                        pass
                    after = dict(hood.state.raw)
                    _report(diff_states(_redacted(before), _redacted(after)))
                return 0

            print(f"\nWRITING {field}={value} to a physical appliance.")
            await hood.async_set_fields({field: value})

            await asyncio.sleep(5)
            after = dict(hood.state.raw)
            _report(diff_states(_redacted(before), _redacted(after)))
            return 0
        finally:
            await client.async_stop()


def _report(changes: dict[str, tuple[Any, Any]]) -> None:
    if not changes:
        print("\nno reported change. The device may have ignored the write, "
              "or it may not echo this field.")
        return
    print("\nchanged:")
    for key, (old, new) in sorted(changes.items()):
        print(f"  {key}: {old!r} -> {new!r}")


def run() -> int:
    try:
        return asyncio.run(main())
    except KeyboardInterrupt:
        return 130
