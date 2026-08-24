# pyzephyrconnect

Python client for Zephyr / Gemtek range hoods.

These hoods expose no local API. All communication is a cloud round-trip
through AWS IoT Core device shadows. See [PROTOCOL.md](PROTOCOL.md) for how
the protocol was reverse-engineered.

## Install

    pip install pyzephyrconnect

## Read state

```python
import aiohttp
from pyzephyrconnect import ZephyrClient

async with aiohttp.ClientSession() as session:
    client = ZephyrClient("you@example.com", "password", session)
    for caps in await client.async_setup():
        print(caps.model, caps.max_fan_speed)
        await client.async_start(caps.thing_name)
        print(client.state(caps.thing_name))
```

## Probe CLI

The write path actuates a physical fan and light. The CLI writes one field
at a time, refuses anything outside an allowlist, and requires `--confirm`:

    export ZEPHYR_USER=you@example.com
    python -m pyzephyrconnect --watch
    python -m pyzephyrconnect --set light=1 --confirm

Destructive writes need `--force` as well. `resetgreasefilter` zeroes a usage
counter that cannot be reconstructed.

## Status

Read path verified against a Zephyr AK7400AS. Write path is under
validation; field semantics for `act` and the units of the `use*time`
counters are not yet established.

## License

GPL-3.0-or-later
