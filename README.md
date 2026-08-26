# pyzephyrconnect

Python client for Zephyr / Gemtek range hoods.

These hoods expose no local API. All communication is a cloud round-trip
through AWS IoT Core device shadows. See [PROTOCOL.md](PROTOCOL.md) for how
the protocol was reverse-engineered.

## Install

```bash
pip install pyzephyrconnect
```

## Read state

```python
import aiohttp
from pyzephyrconnect import ZephyrClient

async with aiohttp.ClientSession() as session:
    client = ZephyrClient.from_credentials("you@example.com", "password", session)
    try:
        for hood in await client.async_setup():
            print(hood.capabilities.model, hood.capabilities.max_fan_speed)
            await hood.async_start()
            print(hood.state)
    finally:
        await client.async_stop()
```

## Persisting tokens

The library never persists credentials - storage is yours. Supply tokens
from a previous session and a callback to save new ones, and a restart
skips the SRP login entirely:

```python
from pyzephyrconnect import ZephyrClient, ZephyrTokens, ZephyrDataError

try:
    tokens = ZephyrTokens.from_dict(saved) if saved else None
except ZephyrDataError:
    # from_dict validates rather than coercing, so a corrupted or partial
    # record raises here instead of failing much later as a SECRET_HASH
    # Cognito rejects. Discard it - a full SRP login rebuilds it.
    tokens = None

client = ZephyrClient.from_credentials(
    username, password, session,
    tokens=tokens,
    token_updater=lambda t: save(t.as_dict()),
)
```

To keep the password out of the library completely, subclass `AbstractAuth`
and implement `async_get_tokens()`.

## Probe CLI

The write path actuates a physical fan and light. The CLI writes one field
at a time, refuses anything outside an allowlist, and requires `--confirm`:

```bash
export ZEPHYR_USER=you@example.com
python -m pyzephyrconnect --watch
python -m pyzephyrconnect --set light=1 --confirm
```

Destructive writes need `--force` as well. `resetgreasefilter` zeroes a usage
counter that cannot be reconstructed.

## Status

Read and write paths both verified against a Zephyr AK7400AS. `power`,
`light`, `fan`, `setdelaytimer` (seconds) and `setcleanairfunction` have
established semantics; `resetgreasefilter` ships untested by design.

Filter counters are in minutes, run-time counters in hours - see
[PROTOCOL.md](PROTOCOL.md) §5 before deriving anything from them.

Still unestablished: the `act` mode strings and the delay-timer ceiling.
See [PROTOCOL.md](PROTOCOL.md) §7.

## License

GPL-3.0-or-later
