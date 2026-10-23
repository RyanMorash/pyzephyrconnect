Quick start
===========

Requires Python 3.12 or newer.

.. code-block:: bash

   pip install pyzephyrconnect

The install pulls in ``aiohttp``, ``boto3``, ``pycognito``, and
``paho-mqtt``. You supply the :class:`aiohttp.ClientSession`; the
library does not open one for you, and it does not close yours.

.. code-block:: python

   import asyncio

   import aiohttp
   from pyzephyrconnect import ZephyrClient


   async def main() -> None:
       async with aiohttp.ClientSession() as session:
           client = ZephyrClient.from_credentials(
               "you@example.com",
               "password",
               session,
           )
           try:
               for hood in await client.async_setup():
                   print(hood.capabilities.model, hood.capabilities.max_fan_speed)
                   await hood.async_start()
                   print(hood.state)
           finally:
               await client.async_stop()


   asyncio.run(main())

:meth:`~pyzephyrconnect.client.ZephyrClient.async_setup` runs once per
client and returns one :class:`~pyzephyrconnect.hood.Hood` per device on
the account. :meth:`~pyzephyrconnect.hood.Hood.async_start` opens that
hood's push connection.
:meth:`~pyzephyrconnect.client.ZephyrClient.async_stop` closes every
hood and retires the credential supervisor. Wire it into shutdown
before you start anything: it is the reliable teardown, including when
the caller is cancelled.

Read credentials from a secret store. The snippet above uses literals
only to show the arguments.

What to read next:

* :doc:`usage` for tokens, writes, units, and errors.
* :doc:`cli` for the attended probe, which is the safest way to try a
  single field against hardware.
* :doc:`api/index` for the supported names.
