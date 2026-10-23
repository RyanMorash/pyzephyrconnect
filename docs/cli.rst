Probe CLI
=========

``python -m pyzephyrconnect`` reads one account and, with an explicit
flag, writes one shadow field. The write path actuates a physical fan
and light, so the command refuses anything outside
:data:`~pyzephyrconnect.const.WRITABLE_FIELDS` and requires
``--confirm``. Destructive fields also require ``--force``.

.. code-block:: bash

   export ZEPHYR_USER=you@example.com
   export ZEPHYR_PASS='your-password'   # omit to be prompted
   python -m pyzephyrconnect --watch
   python -m pyzephyrconnect --set light=1 --confirm

``ZEPHYR_USER`` and ``ZEPHYR_PASS`` supply the account. Either one that
is unset is prompted for. The password prompt does not echo.

A ``--set`` argument is parsed and checked before credentials are read,
so a refused write exits without a login and without touching the
network.

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Option
     - Meaning
   * - ``--watch``
     - After printing the current state, wait and then print a
       before/after diff. The wait is not a live stream.
   * - ``--seconds N``
     - How long ``--watch`` waits. Default 300.
   * - ``--set FIELD=VALUE``
     - Write one integer field. Implies a real actuation.
   * - ``--confirm``
     - Required for every write.
   * - ``--force``
     - Additionally required for :data:`~pyzephyrconnect.const.DANGEROUS_FIELDS`.
   * - ``--thing THING``
     - Which device to use. Default is the first device returned.
       A name that matches nothing is reported as "no device matches"
       and the available names are not printed.
   * - ``--verbose``
     - Debug logging.

Exit status is 0 on success, 1 when the account has no devices, 2 for a
refused or invalid argument, and 130 on Ctrl-C.

Writable fields are ``power``, ``light``, ``fan``, ``setdelaytimer``,
``setcleanairfunction``, ``setrecirculating``, and
``resetgreasefilter``. ``resetgreasefilter`` and ``setrecirculating``
are the destructive pair: the first zeroes a counter that cannot be
reconstructed, and the second changes filter accounting.
``resetgreasefilter`` has not been run against hardware. The attended
sequence for trying fields one at a time is :doc:`validation`.

The CLI uses the default MQTT client-ID suffix, ``-py``. Close other
Python clients that also use the default before a long ``--watch``, or
they will evict each other. The vendor phone app uses a different ID
and can stay open. The suffix rules are in :ref:`mqtt-client-id`. The
CLI does not take a suffix flag.
