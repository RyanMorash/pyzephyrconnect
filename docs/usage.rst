Using the client
================

Lifecycle
---------

One :class:`~pyzephyrconnect.client.ZephyrClient` is one account and one
discovery. :meth:`~pyzephyrconnect.client.ZephyrClient.async_setup`
authenticates, lists devices, and returns the hoods. Calling it again
raises :exc:`~pyzephyrconnect.exceptions.ZephyrError`. Build a new
client to re-discover. A failed setup can be retried on the same
client; the one-run guard latches only after discovery completes.

Keep the :class:`aiohttp.ClientSession` open for the life of the
client. Every REST call uses it.

.. code-block:: python

   hoods = await client.async_setup()
   try:
       for hood in hoods:
           await hood.async_start()
   finally:
       await client.async_stop()

:meth:`~pyzephyrconnect.hood.Hood.async_start` records the intent to
run, then connects. If it raises, that intent is rolled back, so a
failed start does not leave the supervisor reconnecting a hood the
caller has abandoned. Two live connections that share an MQTT client ID
evict each other; a zombie hood and its replacement would.

:meth:`~pyzephyrconnect.hood.Hood.async_stop` closes one hood. It does
not retire the account-level supervisor.
:meth:`~pyzephyrconnect.client.ZephyrClient.async_stop` does both.

:attr:`~pyzephyrconnect.client.ZephyrClient.identity_id` is readable
after setup. It is the full ``us-west-2:uuid`` Cognito identity: stable
across password and email changes, shared by every hood on the account,
and the natural key for the account. :attr:`~pyzephyrconnect.hood.Hood.thing_name`
identifies one device. Treat both as personal data.

Reading state
-------------

:attr:`~pyzephyrconnect.hood.Hood.state` is the latest known
:class:`~pyzephyrconnect.models.HoodState`, or ``None`` before the first
report. :meth:`~pyzephyrconnect.hood.Hood.async_start` requests the
shadow document, so a read of ``state`` immediately after start can
still be the snapshot ``discoverdevice`` provided during setup.

:meth:`~pyzephyrconnect.hood.Hood.async_poll` reads over HTTPS. It works
whether or not MQTT is up, records the result, and notifies listeners.
This is also how a terminal supervisor failure reaches you: the next
poll re-raises it. A consumer that never polls will not see that error.

:attr:`~pyzephyrconnect.hood.Hood.connected` is this hood's push
connection. :attr:`~pyzephyrconnect.client.ZephyrClient.connected` is
``True`` while at least one hood is up. On a multi-hood account the
client flag is an aggregate.

:attr:`~pyzephyrconnect.hood.Hood.capabilities` comes from
``discoverdevice`` and does not change after setup. Gate features on it.
Numeric maxima are ``None`` when the model omits them; a present but
unparseable maximum raises :exc:`~pyzephyrconnect.exceptions.ZephyrDataError`
once, at setup.

Listening for updates
---------------------

.. code-block:: python

   def on_state(state: HoodState) -> None:
       if state.fan is None:
           return
       print(state.fan)

   unsubscribe = hood.add_listener(on_state)
   # later
   unsubscribe()

The callback receives a :class:`~pyzephyrconnect.models.HoodState` on the
event loop. See :ref:`writes` for which fields are already filled in
before the device echoes them. The callback is synchronous. One callback
that raises is logged and does not stop the others. ``unsubscribe`` is
safe to call more than once.

Do not call back into the hood from the callback. A notification that
follows a write runs while the hood's lock is held, and
:class:`asyncio.Lock` is not reentrant. Schedule follow-up work so it
runs after the callback returns.

.. _writes:

Writing
-------

The typed methods are the write path. Each one publishes
``state.reported``. This hardware acts on ``reported``. A write to
``state.desired`` is accepted by AWS IoT and ignored by the device, so
the library never sends one.

Call them only while :attr:`~pyzephyrconnect.hood.Hood.connected` is
true. Otherwise they raise
:exc:`~pyzephyrconnect.exceptions.ZephyrNotConnectedError`. Reads do not
raise that exception.

.. list-table::
   :header-rows: 1
   :widths: 45 55

   * - Method
     - Effect
   * - :meth:`~pyzephyrconnect.hood.Hood.async_set_power`
     - Master switch with memory. Off clears fan and light. On restores
       the levels that were running. Fan and light writes do not send
       ``power``; the device raises it itself.
   * - :meth:`~pyzephyrconnect.hood.Hood.async_set_light`
     - Light level, from 0 through the hood's advertised maximum.
   * - :meth:`~pyzephyrconnect.hood.Hood.async_set_fan`
     - Fan speed, from 0 through the hood's advertised maximum.
   * - :meth:`~pyzephyrconnect.hood.Hood.async_set_clean_air`
     - Clean-air mode. Enabling it starts the fan at speed 1.
   * - :meth:`~pyzephyrconnect.hood.Hood.async_set_delay_timer`
     - Delay-off, in seconds. The device counts ``delaytimer`` down
       itself and turns off at zero.
   * - :meth:`~pyzephyrconnect.hood.Hood.async_set_recirculating`
     - Recirculating mode. Changes filter accounting.
   * - :meth:`~pyzephyrconnect.hood.Hood.async_reset_grease_filter`
     - Zeroes the grease-filter counter. The value cannot be
       reconstructed. Untested on hardware by design.

:meth:`~pyzephyrconnect.hood.Hood.async_set_light` and
:meth:`~pyzephyrconnect.hood.Hood.async_set_fan` reject a negative value,
and reject a value above a positive advertised maximum, before anything
is published. A hood that omits the maximum is not blanket-refused.
:meth:`~pyzephyrconnect.hood.Hood.async_set_delay_timer` rejects
negatives. Its argument is seconds. The vendor app shows two presets;
the device accepts other non-negative values, proven up to 3600. Above
that the device's own ceiling is unprobed (:doc:`protocol`, open
items), so a larger value may be clamped or rejected by the hardware.
A caller working in minutes multiplies by 60.

After a successful publish, listeners see the written fields
immediately. The device's own follow-on changes, such as ``power``
rising because the fan was written, or ``delaytimer`` counting down from
``setdelaytimer``, arrive with the echo. Destructive fields
(recirculating mode and the grease-filter reset) are left out of that
optimistic update. Showing them before the device confirms them would
report a change that cannot be undone.

:meth:`~pyzephyrconnect.hood.Hood.async_set_fields` writes an arbitrary
allowlisted map. It exists for the probe CLI. Prefer the typed methods.
Anything outside :data:`~pyzephyrconnect.const.WRITABLE_FIELDS` raises
:exc:`~pyzephyrconnect.exceptions.ZephyrWriteError` and is not published.

``update/delta`` messages are dropped. A delta is a wish, not
device-authored state. Merging one invents a change the hood did not
report.

Units
-----

Filter counters and run-time counters use different units. Mixing them
is wrong by a factor of 60. Established against a Zephyr AK7400AS; see
:doc:`protocol` before deriving anything from another model.

.. list-table::
   :header-rows: 1
   :widths: 55 45

   * - Field
     - Unit
   * - ``use_grease_filter_time``, ``use_charcoal_filter_time``
     - minutes
   * - ``max_grease_filter_hours``, ``max_charcoal_filter_hours``
     - hours
   * - ``use_fan_time``, ``use_light_time``
     - hours
   * - :meth:`~pyzephyrconnect.hood.Hood.async_set_delay_timer`
     - seconds

Remaining filter life, using the grease counter as the example:

.. code-block:: text

   remaining = 1 - use_grease_filter_time / (max_grease_filter_hours * 60)

Unknown versus zero
-------------------

Absent is not zero. :class:`~pyzephyrconnect.models.HoodState` fields
default to ``None``, meaning the device did not report the field or
reported something unparseable. A missing ``alarm_fault_code`` is
unknown, not "no fault".

Four counters are the exception, because zero is their real starting
value: ``use_grease_filter_time``, ``use_charcoal_filter_time``,
``use_light_time``, and ``use_fan_time``.

``bool(None)`` is ``False``. ``bool(state.alarm_fault_code)`` and
``state.alarm_fan or state.fan_warning`` therefore read as "no problem"
when the field is unknown. Compare with ``None`` explicitly.
``None > 0`` raises :class:`TypeError`; check a capability maximum
before comparing it.

String capability fields default to ``""``. ``supports_recirculating``
and ``supports_tru_hue`` default to ``False``, which means "not
advertised".

``act`` has been observed as ``"Disabled"`` and nothing else. Treat it
as a free-form string. Do not build an enum on one sample.

.. _persisting-tokens:

Persisting tokens
-----------------

The library does not store credentials. Pass tokens saved from a
previous session and a callback that receives new ones, and a restart
skips the SRP login for as long as Cognito still accepts the refresh
token:

.. code-block:: python

   from pyzephyrconnect import ZephyrClient, ZephyrDataError, ZephyrTokens

   try:
       tokens = ZephyrTokens.from_dict(saved) if saved else None
   except ZephyrDataError:
       # from_dict validates rather than coercing. A partial record
       # fails here, instead of later as a SECRET_HASH Cognito rejects.
       tokens = None

   client = ZephyrClient.from_credentials(
       username,
       password,
       session,
       tokens=tokens,
       token_updater=lambda fresh: save(fresh.as_dict()),
   )

:meth:`~pyzephyrconnect.auth.ZephyrTokens.as_dict` returns JSON-serializable
primitives: ``username``, ``id_token``, ``refresh_token``, ``identity_id``,
and ``expires_at`` (POSIX seconds). ``username`` has to be stored with
the tokens. Cognito's ``SECRET_HASH`` is
``HMAC-SHA256(client_secret, username + client_id)``, recomputed on
every refresh.

:meth:`~pyzephyrconnect.auth.ZephyrTokens.from_dict` raises
:exc:`~pyzephyrconnect.exceptions.ZephyrDataError` when a string field
is missing, empty, or not a string, or when ``expires_at`` is missing
or not a finite number. Discard the record and pass ``tokens=None``.
A full SRP login rebuilds it.

``token_updater`` runs on the event loop and must not block. If
persisting needs I/O, schedule that work. A rejected or expired refresh
token falls back to a password login. That fallback needs the password
still held by :class:`~pyzephyrconnect.auth.CredentialsAuth`.

.. warning::

   ``id_token`` and ``refresh_token`` are credentials. A Cognito refresh
   token lasts about 30 days and is enough on its own to take over the
   account. Wherever you write :meth:`~pyzephyrconnect.auth.ZephyrTokens.as_dict`
   is a credential store. Strip those keys, and ``identity_id``, from
   diagnostic dumps. The library's ``repr`` omits the two token fields;
   that protects its own logs, not yours.

Skipping ``tokens`` and ``token_updater`` is valid. Each process then
starts with a fresh SRP login, and there is no second long-lived
secret to store.

Supplying your own auth
-----------------------

Subclass :class:`~pyzephyrconnect.auth.AbstractAuth` when the library
should never see the password. One method is abstract. The identity
exchange, the credential cache, the MQTT client ID, and the policy
attach stay on the base class, because
:class:`~pyzephyrconnect.client.ZephyrClient` calls them.

.. code-block:: python

   from pyzephyrconnect import AbstractAuth, ZephyrClient, ZephyrTokens


   class StoredAuth(AbstractAuth):
       async def async_get_tokens(self) -> ZephyrTokens:
           # Return cached tokens while ZephyrTokens.expired is false.
           # Called on every REST request and by the supervisor.
           ...


   client = ZephyrClient(StoredAuth(session, client_id_suffix="-ha"))

``client_id_suffix`` is keyword-only. An empty suffix raises
:class:`ValueError` at construction: it would make the MQTT client ID
the bare identity, which is what the vendor phone app connects as.

.. _mqtt-client-id:

MQTT client ID
--------------

AWS IoT treats two live connections that share a client ID as one
session and evicts one for the other. The library's ID is the Cognito
identity, a suffix identifying this consumer, and ``-<thingName>`` per
hood. The default suffix is ``-py``, which is safe for exactly one
Python client on the account. The phone app, a second process, or a
Home Assistant integration needs its own stable suffix:

.. code-block:: python

   client = ZephyrClient.from_credentials(
       username,
       password,
       session,
       client_id_suffix="-ha",
   )

The same keyword is accepted by
:class:`~pyzephyrconnect.auth.CredentialsAuth` and
:class:`~pyzephyrconnect.auth.AbstractAuth`. Keep the ``us-west-2:``
prefix on the identity. AWS IoT caps the whole client ID at 128
characters, and the per-hood thing name is appended on top of identity
plus suffix, so keep the suffix short. It must not change under a live
socket.

Credential refresh
------------------

The presigned WebSocket URL embeds a signature over credentials that
expire in an hour. AWS IoT drops the session at expiry, and paho would
reconnect to that same dead URL forever. A supervisor inside the client
wakes about once a minute, refreshes credentials, and rebuilds sockets
ahead of expiry. It starts when a hood is started and retires when
:meth:`~pyzephyrconnect.client.ZephyrClient.async_stop` runs, or on its
own once nothing is supposed to be connected.

Sockets are rebuilt when the credential generation changes, not merely
when the cache looks close to expiry. Any REST call can refresh the
cache as a side effect and leave every live socket signed under the
previous credentials.

There is nothing to call to keep the session alive. Poll only if you
want a safety-net read, or degraded HTTPS updates while MQTT is down.

:exc:`~pyzephyrconnect.exceptions.ZephyrAuthError` and
:exc:`~pyzephyrconnect.exceptions.ZephyrPolicyError` stop the
supervisor, disconnect the hoods, and are stored so the next
:meth:`~pyzephyrconnect.hood.Hood.async_poll` re-raises them (a fresh
instance, so tracebacks do not grow without bound). Everything else is
retried on the next tick. A DNS failure stays a
:exc:`~pyzephyrconnect.exceptions.ZephyrTransportError`. Treating
:exc:`~pyzephyrconnect.exceptions.ZephyrAuthError` as "this account must
log in again" is safe: a Wi-Fi blip does not raise it.

Errors
------

Every exception raised by the library subclasses
:exc:`~pyzephyrconnect.exceptions.ZephyrError`.

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Exception
     - When
   * - :exc:`~pyzephyrconnect.exceptions.ZephyrAuthError`
     - Cognito or the identity exchange rejected the credentials. Terminal
       for the supervisor.
   * - :exc:`~pyzephyrconnect.exceptions.ZephyrPolicyError`
     - The IoT policy is not attached, or IoT refused the attach.
       Without the policy, connect, subscribe, and publish all succeed
       and every message is dropped. Terminal for the supervisor.
   * - :exc:`~pyzephyrconnect.exceptions.ZephyrCertificateError`
     - TLS verification failed against system trust plus the bundled
       TWCA anchors. The vendor REST host's intermediate omits the
       Subject Key Identifier extension, so those anchors are added on
       top of system trust. This is not pinning, and verification is
       not optional.
   * - :exc:`~pyzephyrconnect.exceptions.ZephyrTransportError`
     - Network, timeout, or throttling. Retryable.
   * - :exc:`~pyzephyrconnect.exceptions.ZephyrNotConnectedError`
     - A write had no live shadow connection. Start the hood, or wait
       until ``connected`` is true, and retry.
   * - :exc:`~pyzephyrconnect.exceptions.ZephyrWriteError`
     - The field is not writable, the value is out of range, or the
       payload was empty. Nothing was published.
   * - :exc:`~pyzephyrconnect.exceptions.ZephyrDataError`
     - A capability was present but unparseable, or
       :meth:`~pyzephyrconnect.auth.ZephyrTokens.from_dict` was given a
       malformed record.

Endpoints
---------

:class:`~pyzephyrconnect.const.Endpoints` defaults to the production
Zephyr / Gemtek cloud. Override it to point REST and MQTT at a staging
host, or to aim tests at a fake, without patching module globals:

.. code-block:: python

   from pyzephyrconnect import Endpoints, ZephyrClient

   client = ZephyrClient.from_credentials(
       username,
       password,
       session,
       endpoints=Endpoints(device_api_base="https://staging.example/prod"),
   )

The auth object carries the endpoints. REST and MQTT cannot be aimed at
different clouds by accident.

Logging
-------

The library logger is ``pyzephyrconnect``. It does not log thing names,
full topics, or raw payloads. Topic logs use the leaf segment
(``accepted``, ``delta``, ``rejected``). Where an exception message
might name a policy or embed a token, the library logs the exception
type.

Your logs are yours to scrub. In particular:

* :attr:`~pyzephyrconnect.hood.Hood.thing_name`, serial, MAC, and
  ``identity_id`` identify a home and its owner.
* ``getowndevices`` returns precise coordinates.
  :attr:`~pyzephyrconnect.models.HoodCapabilities.raw` keeps the
  discovery payload, including those identifiers.
* :attr:`~pyzephyrconnect.models.HoodState.raw` is the shadow's
  ``reported`` block. Discovery-derived state has thing name, serial,
  MAC, and location removed before it is stored there. Shadow messages
  arrive without those keys. It is still a device payload; do not log it.
* :meth:`~pyzephyrconnect.auth.ZephyrTokens.as_dict` contains live
  credentials. See :ref:`persisting-tokens`.
