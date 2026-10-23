Hood
====

These are the attributes and methods a consumer calls. The class has
other public methods, left unprefixed because
:class:`~pyzephyrconnect.client.ZephyrClient` and the refresh supervisor
call them from another module. They are not a stable surface, and they
are omitted here.

..
   Sphinx documents ``__init__`` whenever that method has a docstring.
   Hood's constructor is the internal wiring ZephyrClient passes in,
   including the shadow factory, so it stays off this page.

.. autoclass:: pyzephyrconnect.hood.Hood
   :members: thing_name, capabilities, state, connected, async_start, async_stop, async_poll, add_listener, async_set_fields, async_set_power, async_set_light, async_set_fan, async_set_clean_air, async_set_delay_timer, async_set_recirculating, async_reset_grease_filter
   :exclude-members: __init__
