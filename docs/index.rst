pyzephyrconnect
===============

Python client for Zephyr / Gemtek range hoods. Version |release|.

These hoods expose no local API. Every read and write is a cloud
round-trip through AWS IoT Core device shadows, over a SigV4-presigned
WebSocket. The protocol was reverse-engineered from the vendor iOS app.
:doc:`protocol` is the record of that work, and the reference for what
the hardware actually does.

.. warning::

   A write actuates a physical fan and light.
   :meth:`~pyzephyrconnect.hood.Hood.async_reset_grease_filter` zeroes a
   usage counter that cannot be reconstructed, and ships untested by
   design.

The library is licensed under the `GNU GPL v3 or later <https://www.gnu.org/licenses/gpl-3.0.html>`_.

.. toctree::
   :maxdepth: 2
   :caption: Guide

   quickstart
   usage
   cli

.. toctree::
   :maxdepth: 2
   :caption: Reference

   api/index
   Protocol notes <protocol>
   Hardware validation <validation>

How a call is put together
--------------------------

Five layers, each readable on its own. Consumers normally stay on
:class:`~pyzephyrconnect.client.ZephyrClient` and
:class:`~pyzephyrconnect.hood.Hood`.

* ``auth`` exchanges a Cognito ID token for hour-long AWS credentials
  and attaches the IoT policy. :class:`~pyzephyrconnect.auth.AbstractAuth`
  is the extension point: implement
  :meth:`~pyzephyrconnect.auth.AbstractAuth.async_get_tokens` and the
  rest is inherited.
* ``api`` calls the two vendor REST endpoints, ``getowndevices`` and
  ``discoverdevice``.
* ``presign`` builds the SigV4 WebSocket URL. The standard library only;
  ``now`` is a parameter so the signature can be tested without a clock.
* ``shadow`` is one MQTT connection per hood, over that URL.
* ``hood`` and ``models`` hold one device's capabilities, state, and
  controls. The typed ``async_set_*`` methods are the write allowlist
  made structural.

Reads are hybrid on purpose. ``discoverdevice`` supplies capabilities
and an initial state over HTTPS before MQTT exists, MQTT then carries
live push, and ``discoverdevice`` stays available through
:meth:`~pyzephyrconnect.hood.Hood.async_poll` so a consumer degrades to
slower updates instead of going unavailable.

Building these docs
-------------------

The published copy is https://pyzephyrconnect.readthedocs.io/.
From a checkout:

.. code-block:: bash

   pip install -e ".[docs]"
   sphinx-build -W --keep-going -b html docs docs/_build/html

``docs/api-notes.md`` is the 0.1.0 design note and is not part of this
site. :doc:`protocol` and :doc:`validation` are rendered from
``PROTOCOL.md`` and ``VALIDATION.md`` at the repository root, which
remain the files to edit.
