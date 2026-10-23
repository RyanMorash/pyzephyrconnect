API reference
=============

Import the names on this page from :mod:`pyzephyrconnect`. Autodoc
lists each object under the module that defines it. That path is where
the class lives, not a second public import path.

.. code-block:: python

   from pyzephyrconnect import (
       AbstractAuth,
       CredentialsAuth,
       DEFAULT_ENDPOINTS,
       Endpoints,
       Hood,
       HoodCapabilities,
       HoodState,
       ZephyrAuthError,
       ZephyrCertificateError,
       ZephyrClient,
       ZephyrDataError,
       ZephyrError,
       ZephyrNotConnectedError,
       ZephyrPolicyError,
       ZephyrTokens,
       ZephyrTransportError,
       ZephyrWriteError,
   )

.. automodule:: pyzephyrconnect
   :no-members:

.. toctree::
   :maxdepth: 1

   client
   hood
   models
   auth
   exceptions
   constants
