certbot-dns-opteamax
====================

Opteamax DNS Authenticator plugin for Certbot

This plugin automates the process of completing a ``dns-01`` challenge by
creating, and subsequently removing, TXT records using the Opteamax OXAPI.


Installation
------------

::

    pip install git+https://github.com/plieven/certbot-dns-opteamax.git


Named Arguments
---------------

To start using DNS authentication for Opteamax, pass the following arguments on
certbot's command line:

========================================= =================================================================
``--authenticator dns-opteamax``          select the authenticator plugin (Required)

``--dns-opteamax-credentials``            Opteamax credentials
                                          INI file. (Required)
========================================= =================================================================


Credentials
-----------

Authenticate with an API token (recommended). Create one in the Opteamax
customer panel under *API-Tokens* and allow it the *DNS* area; tokens start with
``oxt_``. An example ``oxapi_credentials.ini`` file:

.. code-block:: ini

   dns_opteamax_token = oxt_your_api_token

Optional: ``dns_opteamax_api_url`` overrides the API endpoint
(default ``https://api.opteam.ax/api/v2``).

Username and password are still accepted but deprecated; the plugin prints a
warning when they are used:

.. code-block:: ini

   dns_opteamax_username = your_oxapi_username
   dns_opteamax_password = your_oxapi_password

If both are present, the token is used.

Keep the file private, e.g. ``chmod 600 oxapi_credentials.ini``.


Examples
--------

To acquire a single certificate for ``example.com``:

.. code-block:: bash

   certbot certonly \
     --authenticator dns-opteamax \
     --dns-opteamax-credentials /etc/letsencrypt/.secrets/oxapi_credentials.ini \
     -d 'example.com'
