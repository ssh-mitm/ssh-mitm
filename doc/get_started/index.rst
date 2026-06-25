:fas:`rocket` Get Started
=========================

SSH-MITM acts as a proxy between an SSH client and its server.
Placed on the network path, it terminates both connections independently
and forwards all traffic — giving the auditor full visibility while the
session continues normally from the user's perspective.

.. image:: ../_static/ssh-mitm-setup.svg
    :class: dark-light
    :alt: SSH-MITM proxy setup diagram


Install
-------

.. tab-set::

    .. tab-item:: AppImage

        No installation required — download and run:

        .. code-block:: none

            $ wget https://github.com/ssh-mitm/ssh-mitm/releases/latest/download/ssh-mitm-x86_64.AppImage
            $ chmod +x ssh-mitm-x86_64.AppImage

        In all commands below, replace ``ssh-mitm`` with ``./ssh-mitm-x86_64.AppImage``.

    .. tab-item:: Snap

        .. code-block:: none

            $ sudo snap install ssh-mitm

    .. tab-item:: Flatpak

        .. code-block:: none

            $ flatpak install flathub at.ssh_mitm.server

    .. tab-item:: pip

        .. code-block:: none

            $ pip install ssh-mitm

For a full list of installation options see :doc:`/develop/installation`.


Start SSH-MITM
--------------

Point SSH-MITM at the target host — use a system you are authorized to test:

.. code-block:: none

    $ ssh-mitm server --remote-host <target-host>


Route a client connection
--------------------------

Have the SSH client connect through SSH-MITM on port 10022:

.. code-block:: none

    $ ssh -p 10022 user@<mitm-host>

SSH-MITM intercepts the session and logs the credentials immediately:

.. code-block:: none
    :class: no-copybutton

    INFO     Client connection established with parameters:
                 Remote Address: <target-host>:22
                 Username:       user
                 Password:       secret
                 Agent:          no agent

.. image:: ../_static/ssh-mitm-password.png
    :class: dark-light
    :alt: SSH-MITM intercepting credentials


Attach to the live session
---------------------------

For every intercepted connection, SSH-MITM opens a mirrorshell on a
local port:

.. code-block:: none
    :class: no-copybutton

    INFO     ℹ created mirrorshell on port 34463. connect with: ssh -p 34463 127.0.0.1

Connect to it from a second terminal — no password required:

.. code-block:: none

    $ ssh -p 34463 127.0.0.1

The mirror shell reflects the session in real time. Commands typed in
either window appear in both. The auditor can also inject commands
independently, without the user noticing.


Interactive tutorial
--------------------

No target server available? The interactive tutorial simulates all five
scenarios using a built-in mock SSH server:

.. code-block:: none

    $ ssh-mitm tutorial

.. image:: ../_static/ssh-mitm-tutorial.png
    :class: dark-light
    :alt: SSH-MITM interactive tutorial UI

The tutorial runs across two windows. In the **terminal**, SSH-MITM logs
what it captures from each simulated session. In the **browser**, each
chapter describes the scenario and asks you to locate the intercepted
value in the proxy output.

All five chapters are set during an authorized assessment of
**Logfile Inc.** and cover the most common interception scenarios
in a realistic order.

.. card:: Chapter 1 — Password Authentication

   A developer connects to the internal dev server using password
   authentication. SSH-MITM logs the username and password in plaintext.
   The proxied session continues normally on the remote server.

   :doc:`→ Authentication </user_guide/authentication>`

.. card:: Chapter 2 — Public Key Auth & Agent Forwarding

   The same developer switches to key-based authentication. SSH-MITM
   records the accepted public key fingerprint. With agent forwarding
   enabled, the forwarded agent is accessible through the proxy and can
   authenticate to further systems as the connecting user.

   :doc:`→ SSH Agent </user_guide/sshagent>`

.. card:: Chapter 3 — SFTP File Download

   The developer downloads a file from a staging server via SFTP.
   SSH-MITM logs every SFTP operation, including the file path and
   the transferred content.

   :doc:`→ File transfers </user_guide/file_transfer>`

.. card:: Chapter 4 — SSH Command Execution

   An automated script runs a non-interactive command on a production
   server via SSH exec. SSH-MITM captures the exact command string and
   the server response.

   :doc:`→ Session interception </user_guide/sessions>`

.. card:: Chapter 5 — Session Mirroring

   A network administrator opens an SSH session to a router and leaves
   the terminal unattended. SSH-MITM exposes the session via a local
   mirrorshell port. An auditor attaches to the port and reads the
   device configuration while the original session remains active.

   :doc:`→ Session interception </user_guide/sessions>`

.. card:: To be continued...

   The Logfile Inc. assessment is ongoing. More chapters are in
   development — covering additional techniques and scenarios encountered
   during the engagement.

   :doc:`→ Audit Guide </user_guide/index>`


Go deeper
---------

The :doc:`Audit Guide </user_guide/index>` covers all interception
techniques in depth — authentication, file transfers, port forwarding,
protocol-specific interception, and client auditing.
