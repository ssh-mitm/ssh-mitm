======================================================
:fab:`linux` Intercept PowerShell Remoting (PSRP)
======================================================

`PowerShell remoting over SSH <https://learn.microsoft.com/en-us/powershell/scripting/learn/remoting/ssh-remoting-in-powershell>`_
(PSRP over SSH) lets Windows and Linux clients run remote PowerShell sessions
without WinRM by using the SSH subsystem mechanism.
SSH-MITM intercepts these sessions transparently — logging credentials and
relaying the binary PSRP stream verbatim to the real server.


How PowerShell remoting over SSH works
=======================================

The client (``Enter-PSSession``, ``Invoke-Command``, or ``New-PSSession``)
connects to the SSH server and requests the ``powershell`` subsystem.  The
server must have this subsystem registered in ``/etc/ssh/sshd_config``:

.. code-block:: text

    Subsystem powershell /usr/bin/pwsh -sshs -NoLogo

Once the subsystem is granted, both sides exchange binary PSRP frames over the
SSH channel for the full lifetime of the session.  PSRP is a proprietary
Microsoft binary protocol — SSH-MITM relays it byte-for-byte without parsing.

Unlike NETCONF or SFTP, PSRP has no line-oriented framing, so SSH-MITM cannot
safely parse individual messages in the default forwarder.  All traffic is
forwarded transparently; custom forwarder plugins can hook into the raw stream
(see :doc:`../develop/plugins`).


Prerequisites on the target host
=================================

The SSH server that SSH-MITM forwards to must have PowerShell Core (``pwsh``)
installed and the ``powershell`` subsystem registered in ``sshd_config``.

openSUSE Tumbleweed
-------------------

Register the Microsoft package repository and install PowerShell Core:

.. code-block:: bash

    # Import the Microsoft signing key
    sudo rpm --import https://packages.microsoft.com/keys/microsoft.asc

    # Register the repository (adjust the URL for the current release if needed —
    # see https://learn.microsoft.com/en-us/powershell/scripting/install/install-rhel)
    sudo zypper addrepo https://packages.microsoft.com/rhel/8/prod microsoft-prod
    sudo zypper refresh

    # Install PowerShell Core
    sudo zypper install -y powershell

After installation verify the binary path:

.. code-block:: bash

    which pwsh          # → /usr/bin/pwsh
    pwsh --version      # → PowerShell 7.x.x

Register the subsystem with OpenSSH and restart the service:

.. code-block:: bash

    # Append the Subsystem line if it is not present yet
    grep -q "^Subsystem powershell" /etc/ssh/sshd_config || \
        echo "Subsystem powershell $(which pwsh) -sshs -NoLogo" \
        | sudo tee -a /etc/ssh/sshd_config

    sudo systemctl restart sshd

    # Confirm the line is active
    sudo sshd -T | grep "subsystem powershell"

Ubuntu / Debian
---------------

.. code-block:: bash

    # Install PowerShell Core from the Microsoft repository
    # (see https://learn.microsoft.com/en-us/powershell/scripting/install/install-ubuntu)
    sudo apt-get install -y powershell

    grep -q "^Subsystem powershell" /etc/ssh/sshd_config || \
        echo "Subsystem powershell $(which pwsh) -sshs -NoLogo" \
        | sudo tee -a /etc/ssh/sshd_config

    sudo systemctl restart sshd

Other distributions and Windows
--------------------------------

For other Linux distributions (Fedora, RHEL, Alpine, …) and for Windows Server
(OpenSSH) refer to the
`Microsoft documentation on PowerShell remoting over SSH
<https://learn.microsoft.com/en-us/powershell/scripting/learn/remoting/ssh-remoting-in-powershell>`_.
The ``sshd_config`` entry and the SSH-MITM workflow are identical regardless of
the operating system on the target host.


Setting up a local test environment
=====================================

The following steps let you test PowerShell interception on a single
openSUSE Tumbleweed machine without a separate target host.

**Requirements:** PowerShell Core and OpenSSH server installed (see above).

.. code-block:: bash

    # 1 — verify the powershell subsystem is registered (see Prerequisites above)
    sudo sshd -T | grep "subsystem powershell"

    # 2 — start SSH-MITM pointing at localhost port 22
    ssh-mitm server --remote-host 127.0.0.1 --remote-port 22 --listen-port 10022

In a second terminal, open an intercepted PowerShell session:

.. code-block:: bash

    pwsh -Command "Enter-PSSession -HostName 127.0.0.1 -Port 10022 -UserName $USER"

Accept the host-key warning (SSH-MITM presents its own generated key), enter
your password, and you will land in a remote PowerShell session that has been
routed transparently through SSH-MITM.


Intercepting a session against a real target
============================================

1. Start SSH-MITM
-----------------

.. code-block:: bash

    ssh-mitm server --remote-host <target-host>

By default SSH-MITM listens on port **10022**.

2. Connect through SSH-MITM
----------------------------

**From Linux (PowerShell Core):**

.. code-block:: bash

    pwsh -Command "Enter-PSSession -HostName <mitm-host> -Port 10022 -UserName <user>"

Or non-interactively:

.. code-block:: bash

    pwsh -Command "Invoke-Command -HostName <mitm-host> -Port 10022 -UserName <user> -ScriptBlock { hostname }"

**From Windows (PowerShell):**

.. code-block:: powershell

    Enter-PSSession -HostName <mitm-host> -Port 10022 -UserName <user>

3. Check the intercepted credentials
--------------------------------------

SSH-MITM logs the credentials as soon as authentication succeeds:

.. code-block:: none
   :class: no-copybutton

    INFO     Remote authentication succeeded
        Remote Address: <target-host>:22
        Username: testuser
        Password: hunter2
        Agent: no agent
    DEBUG    starting powershell subsystem relay
    ...
    DEBUG    powershell subsystem relay finished


Extending the forwarder
========================

The transparent relay is the default behaviour.  To inspect or modify the PSRP
stream, subclass :class:`~sshmitm.forwarders.powershell.PowerShellForwarder`
and override the data hooks:

.. code-block:: python

    import logging
    from sshmitm.forwarders.powershell import PowerShellForwarder

    class LoggingPowerShellForwarder(PowerShellForwarder):
        """Logs the size of every PSRP chunk in both directions."""

        def handle_client_data(self, data: bytes) -> bytes:
            logging.info("[PSRP] client→pwsh %d bytes", len(data))
            return data

        def handle_server_data(self, data: bytes) -> bytes:
            logging.info("[PSRP] pwsh→client %d bytes", len(data))
            return data

Register the plugin in your ``pyproject.toml``:

.. code-block:: toml

    [project.entry-points."sshmitm.PowerShellBaseForwarder"]
    logging = "mypkg.ps_log:LoggingPowerShellForwarder"

Activate it with:

.. code-block:: bash

    ssh-mitm server --remote-host <target> --powershell-interface logging

See :doc:`../develop/plugins` for the full plugin development guide.


Limitations
===========

* **PSRP is opaque** — SSH-MITM relays the binary PSRP stream verbatim.  The
  default forwarder does not parse individual PowerShell commands or output.
  A plugin can capture the raw bytes for offline analysis.

* **Certificate-based authentication** — if the client is configured to use
  SSH certificate authentication, SSH-MITM can intercept the session only when
  ``--accept-first-publickey`` is used or a matching CA key is available.

* **Known-hosts pinning** — clients that pin the server's host key will reject
  SSH-MITM's generated key.  Remove the old entry from ``~/.ssh/known_hosts``
  before testing, or pass a real host key with ``--host-key``.
