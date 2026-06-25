:fas:`magnifying-glass` SSH Client Auditing
===========================================

Every SSH connection begins with a key exchange message that reveals the
client's version string and its ordered list of supported algorithms.
SSH-MITM reads this information automatically on every connection and
matches it against a database of known SSH client software.

This makes it possible to:

- Identify the exact SSH client and version that is connecting.
- Detect known vulnerabilities that apply to that version.
- Determine whether the client already has a cached host key fingerprint
  for the target server (see :doc:`fingerprint`).

No additional configuration is required. The audit runs for every session
the proxy handles.


Reading the audit output
========================

When a client connects, SSH-MITM logs the client version string and prints
a summary of any findings:

.. code-block:: none
    :class: no-copybutton

    INFO     connected client version: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3
    INFO     openssh - possible vulnerabilities
        CVE-2021-36368: https://docs.ssh-mitm.at/vulnerabilities/CVE-2021-36368.html
    INFO     openssh: Client has a locally cached remote fingerprint!

The audit output appears immediately after the client connects — before any
authentication takes place.


What the audit detects
======================

Client version and identity
---------------------------

The SSH version string (e.g. ``SSH-2.0-OpenSSH_8.2p1``) is sent in
plaintext at the start of every connection. SSH-MITM extracts the client
name and version number and looks them up in its client database.

Known CVEs
----------

If the detected version falls within the affected range for a known
vulnerability, SSH-MITM reports the CVE identifier and a link to the
details page. Example output for PuTTY:

.. code-block:: none
    :class: no-copybutton

    INFO     putty - possible vulnerabilities
        CVE-2021-36367: https://docs.ssh-mitm.at/vulnerabilities/CVE-2021-36367.html

See :doc:`/vulnerabilities/findings` for the full list of vulnerabilities
discovered through SSH-MITM research.

Cached host key fingerprint detection
--------------------------------------

During key exchange, the client sends its preferred list of host key
algorithms (e.g. ``ssh-rsa``, ``ssh-ed25519``, ``ecdsa-sha2-nistp256``).
When the client already has a cached fingerprint for the target server,
it moves the matching algorithm to the top of the list.

SSH-MITM detects this reordering and reports whether the client has a
prior entry in its ``~/.ssh/known_hosts``:

.. code-block:: none
    :class: no-copybutton

    INFO     openssh: Client has a locally cached remote fingerprint!

A client without a cached fingerprint will show the default algorithm
order — with ``ssh-ed25519`` or ``ecdsa-sha2-nistp256`` first. A client
that has connected before will put the previously used algorithm first.

This behavior is documented in the fingerprint detection section of
:doc:`fingerprint`.


Key negotiation data
====================

The raw key negotiation data is available via the ``--log-level debug``
flag. It includes all algorithm lists exchanged during the handshake:

.. code-block:: none

    $ ssh-mitm server --remote-host <target> --log-level debug

.. code-block:: none
    :class: no-copybutton

    DEBUG    kex_algorithms: ['curve25519-sha256', 'diffie-hellman-group14-sha256', ...]
    DEBUG    server_host_key_algorithms: ['ssh-rsa', 'ssh-ed25519', ...]
    DEBUG    encryption_algorithms_client_to_server: ['chacha20-poly1305@openssh.com', ...]
    DEBUG    mac_algorithms_client_to_server: ['umac-64-etm@openssh.com', ...]

This is useful when investigating an unknown client or verifying
algorithm support on a specific software version.


Writing a custom client audit plugin
======================================

To extend the built-in audit with custom checks, subclass
:class:`~sshmitm.plugins.session.clientaudit.SSHClientAudit` and override
the ``audit`` method. Register the subclass using the module system — see
:doc:`/develop/index` for details.
