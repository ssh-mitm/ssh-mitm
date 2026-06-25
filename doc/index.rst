=================================
SSH-MITM - ssh audits made simple
=================================

.. image:: _static/intro.png
    :class: dark-light

**SSH-MITM** is an open-source man-in-the-middle SSH server for security audits and malware analysis.
It intercepts SSH sessions in real time — supporting password and public-key authentication,
session hijacking, file transfer interception, and port forwarding — through a flexible plugin system.

.. admonition:: :fas:`scale-balanced` Legal Notice
   :class: legal-notice

   SSH-MITM is intended for authorized security audits, penetration testing, and research only.
   Do not use it against systems you do not own or have explicit written permission to test.
   Unauthorized interception of SSH traffic may be illegal in your jurisdiction.
   See the :doc:`Legal Notice </user_guide/legal>` for details.


Features
========

.. grid:: 1 2 3 3
   :gutter: 3

   .. grid-item-card:: :fas:`terminal` Session Hijacking
      :link: user_guide/sessions
      :link-type: doc

      Mirror live SSH sessions and interact with them in real time.
      Commands executed in either session appear in both.

   .. grid-item-card:: :fas:`file-arrow-up` File Interception
      :link: user_guide/file_transfer
      :link-type: doc

      Intercept, store, or replace files during SCP and SFTP transfers
      without interrupting the client.

   .. grid-item-card:: :fas:`network-wired` Port Forwarding
      :link: user_guide/portforwarding
      :link-type: doc

      Intercept TCP tunnels and dynamic port forwarding with full
      SOCKS 4/5 support.

   .. grid-item-card:: :fas:`key` Authentication
      :link: user_guide/authentication
      :link-type: doc

      Supports password and public-key authentication with automatic
      fallback. Redirect sessions without a forwarded agent to a honeypot.

   .. grid-item-card:: :fas:`shield-halved` FIDO2 Token Phishing
      :link: user_guide/trivialauth
      :link-type: doc

      Intercept hardware token authentication via the trivial
      authentication attack (CVE-2021-36367, CVE-2021-36368).

   .. grid-item-card:: :fab:`windows` PowerShell Remoting (PSRP)
      :link: user_guide/powershell
      :link-type: doc

      Intercept PowerShell remoting sessions over SSH. Log executed commands,
      output, errors, and state transitions. Write human-readable per-session
      transcript files.

   .. grid-item-card:: :fas:`graduation-cap` Interactive Tutorial
      :link: get_started/tutorial
      :link-type: doc

      Learn SSH-MITM step by step in a browser-based guide — no target
      server needed. Run ``ssh-mitm tutorial`` to get started.

   .. grid-item-card:: :fas:`puzzle-piece` Plugin Browser
      :link: user_guide/plugin_browser
      :link-type: doc

      Explore all available plugins and their configuration options
      interactively in the terminal — without editing any files.


Security Research
=================

.. card:: :fas:`magnifying-glass` Vulnerabilities discovered through SSH-MITM research

   Operating from the Man-in-the-Middle position makes it possible to observe SSH client
   behavior that is invisible from either endpoint. During security audits using SSH-MITM,
   **6 previously unknown vulnerabilities** were discovered in widely-deployed SSH software —
   including PuTTY, OpenSSH, Dropbear, Midnight Commander, and MobaXterm. Each was reported
   to the vendor and assigned a CVE number.

   :bdg-link-primary-line:`CVE-2021-36367 <vulnerabilities/CVE-2021-36367.html>` :bdg-link-primary-line:`CVE-2021-36368 <vulnerabilities/CVE-2021-36368.html>` :bdg-link-primary-line:`CVE-2021-36369 <vulnerabilities/CVE-2021-36369.html>` :bdg-link-primary-line:`CVE-2021-36370 <vulnerabilities/CVE-2021-36370.html>` :bdg-link-primary-line:`CVE-2022-38336 <vulnerabilities/CVE-2022-38336.html>` :bdg-link-primary-line:`CVE-2022-38337 <vulnerabilities/CVE-2022-38337.html>`
   +++
   :doc:`→ Security Research Findings <vulnerabilities/findings>`

Quick Start
===========

Placed between a client and its SSH server, SSH-MITM intercepts the connection transparently —
forwarding it to the target while giving the auditor full visibility and control:

.. image:: _static/ssh-mitm-setup.svg
    :class: dark-light
    :alt: SSH-MITM setup diagram

1. Install
----------

No installation required. Download the AppImage and you are ready to go:

.. code-block:: none

    $ wget https://github.com/ssh-mitm/ssh-mitm/releases/latest/download/ssh-mitm-x86_64.AppImage
    $ chmod +x ssh-mitm-x86_64.AppImage

For other installation options (pip, Flatpak, Snap) see the :doc:`installation guide <get_started/installation>`.

2. Start SSH-MITM
-----------------

Point SSH-MITM at your target host — use a system you are authorized to test:

.. code-block:: none

    $ ./ssh-mitm-x86_64.AppImage server --remote-host <target-host>

3. Route a client connection
-----------------------------

Have the SSH client connect through SSH-MITM on port 10022:

.. code-block:: none

    $ ssh -p 10022 user@mitm-host

SSH-MITM intercepts the session and logs the credentials immediately:

.. code-block:: none
    :class: no-copybutton

    INFO     Remote authentication succeeded
        Remote Address: <target-host>:22
        Username: user
        Password: secret
        Agent: no agent

.. image:: _static/ssh-mitm-password.png
    :class: dark-light
    :alt: SSH-MITM intercepting credentials

4. Attach to the live session
------------------------------

For every intercepted connection, SSH-MITM opens a mirror shell on a local port:

.. code-block:: none
    :class: no-copybutton

    INFO     ℹ created mirrorshell on port 34463. connect with: ssh -p 34463 127.0.0.1

Connect to it from a separate terminal:

.. code-block:: none

    $ ssh -p 34463 127.0.0.1

The mirror shell reflects the session in real time. The auditor can observe the user's activity
and inject commands independently, without affecting the original connection.


.. toctree::
   :maxdepth: 1
   :hidden:

   get_started/index
   Audit Guide <user_guide/index>
   develop/index
   Vulnerability Research <vulnerabilities/index>
   changelog
