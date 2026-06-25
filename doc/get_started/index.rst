:fas:`rocket` Get Started
=========================

.. code-block:: none
    :class: no-copybutton

    INFO     Client connection established with parameters:
                 Remote Address: 192.168.1.42:22
                 Username:       alice
                 Password:       Tr0ub4dor&3
                 Agent:          no agent

SSH-MITM intercepts SSH sessions by terminating both connections — towards
the client and towards the server. Credentials, file transfers, commands,
and live sessions are visible in plaintext, while the proxied connection
continues uninterrupted.

The interactive tutorial demonstrates these techniques with a built-in
mock SSH server. No target, no lab setup, no additional configuration.

.. code-block:: none

    $ ssh-mitm tutorial

.. image:: ../_static/ssh-mitm-tutorial.png
    :class: dark-light
    :alt: SSH-MITM interactive tutorial UI


Install
-------

.. tab-set::

    .. tab-item:: AppImage

        No installation required — download and run:

        .. code-block:: none

            $ wget https://github.com/ssh-mitm/ssh-mitm/releases/latest/download/ssh-mitm-x86_64.AppImage
            $ chmod +x ssh-mitm-x86_64.AppImage
            $ ./ssh-mitm-x86_64.AppImage tutorial

    .. tab-item:: Snap

        .. code-block:: none

            $ sudo snap install ssh-mitm
            $ ssh-mitm tutorial

    .. tab-item:: Flatpak

        .. code-block:: none

            $ flatpak install flathub at.ssh_mitm.server
            $ flatpak run at.ssh_mitm.server tutorial

    .. tab-item:: pip

        .. code-block:: none

            $ pip install ssh-mitm
            $ ssh-mitm tutorial

For a full list of installation options see :doc:`/develop/installation`.


How the tutorial works
----------------------

The tutorial runs across two windows simultaneously.

In the **terminal**, SSH-MITM intercepts simulated SSH sessions and logs
what it captured: credentials, key fingerprints, filenames, command
strings, mirrorshell ports. The interception mechanism is identical to
what SSH-MITM uses against real targets.

In the **browser**, each chapter describes the scenario and asks you to
locate a specific value in the SSH-MITM output. The value is not provided
— you identify it from the proxy log. Each chapter concludes with a
technical explanation of why the interception is possible.


The scenario
------------

All five chapters are set during an authorized assessment of
**Meridian Systems**. SSH-MITM is running as a transparent proxy on the
internal development network. The chapters cover the most common
interception scenarios in a realistic order.

.. card:: Chapter 1 — Password Authentication

   A developer connects to the internal dev server using password
   authentication. SSH-MITM logs the username and password in plaintext.
   The proxied session continues normally on the remote server.

   :doc:`→ Authentication </user_guide/authentication>`

.. card:: Chapter 2 — Public Key Auth & Agent Forwarding

   The same developer switches to key-based authentication after a
   security reminder. SSH-MITM can no longer capture a reusable
   password, but it records the public key fingerprint that the server
   accepted. With agent forwarding enabled, the forwarded agent is
   accessible through the proxy and can be used to authenticate to
   further systems as the connecting user.

   :doc:`→ SSH Agent </user_guide/sshagent>`

.. card:: Chapter 3 — SFTP File Download

   The developer downloads a file from a staging server via SFTP.
   SSH-MITM logs every SFTP operation, including the file path and
   the transferred content. File replacements or modifications in
   transit are also possible without disrupting the session.

   :doc:`→ File transfers </user_guide/file_transfer>`

.. card:: Chapter 4 — SSH Command Execution

   An automated script runs a single non-interactive command on a
   production server via SSH exec. SSH-MITM captures the exact command
   string and the server response before either reaches its destination.

   :doc:`→ Session interception </user_guide/sessions>`

.. card:: Chapter 5 — Session Mirroring

   A network administrator opens an SSH session to a router and leaves
   the terminal unattended. SSH-MITM creates a local mirrorshell port
   that mirrors the session in real time. An auditor can attach to that
   port, execute commands, and read the device configuration — all while
   the original session remains active.

   :doc:`→ Session interception </user_guide/sessions>`


After the tutorial
------------------

The :doc:`Audit Guide </user_guide/index>` covers all interception
techniques in depth — authentication, file transfers, port forwarding,
protocol-specific interception, and client auditing.


Adding custom tutorials
-----------------------

Additional tutorials can be installed as Python packages. Register the
tutorial class under the ``sshmitm.Tutorial`` entry point in
``pyproject.toml``:

.. code-block:: toml

    [project.entry-points."sshmitm.Tutorial"]
    my-tutorial = "my_package.my_module:MyTutorial"


