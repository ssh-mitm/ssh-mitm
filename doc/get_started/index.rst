:fas:`rocket` Get Started
=========================

SSH-MITM positions itself between an SSH client and its server,
decrypting sessions in real time without breaking the connection.

The fastest way to start is the **interactive tutorial** — it runs a
built-in mock SSH server so you can practice interception techniques
without needing a target.


Step 1 — Install
-----------------

.. tab-set::

    .. tab-item:: AppImage

        No installation required — download and run:

        .. code-block:: none

            $ wget https://github.com/ssh-mitm/ssh-mitm/releases/latest/download/ssh-mitm-x86_64.AppImage
            $ chmod +x ssh-mitm-x86_64.AppImage

        Replace ``ssh-mitm`` with ``./ssh-mitm-x86_64.AppImage`` in all
        commands on this page.

    .. tab-item:: Snap

        .. code-block:: none

            $ sudo snap install ssh-mitm

    .. tab-item:: Flatpak

        .. code-block:: none

            $ flatpak install flathub at.ssh_mitm.server

        Replace ``ssh-mitm`` with ``flatpak run at.ssh_mitm.server`` in all
        commands on this page.

    .. tab-item:: pip

        .. code-block:: none

            $ pip install ssh-mitm


Step 2 — Start the tutorial
----------------------------

.. code-block:: none

    $ ssh-mitm tutorial

This opens a browser-based, step-by-step guide in your default browser.
Pass ``--port`` to use a fixed port, or ``--no-browser`` to skip the
automatic browser launch.

.. image:: ../_static/ssh-mitm-tutorial.png
    :class: dark-light
    :alt: SSH-MITM interactive tutorial UI


The engagement
--------------

Every tutorial takes place during the same authorized red team assessment
of **Meridian Systems**, a mid-sized technology company.
You have positioned SSH-MITM on the internal development network.
The story continues from one chapter to the next.

.. list-table::
   :header-rows: 1
   :widths: 5 30 40 25

   * - #
     - Tutorial
     - What happens
     - Go deeper
   * - 1
     - **Password Authentication**
     - Alice, a senior developer, connects to the dev server the same way
       she does every morning. Her password appears in plaintext in the
       SSH-MITM log.
     - :doc:`/user_guide/authentication`
   * - 2
     - **Public Key Auth & Agent Forwarding**
     - After a security reminder from IT, Alice switches to key-based
       authentication — but enables agent forwarding for convenience.
       A forwarded agent gives more access than a password.
     - :doc:`/user_guide/sshagent`
   * - 3
     - **SFTP File Download**
     - Alice downloads a file from the staging server. SSH-MITM logs the
       filename and captures the content before it reaches her machine.
     - :doc:`/user_guide/file_transfer`
   * - 4
     - **SSH Command Execution**
     - Alice runs an automated script on the production server — a single
       remote command that exposes more of the internal infrastructure
       than she intended.
     - :doc:`/user_guide/sessions`
   * - 5
     - **Session Mirroring**
     - The network admin connects to the core router via SSH and leaves the
       terminal unattended. You attach to the mirrored session and read the
       running configuration.
     - :doc:`/user_guide/sessions`


After the tutorial
------------------

The :doc:`Audit Guide </user_guide/index>` covers all interception
techniques in depth — authentication, file transfers, port forwarding,
protocol-specific interception, and client auditing.


Adding custom tutorials
-----------------------

Extra tutorials can be installed as Python packages. Register the tutorial
class under the ``sshmitm.Tutorial`` entry point in ``pyproject.toml``:

.. code-block:: toml

    [project.entry-points."sshmitm.Tutorial"]
    my-tutorial = "my_package.my_module:MyTutorial"


.. toctree::
   :maxdepth: 1
   :hidden:

   installation
