:fas:`graduation-cap` Interactive Tutorial
==========================================

SSH-MITM ships with a browser-based, step-by-step tutorial that lets you
practice real interception techniques without needing a target server.
A built-in mock SSH server handles every exercise automatically.

.. code-block:: none

    $ ssh-mitm tutorial

This opens the tutorial in your default browser. Pass ``--port`` to use a
fixed port, or ``--no-browser`` to suppress automatic browser launch.

.. image:: ../_static/ssh-mitm-tutorial.png
    :class: dark-light
    :alt: SSH-MITM interactive tutorial UI


The Engagement
--------------

Every tutorial takes place during the same authorized red team assessment
of **Meridian Systems**, a mid-sized technology company.
You have positioned SSH-MITM on the internal development network.
The first connections are coming in.

The story continues from one tutorial to the next — each chapter reveals
a little more about what is happening on the network.


Tutorials
---------

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


Adding Custom Tutorials
-----------------------

Extra tutorials can be installed as Python packages. Register your tutorial
class under the ``sshmitm.Tutorial`` entry point in your package's
``pyproject.toml``:

.. code-block:: toml

    [project.entry-points."sshmitm.Tutorial"]
    my-tutorial = "my_package.my_module:MyTutorial"
