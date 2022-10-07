===========================================
:fas:`terminal` Intercept terminal sessions
===========================================

Hijack a SSH terminal session
=============================

Getting the plain text credentials is only half the fun.
SSH-MITM proxy server is able to hijack a ssh session and allows you to interact with it.

Let's get started with hijacking the session.

When a client connects, the ssh-mitm proxy server starts a new server, where you can connect with another ssh client.
This server is used to hijack the session.

.. code-block:: none
    :class: no-copybutton

    INFO     ℹ created mirrorshell on port 34463. connect with: ssh -p 34463 127.0.0.1

To hijack the session, you can use your favorite ssh client. This connection does not require authentication.

.. code-block:: none

    $ ssh -p 34463 127.0.0.1

After you are connected, your session will only be updated with new responses, but you are able to execute commands.

Try to execute somme commands in the hijacked session or in the original session.

The output will be shown in both sessions.

Log all terminal sessions
=========================

There are some situations, where it's necessary to log the
terminal session and to reply and analyze the full session.

SSH-MITM stores the session in a ``typescript`` compatible format.
Those recorded sessions can be replayed with ``scriptreplay``.

To start SSH-MITM to log the session, the arguments ``--session-log-dir`` and ``--store-ssh-session`` must be provided:

.. code-block:: none

    $ ssh-mitm server --session-log-dir ~/sshlogs --store-ssh-session
    INFO     ℹ session 7c43d2b2-51e7-4351-a468-c6768ea04d30 created

SSH-MITM generates a unique Id for each client.
The log direcory contains subfolders for each session.

.. code-block:: none

    $ tree
    .
    └── 7c43d2b2-51e7-4351-a468-c6768ea04d30
        ├── publickeys
        └── terminal_testuser@127.0.0.1
            ├── ssh_in_1665144225_7vjwtrur.log
            ├── ssh_out_1665144225_70d5m57y.log
            └── ssh_time_1665144225_7qgv99bo.log

    2 directories, 4 files


The subfolder ``terminal_testuser@127.0.0.1`` contains the terminal session. There are 3 files.

* **ssh_in_1665144225_7vjwtrur.log** -> the complete user input with passwords but also control characters
* **ssh_out_1665144225_70d5m57y.log** -> server output
* **ssh_time_1665144225_7qgv99bo.log** -> timing file for ``scriptreplay``

To replay the session the tool ``scriptreplay`` must be installed.

.. code-block:: bash

    $ scriptreplay -t ssh_time_1665144225_7qgv99bo.log ssh_out_1665144225_70d5m57y.log

The recorded session will be replayed in the current terminal window.
