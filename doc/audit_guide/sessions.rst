===========================================
:fas:`terminal` Intercept terminal sessions
===========================================

.. tip:: **Try it first**

   The interactive tutorial covers both session interception techniques
   in a safe environment — no target server needed:

   - **Chapter 4** intercepts a non-interactive SSH command (exec channel).
   - **Chapter 5** attaches to a live session via mirrorshell.

   .. code-block:: none

       $ ssh-mitm tutorial

   See :doc:`/get_started/index` for the full tutorial list.


Mirror a live SSH session
=========================

.. admonition:: Logfile Inc. assessment

   Thomas Webb (``twebb``), the network administrator, often leaves his SSH
   session to ``router01`` open for hours while away from his desk. Attaching
   to the mirrorshell gives the auditor access to the device configuration —
   including a read-write SNMP community string — without Webb noticing.
   Chapter 5 demonstrates this.

When a client connects through SSH-MITM and opens a shell, the proxy
automatically creates a **mirrorshell** — a live copy of the session on a
local port. The port number is printed immediately when the connection arrives:

.. code-block:: none
    :class: no-copybutton

    INFO     ℹ created mirrorshell on port 34463. connect with: ssh -p 34463 127.0.0.1

Attach to it from a second terminal — no password required:

.. code-block:: none

    $ ssh -p 34463 127.0.0.1

Both sides of the connection now share the same session. Commands typed
in either window appear in both, and output from the server is visible
everywhere. The original user has no indication that a second party is
connected.

.. note::

    An auditor who attaches to the mirrorshell can also inject commands
    independently of what the user is doing. If the user steps away from
    their terminal, the auditor has full access to everything the user's
    session can reach.


Intercept non-interactive commands
===================================

.. admonition:: Logfile Inc. assessment

   In the Logfile Inc. scenario, Max Morgan (``mmorgan``) runs deployment
   scripts on ``web01`` using non-interactive SSH commands — common in CI/CD
   pipelines and automated maintenance tasks. Chapter 4 demonstrates the
   interception.

Non-interactive SSH commands (``ssh user@host "command"``) use the
*exec channel* type. SSH-MITM intercepts the exec channel before it
reaches the real server and logs the exact command string:

.. code-block:: none
    :class: no-copybutton

    INFO     session b3f1... - SSH Exec request: cat ~/.aws/credentials

The command is forwarded to the server and the response is returned to
the client, so the user notices nothing unusual.


Record terminal sessions
========================

To capture a full session for later review, enable session logging:

.. code-block:: none

    $ ssh-mitm server --session-log-dir ~/sshlogs --store-ssh-session

SSH-MITM creates a sub-directory per session with a ``typescript``-compatible
recording that can be replayed with ``scriptreplay``:

.. code-block:: none

    $ tree ~/sshlogs
    .
    └── 7c43d2b2-51e7-4351-a468-c6768ea04d30
        ├── publickeys
        └── terminal_testuser@127.0.0.1
            ├── ssh_in_1665144225_7vjwtrur.log    # user input (includes passwords, control chars)
            ├── ssh_out_1665144225_70d5m57y.log   # server output
            └── ssh_time_1665144225_7qgv99bo.log  # timing file for scriptreplay

Replay a recorded session:

.. code-block:: bash

    $ scriptreplay -t ssh_time_1665144225_7qgv99bo.log ssh_out_1665144225_70d5m57y.log
