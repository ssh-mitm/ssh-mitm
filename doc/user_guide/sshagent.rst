:fas:`user-secret` SSH Agent
============================

.. tip:: **Try it first**

   **Chapter 2** of the interactive tutorial shows how agent forwarding
   exposes access beyond the first intercepted server — in a safe
   environment with no real target needed.

   .. code-block:: none

       $ ssh-mitm tutorial

   See :doc:`/get_started/index` for the full tutorial list.

.. _sshagent-quickstart:

Quickstart
----------

SSH-MITM can expose a client's forwarded SSH agent as a local Unix socket,
giving auditors direct access to the agent without touching the client.
(New to SSH agents? See `Background: What is an SSH Agent?`_ below.)

**Start SSH-MITM with agent socket exposure:**

.. code-block:: bash

    ssh-mitm server --remote-host <target-host> --expose-agent-socket

When a client connects with agent forwarding enabled (``ssh -A``), SSH-MITM
prints ready-to-use commands to the log:

.. code-block:: none
    :class: no-copybutton

    ℹ <session-id> - agent socket ready - docs: https://docs.ssh-mitm.at/user_guide/sshagent.html
    ℹ <session-id> - ssh-add:  SSH_AUTH_SOCK=/tmp/ssh-mitm-abc12345.agent ssh-add -l
    ℹ <session-id> - ssh:      SSH_AUTH_SOCK=/tmp/ssh-mitm-abc12345.agent ssh alice@<target-host>

Copy any line directly from the log and run it.  The ``SSH_AUTH_SOCK``
variable is all that is needed — every standard agent client (``ssh-add``,
``ssh``, ``git``, …) honours it.

.. note::

    Agent forwarding works for interactive SSH sessions, but also for
    ``scp`` and ``sftp`` when the client uses **OpenSSH 8.4 or later**.
    SSH-MITM intercepts the agent regardless of which protocol the client uses.


Auditing the Forwarded Agent
-----------------------------

This section walks through a complete agent audit using ``ssh-add`` with the
``SSH_AUTH_SOCK`` printed by SSH-MITM.  All commands run on the SSH-MITM host.

Set the variable once for the current shell to avoid repeating it:

.. code-block:: bash

    export SSH_AUTH_SOCK=/tmp/ssh-mitm-abc12345.agent


Listing keys
~~~~~~~~~~~~

Show which keys the client currently holds:

.. code-block:: bash

    ssh-add -l          # fingerprints (short)
    ssh-add -L          # full public keys (useful for further analysis)

A client that connects with ``ForwardAgent yes`` but no keys loaded will show
``The agent has no identities.``


Adding a key
~~~~~~~~~~~~

A key can be added to the forwarded agent — for example to test whether a
specific key grants access to other systems in scope:

.. code-block:: bash

    ssh-add /path/to/private_key

The key is available in the agent for the duration of the session.

.. warning::

    Adding a key to a client's agent modifies their session state and is
    immediately visible to the client.  Only do this in explicitly authorised
    audits.


Removing keys
~~~~~~~~~~~~~

Remove a single key (pass the corresponding public key file or private key):

.. code-block:: bash

    ssh-add -d /path/to/private_key

Remove all keys at once:

.. code-block:: bash

    ssh-add -D

.. warning::

    Removing keys from a client's agent is immediately visible to the client
    if they run ``ssh-add -l`` themselves.  Use this only in authorised audits.


Locking and unlocking the agent
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

An SSH agent can be locked with a password so that no operations are possible
until it is unlocked again.  This is useful for testing whether automated
processes depend on an always-unlocked agent.

Lock the agent:

.. code-block:: bash

    ssh-add -x          # prompts for a lock password

Unlock the agent:

.. code-block:: bash

    ssh-add -X          # prompts for the same password

.. note::

    Most agents reject an empty lock password.  The client's ``ssh`` process
    will fail with ``sign_and_send_pubkey: signing failed for RSA`` (or similar)
    while the agent is locked.

.. warning::

    Locking the agent is immediately visible to the client — any ongoing or
    new SSH operation that requires the agent will fail.  Use this only in
    explicitly authorised audits.


Authenticating against other hosts
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Use the client's agent to open an SSH connection to any host the client's
keys grant access to:

.. code-block:: bash

    ssh alice@<other-host>

This lets an auditor verify which systems are reachable with the intercepted
agent — a key question in lateral-movement assessments.


Background: What is an SSH Agent?
-----------------------------------

SSH private keys are usually stored encrypted on disk.  Without an agent,
SSH must decrypt the key file on every connection — meaning you have to type
your passphrase every single time.

An SSH agent is a small background program that solves this: you load your
key into it once, enter the passphrase once, and the agent keeps the
decrypted key in memory for the rest of your session.  Every SSH connection
then asks the agent to sign the authentication challenge silently, without
prompting you again.

.. code-block:: none
    :class: no-copybutton

    $ ssh-add ~/.ssh/id_rsa      # load key — passphrase entered once
    Enter passphrase for /home/alice/.ssh/id_rsa: ********

    $ ssh alice@server1          # no passphrase prompt
    $ ssh alice@server2          # no passphrase prompt

The agent communicates with SSH clients through a Unix socket.  Its path is
stored in the ``SSH_AUTH_SOCK`` environment variable, which SSH reads
automatically.  The socket file lives in a temporary directory under
``/tmp`` — and any process that can access it (including the root user) can
use all keys the agent holds.

To limit the damage if a machine is compromised, keys can be protected with
a **FIDO2 hardware token**: every signing operation requires a physical button
press on a separate device, which software alone cannot bypass.
**SSH-Askpass** offers a software-only alternative, but it can be bypassed by
malware or an attacker who controls the desktop.  FIDO2 is always the
stronger choice.


SSH Agent Forwarding
---------------------

Agent forwarding lets you use your **local** SSH agent on a **remote** server
— without ever copying your private key there.

**A typical scenario:** Alice logs in to a ``dev-server`` at work.  From there
she wants to push code to a ``git-server``.  Her private key lives on her
laptop.  Without forwarding she would have to copy the key to ``dev-server``
(a security risk) or create a separate key just for that server.

With ``ssh -A``, the SSH connection tunnels signing requests back to Alice's
local agent:

.. mermaid::

    sequenceDiagram
        participant L as laptop [agent]
        participant D as dev-server
        participant G as git-server

        L->>D: ssh -A
        D->>G: ssh
        note over G: uses laptop's agent

Alice's private key never leaves her laptop.  ``dev-server`` only receives
the signed authentication response, not the key itself.

**The security risk:** While Alice's session is active, the forwarded agent
socket on ``dev-server`` is accessible to the root user — and to any attacker
who gains root access.  They can use that socket to authenticate to any
system Alice's key grants access to, without ever seeing the private key.
When Alice closes her session, the socket disappears.

Agent forwarding is available for interactive shell sessions and, since
**OpenSSH 8.4**, also for ``scp`` and ``sftp``.

.. warning::

    Only forward your agent to servers you fully trust.  A compromised server
    with root access can silently use your agent for as long as your session
    is open.  If agent forwarding is unavoidable, protect your key with a
    FIDO2 token — every signing operation then requires a physical button
    press that a remote attacker cannot trigger.

Security considerations
""""""""""""""""""""""""

The security risks of agent forwarding are specified in
`draft-ietf-secsh-agent-02 §6 <https://datatracker.ietf.org/doc/html/draft-ietf-secsh-agent-02>`_.
The core principle: anyone with access to a forwarded agent socket has the
same power as someone holding the private key — for as long as the session
remains open.


SSH-MITM — abusing a forwarded SSH agent
------------------------------------------

SSH-MITM acts as a full proxy: it terminates the client connection and opens
a separate connection to the real server independently.  When the client
forwards its agent, SSH-MITM receives it and uses it to authenticate against
the real server on the client's behalf — making a complete man-in-the-middle
attack possible even with public-key authentication.

In the tutorial scenario (Chapter 2), Alice connects to the dev server with
``ssh -A``.  SSH-MITM intercepts the connection, receives the forwarded agent,
and authenticates to the real server as Alice.  Her session continues as
normal while the agent is fully accessible to the auditor.


Host-bound public key authentication
""""""""""""""""""""""""""""""""""""""

OpenSSH 8.9 introduced ``publickey-hostbound-v00@openssh.com`` to prevent
signature replay attacks: the client's signature is cryptographically bound
to the host key of the server it is connecting to, so a captured signature
cannot be used against a different server.

.. tip::

    For protocol details, wire formats, and a full walkthrough of destination
    constraints, see :doc:`publickey-hostbound`.

In a proxy scenario this works exactly as designed.  The client connects to
SSH-MITM and produces a signature bound to SSH-MITM's host key — correct
behaviour, because SSH-MITM is the server it is talking to.  SSH-MITM then
opens a separate connection to the real server and requests a fresh signature
from the forwarded agent, bound to the real server's host key.  No replay
takes place on either leg.

**What about FIDO2 keys?**  When a FIDO2-protected key is used, every signing
operation requires a physical button press.  With a straightforward proxy
attack, the user would have to confirm **twice**: once for SSH-MITM and once
for the real server — which is suspicious.  This is where the
:doc:`trivial authentication attack </user_guide/trivialauth>` comes in: by
authenticating the client to SSH-MITM without using the private key at all,
the attacker reduces the number of confirmations to exactly one — the one the
user expects.

.. seealso::

    :doc:`publickey-hostbound` — full protocol details, wire formats, and a
    complete walkthrough of the destination-constraint mechanism.

SSH-Agent Breaking
"""""""""""""""""""

When a client connects without agent forwarding enabled, SSH-MITM can
send an unsolicited request asking the client to forward its agent anyway.
A correctly configured SSH client will **reject this request and close the
session** — this is the expected and secure behaviour.

This feature is useful for auditing whether clients are hardened against
unauthorized agent forwarding requests:

.. code-block:: bash

    ssh-mitm server --remote-host <target-host> --request-agent-breakin

.. note::

    If the client closes the session, it is hardened against this request.
    If the session stays open, the client ignored the request — but the agent
    is not necessarily forwarded.  Only if the client also forwards its agent
    does the forwarded agent socket become available for interception.
