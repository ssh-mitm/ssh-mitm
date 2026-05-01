:fas:`user-secret` SSH Agent
============================

.. _sshagent-quickstart:

Quickstart
----------

SSH-MITM can expose a client's forwarded SSH agent as a local Unix socket,
giving auditors direct access to the agent without touching the client.

**Start SSH-MITM with agent socket exposure:**

.. code-block:: bash

    ssh-mitm server --expose-agent-socket

When a client connects with agent forwarding enabled (``ssh -A``), SSH-MITM
prints ready-to-use commands to the log:

.. code-block:: none
    :class: no-copybutton

    ℹ <session-id> - agent socket ready - docs: https://docs.ssh-mitm.at/user_guide/sshagent.html
    ℹ <session-id> - ssh-add:  SSH_AUTH_SOCK=/tmp/ssh-mitm-abc12345.agent ssh-add -l
    ℹ <session-id> - ssh:      SSH_AUTH_SOCK=/tmp/ssh-mitm-abc12345.agent ssh user@host

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

Load an additional private key into the client's agent — for example a key
from the SSH-MITM host that should be tested against other systems:

.. code-block:: bash

    ssh-add /path/to/private_key

The key is now available for authentication in the client's agent for the
duration of the session.


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


Authenticating against other hosts
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Use the client's agent to open an SSH connection to any host the client's
keys grant access to:

.. code-block:: bash

    ssh -A user@target-host

This lets an auditor verify which systems are reachable with the intercepted
agent — a key question in lateral-movement assessments.


Background: What is an SSH Agent?
-----------------------------------

There are several ways in which SSH keys can be managed locally. One of the
most common use cases is to store a key in the file system. SSH clients are
able to read them from specific directories. For example, an RSA key may be
stored as ``.ssh/id_rsa`` in the user's home directory.

To protect these keys from unauthorized access after theft or loss, it is
recommended to store them encrypted. For this purpose it is necessary to
enter a password.

The SSH Agent can be used to manage these keys. The password input, for
decrypting, is only necessary once during loading into the SSH Agent. All
further cryptographic operations are then performed without the need to enter
a password.

For the communication between SSH Agent and SSH Client a Unix socket is
created and stored in a new subdirectory in ``/tmp``. Because of this design,
any user with appropriate privileges, such as the root user, is able to access
and use this Unix socket.

For this reason, it is important that privileged users are trusted or that
their accounts are not compromised.

To protect against misuse, a key can be secured with SSH-Askpass or a FIDO2
key. In both cases, user confirmation is required.

The big advantage of a FIDO2 key is that the confirmation is done via
separate hardware and cannot be compromised by a malware-infected machine.
SSH-Askpass is a software solution that can be bypassed by malware or an
attacker who controls the victim's desktop.

For this reason, the use of a FIDO2 key is recommended over the use of
SSH-Askpass.


SSH Agent Forwarding
---------------------

Many SSH clients offer the possibility to pass a local agent to a remote
server. The corresponding protocol was defined in
``draft-ietf-secsh-agent-00``. The corresponding draft was already defined in
2001 and almost all SSH clients support it.

A passed SSH agent can then be used to log in to another server.

The advantage is that no sensitive data, such as private SSH keys, need to be
stored permanently on the remote servers, but a secure login using public-key
authentication is still possible.

In most cases, agent forwarding is only supported for a shell connection.
Agent forwarding is theoretically also possible for file transfers using SCP
and SFTP, but most programs do not support this feature.  OpenSSH added agent
forwarding to ``scp`` and ``sftp`` in **version 8.4** in order to support
remote-to-remote file operations without copying through the local host.

However, SSH Agent Forwarding is associated with a security risk. This is
because privileged users can access and abuse the forwarded agent sockets.

For this reason, agent forwarding should not be used. However, there are use
cases where working without agent forwarding is more costly. One possibility
is working on a development server. From this server, it is often necessary
to access a Git server to synchronize changes. Without a forwarded agent,
custom keys would have to be created to access the Git server. These, in
turn, could be stolen and thus abused if the server were compromised.

In order to make it as difficult as possible to misuse the leaked keys, it is
necessary to protect them with a FIDO2 token or SSH-Askpass. In the case of
a passed-through agent, both solutions have a comparable level of security.

Nevertheless, the use of FIDO2 keys is recommended because a vulnerability in
the client could eventually leak them.

.. warning::

    SSH Agent Forwarding should not be used. It can prevent a lot of security
    risks. Agent forwarding often makes it easier to work with multiple
    servers. However, for most use cases there are ways to accomplish the same
    tasks without agent forwarding.

    If agent forwarding is still required, an FIDO2 token should be used. If
    this is not possible, SSH-Askpass can also be used.


Security considerations
""""""""""""""""""""""""

Using ssh agent forwarding comes with some security risks and should not be
used when the integrity of a machine is not trusted.
(https://tools.ietf.org/html/draft-ietf-secsh-agent-02)

.. code-block:: none
    :class: no-copybutton

    6.  Security Considerations

    The authentication agent is used to control security-sensitive
    operations, and is used to implement single sign-on.

    Anyone with access to the authentication agent can perform private key
    operations with the agent.  This is a power equivalent to possession of
    the private key as long as the connection to the key is maintained.  It
    is not possible to retrieve the key from the agent.

    It is recommended that agent implementations allow and perform some form
    of logging and access control.  This access control may utilize
    information about the path through which the connection was received (as
    collected with SSH_AGENT_FORWARDING_NOTICE messages; however, the path
    is reliable only up to and including the first unreliable machine.).
    Implementations should also allow restricting the operations that can be
    performed with keys - e.g., limiting them to challenge-response only.

    One should note that a local superuser will be able to obtain access to
    agents running on the local machine.  This cannot be prevented; in most
    operating systems, a user with sufficient privileges will be able to
    read the keys from the physical memory.

    The authentication agent should not be run or forwarded to machine whose
    integrity is not trusted, as security on such machines might be
    compromised and might allow an attacker to obtain unauthorized access to
    the agent.

    Adding a key with SSH_AGENT_ADD_KEY over the net (especially over the
    Internet) is generally not recommended, because at present the private
    key has to be moved unencrypted. Implementations SHOULD warn the user of
    the implications. Even moving the key in encrypted form could be
    considered unwise.


SSH-MITM — abusing a forwarded SSH agent
------------------------------------------

SSH-MITM supports agent forwarding, which allows a remote host to authenticate
against another remote host.

This is done by requesting the agent from the client and using it for remote
authentication. By using this feature, it is possible to do a full
man-in-the-middle attack when public-key authentication is used.

Since OpenSSH 8.4 the commands ``scp`` and ``sftp`` support agent forwarding.
Older releases or other implementations do not support agent forwarding for
file transfers.

.. note::

    Currently, SSH-MITM only uses the forwarded agent for remote
    authentication, but does not allow rewriting the
    ``SSH_AGENT_FORWARDING_NOTICE`` message.

    If a client uses an agent which displays a warning when the client is
    accessed, the original notice will be shown.


SSH-Agent Breaking
"""""""""""""""""""

SSH-MITM can try to break in to the client and force agent forwarding.
Most clients should ignore this breakin attempt or close the session.

This feature allows an auditor to check if the client is resistant against
agent breaking attempts.

.. code-block:: bash

    ssh-mitm server --request-agent-breakin
