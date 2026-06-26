:fas:`key` publickey-hostbound Authentication
==============================================

OpenSSH 8.9 introduced ``publickey-hostbound-v00@openssh.com``, an extension
to SSH public-key authentication that binds a login credential to a specific
server.  SSH-MITM supports this method on the server side so that modern
OpenSSH clients can authenticate transparently through an interception proxy.

This page is a technical companion to :doc:`sshagent`.  It starts with the
concept, builds up to the protocol details, and finishes with the MITM
implications in the context of the tutorial scenario (Alice connecting to the
dev server with ``ssh -A``, Chapter 2).


The problem with standard public-key authentication
-----------------------------------------------------

When you log in to an SSH server with a public key, your SSH client signs a
piece of data to prove it holds the matching private key.  That data looks
roughly like this:

.. code-block:: none

    session_id  +  username  +  "publickey"  +  your_public_key

Notice what is **not** in there: any information about *which server* you are
connecting to.  The signature only proves "I have this key" — not "I have this
key *and* I intend to log in to this specific server."

In practice this is usually fine, because each SSH connection has a unique
``session_id`` (derived from a key-exchange shared secret), so a captured
signature cannot be trivially replayed.  But it means the server's identity
plays no cryptographic role in the authentication — it is not covered by the
signature at all.


What publickey-hostbound adds
------------------------------

``publickey-hostbound-v00@openssh.com`` extends the signed data with the
server's host key:

.. code-block:: none

    session_id  +  username  +  "publickey-hostbound-v00@openssh.com"
                +  your_public_key  +  server_host_key   ← new

Now the signature is only valid for *this exact server*.  If an attacker
intercepts the connection and presents a different host key, the signed blob
will be different and the signature will not verify.

Think of it as the difference between signing a blank cheque ("pay to whoever
presents this") and signing a cheque made out to a specific recipient and bank
account.


SSH Agent and destination constraints
---------------------------------------

Before explaining how SSH-MITM handles this, it helps to understand the SSH
agent and how destination constraints build on top of it.

What is an SSH agent?
~~~~~~~~~~~~~~~~~~~~~~

An SSH agent is a background process that holds your decrypted private keys in
memory.  Instead of typing your passphrase every time you connect to a server,
you unlock the key once with ``ssh-add`` and the agent signs on your behalf
from then on.

Your SSH client communicates with the agent over a Unix socket
(``$SSH_AUTH_SOCK``).  When the client needs to prove it holds a private key,
it sends the to-be-signed data to the agent and the agent returns the
signature — the private key itself never leaves the agent.

See also: :ref:`sshagent-quickstart`

What are destination constraints?
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

OpenSSH 8.9 added the ``-h`` flag to ``ssh-add``.  It lets you tell the agent
*where* a key is allowed to be used:

.. code-block:: bash

    # This key may only be used to log in to <target-host>
    ssh-add -h <target-host> ~/.ssh/id_ed25519

The agent stores this constraint alongside the private key.  From this point on
it will refuse to sign anything with that key unless it can verify that the
current SSH connection really goes to ``<target-host>``.

For the agent to verify this, two things must happen:

1. **The client tells the agent about the connection** using the
   ``session-bind`` extension (see below).
2. **The server must support publickey-hostbound**, so that the agent's host
   key check is cryptographically meaningful.

If either is missing, the agent simply refuses to sign — and the login fails
with ``Permission denied``.

Multi-hop forwarding
~~~~~~~~~~~~~~~~~~~~~

Destination constraints also work across forwarded agents.  You can express an
allowed forwarding path with the ``>`` notation:

.. code-block:: bash

    # Key may be forwarded through a jump host to reach the target
    ssh-add -h "<hop-host>><username>@<target-host>" ~/.ssh/id_ed25519

The agent tracks each hop in the forwarding chain and verifies the full path
before signing.

Constraint immutability
~~~~~~~~~~~~~~~~~~~~~~~~

Once a key is loaded, its constraints cannot be changed.  To add or modify
constraints, remove the key first and re-add it:

.. code-block:: bash

    ssh-add -d ~/.ssh/id_ed25519
    ssh-add -h <target-host> ~/.ssh/id_ed25519


How the three pieces fit together
-----------------------------------

The full mechanism relies on three protocol extensions that work together:

.. mermaid::

    sequenceDiagram
        participant U as User
        participant A as ssh-agent
        participant C as SSH Client
        participant S as Server

        U->>A: ssh-add -h <target-host> key<br/>(stores constraint + resolves host key)

        C->>S: TCP connect + SSH handshake (key exchange)
        note over C,S: session_id established,<br/>server signs it with its host key

        C->>A: session-bind(server_hostkey, session_id, server_sig)
        note over A: records: this connection goes to server_hostkey

        C->>S: USERAUTH_REQUEST (hostbound, probe — no signature yet)
        S->>C: USERAUTH_PK_OK (key accepted)

        C->>A: sign(session_id ‖ username ‖ pubkey ‖ server_hostkey)
        A->>A: check session-bind ✓  check constraint ✓
        A-->>C: signature

        C->>S: USERAUTH_REQUEST (hostbound, with signature)
        S->>C: USERAUTH_SUCCESS

**Step 1 — constraint stored in the agent**

``ssh-add -h`` encodes the destination in the agent's key record.  The agent
resolves the hostname to a host key using your local ``known_hosts`` file and
stores that key fingerprint as the allowed destination.

**Step 2 — session-bind**

After the SSH handshake but before authentication, the client sends a
``session-bind`` message to the agent.  This message contains the server's
host key, the session ID, and the server's signature over the session ID (which
proves the server genuinely holds the corresponding private key).

The agent records this binding.  It now knows: "this agent connection
corresponds to a session with *this specific server*."

**Step 3 — constrained signing**

When the client asks the agent to sign the authentication blob, the agent
checks:

- Is there a session-bind for this ``session_id``?
- Does the ``server_host_key`` in the blob match the binding?
- Does that host key match the destination constraint on the key?

Only if all three checks pass does the agent sign.  An attacker presenting a
different host key breaks check 2 and the agent refuses.


Technical protocol details
---------------------------

This section documents the exact wire formats for readers who need them.

Authentication request (wire format)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: none

    Standard publickey (RFC 4252 §7):

    byte       SSH2_MSG_USERAUTH_REQUEST
    string     username
    string     "ssh-connection"
    string     "publickey"
    bool       has_signature
    string     algorithm
    string     public_key_blob
    [string    signature]

    publickey-hostbound:

    byte       SSH2_MSG_USERAUTH_REQUEST
    string     username
    string     "ssh-connection"
    string     "publickey-hostbound-v00@openssh.com"
    bool       has_signature
    string     algorithm
    string     public_key_blob
    string     server_host_key_blob       ← extra field
    [string    signature]

Signed blob comparison
~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: none

    Standard publickey:

    string     session_identifier
    byte       SSH2_MSG_USERAUTH_REQUEST  (50)
    string     username
    string     "ssh-connection"
    string     "publickey"
    bool       true
    string     algorithm
    string     public_key_blob

    publickey-hostbound:

    string     session_identifier
    byte       SSH2_MSG_USERAUTH_REQUEST  (50)
    string     username
    string     "ssh-connection"
    string     "publickey-hostbound-v00@openssh.com"
    bool       true
    string     algorithm
    string     public_key_blob
    string     server_host_key_blob       ← binds signature to this server

Extension negotiation (EXT_INFO)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The server signals hostbound support in its first ``SSH2_MSG_EXT_INFO``
message (RFC 8308), sent immediately after ``SSH2_MSG_NEWKEYS``:

.. code-block:: none

    string     "publickey-hostbound@openssh.com"
    string     "0"

An OpenSSH client that sees this extension prefers the hostbound method over
plain ``publickey`` for all subsequent authentication attempts.

Session-bind message
~~~~~~~~~~~~~~~~~~~~~

.. code-block:: none

    byte       SSH_AGENTC_EXTENSION  (0x1b)
    string     "session-bind@openssh.com"
    string     hostkey             (server's public host key)
    string     session_identifier
    string     signature           (server's signature over session_identifier)
    bool       is_forwarding

Destination constraint (stored in agent)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code-block:: none

    byte          SSH_AGENT_CONSTRAIN_EXTENSION  (0xff)
    string        "restrict-destination-v00@openssh.com"
    constraint[]:
      string      from_hostname   (empty for the originating client)
      keyspec[]   from_hostkeys
      string      to_username     (empty = any)
      string      to_hostname
      keyspec[]   to_hostkeys

Agent signing decision
~~~~~~~~~~~~~~~~~~~~~~~

.. mermaid::

    flowchart TD
        A[Signing request received] --> B{session-bind recorded\nfor this session_id?}
        B -- No --> FAIL[Refuse: no binding]
        B -- Yes --> C{hostkey in blob matches\nbinding hostkey?}
        C -- No --> FAIL2[Refuse: hostkey mismatch]
        C -- Yes --> D{hostkey + username match\ndestination constraint?}
        D -- No --> FAIL3[Refuse: constraint violation]
        D -- Yes --> E{is_forwarding &&\nintermediate-hop\nconstraint?}
        E -- Fail --> FAIL4[Refuse: path violation]
        E -- Pass / not applicable --> OK[Sign and return signature]


How SSH-MITM implements publickey-hostbound
--------------------------------------------

SSH-MITM patches Paramiko's ``AuthHandler`` at startup so that clients using
the hostbound method can authenticate transparently.

Without this support, a client with ``ssh-add -h`` constraints would receive
``Permission denied`` immediately — a clear signal that something is wrong
with the connection.  With the support in place, the client authenticates
normally and the interception remains transparent.

The patch is applied in ``sshmitm/cli.py``:

.. code-block:: python

    AuthHandler._parse_service_request = auth_handler.auth_handler_parse_service_request
    AuthHandler._parse_userauth_request = auth_handler.auth_handler_parse_userauth_request

**What the server-side patch does:**

1. Advertises ``publickey-hostbound@openssh.com=0`` in the first
   ``EXT_INFO`` message (sent right after ``NEWKEYS``).
2. When a hostbound request arrives, reads ``server_host_key_blob`` from
   the packet and verifies it matches SSH-MITM's own host key.
3. Reconstructs the hostbound signed blob and verifies the client's signature.
4. Sends a second ``EXT_INFO`` after ``SSH_MSG_SERVICE_ACCEPT`` with
   refreshed ``server-sig-algs`` — matching standard OpenSSH server behaviour.

The probe/auth two-phase flow is fully supported:

.. mermaid::

    sequenceDiagram
        participant C as Client
        participant M as SSH-MITM

        C->>M: SSH_MSG_SERVICE_REQUEST ("ssh-userauth")
        M->>C: SSH_MSG_SERVICE_ACCEPT
        M->>C: SSH2_MSG_EXT_INFO (server-sig-algs)
        C->>M: USERAUTH_REQUEST (hostbound, sig=false) ← probe
        M->>C: USERAUTH_PK_OK
        C->>M: USERAUTH_REQUEST (hostbound, sig=true)  ← auth
        M->>C: USERAUTH_SUCCESS


MITM implications
------------------

The table below summarises what SSH-MITM can and cannot do depending on how
the client has configured its keys.

.. list-table::
   :header-rows: 1
   :widths: 45 12 43

   * - Scenario
     - MITM possible?
     - Reason
   * - Regular key, no ``-h`` constraint
     - Yes
     - Agent has no restrictions; SSH-MITM uses the forwarded agent to
       authenticate upstream.
   * - Key with ``-h``, client connects to SSH-MITM as the declared
       destination (ARP spoofing + first connection / TOFU)
     - Yes
     - SSH-MITM's host key is stored in ``known_hosts`` as the target.
       The session-bind matches the constraint → agent allows signing.
       SSH-MITM authenticates upstream with its own dedicated credentials.
   * - Key with ``-h``, client already knows the real server's host key
     - No
     - The client rejects SSH-MITM's host key before authentication begins
       (fingerprint mismatch with ``StrictHostKeyChecking``).
   * - Key with ``-h``, client accepted SSH-MITM's key, upstream auth
       via forwarded agent
     - No
     - The session-bind for the upstream connection uses the real server's
       host key, which does not match SSH-MITM's key in the constraint.
       The agent refuses to sign.

The three scenarios in diagram form:

.. mermaid::

    sequenceDiagram
        participant C as Client (no -h constraint)
        participant M as SSH-MITM
        participant S as Real Server

        C->>M: connect — accepts SSH-MITM host key
        C->>M: authenticate with publickey-hostbound ✓
        M->>S: connect (new session)
        M->>S: authenticate via forwarded agent (no constraint → signs) ✓
        note over C,S: full MITM — session intercepted

.. mermaid::

    sequenceDiagram
        participant C as Client (ssh-add -h realserver, key known)
        participant M as SSH-MITM

        C->>M: connect
        note over C: host key mismatch — StrictHostKeyChecking blocks
        C--xM: connection refused before authentication
        note over C,M: MITM blocked at fingerprint check

.. mermaid::

    sequenceDiagram
        participant A as ssh-agent (constrained key)
        participant C as Client
        participant M as SSH-MITM
        participant S as Real Server

        C->>M: connect — accepted SSH-MITM key on first use (TOFU)
        C->>A: session-bind(SSH-MITM host key, session_id_1)
        C->>M: authenticate with publickey-hostbound ✓

        M->>S: connect (new session, session_id_2)
        M->>A: sign(... real server host key ...)
        A->>A: real server key ≠ SSH-MITM key in constraint
        A--xM: agent refuses to sign
        note over M,S: upstream auth blocked — MITM incomplete

.. note::

    The fundamental protection is always the **host key fingerprint**.
    ``StrictHostKeyChecking`` (the default in modern OpenSSH) blocks the
    connection before any authentication is attempted if the host key does not
    match the stored one.


ARP-spoof honeypot scenario
-----------------------------

A common audit use case combines ARP spoofing with a honeypot backend.  In
this scenario SSH-MITM *is* the declared destination from the client's
perspective:

1. ARP spoofing redirects the client to the SSH-MITM host.
2. The client connects for the first time and accepts SSH-MITM's host key
   (TOFU — Trust On First Use).  The key is stored in ``known_hosts`` under
   the target hostname.
3. ``ssh-add -h <target-host>`` resolves ``<target-host>``
   via ``known_hosts`` and finds SSH-MITM's key — that key becomes the
   constraint.
4. On the next connection the session-bind uses SSH-MITM's key, which matches
   the stored constraint → the agent signs.
5. SSH-MITM forwards the session to a honeypot using its own credentials.
   The client's private key is never exposed upstream.

.. code-block:: bash

    ssh-mitm server --listen-port 10022 \
        --remote-host <honeypot-host> --remote-port 22

In this scenario ``publickey-hostbound`` and ``ssh-add -h`` do **not** protect
the client, because SSH-MITM is the accepted destination.  The protection only
works when the client already knows the real server's key and
``StrictHostKeyChecking`` rejects the fake one.


Testing
--------

The following example verifies end-to-end that an OpenSSH client uses the
hostbound method when connecting through SSH-MITM with a destination-constrained
key.

**Step 1 — start SSH-MITM and accept its host key:**

.. code-block:: bash

    ssh-mitm server --listen-port 10022 --remote-host localhost --remote-port 22 &

    # First connection: accept and store SSH-MITM's host key
    ssh -o StrictHostKeyChecking=no -p 10022 alice@localhost exit

**Step 2 — reload the key with a destination constraint:**

.. code-block:: bash

    ssh-add -d ~/.ssh/id_ecdsa

    # ssh-add resolves [localhost]:10022 via known_hosts
    # → stores SSH-MITM's host key as the allowed destination
    ssh-add -h "[localhost]:10022" ~/.ssh/id_ecdsa

**Step 3 — connect with strict checking and agent forwarding:**

.. code-block:: bash

    ssh -o StrictHostKeyChecking=yes -A -p 10022 alice@localhost

SSH-MITM's log confirms that the hostbound method was used:

.. code-block:: none
    :class: no-copybutton

    INFO  Auth request using publickey-hostbound-v00@openssh.com for user alice
    DEBUG check_auth_publickey: username=alice, sig_attached=False   ← probe
    DEBUG check_auth_publickey: username=alice, sig_attached=True    ← auth

Without the ``publickey-hostbound`` advertisement, the client would fall back
to plain ``publickey``.  The agent — holding only a destination-constrained
key — would refuse to sign (no session-bind was established for plain pubkey
auth), and the login would fail with ``Permission denied``.


Reference
----------

- `OpenSSH agent restriction <https://www.openssh.org/agent-restrict.html>`_
- RFC 4252 §7 — Public Key Authentication Method
- RFC 8308 — Extension Negotiation in the Secure Shell (SSH) Protocol
- ``ssh-add(1)``, ``ssh_config(5)``
