.. Old URL: /trivialauth.html (root level, before move to user_guide/)
.. Redirect in conf.py: "trivialauth" → "user_guide/trivialauth.html"
.. External backlinks: NVD (CVE-2021-36368), SentinelOne, OpenCVE,
..                     Ubuntu Security, Debian Security Tracker

.. _trivialauth:

:fas:`handshake-slash` Trivial Authentication
=============================================

Trivial authentication is a phishing attack that exploits the ambiguity of
FIDO2 hardware token confirmations during an SSH man-in-the-middle attack
with agent forwarding.

In :doc:`Chapter 2 of the tutorial </get_started/index>`, Alice connects to
the dev server with ``ssh -A`` and SSH-MITM intercepts her forwarded agent.
A natural follow-up question is: *does a FIDO2 token protect against this?*

The answer depends on how the attacker approaches the authentication step.


The assumption
--------------

Alice uses a FIDO2 hardware token to protect her SSH key.  She reasons that
even if someone intercepts her connection, she would notice: a proxy would
have to authenticate her twice — once to the MITM server and once to the
real server.  She would see two FIDO2 confirmation requests instead of one
and know something is wrong.

That reasoning is correct for a straightforward proxy attack:

.. mermaid::

    sequenceDiagram
        participant L as Alice's laptop
        participant M as SSH-MITM
        participant S as real server

        L->>M: ssh -A  [FIDO2 ①]
        M->>S: agent   [FIDO2 ②]
        note over L,S: two confirmations — suspicious

The trivial authentication attack eliminates the first confirmation.


How it works
------------

The attack exploits authentication methods that require no client interaction
to succeed — so-called *trivial* authentication methods.

Instead of asking Alice to authenticate with her public key (which would
trigger the FIDO2 token), SSH-MITM accepts her login using a method that
needs no key at all.  Alice's session is established without her token being
touched.  SSH-MITM then uses her forwarded agent to authenticate to the real
server — and that is the only moment the FIDO2 token is activated.

From Alice's perspective:

.. mermaid::

    sequenceDiagram
        participant L as Alice's laptop
        participant M as SSH-MITM
        participant S as real server

        L->>M: trivial auth (no FIDO2)
        M->>S: agent  [FIDO2 ①]
        note over L,S: one confirmation — expected

The confirmation that appears on Alice's screen looks like any normal key usage:

.. code-block:: none
    :class: no-copybutton

    Confirm user presence for key ED25519-SK SHA256:...

Alice confirms — reasonably assuming it is for the server she just connected
to.  In fact, it authorises SSH-MITM's connection to the real server on her
behalf.  There is no reliable way for Alice to determine which server is
actually prompting, because the confirmation request itself carries no
information about the destination.


.. _protection:

Protection: destination constraints
-------------------------------------

OpenSSH 8.9 introduced *destination constraints* for ``ssh-add`` as the
response to :doc:`CVE-2021-36368 </vulnerabilities/CVE-2021-36368>`.  Keys
can be loaded with explicit restrictions on which hosts they may be used at
and through which forwarding hops they may pass.

.. code-block:: bash

    ssh-add -h <target-host> ~/.ssh/id_ed25519

With this constraint, the key may only be used directly from Alice's own
machine to ``<target-host>``.  If SSH-MITM receives the forwarded agent and
tries to authenticate to the real server, the agent checks the full hop chain
— and refuses, because SSH-MITM is not listed as an authorised intermediate
host.

For a key to be usable through an intermediate host, every hop must be
listed explicitly:

.. code-block:: bash

    ssh-add -h <hop-host> -h <hop-host>><target-host> ~/.ssh/id_ed25519

.. note::

    Destination constraints require support in both the SSH client and the
    server on each hop (OpenSSH 8.9 or later).  An attacker with direct
    access to the agent socket can still attempt to use it — but the agent
    will only honour authentication requests for explicitly permitted
    destinations.


Discovery
---------

The trivial authentication attack was identified by **Manfred Kaiser
(AUT-milCERT)** during a security audit, in cooperation with **Simon Tatham**
(PuTTY) and **Matt Johnston** (Dropbear).  All three projects were notified
and coordinated their responses before the findings were published.


Assigned CVEs
-------------

* PuTTY: :doc:`CVE-2021-36367 </vulnerabilities/CVE-2021-36367>`
* OpenSSH: :doc:`CVE-2021-36368 </vulnerabilities/CVE-2021-36368>`
* Dropbear: :doc:`CVE-2021-36369 </vulnerabilities/CVE-2021-36369>`


Reactions
---------

**PuTTY**

PuTTY responded in two stages, each addressing a different level of
protection:

- **0.71**: introduced *trust sigils* — a visual marker (``(!)``) that
  appears in the terminal or title bar when the server accepted the session
  without substantive authentication.  The connection is still established,
  but the user is given a visible signal that no real authentication took
  place.
- **0.76**: added ``-o RejectTrivialAuth=yes``.  When set, PuTTY terminates
  the connection immediately if the server accepts a trivial authentication
  method, rather than proceeding with the session.

.. list-table::
    :widths: 25 75
    :header-rows: 1

    * - PuTTY version
      - Behaviour
    * - < 0.71
      - Trivial auth accepted silently — no indicator shown.  Attack
        completely invisible to the user.
    * - 0.71 – 0.75
      - Trust sigil displayed.  Connection still established; attack works
        if the user does not notice or understand the sigil.
    * - ≥ 0.76
      - ``-o RejectTrivialAuth=yes`` available.  Connection is terminated
        if the server accepts trivial auth.

Simon Tatham's position is that the trust sigil system already defends
against every known spoofing attack a server could attempt this way;
``RejectTrivialAuth`` is an additional option for users who prefer a stricter
policy rather than a visual warning.

**OpenSSH**

OpenSSH's position is that the behaviour is not an authentication bypass,
since no credential is being forged — the server simply does not require one.
The core issue, as described in the CVE, is the **ambiguity of the FIDO2
confirmation**: when a client uses public-key authentication with agent
forwarding, there is no reliable way to determine from the confirmation prompt
alone whether the key is being used to authenticate to the directly connected
server or to a further server reached through the forwarded agent.

This ambiguity was addressed in OpenSSH 8.9 by introducing *agent restriction
keys* (destination constraints, see `protection`_ above).  These bind the use
of a forwarded agent key to explicitly authorised destinations — the agent
itself enforces where the key may be used, so the FIDO2 confirmation is
unambiguous: it can only be triggered for a destination Alice explicitly
approved.

**Dropbear**

Dropbear is a lightweight SSH implementation widely used on embedded systems
and IoT devices (routers, OpenWRT, Buildroot).  This makes the vulnerability
particularly relevant in scenarios where users connect to network devices
through jump hosts with agent forwarding enabled — a common setup on managed
network infrastructure.

Dropbear 2022.82 added the client option ``-o DisableTrivialAuth``.  When
set, the client rejects connections where the server accepted a trivial
authentication method and terminates with an error rather than proceeding
silently.

From the release announcement:

.. code-block:: none
    :class: no-copybutton

    Added client option "-o DisableTrivialAuth". This can be used to prevent
    the server immediately accepting successful authentication (before any auth
    request) which could cause UI confusion and security issues with agent
    forwarding - it isn't clear which host is prompting to use a key.
    Thanks to Manfred Kaiser from Austrian MilCERT


SSH-MITM — proof of concept
-----------------------------

SSH-MITM supports the trivial authentication attack via the
``--enable-trivial-auth`` flag.  Agent forwarding should be enabled on the
client side to complete the attack:

.. code-block:: bash

    ssh-mitm server --remote-host <target-host> --enable-trivial-auth

Connect as Alice with agent forwarding:

.. code-block:: bash

    ssh -A -p 10022 alice@<mitm-host>

To verify the default behaviour without the bypass — where two FIDO2
confirmations are required — omit the flag:

.. code-block:: bash

    ssh-mitm server --remote-host <target-host>

In this case Alice must authenticate to SSH-MITM using publickey, triggering
a first FIDO2 confirmation.  The agent is then used to authenticate to the
real server, triggering a second.  Two confirmations — the difference is
immediately noticeable.

.. note::

    If the client does not use agent forwarding, a fallback host can be
    configured to handle those sessions separately.


Technical details: the three authentication methods
----------------------------------------------------

The attack combines three authentication methods in sequence.

**1. Publickey — probing only**

SSH-MITM first checks Alice's public keys against the real server to find out
which key she would use for login.  This step must never result in a
successful login on the SSH-MITM side — a successful publickey authentication
would trigger a FIDO2 confirmation and alert Alice.

**2. Trivial authentication — establishing the session**

Once the key is known, SSH-MITM rejects the publickey attempt and switches to
a trivial authentication method:

- **none**: grants access immediately without any credentials.  Simple to
  implement, but the client is forced into a session immediately, which
  prevents testing further authentication methods.
- **keyboard-interactive with zero prompts**: sends no prompts to the client,
  so no user interaction is required.  The session is established silently
  and other authentication methods can still be tested beforehand.

In both cases, Alice's private key and FIDO2 token are not involved.

**3. Agent forwarding — reaching the real server**

With Alice's session established and her agent forwarded, SSH-MITM
authenticates to the real server using the forwarded agent.  This is the
only step that requires Alice's key — triggering exactly one FIDO2
confirmation, the one she expected all along.


.. rubric:: Permalink

- Current: https://docs.ssh-mitm.at/user_guide/trivialauth.html
- Previous: https://docs.ssh-mitm.at/trivialauth.html
