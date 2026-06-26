:fas:`building` Logfile Inc. — Scenario Guide
================================================

All interactive tutorial chapters are set during a single authorized
penetration test of **Logfile Inc.**  This page describes the story,
the characters, and the infrastructure so that new chapters stay
consistent with what already exists.

For the published, reader-facing version of the scenario see
:doc:`/get_started/scenario`.


The Company
-----------

Logfile Inc. is a mid-sized software company that develops and operates
a customer portal for a handful of business clients.  The engineering
team is small, the network is flat, and security has not kept pace with
growth.  SSH keys are shared between machines, agent forwarding is
enabled by default in the company-wide SSH config, and no one has
audited the router since it was first set up.

The authorized assessment covers all hosts on the corporate LAN.  The
auditor has no prior knowledge of credentials or network topology.


Characters
----------

New chapters must use the existing characters.  Their usernames,
roles, and behavioral traits are load-bearing — they explain *why*
each vulnerability is exploitable.

.. list-table::
   :header-rows: 1
   :widths: 12 20 15 53

   * - Username
     - Name
     - Role
     - Defining trait
   * - ``mmorgan``
     - Max Morgan
     - Developer
     - Ignores fingerprint warnings, deleted ``known_hosts`` entry on a
       Stack Overflow recommendation.  Has three SSH keys — one from a
       machine he replaced last year, never removed from servers.
       Connects to ``web01`` daily.
   * - ``sking``
     - Sarah King
     - DevOps Engineer
     - Security-conscious: uses a strong key with a passphrase.  Also
       enabled agent forwarding because the company SSH template
       required it.  Does not know what agent forwarding exposes.
   * - ``lchen``
     - Lisa Chen
     - IT Manager
     - Drafted the password → key migration policy.  Copied
       ``ForwardAgent yes`` into the SSH guide from an online tutorial.
       Has elevated access to most systems.
   * - ``twebb``
     - Thomas Webb
     - Network Admin
     - Seven years at the company, knows every IP.  Connects to
       ``router01`` a few times a week and leaves sessions open for
       hours while stepping away from his desk.


Infrastructure
--------------

The lab uses the ``127.0.0.0/8`` loopback range subdivided into
``/24`` subnets.  The second octet is the segment number.

.. list-table::
   :header-rows: 1
   :widths: 20 20 60

   * - Host
     - Lab address
     - Role in the story
   * - SSH-MITM proxy
     - ``127.0.0.1:10022``
     - The auditor's interception point.  Port 10022 is the only
       constant across all chapters.
   * - ``web01``
     - ``127.2.0.1``
     - Main application server (Django).  Accepts both password and
       public-key SSH auth.  Host keys were regenerated after a disk
       replacement three months ago — some clients have not reconnected
       since.  Max and Sarah connect here daily.
   * - ``files``
     - ``127.2.0.2``
     - Internal file server (SFTP only).  Holds deployment artefacts,
       config backups, and company documents.  Max downloads project
       files; Lisa distributes policy templates.
   * - ``logfilegit``
     - ``127.2.0.3``
     - Self-hosted Git platform.  Publishes registered SSH public keys
       at ``/<username>.keys`` without authentication — the same
       pattern as GitHub and GitLab.  Max has three keys registered.
   * - ``db01``
     - ``127.3.0.1``
     - Production PostgreSQL database.  Not directly reachable from the
       developer LAN; only ``web01`` and ``files`` may connect.  No SSH
       service — an indirect target via lateral movement only.
   * - ``router01``
     - ``127.4.0.1``
     - Core network router managed by Thomas.  SNMP is enabled with a
       read-write community string stored in the running config.
       Thomas's sessions stay open for hours.


Chapter Map
-----------

.. list-table::
   :header-rows: 1
   :widths: 8 30 15 47

   * - Chapter
     - Title
     - Actor
     - What happens
   * - Prologue
     - Host Key Verification
     - ``mmorgan``
     - Max connects to ``web01`` for the first time through SSH-MITM.
       He accepts the host key without checking the fingerprint.
       A second connection reveals his key-exchange preference has
       changed — exposing his fingerprint state via CVE-2020-14145
       before any credential is entered.
   * - Ch 1
     - Password Authentication
     - ``mmorgan``
     - Max logs in to ``web01`` with his password.  SSH-MITM logs the
       username and password in cleartext.
   * - Ch 2
     - Public Key Auth & Agent Forwarding
     - ``sking``
     - Sarah logs in to ``web01`` using public-key auth with agent
       forwarding enabled.  SSH-MITM records the accepted public key
       fingerprint and gains access to her forwarded agent.
   * - Ch 3
     - SFTP File Download Interception
     - ``mmorgan``
     - Max downloads a file from the ``files`` server.  SSH-MITM logs
       the filename and intercepts the file contents.
   * - Ch 4
     - SSH Command Execution Interception
     - ``mmorgan``
     - Max's deployment script runs a non-interactive command on
       ``web01`` via SSH exec.  SSH-MITM captures the exact command
       string and the server response.
   * - Ch 5
     - SSH Session Mirroring
     - ``twebb``
     - Thomas opens a session to ``router01`` and steps away.
       SSH-MITM exposes the session via a mirrorshell port.  The
       auditor reads the router's running config — including the SNMP
       read-write community string.
   * - Ch 6
     - SSH Key Enumeration
     - ``mmorgan`` (keys)
     - LogfileGit exposes Max's registered public keys.
       ``ssh-mitm check-publickey`` queries the user-validity oracle
       (CVE-2016-20012) on ``web01`` and ``db01``, mapping which key
       grants access to which server.


Story Arc
---------

The chapters form a single coherent engagement.  Each one hands
something to the next:

.. code-block:: none

   Prologue ─ auditor in position, Max connects without checking fingerprint
       │
       ▼
   Ch 1 ── Max's password captured → auditor has credentials for web01
       │
       ▼
   Ch 2 ── Sarah's agent captured → lateral movement beyond web01 possible
       │
       ▼
   Ch 3 ── file download intercepted → sensitive artefacts visible in transit
       │
       ▼
   Ch 4 ── deployment command captured → automation scripts exposed
       │
       ▼
   Ch 5 ── Thomas's router session mirrored → SNMP read-write secret extracted
       │
       ▼
   Ch 6 ── LogfileGit key enumeration → Max's access mapped across infrastructure


Known Inconsistencies
---------------------

These are places where the mock implementation does not yet match the
scenario text.  Fix them before they confuse learners.

**Ch 5 — Router mock (router01)**

The simulated router shell currently shows details that contradict the
scenario:

- Hostname in the running config: ``prod-router-01`` → should be
  ``router01``
- SSH port in the running config: ``service ssh port 22`` → should be
  ``:20022``
- Interface addresses: ``10.0.0.1`` / ``192.168.1.1`` — these are
  placeholder addresses, not the lab ``127.4.x.x`` range; acceptable
  for a simulated router CLI but worth documenting
- Active session shown by ``show users``: user ``admin`` from
  ``10.0.0.50`` → should be ``twebb`` from ``127.1.0.1``

**Ch 6 — Max's old key is too clean**

The scenario says Max's key from his replaced laptop "is still valid
on several servers."  In the current mock, that key (registered on
LogfileGit as ``mmorgan@old-laptop``) is not accepted anywhere.  The
inconsistency is harmless for the current tutorial step but breaks the
narrative detail.  A future fix: make it valid on ``files`` but not on
``web01`` or ``db01``.

**index.rst Chapter 6 description**

The get-started index describes Ch 6 as starting with "an intercepted
git clone."  The actual tutorial has no git-clone interception step —
the learner navigates directly to LogfileGit.  Either add a
git-clone-interception step to the tutorial or update the description
in index.rst.

**Ch 3 — File contents not scenario-consistent**

The random files available on the ``files`` mock server use generic
names (``Alice Morgan``, ``Bob Chen``) that do not match Logfile Inc.
staff.  The filenames are realistic enough, but the CSV contents
reference people outside the scenario.  Lower priority — learners only
see the filename, not the content.

**Ch 4 — Paths use ``developer`` instead of ``mmorgan``**

The mock SSH-exec outputs reference ``/home/developer/`` as the home
directory.  Max Morgan's username is ``mmorgan``; the paths should
reflect that.


Guidelines for New Chapters
-----------------------------

**Stay in the story.**
New chapters should fit within the existing engagement.  Each chapter
is one technique that the auditor discovers or applies during the
assessment.  The technique should follow logically from what came
before — or open a new thread that later chapters can pick up.

**Use existing characters.**
Do not introduce new staff members without a clear narrative reason.
Prefer assigning a chapter to an existing character whose traits make
the vulnerability believable.  Lisa Chen (elevated access, ForwardAgent
enabled) is largely unexplored and a natural fit for future chapters.

**Keep infrastructure consistent.**
Lab addresses, ports, and hostnames must match the table above.  The
only constant that must never change is the SSH-MITM proxy port
(:10022 by default).  All other service ports are in the 20000 range
to avoid requiring root.

**No positioning narrative.**
Chapters do not explain how the auditor got into the network path.
The proxy is already in position.  Focus on what SSH-MITM can observe
or extract — not on ARP spoofing, DNS poisoning, or similar setup
steps.

**Techniques not yet covered (possible future chapters):**

- Lisa Chen logs in to ``web01`` with her elevated account →
  agent captured, more doors opened
- Lateral movement from ``web01`` to ``db01`` via Sarah's agent
- Port forwarding: a developer forwards a local port to an internal
  service through the proxy
- NETCONF session on ``router01`` (Thomas)
- SCP transfer with rsync injection (CVE-2022-29154)
