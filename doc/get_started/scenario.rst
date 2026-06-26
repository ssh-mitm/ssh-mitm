:fas:`building` The Logfile Inc. Assessment
============================================

All interactive tutorial chapters are set during a single authorized
penetration test engagement against **Logfile Inc.**, a mid-sized
software company.  Each chapter introduces a new SSH interception
technique while advancing the same story — the infrastructure, the
people, and the context carry over from chapter to chapter, building
a coherent picture of the target environment.


The Company
-----------

Logfile Inc. develops and operates a customer portal and supporting
back-end services for a handful of business clients.  The engineering
team is small: a few developers, one DevOps engineer, and a network
administrator who doubles as IT support.  The internal network is a
flat corporate LAN; most servers are reachable from any employee
workstation.

The company has grown quickly and security has not kept pace.  Hosts
run outdated software.  SSH keys are shared between machines.  Agent
forwarding is enabled by default in the company-wide SSH config.  No
one has audited the router since it was first set up.

Your engagement covers all hosts on the corporate LAN.


Staff
-----

.. grid:: 1 2 2 2
   :gutter: 3

   .. grid-item-card:: :fas:`code` Max Morgan
      :class-header: sd-bg-primary sd-text-white

      Developer · ``mmorgan``
      ^^^
      .. image:: /_static/portrait-mmorgan.svg
         :width: 140px
         :align: center

      Max has been writing code at Logfile Inc. for three years.  He is
      good at his job and proud of it.  Security is not something he thinks
      about much — not because he is careless, but because nothing bad has
      ever happened and there is always another feature to ship.

      He has three SSH key pairs: one on his main workstation, one on his
      laptop, and one on a machine he replaced last year.  He never removed
      the old key from the servers.  When SSH warned him about a changed
      host key once, he deleted the ``known_hosts`` entry and reconnected —
      following a Stack Overflow answer that ranked first in the search
      results.

      Max connects to ``web01`` every day.  He does not verify fingerprints.
      He never has.

      .. rst-class:: sd-text-muted sd-fs-6

         *Avatar seed:* ``wioasffh``

   .. grid-item-card:: :fas:`terminal` Sarah King
      :class-header: sd-bg-primary sd-text-white

      DevOps Engineer · ``sking``
      ^^^
      .. image:: /_static/portrait-sking.svg
         :width: 140px
         :align: center

      Sarah joined a year ago to bring structure to the deployment
      pipelines.  She is methodical and takes security seriously.  When the
      IT department issued a reminder to switch from passwords to SSH keys,
      she was the first to comply — and she set it up properly, with a
      strong key and a passphrase.

      She also enabled agent forwarding.  The company SSH config template
      already had it, and the internal documentation said it was "required
      for jumping between servers."  Sarah did not question it.  She trusts
      her tools.

      From her perspective, she is the most security-conscious person on
      the team.  She is not wrong — she just does not know what agent
      forwarding exposes when the connection passes through an untrusted
      host.

      .. rst-class:: sd-text-muted sd-fs-6

         *Avatar seed:* ``01w1bbaj``

   .. grid-item-card:: :fas:`shield-halved` Lisa Chen
      :class-header: sd-bg-primary sd-text-white

      IT Manager · ``lchen``
      ^^^
      .. image:: /_static/portrait-lchen.svg
         :width: 140px
         :align: center

      Lisa manages user accounts, access permissions, and IT security
      policy for Logfile Inc.  She is organised, thorough, and takes
      compliance seriously — in the sense that she makes sure the boxes
      get ticked.

      After reading about a credential theft incident at another company,
      she drafted and circulated a security notice requiring all staff to
      switch from password authentication to SSH keys.  She also updated
      the internal SSH guide, copying the ``ForwardAgent yes`` line from a
      tutorial she found online because the document said it was "required
      for accessing multiple servers."  She did not know what agent
      forwarding does at the protocol level.  She still does not.

      Lisa has elevated access to most systems for administrative purposes.
      She does not log in to servers often, but when she does, her
      credentials open more doors than most.

      .. rst-class:: sd-text-muted sd-fs-6

         *Avatar seed:* ``mf64hivx``

   .. grid-item-card:: :fas:`network-wired` Thomas Webb
      :class-header: sd-bg-primary sd-text-white

      Network Administrator · ``twebb``
      ^^^
      .. image:: /_static/portrait-twebb.svg
         :width: 140px
         :align: center

      Thomas has been at Logfile Inc. for seven years, longer than anyone
      else on the technical team.  He set up the network, installed the
      router, and configured SNMP when the company was a quarter of its
      current size.  He knows every IP address by heart and keeps most of
      the credentials in his head.

      He connects to ``router01`` a few times a week for routine checks.
      His sessions often stay open for hours — he gets interrupted, takes a
      call, walks over to help a colleague, and forgets the terminal is
      still running.  Nobody has ever pointed this out as a problem.

      Thomas is not negligent.  He is just used to the idea that the
      internal network is safe because it is internal.

      .. rst-class:: sd-text-muted sd-fs-6

         *Avatar seed:* ``o6hwlufd``


Infrastructure
--------------

.. warning::

   **Lab addressing — not a real network.**
   All tutorial exercises use addresses from the ``127.0.0.0/8`` loopback
   range.  RFC 5735 reserves the entire /8 block for loopback:
   ``127.0.0.1`` is only the most common alias, but every address from
   ``127.0.0.1`` to ``127.255.255.255`` routes back to the local machine
   without touching a network interface.  Nothing leaves the host.

   The lab subdivides this space into ``/24`` subnets that mirror the
   Logfile Inc. network segments.  No configuration is needed — all
   addresses are immediately reachable on any Linux system.

   .. list-table::
      :header-rows: 1
      :widths: 30 25 45

      * - Segment
        - Lab subnet
        - Hosts
      * - Auditor
        - ``127.0.0.0/24``
        - SSH-MITM proxy: ``127.0.0.1:10022``
      * - Developer LAN
        - ``127.1.0.0/24``
        - Workstations: ``127.1.0.1``
      * - Application servers
        - ``127.2.0.0/24``
        - web01: ``.1`` · files: ``.2`` · logfilegit: ``.3``
      * - Database
        - ``127.3.0.0/24``
        - db01: ``127.3.0.1``
      * - Management
        - ``127.4.0.0/24``
        - router01: ``127.4.0.1``

.. mermaid::

   flowchart LR
       subgraph devlan["Developer LAN · 127.1.0.0/24"]
           ws(["Workstations"])
       end

       subgraph appnet["Application servers · 127.2.0.0/24"]
           direction TB
           web["web01 · 127.2.0.1<br/>HTTP :20080  HTTPS :20443  SSH :20022"]
           files["files · 127.2.0.2<br/>SFTP :20022"]
           git["logfilegit · 127.2.0.3<br/>HTTPS :20443  SSH :20022"]
       end

       subgraph dbnet["Database · 127.3.0.0/24"]
           db["db01 · 127.3.0.1<br/>PostgreSQL :25432"]
       end

       subgraph mgmt["Management · 127.4.0.0/24"]
           router["router01 · 127.4.0.1<br/>SSH :20022  SNMP :20161"]
       end

       ws -->|"SSH :20022 · HTTPS :20443"| web
       ws -->|"SFTP :20022"| files
       ws -->|"SSH :20022 · HTTPS :20443"| git
       ws -->|"SSH :20022"| router
       web -->|"PostgreSQL :25432"| db
       files -->|"PostgreSQL :25432"| db


.. card:: :fas:`globe` web01.logfileinc.internal
   :class-header: sd-font-weight-bold

   SSH :20022 · HTTP :20080 · HTTPS :20443

   The company's main application server.  It runs the customer portal
   — a Python/Django web application that serves client-facing features
   — and several internal management interfaces only reachable from the
   corporate LAN.  Developers push code to the internal Git platform on
   logfilegit and deploy to this server via SSH.

   Max Morgan and Sarah King both connect to web01 multiple times per
   day; Lisa Chen logs in occasionally to restart services or check
   application logs.  The server accepts both password and public-key
   SSH authentication.  SSH host keys were regenerated after a disk
   replacement three months ago, so some clients have not reconnected
   since — a detail that is visible to anyone watching the key exchange.

.. card:: :fas:`folder-open` files.logfileinc.internal
   :class-header: sd-font-weight-bold

   SFTP :20022

   The internal file server used for shared documents, configuration
   backups, and project assets that do not belong in version control.
   Staff transfer files using SFTP; there is no web interface and no
   HTTP service.  Access is restricted to accounts on the corporate LAN.

   Max Morgan retrieves project files and deployment artifacts from it
   regularly.  Lisa Chen uses it to distribute company-wide documents
   and policy templates, including the SSH key migration guide.  Files
   on this server are transferred in the clear through the SFTP
   session — visible to anyone with access to the SSH stream.

.. card:: :fas:`code-branch` logfilegit.logfileinc.internal
   :class-header: sd-font-weight-bold

   SSH :20022 · HTTPS :20443

   Logfile Inc.'s self-hosted Git platform, used by the entire
   development team for source code, code review, and issue tracking.
   Developers clone repositories and push commits over SSH; the web
   interface is available over HTTPS.

   Like GitHub and GitLab, logfilegit publishes the registered SSH
   public keys for every user account at ``/<username>.keys``, visible
   without authentication.  All three developers have at least one SSH
   key registered.  Max Morgan has three — one from a workstation he
   no longer uses that is still valid on several servers.

.. card:: :fas:`database` db01.logfileinc.internal
   :class-header: sd-font-weight-bold

   PostgreSQL :25432

   The production database server.  It runs PostgreSQL and is isolated
   on its own subnet — it is not directly reachable from the developer
   workstation LAN.  Only the application servers (web01 and files) are
   permitted to connect.  There is no SSH service on this host; all
   access goes through the application tier.

   The database holds customer data, session state, and application logs.
   It is not a direct target for SSH-MITM, but lateral movement via a
   compromised application server could reach it.

.. card:: :fas:`network-wired` router01.logfileinc.internal
   :class-header: sd-font-weight-bold

   SSH :20022 · SNMP :20161

   The core network router connecting all internal subnets.  Thomas Webb
   configured it years ago and has been managing it via SSH ever since.
   SNMP is enabled for network monitoring, with separate read-only and
   read-write community strings stored in the running configuration.

   The router is the only device on the dedicated management subnet.
   Thomas's sessions frequently stay open for hours while he steps away
   from his desk — leaving an authenticated shell unattended in the
   proxy.


.. rubric:: Credits

Character portraits are generated with `DiceBear <https://dicebear.com>`_ using
the `Micah <https://www.figma.com/community/file/829741575478342595>`_ avatar style
by Micah Lanier, licensed under
`CC BY 4.0 <https://creativecommons.org/licenses/by/4.0/>`_.
