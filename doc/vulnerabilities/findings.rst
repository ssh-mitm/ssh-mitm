.. _findings:

:fas:`magnifying-glass` Security Research Findings
===================================================

SSH-MITM was originally developed as an active security research tool — not just to
intercept sessions, but to understand how SSH clients behave when confronted with a
manipulated server. Operating from the Man-in-the-Middle position makes it possible
to observe authentication flows, protocol negotiations, and client-side decisions that
are invisible from either endpoint alone.

During this research, several previously unknown vulnerabilities were discovered in
widely-deployed SSH software. Each was reported to the respective vendor,
assigned a CVE number, and in most cases led to a fixed release.

.. grid:: 1 2 2 2
   :gutter: 3

   .. grid-item-card:: CVE-2026-60000 · OpenSSH
      :link: CVE-2026-60000
      :link-type: doc

      :bdg-info:`CVSS 3.7`

      OpenSSH's GSSAPI authentication violated RFC 4462 in ways that let an attacker
      bypass ``MaxAuthTries`` entirely, reveal valid usernames in a single packet, and
      trigger unlimited privileged credential-acquisition calls — all from one root
      cause fixed in a single OpenSSH 10.4 commit.

   .. grid-item-card:: CVE-2022-38337 · MobaXterm
      :link: CVE-2022-38337
      :link-type: doc

      :bdg-warning:`CVSS 5.4`

      MobaXterm used a hardcoded password (``MobaPasswordCancel``) internally. In
      combination with a MitM server, this could be used to trigger fail2ban bans
      against the legitimate user.

   .. grid-item-card:: CVE-2022-38336 · MobaXterm
      :link: CVE-2022-38336
      :link-type: doc

      :bdg-warning:`CVSS 5.4`

      MobaXterm did not warn users when an SSH server's host key changed, suppressing
      the standard security prompt that would normally alert a user to a potential
      Man-in-the-Middle attack.

   .. grid-item-card:: CVE-2021-36370 · Midnight Commander
      :link: CVE-2021-36370
      :link-type: doc

      :bdg-danger:`CVSS 7.5`

      Midnight Commander performed no SSH host key verification when opening remote
      connections, allowing a MitM attacker to intercept sessions without detection.

   .. grid-item-card:: CVE-2021-36369 · Dropbear
      :link: CVE-2021-36369
      :link-type: doc

      :bdg-danger:`CVSS 8.1`

      The Dropbear SSH client accepted trivial authentication without warning,
      making it susceptible to silent Man-in-the-Middle credential harvesting —
      particularly relevant on embedded systems and IoT devices.

   .. grid-item-card:: CVE-2021-36368 · OpenSSH
      :link: CVE-2021-36368
      :link-type: doc

      :bdg-info:`CVSS 3.7`

      OpenSSH clients using FIDO2 hardware tokens with agent forwarding could not
      determine whether a key confirmation was for their own connection or for an
      attacker's connection through a forwarded agent.

   .. grid-item-card:: CVE-2021-36367 · PuTTY
      :link: CVE-2021-36367
      :link-type: doc

      :bdg-danger:`CVSS 8.1`

      PuTTY before 0.71 accepted trivial authentication silently — no indicator was
      shown when a server granted access without requiring credentials. Invisible to
      the user even while being actively exploited.
