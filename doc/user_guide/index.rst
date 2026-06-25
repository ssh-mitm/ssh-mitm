:fas:`book` Audit Guide
=======================

This guide walks through SSH-MITM's interception techniques from first
principles to advanced protocol-level attacks. Each section starts with
a ready-to-run command and builds toward the technical depth needed for
a thorough security audit.

.. grid:: 1 1 2 2
   :gutter: 3

   .. grid-item-card:: :fas:`crosshairs` Positioning
      :shadow: sm

      Understand how SSH-MITM is placed between client and server — direct
      connection, ARP spoofing, DNS hijacking, rogue access point, or
      transparent proxy at a gateway.

      :doc:`attack_scenarios`

   .. grid-item-card:: :fas:`key` Authentication
      :shadow: sm

      Intercept passwords and public keys. Accept the same key as the target
      server, use the forwarded agent for full access, or redirect keyless
      clients to a honeypot.

      :doc:`authentication` · :doc:`sshagent` · :doc:`trivialauth` · :doc:`publickey-hostbound`

   .. grid-item-card:: :fas:`terminal` Interception
      :shadow: sm

      Mirror live SSH sessions, inject commands via mirrorshell, capture or
      replace files during SCP and SFTP transfers, and intercept port
      forwarding tunnels to reach internal services.

      :doc:`sessions` · :doc:`file_transfer` · :doc:`portforwarding`

   .. grid-item-card:: :fas:`network-wired` Protocols
      :shadow: sm

      Intercept tools and protocols that use SSH as a transport — Git and
      rsync over SSH, PowerShell Remoting, NETCONF, and Mosh.

      :doc:`git` · :doc:`rsync` · :doc:`powershell` · :doc:`netconf` · :doc:`mosh`

   .. grid-item-card:: :fas:`magnifying-glass` Client Auditing
      :shadow: sm

      Identify SSH client software and version from key negotiation behavior.
      Match observed patterns against known CVEs automatically.

      :doc:`fingerprint` · :doc:`client_audit`

   .. grid-item-card:: :fas:`gear` Reference
      :shadow: sm

      Plugin browser, full configuration reference, transparent proxy mode,
      FAQ, and legal notice.

      :doc:`plugin_browser` · :doc:`configuration` · :doc:`transparent` · :doc:`faq` · :doc:`legal`


.. toctree::
   :caption: Positioning
   :maxdepth: 1
   :hidden:

   attack_scenarios

.. toctree::
   :caption: Authentication
   :maxdepth: 1
   :hidden:

   authentication
   sshagent
   trivialauth
   publickey-hostbound

.. toctree::
   :caption: Interception
   :maxdepth: 1
   :hidden:

   sessions
   file_transfer
   portforwarding

.. toctree::
   :caption: Protocols
   :maxdepth: 1
   :hidden:

   git
   rsync
   powershell
   netconf
   mosh

.. toctree::
   :caption: Client Auditing
   :maxdepth: 1
   :hidden:

   fingerprint
   client_audit

.. toctree::
   :caption: Reference
   :maxdepth: 1
   :hidden:

   plugin_browser
   configuration
   transparent
   faq
   legal
