:fas:`book` Audit Guide
=======================

This guide walks through SSH-MITM's interception techniques from first
principles to advanced protocol-level attacks. Each section starts with
a ready-to-run command and builds toward the technical depth needed for
a thorough security audit.

.. grid:: 1 2 3 3
   :gutter: 3

   .. grid-item-card:: :fas:`terminal` Session Hijacking
      :link: sessions
      :link-type: doc

      Mirror live SSH sessions and interact with them in real time.
      Commands executed in either session appear in both.

   .. grid-item-card:: :fas:`file-arrow-up` File Interception
      :link: file_transfer
      :link-type: doc

      Intercept, store, or replace files during SCP and SFTP transfers
      without interrupting the client.

   .. grid-item-card:: :fas:`network-wired` Port Forwarding
      :link: portforwarding
      :link-type: doc

      Intercept TCP tunnels and dynamic port forwarding with full
      SOCKS 4/5 support.

   .. grid-item-card:: :fas:`key` Authentication
      :link: authentication
      :link-type: doc

      Intercept passwords and public keys. Accept the same key as the
      target server and fall back to password authentication automatically.

   .. grid-item-card:: :fas:`shield-halved` FIDO2 Token Phishing
      :link: trivialauth
      :link-type: doc

      Intercept hardware token authentication via the trivial
      authentication attack (CVE-2021-36367, CVE-2021-36368).

   .. grid-item-card:: :fab:`windows` PowerShell Remoting
      :link: powershell
      :link-type: doc

      Intercept PowerShell remoting sessions over SSH. Log commands,
      output, errors, and state transitions.

   .. grid-item-card:: :fas:`network-wired` NETCONF
      :link: netconf
      :link-type: doc

      Intercept NETCONF management sessions on network devices.
      Log every RPC operation and reply transparently.

   .. grid-item-card:: :fas:`puzzle-piece` Plugin Browser
      :link: plugin_browser
      :link-type: doc

      Explore all available plugins and their configuration options
      interactively in the terminal — without editing any files.


.. toctree::
   :caption: Authentication
   :maxdepth: 1

   authentication
   sshagent
   trivialauth
   publickey-hostbound

.. toctree::
   :caption: Interception
   :maxdepth: 1

   sessions
   file_transfer
   portforwarding

.. toctree::
   :caption: Protocols
   :maxdepth: 1

   powershell
   netconf
   mosh

.. toctree::
   :caption: Client Auditing
   :maxdepth: 1

   fingerprint
   client_audit

.. toctree::
   :caption: Reference
   :maxdepth: 1

   plugin_browser
   configuration
   transparent
   faq
   legal
