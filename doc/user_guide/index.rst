:fas:`book` Audit Guide
=======================

This guide walks through SSH-MITM's interception techniques from first
principles to advanced protocol-level attacks. Each section starts with
a ready-to-run command and builds toward the technical depth needed for
a thorough security audit.

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
