=================================
SSH-MITM - ssh audits made simple
=================================

.. image:: _static/intro.png
    :class: dark-light

**SSH-MITM** is an open-source man-in-the-middle SSH server for security audits and malware analysis.
It intercepts SSH sessions in real time — supporting password and public-key authentication,
session hijacking, file transfer interception, and port forwarding — through a flexible plugin system.

.. admonition:: :fas:`scale-balanced` Legal Notice
   :class: legal-notice

   SSH-MITM is intended for authorized security audits, penetration testing, and research only.
   Do not use it against systems you do not own or have explicit written permission to test.
   Unauthorized interception of SSH traffic may be illegal in your jurisdiction.
   See the :doc:`Legal Notice </user_guide/legal>` for details.


Features
========

.. grid:: 1 2 3 3
   :gutter: 3

   .. grid-item-card:: :fas:`terminal` Session Hijacking
      :link: user_guide/sessions
      :link-type: doc

      Mirror live SSH sessions and interact with them in real time.
      Commands executed in either session appear in both.

   .. grid-item-card:: :fas:`file-arrow-up` File Interception
      :link: user_guide/file_transfer
      :link-type: doc

      Intercept, store, or replace files during SCP and SFTP transfers
      without interrupting the client.

   .. grid-item-card:: :fas:`network-wired` Port Forwarding
      :link: user_guide/portforwarding
      :link-type: doc

      Intercept TCP tunnels and dynamic port forwarding with full
      SOCKS 4/5 support.

   .. grid-item-card:: :fas:`key` Authentication
      :link: user_guide/authentication
      :link-type: doc

      Intercept passwords and public keys. Accept the same key as the
      target server and fall back to password authentication automatically.

   .. grid-item-card:: :fas:`shield-halved` FIDO2 Token Phishing
      :link: user_guide/trivialauth
      :link-type: doc

      Intercept hardware token authentication via the trivial
      authentication attack (CVE-2021-36367, CVE-2021-36368).


Security Research
=================

.. card:: :fas:`magnifying-glass` Vulnerabilities discovered through SSH-MITM research

   Operating from the Man-in-the-Middle position makes it possible to observe SSH client
   behavior that is invisible from either endpoint. During security audits using SSH-MITM,
   **6 previously unknown vulnerabilities** were discovered in widely-deployed SSH software —
   including PuTTY, OpenSSH, Dropbear, Midnight Commander, and MobaXterm. Each was reported
   to the vendor and assigned a CVE number.

   :bdg-link-primary-line:`CVE-2021-36367 <vulnerabilities/CVE-2021-36367.html>` :bdg-link-primary-line:`CVE-2021-36368 <vulnerabilities/CVE-2021-36368.html>` :bdg-link-primary-line:`CVE-2021-36369 <vulnerabilities/CVE-2021-36369.html>` :bdg-link-primary-line:`CVE-2021-36370 <vulnerabilities/CVE-2021-36370.html>` :bdg-link-primary-line:`CVE-2022-38336 <vulnerabilities/CVE-2022-38336.html>` :bdg-link-primary-line:`CVE-2022-38337 <vulnerabilities/CVE-2022-38337.html>`
   +++
   :doc:`→ Security Research Findings <vulnerabilities/findings>`


.. toctree::
   :maxdepth: 1
   :hidden:

   get_started/index
   Audit Guide <user_guide/index>
   develop/index
   Vulnerability Research <vulnerabilities/index>
   changelog
