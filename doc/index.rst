=================================
SSH-MITM - ssh audits made simple
=================================

.. div:: sd-fs-5 sd-font-weight-bold

   SSH-MITM is an open-source man-in-the-middle SSH server for security audits and malware analysis.
   Placed on the network path between client and server, it intercepts SSH sessions in real time
   through a flexible plugin system.

.. image:: _static/intro.png
    :class: dark-light
    :width: 60%
    :align: center

.. admonition:: :fas:`scale-balanced` Legal Notice
   :class: legal-notice

   SSH-MITM is intended for authorized security audits, penetration testing, and research only.
   Do not use it against systems you do not own or have explicit written permission to test.
   Unauthorized interception of SSH traffic may be illegal in your jurisdiction.
   See the :doc:`Legal Notice </user_guide/legal>` for details.


.. grid:: 1 1 2 2
   :gutter: 3

   .. grid-item-card:: :fas:`rocket` Get Started
      :link: get_started/index
      :link-type: doc

      New to SSH-MITM? The interactive tutorial walks through five
      real interception scenarios — no target server needed.
      Up and running in under two minutes.

   .. grid-item-card:: :fas:`book` Audit Guide
      :link: user_guide/index
      :link-type: doc

      All interception techniques in depth — authentication, file
      transfers, port forwarding, NETCONF, PowerShell, and client
      auditing.


Features
========

SSH-MITM acts as a proxy between SSH client and server — it terminates both
connections independently and forwards all traffic. This gives the auditor
full visibility into the session without disrupting it.

.. image:: _static/ssh-mitm-setup.svg
    :class: dark-light
    :alt: SSH-MITM proxy setup diagram

.. list-table::
   :widths: 1 99
   :class: feature-list

   * - :fas:`key`
     - Read **passwords and public keys** in cleartext as they pass through the proxy —
       even when the client uses key-based auth, SSH-MITM falls back to password automatically.
       :doc:`→ Authentication </user_guide/authentication>`
   * - :fas:`terminal`
     - **Attach to any live SSH session** and inject commands invisibly via mirrorshell —
       the original user sees nothing.
       :doc:`→ Session Hijacking </user_guide/sessions>`
   * - :fas:`file-arrow-up`
     - **Intercept or silently replace** every file transferred via SCP or SFTP
       without interrupting the client.
       :doc:`→ File Transfers </user_guide/file_transfer>`
   * - :fas:`network-wired`
     - Intercept every **TCP tunnel and SOCKS connection** routed through the proxy.
       :doc:`→ Port Forwarding </user_guide/portforwarding>`
   * - :fas:`shield-halved`
     - **Bypass hardware token authentication** without touching the token —
       using the trivial authentication attack (CVE-2021-36367, CVE-2021-36368).
       :doc:`→ FIDO2 Token Phishing </user_guide/trivialauth>`
   * - :fas:`magnifying-glass`
     - **Identify SSH client software and known CVEs** from key negotiation behavior alone —
       no active probing required.
       :doc:`→ Client Auditing </user_guide/client_audit>`
   * - :fab:`windows`
     - Full visibility into **PowerShell Remoting (PSRP)** and **NETCONF** management sessions.
       :doc:`→ Protocols </user_guide/powershell>`

:doc:`→ Audit Guide </user_guide/index>`


Security Research
=================

SSH-MITM was originally developed as a research tool — not just a proxy.
The Man-in-the-Middle position makes it possible to observe SSH client
behavior that is invisible from either endpoint: how clients negotiate
algorithms, which authentication methods they accept, and how they respond
to unexpected server behavior.

This research approach led to the discovery of **6 previously unknown
vulnerabilities** in widely-deployed SSH software — including PuTTY,
OpenSSH, Dropbear, Midnight Commander, and MobaXterm. Each was reported
to the vendor and assigned a CVE number.

:bdg-link-primary-line:`CVE-2021-36367 <vulnerabilities/CVE-2021-36367.html>`
:bdg-link-primary-line:`CVE-2021-36368 <vulnerabilities/CVE-2021-36368.html>`
:bdg-link-primary-line:`CVE-2021-36369 <vulnerabilities/CVE-2021-36369.html>`
:bdg-link-primary-line:`CVE-2021-36370 <vulnerabilities/CVE-2021-36370.html>`
:bdg-link-primary-line:`CVE-2022-38336 <vulnerabilities/CVE-2022-38336.html>`
:bdg-link-primary-line:`CVE-2022-38337 <vulnerabilities/CVE-2022-38337.html>`

The initial findings — the trivial authentication attack and how FIDO2
hardware tokens can be phished through a positioned proxy — were presented
at **DeepSec 2021**:

.. figure:: images/ds2021-video-small.png
   :target: https://vimeo.com/showcase/9059922/video/651517195
   :class: dark-light
   :alt: DeepSec 2021 talk — click to watch on Vimeo
   :width: 80%

   `Watch on Vimeo <https://vimeo.com/showcase/9059922/video/651517195>`_ ·
   `Download slides <https://github.com/ssh-mitm/ssh-mitm/files/7568291/deepsec.pdf>`_

:doc:`→ Security Research Findings <vulnerabilities/findings>`


.. toctree::
   :maxdepth: 1
   :hidden:

   Get Started <get_started/index>
   Audit Guide <user_guide/index>
   Security Research <vulnerabilities/index>
   Development <develop/index>
