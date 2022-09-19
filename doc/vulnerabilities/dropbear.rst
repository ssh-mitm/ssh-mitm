Dropbear
========

Dropbear is a software package written by Matt Johnston that provides a Secure Shell-compatible server and client.
It is designed as a replacement for standard OpenSSH for environments with low memory and processor resources, such as embedded systems.
It is a core component of OpenWrt and other router distributions.

.. note::

   The vulnerabilities are divided into 3 categories. At the CVE numbers you can see an icon to identify the support by SSH-MITM.

   * :fas:`check;sd-text-success` Integrated in SSH-MITM - A test or exploit is integrated in SSH-MITM and relevant information is available in the documentation.
   * :fas:`info;sd-text-primary` extended information describing how the vulnerability works or vulnerabilities can be exploited without SSH-MITM
   * :fas:`link;sd-text-info` same entry as from official CVE databases
   * :fas:`question;sd-text-warning` disputed vulnerabilities - it's not clear if this is a security issue or not
   * :fas:`ban;sd-text-light` rejected CVE number - the CVE Number was rejected because of no security issues


.. toctree::
   :maxdepth: 1

   CVE-2021-36369
   CVE-2018-15599
