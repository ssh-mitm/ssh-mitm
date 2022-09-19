Vulnerabilities
===============

This page lists vulnerabilities in SSH clients and servers as well as SSH relevant programs of the last years.

.. note::

   The vulnerabilities are divided into 4 categories to show the risk.

   ======================== =================== =================================
   Severity                 Base Score Range    Description
   ======================== =================== =================================
   :bdg-light:`none`        0.0                 No risk or not a vulnerability
   :bdg-info:`low`          0.1-3.9             Low risk
   :bdg-warning:`medium`    4.0-6.9             Medium risk
   :bdg-danger:`high`       7.0-10.0            High risk
   ======================== =================== =================================

   At the CVE numbers you can see an icon to identify the support by SSH-MITM.

   * :fas:`check;sd-text-success` Integrated in SSH-MITM - A test or exploit is integrated in SSH-MITM and relevant information is available in the documentation.
   * :fas:`info;sd-text-primary` extended information describing how the vulnerability works or vulnerabilities can be exploited without SSH-MITM
   * :fas:`link;sd-text-info` same entry as from official CVE databases
   * :fas:`question;sd-text-warning` disputed vulnerabilities - it's not clear if this is a security issue or not
   * :fas:`ban;sd-text-light` rejected CVE number - the CVE Number was rejected because of no security issues

.. toctree::
   :maxdepth: 2

   openssh
   putty
   dropbear
   winscp
   midnightcommander
   rsync
