:fas:`skull` Vulnerabilities
============================

The following section provides an overview of recent vulnerabilities in
SSH clients, servers, and related programs. This information is crucial
for understanding potential threats and ensuring the security of your
SSH-based systems during malware analysis, security audits, and other projects.

Understanding the common vulnerabilities and their impact is essential for
organizations looking to secure their infrastructure and minimize the risk
of a successful attack.


.. note::

   **Listed vulnerabilities are either integrated in SSH-MITM or were discovered by Manfred Kaiser (AUT-milCERT).**

   The vulnerabilities are divided into 4 categories to show the risk.

   .. toggle::

      ======================== =================== =================================
      Severity                 Base Score Range    Description
      ======================== =================== =================================
      :bdg-light:`none`        0.0                 No risk or not a vulnerability
      :bdg-info:`low`          0.1-3.9             Low risk
      :bdg-warning:`medium`    4.0-6.9             Medium risk
      :bdg-danger:`high`       7.0-10.0            High risk
      ======================== =================== =================================

.. toctree::
   :maxdepth: 2
   :titlesonly:

   findings
   openssh
   putty
   dropbear
   winscp
   midnightcommander
   rsync
   mobaxterm
