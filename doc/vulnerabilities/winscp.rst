WinSCP
======

WinSCP (Windows Secure Copy) is a free and open-source SSH File Transfer Protocol (SFTP),
File Transfer Protocol (FTP), WebDAV, Amazon S3, and secure copy protocol (SCP) client for Microsoft Windows.
Its main function is secure file transfer between a local computer and a remote server.
Beyond this, WinSCP offers basic file manager and file synchronization functionality.
For secure transfers, it uses the Secure Shell protocol (SSH) and supports the SCP protocol in addition to SFTP.

Development of WinSCP started around March 2000 and continues.
Originally it was hosted by the University of Economics in Prague, where its author worked at the time.
Since July 16, 2003, it is licensed under the GNU GPL. It is hosted on SourceForge and GitHub.

WinSCP is based on the implementation of the SSH protocol from PuTTY and FTP protocol from FileZilla.
It is also available as a plugin for Altap Salamander file manager, and there exists a third-party plugin for the FAR file manager.

.. note::

   The vulnerabilities are divided into 3 categories. At the CVE numbers you can see an icon to identify the support by SSH-MITM.

   * :fas:`check;sd-text-success` Integrated in SSH-MITM - A test or exploit is integrated in SSH-MITM and relevant information is available in the documentation.
   * :fas:`info;sd-text-primary` extended information describing how the vulnerability works or vulnerabilities can be exploited without SSH-MITM
   * :fas:`times;sd-text-secondary` reference to the CVE number - for these vulnerabilities only the information exists which is also visible in the official CVE entry

.. toctree::
   :maxdepth: 1

   CVE-2019-6111
   CVE-2019-6110
   CVE-2019-6109
   CVE-2018-20685
