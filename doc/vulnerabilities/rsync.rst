rsync
=====

rsync is a utility for efficiently transferring and synchronizing files between a computer and a storage
drive and across networked computers by comparing the modification times and sizes of files.

Rsync is written in C as a single threaded application.
The rsync algorithm is a type of delta encoding, and is used for minimizing network usage.
Zlib may be used for additional data compression, and SSH or stunnel can be used for security.
Rsync is the facility typically used for synchronizing software repositories on mirror sites used by package management systems.

Rsync is typically used for synchronizing files and directories between two different systems.
For example, if the command `rsync local-file user@remote-host:remote-file` is run, rsync will use SSH to connect as user to remote-host.
Once connected, it will invoke the remote host's rsync and then the two programs will determine what parts of the
local file need to be transferred so that the remote file matches the local one.

Rsync can also operate in a daemon mode (rsyncd), serving and receiving files in the native rsync protocol (using the "rsync://" syntax).

.. note::

   The vulnerabilities are divided into 3 categories. At the CVE numbers you can see an icon to identify the support by SSH-MITM.

   * :fas:`check;sd-text-success` Integrated in SSH-MITM - A test or exploit is integrated in SSH-MITM and relevant information is available in the documentation.
   * :fas:`info;sd-text-primary` extended information describing how the vulnerability works or vulnerabilities can be exploited without SSH-MITM
   * :fas:`link;sd-text-info` same entry as from official CVE databases
   * :fas:`question;sd-text-warning` disputed vulnerabilities - it's not clear if this is a security issue or not
   * :fas:`ban;sd-text-light` rejected CVE number - the CVE Number was rejected because of no security issues

.. toctree::
   :maxdepth: 1

   CVE-2022-29154
   CVE-2021-3755
