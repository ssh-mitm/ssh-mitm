======================================
:fas:`copy` File transferrs (SCP/SFTP)
======================================

SSH-MITM is able to intercept SCP and SFTP file transferrs.
It's also possible to store or replace transferred files.

Secure copy protocol (SCP)
==========================

Secure copy protocol (SCP) is a means of securely transferring computer files
between a local host and a remote host or between two remote hosts.
"SCP" commonly refers to both the Secure Copy Protocol and the program itself.

According to OpenSSH developers in April 2019, SCP is outdated, inflexible and not readily fixed;
they recommend the use of more modern protocols like SFTP and rsync for file transfer.
As of OpenSSH version 9.0, scp client therefore uses SFTP for file transfers by default
instead of the legacy SCP/RCP protocol.

Store intercepted files
-----------------------

To copy a from a server to the client, following SCP command was used:

.. code-block:: none

    $ scp -P 10022 testuser@proxyserver:/bin/bash .

To store files, which are transferred with SCP, following arguments must be provided:

.. code-block:: none

    $ ssh-mitm server --session-log-dir ~/sshlogs --store-scp-files
    INFO     ℹ session 7c43d2b2-51e7-4351-a468-c6768ea04d30 created

SSH-MITM generates a unique Id for each client and the log direcory contains subfolders for each session.
Also a uniquie Id for each file transfer is assigned.

.. code-block:: none

    INFO     file bash -> a5a0e5d2-4cbd-4c25-8430-a3b79e71273d

The reason for the unique id as filename is, multiple files with the same filename can be transferred.
This avoids name collissions and avoids overriting already existing files.

.. code-bloc

.. code-block:: none

    $ tree
    .
    └── 7c43d2b2-51e7-4351-a468-c6768ea04d30
        ├── publickeys
        └── scp
            └── a5a0e5d2-4cbd-4c25-8430-a3b79e71273d

    2 directories, 4 files


Replace files
-------------

There are some situation, where it's useful to replace a transferred file with another one.

This can be done with another SCP-interface in SSH-MITM.

.. note::

    The default interface replace-file interface replaces all files with a given one.
    This means, all files will be replaces with the same file, but it's easy to extend this
    plugin to provide a more sofficticated workflow, which is able to replace only specific files.

.. code-block:: none

    $ ssh-mitm server --scp-interface replace_file --scp-replace /bin/ls


SSH File Transfer Protocol
==========================

The SSH File Transfer Protocol (SFTP) is a network protocol
that provides file access, file transfer, and file management over any
reliable data stream.
It was designed by the Internet Engineering Task Force (IETF) as an extension
of the Secure Shell protocol (SSH) version 2.0 to provide secure file transfer capabilities.

Store intercepted files
-----------------------

.. code-block:: none

    $ scp -P 10022 testuser@proxyserver:/bin/bash .

to store files, which are transferred with SCP, following arguments must be provided:

.. code-block:: none

    $ ssh-mitm server --session-log-dir ~/sshlogs --store-sftp-files
    INFO     ℹ session 7c43d2b2-51e7-4351-a468-c6768ea04d30 created

SSH-MITM generates a unique Id for each client and the log direcory contains subfolders for each session.
Also a uniquie Id for each file transfer is assigned.

.. code-block:: none

    INFO     file bash -> a5a0e5d2-4cbd-4c25-8430-a3b79e71273d

The reason for the unique id as filename is, multiple files with the same filename can be transferred.
This avoids name collissions and avoids overriting already existing files.

.. code-bloc

.. code-block:: none

    $ tree
    .
    └── 7c43d2b2-51e7-4351-a468-c6768ea04d30
        ├── publickeys
        └── sftp
            └── a5a0e5d2-4cbd-4c25-8430-a3b79e71273d

    2 directories, 4 files


Replace files
-------------

There are some situation, where it's useful to replace a transferred file with another one.

This can be done with another SCP-interface in SSH-MITM.

.. note::

    The default interface replace-file interface replaces all files with a given one.
    This means, all files will be replaces with the same file, but it's easy to extend this
    plugin to provide a more sofficticated workflow, which is able to replace only specific files.

.. code-block:: none

    $ ssh-mitm server --sftp-handler replace_file --sftp-replace /bin/ls
