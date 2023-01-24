:fas:`file-lines` Configuration
===============================

``[SSH-MITM]``
--------------

.. confval:: debug

   :type: boolean
   :values: ``True``, ``False``
   :default: ``False``

   Enables SSH-MITM's debug moe

.. confval:: paramiko-log-level

   :type: string
   :values: ``debug``, ``info``, ``warning```, ``error``
   :default: ``warning``

   Set log level for paramiko (ssh library)

.. confval:: disable-workarounds

   :type: boolean
   :values: ``True``, ``False``
   :default: ``False``

   Disable workarrounds, which are needed for some special clients


``[SSH-Server-Options]``
------------------------

.. confval:: listen-port

   :type: integer
   :default: ``10022``

   Port which is used to listen for incoming ssh connections.
   
   **Note:** Wehn using a port <=1024, SSH-MITM must be started with root privileges.

.. confval:: transparent

   :type: boolean
   :values: ``True``, ``False``
   :default: ``False``

   Starts SSH-MITM in a transparent mode, which uses Linux TProxy for incoming connections.
   
   **Note:** transparent mode requires to start SSH-MITM with root privileges.

.. confval:: host-key

   :type: string
   :values: path to private ssh key
   :default: ``None``

   Path to a private ssh key file. If no path is provided, a random key is generated.

.. confval:: host-key-algorithm

   :type: string
   :values: ``dss``, ``rsa``, ``ecdsa``, ``ed25519``
   :default: ``rsa``

   Algorithm, which is used to generate the random host key.

.. confval:: host-key-length

   :type: integer
   :default: ``2048``

   Key length, which is used to generate the random host key.

.. confval:: request-agent-breakin

   :type: boolean
   :values: ``True``, ``false``
   :default: ``False``

   Request the ssh agent, even if the client does not forward it to the server.

.. confval:: banner-name

   :type: string
   :default: ``None``

   Custom SSH banner name for SSH-MITM. If no banner name is provided, it will use ``SSH-2.0-SSHMITM_3.0.1``





