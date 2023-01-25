:fas:`file-lines` Configuration
===============================

.. |br| raw:: html

   <br />


.. |default| raw:: html

    <i>Default:</i>


.. confval:: [SSH-MITM]

   .. code-block:: ini

      [SSH-MITM]
      debug = False
      paramiko-log-level = warning
      disable-workarounds = False

   :option boolean debug: :bdg-primary-line:`True` :bdg-primary:`False` |br|
      Enables SSH-MITM's debug mode
   :option string paramiko-log-level: :bdg-primary-line:`debug` :bdg-primary-line:`info` :bdg-primary:`warning` |br|
      Set log level for paramiko (ssh library)
   :option boolean disable-workarounds: :bdg-primary-line:`True` :bdg-primary:`False` |br|
      Disable workarrounds, which are needed for some special clients



.. confval:: [SSH-Server-Options]

   .. code-block:: ini

      [SSH-Server-Options]
      listen-port = 10022
      transparent = False
      host-key =
      host-key-algorithm = rsa
      host-key-length = 2048
      request-agent-breakin = False
      banner-name =

   :option integer listen-port: :bdg-primary:`10022` |br|
      Port which is used to listen for incoming ssh connections. |br|
      **Note:** Wehn using a port <=1024, SSH-MITM must be started with root privileges.
   :option boolean transparent: :bdg-primary-line:`True` :bdg-primary:`False` |br|
      Starts SSH-MITM in a transparent mode, which uses Linux TProxy for incoming connections.
      Tansparent mode requires root privileges.

.. confval:: transparent

   :type: boolean
   :values: ``True``, ``False``
   :default: ``False``



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





