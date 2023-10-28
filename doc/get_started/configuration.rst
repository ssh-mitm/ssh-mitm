:fas:`file-lines` Configuration
===============================

.. |br| raw:: html

   <br />


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


.. confval:: [SSH-Server-Modules]

   .. code-block:: ini

      [SSH-Server-Modules]
      ssh-interface = mirrorshell
      scp-interface = store_file
      sftp-interface = base
      sftp-handler = store_file
      server-tunnel-interface = inject
      client-tunnel-interface = socks
      auth-interface = base
      authenticator = passthrough
      session-class = base


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
      Wehn using a port <=1024, SSH-MITM must be started with root privileges.
   :option boolean transparent: :bdg-primary-line:`True` :bdg-primary:`False` |br|
      Starts SSH-MITM in a transparent mode, which uses Linux TProxy for incoming connections.
      Tansparent mode requires root privileges.
   :option string host-key: |br|
      Optional private ssh key, which is used as SSH-MITM's host key.|br|
      When no host-key was provided, a random host key will be generated.
   :option string host-key-algorithm: :bdg-primary-line:`dss` :bdg-primary:`rsa` :bdg-primary-line:`ecdsa` :bdg-primary-line:`ed25519` |br|
      Algorithm, which is used to generate the random host-key.
   :option integer host-key-length: :bdg-primary:`2048` |br|
      The length for the random host key.
   :option boolean request-agent-breakin: :bdg-primary-line:`True` :bdg-primary:`False` |br|
      SSH-MITM tries to request the ssh agent, even if the client does not forward the agent.
   :option string banner-name: |br|
      Custom ssh banner name, which is presented the client on the first connection attempt.|br|
      If no banner name is configured, the default banner name is ``SSH-2.0-SSHMITM_3.0.1``

.. confval:: [Session]

   .. code-block:: ini

      [Session]
      session-log-dir =

Authentication-Plugins
----------------------

.. confval:: [AuthenticatorPassThrough]

   .. code-block:: ini

      [AuthenticatorPassThrough]
      remote-host =
      remote-port = 22
      auth-username =
      auth-password =
      auth-hide-credentials = False
      enable-auth-fallback = False
      fallback-host =
      fallback-port = 22
      fallback-username =
      fallback-password =

.. confval:: [ServerInterface]

   .. code-block:: ini

      [ServerInterface]
      disable-ssh = False
      disable-scp = False
      disable-password-auth = False
      disable-pubkey-auth = False
      accept-first-publickey = False
      disallow-publickey-auth = False
      enable-none-auth = False
      enable-trivial-auth = False
      enable-keyboard-interactive-auth = False
      disable-keyboard-interactive-prompts = False
      extra-auth-methods =
      disable-auth-method-lookup = False


Terminal-Session-Plugins
------------------------

.. confval:: [SSHMirrorForwarder]

   .. code-block:: ini

      [SSHMirrorForwarder]
      ssh-mirrorshell-net = 127.0.0.1
      ssh-mirrorshell-key =
      store-ssh-session = False

SCP-Plugins
-----------

.. confval:: [CVE202229154]

   .. code-block:: ini

      [CVE202229154]
      rsync-inject-file =


.. confval:: [SCPReplaceFile]

   .. code-block:: ini

      [SCPReplaceFile]
      scp_replace_file =

.. confval:: [SCPRewriteCommand]

   .. code-block:: ini

      [SCPRewriteCommand]
      scp-append-string =
      scp-replace-string =

.. confval:: [SCPStorageForwarder]

   .. code-block:: ini

      [SCPStorageForwarder]
      store-scp-files = False
      store-command-data = False


SFTP-Plugins
------------

.. confval:: [SFTPHandlerStoragePlugin]

   .. code-block:: ini

      [SFTPHandlerStoragePlugin]
      store-sftp-files = False

.. confval:: [SFTPProxyReplaceHandler]

   .. code-block:: ini

      [SFTPProxyReplaceHandler]
      sftp-replace-file =


Port-Forwarding-Plugins
-----------------------

.. confval:: [InjectableRemotePortForwardingForwarder]

   .. code-block:: ini

      [InjectableRemotePortForwardingForwarder]
      server-tunnel-net = 127.0.0.1

.. confval:: [SOCKSTunnelForwarder]

   .. code-block:: ini

      [SOCKSTunnelForwarder]
      socks-listen-address = 127.0.0.1

.. confval:: [SOCKS4TunnelForwarder]

   .. code-block:: ini

      [SOCKS4TunnelForwarder]
      socks-listen-address = 127.0.0.1

.. confval:: [SOCKS5TunnelForwarder]

   .. code-block:: ini

      [SOCKS5TunnelForwarder]
      socks-listen-address = 127.0.0.1