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
      log-format = text

   :option boolean debug: :bdg-primary-line:`True` :bdg-primary:`False` |br|
      Enables SSH-MITM's debug mode, providing more verbose output of status information and internal processes.
   :option string paramiko-log-level: :bdg-primary-line:`debug` :bdg-primary-line:`info` :bdg-primary:`warning` |br|
      Sets the log level for Paramiko, the underlying SSH library. Controls the verbosity of Paramiko's logging output.
   :option boolean disable-workarounds: :bdg-primary-line:`True` :bdg-primary:`False` |br|
      Disables workarounds for compatibility issues with certain SSH clients. Some clients may require these workarounds to function correctly.
   :option string log-format: :bdg-primary:`text` :bdg-primary-line:`json` |br|
      Defines the format of the log output. Using `json` suppresses standard output and formats logs as JSON.


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

   :option string ssh-interface: :bdg-primary:`mirrorshell` |br|
      Specifies the interface responsible for managing SSH terminal sessions, including shell interaction and command execution.
   :option string scp-interface: :bdg-primary:`store_file` |br|
      Defines the interface used for handling SCP (Secure Copy Protocol) file transfers, including uploads and downloads.
   :option string sftp-interface: :bdg-primary:`base` |br|
      Sets the base interface for SFTP (SSH File Transfer Protocol) operations, such as file listing, uploads, and downloads.
   :option string sftp-handler: :bdg-primary:`store_file` |br|
      Specifies the handler for SFTP operations, responsible for processing file transfer requests and managing file system interactions.
   :option string server-tunnel-interface: :bdg-primary:`inject` |br|
      Configures the interface for managing server-side tunnel operations, such as remote port forwarding.
   :option string client-tunnel-interface: :bdg-primary:`socks` |br|
      Sets the interface for handling client-side tunnel operations, such as local port forwarding.
   :option string auth-interface: :bdg-primary:`base` |br|
      Defines the interface responsible for authentication processes, including credential validation and session initialization.
   :option string authenticator: :bdg-primary:`passthrough` |br|
      Specifies the authenticator module used for validating user credentials and managing authentication workflows.
   :option string session-class: :bdg-primary:`base` |br|
      Sets the custom session class for SSH-MITM, controlling session behavior, logging, and interaction handling.

.. confval:: [SSH-Server-Options]

   .. code-block:: ini

      [SSH-Server-Options]
      listen-address = ::
      listen-port = 10022
      transparent = False
      host-key =
      host-key-algorithm = rsa
      host-key-length = 2048
      request-agent-breakin = False
      banner-name =

   :option integer listen-address: :bdg-primary:`::` |br|
      Specifies the listen address for incoming connections (default: all interfaces).
   :option integer listen-port: :bdg-primary:`10022` |br|
      Specifies the port on which SSH-MITM listens for incoming SSH connections. |br|
      If a port ≤ 1024 is used, SSH-MITM must be started with root privileges.
   :option boolean transparent: :bdg-primary-line:`True` :bdg-primary:`False` |br|
      Enables transparent mode, which uses Linux TProxy for intercepting incoming connections. |br|
      Transparent mode requires root privileges.
   :option string host-key: |br|
      Specifies the path to a custom private SSH key used as the host key. |br|
      If no host key is provided, a random host key is generated automatically.
   :option string host-key-algorithm: :bdg-primary-line:`dss` :bdg-primary:`rsa` :bdg-primary-line:`ecdsa` :bdg-primary-line:`ed25519` |br|
      Defines the algorithm used to generate the random host key. The default is `rsa`.
   :option integer host-key-length: :bdg-primary:`2048` |br|
      Sets the key length for the generated host key (applies to `dss` and `rsa` algorithms). The default is `2048`.
   :option boolean request-agent-breakin: :bdg-primary-line:`True` :bdg-primary:`False` |br|
      Enables SSH-MITM to request the SSH agent from the client, even if the client does not forward the agent. |br|
      This can be used to attempt unauthorized access to the client's SSH agent.
   :option string banner-name: |br|
      Sets a custom SSH server banner presented to clients during the initial connection. |br|
      If not specified, the default banner is ``SSH-2.0-SSHMITM_<version>``.

.. confval:: [sshmitm.session:Session]

   .. code-block:: ini

      [sshmitm.session:Session]
      session-log-dir =

   :option string session-log-dir: |br|
      Specifies the directory where session logs will be stored.

Authentication-Plugins
----------------------

.. confval:: [sshmitm.authentication:AuthenticatorPassThrough]

   .. code-block:: ini

      [sshmitm.authentication:AuthenticatorPassThrough]
      close-pubkey-enumerator-with-session = False
      remote-host =
      remote-port =
      remote-fingerprints =
      disable-remote-fingerprint-warning = False
      auth-username =
      auth-password =
      auth-hide-credentials = False
      enable-auth-fallback = False
      fallback-host =
      fallback-port = 22
      fallback-username =
      fallback-password =

   :option boolean close-pubkey-enumerator-with-session: :bdg-primary-line:`True` :bdg-primary:`False` |br|
      Closes the public key enumerator when the session is closed. Useful for hiding traces of enumeration activities.
   :option string remote-host: |br|
      Specifies the remote host to connect to for authentication. Default is ``127.0.0.1``.
   :option integer remote-port: |br|
      Specifies the remote port to connect to for authentication. Default is ``22``.
   :option string remote-fingerprints: |br|
      Comma-separated list of expected remote host fingerprints. If empty, fingerprint verification is disabled.
   :option boolean disable-remote-fingerprint-warning: :bdg-primary-line:`True` :bdg-primary:`False` |br|
      Disables the warning message if no remote fingerprints are provided.
   :option string auth-username: |br|
      Specifies the username for remote authentication.
   :option string auth-password: |br|
      Specifies the password for remote authentication.
   :option boolean auth-hide-credentials: :bdg-primary-line:`True` :bdg-primary:`False` |br|
      Prevents logging of credentials, which is useful for presentations or security-sensitive environments.
   :option boolean enable-auth-fallback: :bdg-primary-line:`True` :bdg-primary:`False` |br|
      Enables fallback to a honeypot if authentication is not possible.
   :option string fallback-host: |br|
      Specifies the host for the honeypot fallback. Required if ``enable-auth-fallback`` is set to ``True``.
   :option integer fallback-port: |br|
      Specifies the port for the honeypot fallback. Default is ``22``.
   :option string fallback-username: |br|
      Specifies the username for the honeypot fallback. Required if ``enable-auth-fallback`` is set to ``True``.
   :option string fallback-password: |br|
      Specifies the password for the honeypot fallback. Required if ``enable-auth-fallback`` is set to ``True``.

.. confval:: [sshmitm.interfaces.server:ServerInterface]

   .. code-block:: ini

      [sshmitm.interfaces.server:ServerInterface]
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

   :option boolean disable-ssh: :bdg-primary-line:`True` :bdg-primary:`False` |br|
      Disables SSH functionality, preventing SSH connections to the server.
   :option boolean disable-scp: :bdg-primary-line:`True` :bdg-primary:`False` |br|
      Disables SCP (Secure Copy Protocol) functionality, preventing file transfers via SCP.
   :option boolean disable-password-auth: :bdg-primary-line:`True` :bdg-primary:`False` |br|
      Disables password-based authentication, forcing clients to use alternative authentication methods.
   :option boolean disable-pubkey-auth: :bdg-primary-line:`True` :bdg-primary:`False` |br|
      Disables public key authentication. Note that this is not RFC-4252 compliant.
   :option boolean accept-first-publickey: :bdg-primary-line:`True` :bdg-primary:`False` |br|
      Accepts the first public key provided by the client without checking if the user is allowed to log in using public key authentication.
   :option boolean disallow-publickey-auth: :bdg-primary-line:`True` :bdg-primary:`False` |br|
      Disallows public key authentication but still verifies whether public key authentication would be possible.
   :option boolean enable-none-auth: :bdg-primary-line:`True` :bdg-primary:`False` |br|
      Enables "none" authentication, which allows connections without any authentication.
   :option boolean enable-trivial-auth: :bdg-primary-line:`True` :bdg-primary:`False` |br|
      Enables "trivial success authentication" phishing attack, which simulates a successful authentication without actual validation.
   :option boolean enable-keyboard-interactive-auth: :bdg-primary-line:`True` :bdg-primary:`False` |br|
      Enables "keyboard-interactive" authentication, allowing interactive authentication prompts.
   :option boolean disable-keyboard-interactive-prompts: :bdg-primary-line:`True` :bdg-primary:`False` |br|
      Disables prompts for keyboard-interactive authentication, preventing interactive authentication challenges.
   :option string extra-auth-methods: |br|
      Specifies additional authentication method names that are supported by the server.
   :option boolean disable-auth-method-lookup: :bdg-primary-line:`True` :bdg-primary:`False` |br|
      Disables the lookup of supported authentication methods on the remote server during the authentication process.

Terminal-Session-Plugins
------------------------

.. confval:: [sshmitm.plugins.ssh.mirrorshell:SSHMirrorForwarder]

   .. code-block:: ini

      [sshmitm.plugins.ssh.mirrorshell:SSHMirrorForwarder]
      ssh-mirrorshell-net = 127.0.0.1
      ssh-mirrorshell-key =
      store-ssh-session = False
      ssh-terminal-log-formatter = script

   :option string ssh-mirrorshell-net: :bdg-primary:`127.0.0.1` |br|
      Specifies the local address or network interface where SSH MirrorShell injector sessions are served.
   :option string ssh-mirrorshell-key: |br|
      Specifies the path to the SSH private key used for MirrorShell sessions. If not provided, a default key is used.
   :option boolean store-ssh-session: :bdg-primary-line:`True` :bdg-primary:`False` |br|
      Enables storing of SSH sessions in the `scriptreplay` format for later replay and analysis.
   :option string ssh-terminal-log-formatter: :bdg-primary:`script` |br|
      Defines the format for terminal logs of captured SSH sessions. Currently, only the `script` format is supported.


SCP-Plugins
-----------

.. confval:: [sshmitm.plugins.scp.inject_file:SCPInjectFile]

   .. code-block:: ini

      [sshmitm.plugins.scp.inject_file:SCPInjectFile]
      scp-inject-file =

   :option string scp-inject-file: |br|
      Specifies the path to the file that will be injected during SCP file transfers. This option is required.


.. confval:: [sshmitm.plugins.scp.replace_file:SCPReplaceFile]

   .. code-block:: ini

      [sshmitm.plugins.scp.replace_file:SCPReplaceFile]
      scp-replace-file =

   :option string scp-replace-file: |br|
      Specifies the path to the file that will be used for replacement during SCP file transfers. This option is required.

.. confval:: [sshmitm.plugins.scp.store_file:SCPStorageForwarder]

   .. code-block:: ini

      [SCPStorageForwarder]
      store-scp-files = False
      store-command-data = False

   :option boolean store-scp-files: :bdg-primary-line:`True` :bdg-primary:`False` |br|
      Enables the storage of files transferred via SCP (Secure Copy Protocol).
   :option boolean store-command-data: :bdg-primary-line:`True` :bdg-primary:`False` |br|
      Enables the storage of data from non-interactive SSH commands.

.. confval:: [sshmitm.plugins.scp.rewrite_command:SCPRewriteCommand]

   .. code-block:: ini

      [sshmitm.plugins.scp.rewrite_command:SCPRewriteCommand]
      scp-append-string =
      scp-replace-string =

   :option string scp-append-string: |br|
      Specifies a string that will be appended to the existing SCP command during execution.
   :option string scp-replace-string: |br|
      Specifies a string that will replace the original SCP command during execution.

.. confval:: [sshmitm.plugins.scp.cve202229154:CVE202229154]

   .. code-block:: ini

      [sshmitm.plugins.scp.cve202229154:CVE202229154]
      rsync-inject-file =

   :option string rsync-inject-file: |br|
      Specifies the path to the file that will be injected into the rsync command sent to the server. This option is required.


SFTP-Handler-Plugins
--------------------

.. confval:: [sshmitm.plugins.sftp.store_file:SFTPHandlerStoragePlugin]

   .. code-block:: ini

      [sshmitm.plugins.sftp.store_file:SFTPHandlerStoragePlugin]
      store-sftp-files = False

   :option boolean store-sftp-files: :bdg-primary-line:`True` :bdg-primary:`False` |br|
      Enables the storage of files transferred via SFTP (SSH File Transfer Protocol).

.. confval:: [sshmitm.plugins.sftp.replace_file:SFTPProxyReplaceHandler]

   .. code-block:: ini

      [sshmitm.plugins.sftp.replace_file:SFTPProxyReplaceHandler]
      sftp-replace-file =

   :option string sftp-replace-file: |br|
      Specifies the path to the file that will be used for replacement during SFTP file transfers. This option is required.

Port-Forwarding-Plugins
-----------------------

.. confval:: [InjectableRemotePortForwardingForwarder]

   .. code-block:: ini

      [InjectableRemotePortForwardingForwarder]
      server-tunnel-net = 127.0.0.1

   :option string server-tunnel-net: :bdg-primary:`127.0.0.1` |br|
      Specifies the local address or network interface where tunnel server sessions are served.

.. confval:: [sshmitm.plugins.tunnel.socks:SOCKSTunnelForwarder]

   .. code-block:: ini

      [sshmitm.plugins.tunnel.socks:SOCKSTunnelForwarder]
      socks-listen-address = 127.0.0.1
      socks5-username =
      socks5-password =

   :option string socks-listen-address: :bdg-primary:`127.0.0.1` |br|
      Specifies the listen address for the SOCKS server. Default is ``127.0.0.1``.
   :option string socks5-username: |br|
      Specifies the username for authenticating with the SOCKS5 server.
   :option string socks5-password: |br|
      Specifies the password for authenticating with the SOCKS5 server. Required if ``socks5-username`` is provided.
