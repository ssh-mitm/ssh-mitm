:fas:`puzzle-piece` Developing Plugins
=======================================

SSH-MITM is built around a modular plugin system. Every major component —
session handling, authentication, SSH/SCP/SFTP forwarding, port forwarding —
is a replaceable plugin. This guide explains how to write your own.

.. contents:: Contents
   :local:
   :depth: 2


Architecture Overview
---------------------

All plugins inherit from ``BaseModule`` (``sshmitm.moduleparser.modules.BaseModule``).
The base class provides:

- **Argument parsing** — ``parser_arguments()`` registers CLI flags; ``self.args``
  exposes the parsed values at runtime.
- **Entry-point discovery** — SSH-MITM finds plugins by scanning
  ``[project.entry-points."sshmitm.<BaseClassName>"]`` groups registered in
  ``pyproject.toml``.
- **Instantiation** — the server passes a ``Session`` (or equivalent context
  object) to each plugin's ``__init__``.

A minimal plugin therefore looks like this:

.. code-block:: python

    from sshmitm.forwarders.ssh import SSHForwarder

    class MySSHPlugin(SSHForwarder):

        @classmethod
        def parser_arguments(cls) -> None:
            group = cls.argument_group()
            group.add_argument("--my-option", dest="my_option", help="...")

        def __init__(self, session):
            super().__init__(session)
            # self.args.my_option is available here


Registering a Plugin
--------------------

Plugins are discovered via Python entry points. Add an entry to your package's
``pyproject.toml``:

.. code-block:: toml

    [project.entry-points."sshmitm.SSHBaseForwarder"]
    my-plugin = "mypkg.myplugin:MySSHPlugin"

The key (``my-plugin``) is the name used on the command line:

.. code-block:: bash

    ssh-mitm server --ssh-interface my-plugin

After adding the entry point, reinstall your package (``pip install -e .``) so
the entry point is registered.

The entry-point group must match the **base class name** of the plugin type you
are extending:

.. list-table::
   :header-rows: 1
   :widths: 40 60

   * - Entry-point group
     - Plugin type
   * - ``sshmitm.SSHBaseForwarder``
     - SSH terminal session forwarder
   * - ``sshmitm.SCPBaseForwarder``
     - SCP file-transfer forwarder
   * - ``sshmitm.SFTPHandlerBasePlugin``
     - SFTP file-transfer handler
   * - ``sshmitm.BaseSFTPServerInterface``
     - SFTP server interface
   * - ``sshmitm.LocalPortForwardingBaseForwarder``
     - Local port-forwarding handler
   * - ``sshmitm.RemotePortForwardingBaseForwarder``
     - Remote port-forwarding handler
   * - ``sshmitm.Authenticator``
     - Authentication handler
   * - ``sshmitm.BaseServerInterface``
     - SSH server interface
   * - ``sshmitm.BaseSession``
     - Session handler


Plugin Types
------------

SSH Forwarder Plugins
^^^^^^^^^^^^^^^^^^^^^

**Base class:** ``sshmitm.forwarders.ssh.SSHForwarder``

**CLI argument:** ``--ssh-interface``

SSH forwarder plugins intercept the interactive terminal session between the
SSH client and the remote server. Override the stream methods to read or
modify the data in-flight.

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Method
     - Purpose
   * - ``stdin(text: bytes) -> bytes``
     - Data typed by the user (client → server). Return the bytes to forward.
   * - ``stdout(text: bytes) -> bytes``
     - Output from the remote server (server → client). Return the bytes to forward.
   * - ``stderr(text: bytes) -> bytes``
     - Error output from the remote server. Return the bytes to forward.
   * - ``close_session(channel)``
     - Called when the session closes. Clean up resources here.

**Example — log all terminal output:**

.. code-block:: python

    from sshmitm.forwarders.ssh import SSHForwarder

    class LoggingSSHForwarder(SSHForwarder):
        """Logs all terminal output to a file"""

        @classmethod
        def parser_arguments(cls) -> None:
            group = cls.argument_group()
            group.add_argument(
                "--log-file",
                dest="log_file",
                required=True,
                help="path to the log file",
            )

        def __init__(self, session) -> None:
            super().__init__(session)
            self._log = open(self.args.log_file, "ab")  # noqa: SIM115

        def stdout(self, text: bytes) -> bytes:
            self._log.write(text)
            return text

        def close_session(self, channel) -> None:
            super().close_session(channel)
            self._log.close()

**Registration:**

.. code-block:: toml

    [project.entry-points."sshmitm.SSHBaseForwarder"]
    logging = "mypkg.ssh_log:LoggingSSHForwarder"

**Usage:**

.. code-block:: bash

    ssh-mitm server --ssh-interface logging --log-file /tmp/session.log


SCP Forwarder Plugins
^^^^^^^^^^^^^^^^^^^^^

**Base class:** ``sshmitm.forwarders.scp.SCPForwarder``

**CLI argument:** ``--scp-interface``

SCP forwarder plugins intercept Secure Copy (SCP) file transfers. The SCP
protocol wraps file metadata and content in a simple byte stream; the base
class parses it and exposes higher-level hooks.

.. list-table::
   :header-rows: 1
   :widths: 35 65

   * - Method
     - Purpose
   * - ``handle_traffic(traffic: bytes, isclient: bool) -> bytes``
     - Raw bytes in either direction. ``isclient=True`` means client → server.
   * - ``handle_command(traffic: bytes) -> bytes``
     - Called for SCP control commands (file name, size, permissions).
   * - ``process_data(traffic: bytes) -> bytes``
     - Called for the actual file content bytes.
   * - ``rewrite_scp_command(command: str) -> str``
     - Modify the SCP shell command before it is executed on the server.
   * - ``handle_error(traffic: bytes) -> bytes``
     - Called when the remote side sends an error response.

Useful attributes set by the base class after the first control command:

- ``self.file_command`` — ``"C"`` (file) or ``"D"`` (directory)
- ``self.file_mode`` — Unix permission string (e.g. ``"0644"``)
- ``self.file_size`` — file size in bytes
- ``self.file_name`` — destination file name

**Example — print a hexdump of all SCP traffic:**

.. code-block:: python

    from sshmitm.forwarders.scp import SCPForwarder
    from sshmitm.utils import format_hex

    class SCPDebugForwarder(SCPForwarder):
        """Prints SCP traffic as a hexdump"""

        def handle_traffic(self, traffic: bytes, isclient: bool) -> bytes:
            direction = "client → server" if isclient else "server → client"
            print(f"[SCP] {direction}:")
            print(format_hex(traffic))
            return traffic

**Registration:**

.. code-block:: toml

    [project.entry-points."sshmitm.SCPBaseForwarder"]
    debug = "mypkg.scp_debug:SCPDebugForwarder"

**Usage:**

.. code-block:: bash

    ssh-mitm server --scp-interface debug


SFTP Handler Plugins
^^^^^^^^^^^^^^^^^^^^

**Base class:** ``sshmitm.forwarders.sftp.SFTPHandlerPlugin``

**CLI argument:** ``--sftp-handler``

SFTP handler plugins are instantiated **per file transfer**. The plugin
receives every chunk of file data as it passes through and can inspect,
modify, or store it.

.. list-table::
   :header-rows: 1
   :widths: 45 55

   * - Method
     - Purpose
   * - ``handle_data(data, *, offset, length) -> bytes``
     - Called for every block of file data. Return the bytes to forward.
   * - ``close() -> None``
     - Called when the file transfer completes. Release file handles here.
   * - ``get_interface() -> type | None``
     - Return a custom ``BaseSFTPServerInterface`` subclass if you need to
       intercept SFTP protocol commands (stat, open, list, …).

The plugin's ``__init__`` receives:

- ``sftp`` — the ``SFTPBaseHandle`` for the current file, which carries a
  reference to the ``Session`` via ``sftp.session``.
- ``filename`` — the remote file path being transferred.

**Example — store every transferred file:**

.. code-block:: python

    import os
    from sshmitm.forwarders.sftp import SFTPBaseHandle, SFTPHandlerPlugin

    class SFTPStoragePlugin(SFTPHandlerPlugin):
        """Saves every SFTP file transfer to disk"""

        @classmethod
        def parser_arguments(cls) -> None:
            group = cls.argument_group()
            group.add_argument(
                "--sftp-store-dir",
                dest="sftp_store_dir",
                default="/tmp/sftp-captures",
                help="directory to store captured files",
            )

        def __init__(self, sftp: SFTPBaseHandle, filename: str) -> None:
            super().__init__(sftp, filename)
            os.makedirs(self.args.sftp_store_dir, exist_ok=True)
            safe_name = os.path.basename(filename) or "unnamed"
            dest = os.path.join(self.args.sftp_store_dir, safe_name)
            self._out = open(dest, "wb")  # noqa: SIM115

        def handle_data(self, data: bytes, *, offset=None, length=None) -> bytes:
            self._out.write(data)
            return data

        def close(self) -> None:
            self._out.close()

**Registration:**

.. code-block:: toml

    [project.entry-points."sshmitm.SFTPHandlerBasePlugin"]
    store = "mypkg.sftp_store:SFTPStoragePlugin"

**Usage:**

.. code-block:: bash

    ssh-mitm server --sftp-handler store --sftp-store-dir /tmp/captures

**Providing a custom SFTP server interface**

If your plugin also needs to intercept SFTP protocol-level operations (e.g.,
to lie about a file's size before the client requests it), define a nested
class that extends ``SFTPProxyServerInterface`` and return it from
``get_interface()``:

.. code-block:: python

    from sshmitm.forwarders.sftp import SFTPHandlerPlugin
    from sshmitm.interfaces.sftp import SFTPProxyServerInterface

    class MyHandler(SFTPHandlerPlugin):

        class CustomSFTPInterface(SFTPProxyServerInterface):
            def stat(self, path):
                attrs = super().stat(path)
                # modify attrs here
                return attrs

        @classmethod
        def get_interface(cls):
            return cls.CustomSFTPInterface

        def handle_data(self, data, *, offset=None, length=None) -> bytes:
            return data

        def close(self) -> None:
            pass


Local Port Forwarding Plugins
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Base class:** ``sshmitm.forwarders.tunnel.LocalPortForwardingForwarder``

**CLI argument:** ``--tunnel-client-interface``

Local port forwarding plugins handle connections that the SSH client opens
towards the server (``ssh -L``). The plugin runs as a TCP server that accepts
connections from the client side and decides where to forward them.

The most important hook is the class-level ``setup()`` method, which is called
once when a session is established, before any connections arrive. Use it to
start background threads or TCP listeners.

.. code-block:: python

    from typing import ClassVar
    from sshmitm.forwarders.tunnel import LocalPortForwardingForwarder
    from sshmitm.plugins.session.tcpserver import TCPServerThread

    class MyTunnelPlugin(LocalPortForwardingForwarder):
        """Intercepts local port forwarding connections"""

        servers: ClassVar[list] = []

        @classmethod
        def parser_arguments(cls) -> None:
            group = cls.argument_group()
            group.add_argument(
                "--listen-address",
                dest="listen_address",
                default="127.0.0.1",
                help="address to listen on",
            )

        @classmethod
        def setup(cls, session) -> None:
            args, _ = cls.parser().parse_known_args(None, None)
            thread = TCPServerThread(
                lambda addr, client, remote: cls._handle(session, addr, client, remote),
                network=args.listen_address,
            )
            thread.start()
            cls.servers.append(thread)

        @classmethod
        def _handle(cls, session, addr, client, remote) -> None:
            # custom forwarding logic
            pass

**Registration:**

.. code-block:: toml

    [project.entry-points."sshmitm.LocalPortForwardingBaseForwarder"]
    my-tunnel = "mypkg.tunnel:MyTunnelPlugin"

**Usage:**

.. code-block:: bash

    ssh-mitm server --tunnel-client-interface my-tunnel


Remote Port Forwarding Plugins
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Base class:** ``sshmitm.forwarders.tunnel.RemotePortForwardingForwarder``

**CLI argument:** ``--tunnel-server-interface``

Remote port forwarding plugins handle connections that the SSH server side
opens back to the client (``ssh -R``). The structure mirrors the local
forwarding plugin above.

**Registration:**

.. code-block:: toml

    [project.entry-points."sshmitm.RemotePortForwardingBaseForwarder"]
    my-remote = "mypkg.remote_tunnel:MyRemoteTunnelPlugin"


Authenticator Plugins
^^^^^^^^^^^^^^^^^^^^^

**Base class:** ``sshmitm.authentication.Authenticator``

**CLI argument:** ``--authenticator``

Authenticator plugins control how SSH-MITM validates client credentials and
how it connects to the upstream server. The default implementation performs a
transparent pass-through: it replays the client's credentials against the real
server and accepts if the server accepts.

Key attributes available in the ``__init__`` (after calling ``super().__init__``):

- ``self.session`` — the current ``Session`` instance.
- ``self.REQUEST_AGENT_BREAKIN`` — set to ``True`` to request SSH agent
  forwarding even when the client has not enabled it (for credential harvesting
  scenarios).

Key methods to override:

.. list-table::
   :header-rows: 1
   :widths: 50 50

   * - Method
     - Purpose
   * - ``get_auth_methods(host, port, username) -> list[str] | None``
     - Return the list of auth methods advertised to the client
       (e.g. ``["password", "publickey"]``).
   * - ``get_remote_host_credentials(username, password, key)``
     - Transform or replace the credentials before forwarding to the server.

**Example — accept any password and log it:**

.. code-block:: python

    import logging
    from sshmitm.authentication import Authenticator
    import paramiko

    class LoggingAuthenticator(Authenticator):
        """Accepts all logins and logs credentials"""

        def get_auth_methods(self, host, port, username):
            return ["password"]

        def authenticate(self, username, credentials, *, wait=False):
            logging.info("Login attempt: user=%s password=%s", username, credentials)
            return paramiko.common.AUTH_SUCCESSFUL

**Registration:**

.. code-block:: toml

    [project.entry-points."sshmitm.Authenticator"]
    logging-auth = "mypkg.auth:LoggingAuthenticator"

**Usage:**

.. code-block:: bash

    ssh-mitm server --authenticator logging-auth


Server Interface Plugins
^^^^^^^^^^^^^^^^^^^^^^^^

**Base class:** ``sshmitm.interfaces.server.ServerInterface``

**CLI argument:** ``--server-interface``

The server interface is the Paramiko ``ServerInterface`` that SSH-MITM
presents to connecting clients. Override its methods to change which channel
types and requests are accepted.

Common methods to override:

.. list-table::
   :header-rows: 1
   :widths: 50 50

   * - Method
     - Purpose
   * - ``check_channel_request(kind, chanid) -> int``
     - Accept or deny a channel type (``"session"``, ``"direct-tcpip"``, …).
   * - ``check_channel_shell_request(channel) -> bool``
     - Allow or deny an interactive shell.
   * - ``check_channel_exec_request(channel, command) -> bool``
     - Allow or deny command execution.
   * - ``check_channel_pty_request(...)``
     - Allow or deny a pseudo-terminal.

**Registration:**

.. code-block:: toml

    [project.entry-points."sshmitm.BaseServerInterface"]
    my-interface = "mypkg.server_iface:MyServerInterface"

**Usage:**

.. code-block:: bash

    ssh-mitm server --server-interface my-interface


Session Plugins
^^^^^^^^^^^^^^^

**Base class:** ``sshmitm.session.Session``

**CLI argument:** ``--session-class``

Session plugins wrap the entire lifecycle of a single SSH connection. Subclass
``Session`` to add state or hooks that span all the other plugin types for a
given connection.

Because the ``Session`` class is large, it is usually better to hook into the
more targeted plugin types above. Only use a custom session class when you
need to track state across multiple sub-protocols (SSH + SFTP + SCP) at the
same time.

**Registration:**

.. code-block:: toml

    [project.entry-points."sshmitm.BaseSession"]
    my-session = "mypkg.session:MySession"


Adding CLI Arguments
--------------------

Every plugin can expose its own command-line flags by implementing the
``parser_arguments()`` classmethod:

.. code-block:: python

    @classmethod
    def parser_arguments(cls) -> None:
        group = cls.argument_group()                    # argument group named after the class
        group.add_argument(
            "--my-flag",
            dest="my_flag",
            action="store_true",
            default=False,
            help="enables my feature",
        )
        group.add_argument(
            "--my-file",
            dest="my_file",
            help="path to a file",
        )

At runtime, access the values via ``self.args``:

.. code-block:: python

    def __init__(self, session) -> None:
        super().__init__(session)
        if self.args.my_flag:
            path = os.path.expanduser(self.args.my_file)
            ...

``cls.argument_group()`` creates a named section in the ``--help`` output so
that each plugin's options are grouped separately.


Configuration File Support
--------------------------

All CLI arguments can also be supplied through a configuration file. The
section name is derived from the fully-qualified class name:

.. code-block:: ini

    [mypkg.myplugin:MySSHPlugin]
    my-flag = true
    my-file = ~/captures/session.log

Pass the configuration file to the server with ``--config``:

.. code-block:: bash

    ssh-mitm server --config myconfig.ini --ssh-interface my-plugin


Packaging a Plugin as a Standalone Package
-------------------------------------------

If you want to distribute your plugin independently from SSH-MITM, create a
normal Python package with a ``pyproject.toml`` that declares the entry point:

.. code-block:: toml

    [build-system]
    requires = ["setuptools"]
    build-backend = "setuptools.backends.legacy:build"

    [project]
    name = "sshmitm-my-plugin"
    version = "0.1.0"
    dependencies = ["ssh-mitm"]

    [project.entry-points."sshmitm.SSHBaseForwarder"]
    my-plugin = "mypkg.myplugin:MySSHPlugin"

After ``pip install sshmitm-my-plugin``, the plugin is available to SSH-MITM
automatically — no configuration change needed beyond selecting it on the CLI.
