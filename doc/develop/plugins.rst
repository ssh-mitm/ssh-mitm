:fas:`puzzle-piece` Developing Plugins
=======================================

SSH-MITM is built around a modular plugin system. Every major component —
session handling, authentication, SSH/SCP/SFTP forwarding, NETCONF, and port
forwarding — is a replaceable plugin. This guide explains the architecture and
shows how to write your own plugins.

.. contents:: Contents
   :local:
   :depth: 2


Class Diagram
-------------

The diagram below shows the complete plugin class hierarchy. Every plugin class
ultimately inherits from ``SSHMITMBaseModule``, which provides argument
parsing, entry-point discovery, and configuration-file support.

.. mermaid::

   classDiagram
       direction TB

       class BaseModule {
           +parser_arguments()$
           +argument_group()$
           +args
       }
       class SSHMITMBaseModule {
           +entry_point_prefix = "sshmitm"
       }
       class BaseForwarder {
           +session
       }
       class ExecForwarder {
           +handle_client_data(data)
           +handle_server_data(data)
           +handle_error(data)
           +close_session(channel)
       }
       class SCPBaseForwarder {
           +rewrite_scp_command(command)
           +register_exec_handler()$
       }
       class SCPForwarder
       class NetconfBaseForwarder
       class NetconfForwarder
       class SSHBaseForwarder {
           +handle_client_data(data)
           +handle_server_data(data)
           +handle_server_error(data)
       }
       class SSHForwarder
       class SSHMirrorForwarder
       class SFTPHandlerBasePlugin {
           +handle_data(data, offset, length)
           +close()
       }
       class SFTPHandlerPlugin
       class BaseSFTPServerInterface
       class SFTPProxyServerInterface
       class LocalPortForwardingBaseForwarder {
           +setup(session)$
       }
       class LocalPortForwardingForwarder
       class SOCKSTunnelForwarder
       class RemotePortForwardingBaseForwarder
       class RemotePortForwardingForwarder
       class InjectableRemotePortForwardingForwarder
       class Authenticator {
           +get_auth_methods()
           +authenticate()
       }
       class AuthenticatorPassThrough
       class AuthenticatorRemote
       class BaseServerInterface
       class ServerInterface
       class BaseSession
       class Session
       class MoshForwarder

       BaseModule <|-- SSHMITMBaseModule
       SSHMITMBaseModule <|-- BaseForwarder
       BaseForwarder <|-- ExecForwarder
       BaseForwarder <|-- SSHBaseForwarder
       ExecForwarder <|-- SCPBaseForwarder
       SCPBaseForwarder <|-- SCPForwarder
       ExecForwarder <|-- NetconfBaseForwarder
       NetconfBaseForwarder <|-- NetconfForwarder
       ExecForwarder <|-- MoshForwarder
       SSHBaseForwarder <|-- SSHForwarder
       SSHForwarder <|-- SSHMirrorForwarder
       SSHMITMBaseModule <|-- SFTPHandlerBasePlugin
       SFTPHandlerBasePlugin <|-- SFTPHandlerPlugin
       SSHMITMBaseModule <|-- BaseSFTPServerInterface
       BaseSFTPServerInterface <|-- SFTPProxyServerInterface
       SSHMITMBaseModule <|-- LocalPortForwardingBaseForwarder
       LocalPortForwardingBaseForwarder <|-- LocalPortForwardingForwarder
       LocalPortForwardingForwarder <|-- SOCKSTunnelForwarder
       SSHMITMBaseModule <|-- RemotePortForwardingBaseForwarder
       RemotePortForwardingBaseForwarder <|-- RemotePortForwardingForwarder
       RemotePortForwardingForwarder <|-- InjectableRemotePortForwardingForwarder
       SSHMITMBaseModule <|-- Authenticator
       Authenticator <|-- AuthenticatorPassThrough
       Authenticator <|-- AuthenticatorRemote
       SSHMITMBaseModule <|-- BaseServerInterface
       BaseServerInterface <|-- ServerInterface
       SSHMITMBaseModule <|-- BaseSession
       BaseSession <|-- Session


Architecture Overview
---------------------

All plugins inherit from ``SSHMITMBaseModule``
(``sshmitm.core.modules.SSHMITMBaseModule``), which itself extends ``BaseModule``
from the module parser. The base class provides:

- **Argument parsing** — ``parser_arguments()`` registers CLI flags;
  ``self.args`` exposes the parsed values at runtime.
- **Entry-point discovery** — SSH-MITM finds plugins by scanning
  ``[project.entry-points."sshmitm.<BaseClassName>"]`` groups registered in
  ``pyproject.toml``.
- **Configuration file support** — every CLI argument can alternatively be set
  in an INI file; the section name is derived from the fully-qualified class name.
- **Instantiation** — the server passes a ``Session`` (or equivalent context
  object) to each plugin's ``__init__``.

A minimal plugin looks like this:

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

After adding the entry point, reinstall your package so the entry point is
registered:

.. code-block:: bash

    $ pip install /path/to/your/plugin/

The entry-point group must match the **base class name** of the plugin type you
are extending:

.. list-table::
   :header-rows: 1
   :widths: 45 55

   * - Entry-point group
     - Plugin type
   * - ``sshmitm.SSHBaseForwarder``
     - SSH terminal session forwarder (``--ssh-interface``)
   * - ``sshmitm.SCPBaseForwarder``
     - SCP file-transfer forwarder (``--scp-interface``)
   * - ``sshmitm.NetconfBaseForwarder``
     - NETCONF subsystem forwarder (``--netconf-interface``)
   * - ``sshmitm.SFTPHandlerBasePlugin``
     - SFTP file-transfer handler (``--sftp-handler``)
   * - ``sshmitm.BaseSFTPServerInterface``
     - SFTP server interface (``--sftp-interface``)
   * - ``sshmitm.LocalPortForwardingBaseForwarder``
     - Local port-forwarding handler — ``ssh -L`` (``--local-port-forwarder``)
   * - ``sshmitm.RemotePortForwardingBaseForwarder``
     - Remote port-forwarding handler — ``ssh -R`` (``--remote-port-forwarder``)
   * - ``sshmitm.Authenticator``
     - Authentication handler (``--authenticator``)
   * - ``sshmitm.BaseServerInterface``
     - SSH server interface (``--auth-interface``)
   * - ``sshmitm.BaseSession``
     - Session handler (``--session-class``)
   * - ``sshmitm.ExecHandler``
     - Exec command handler (e.g. Mosh); registered via ``SCPBaseForwarder``


Plugin Types
------------

SSH Forwarder Plugins
^^^^^^^^^^^^^^^^^^^^^

**Base class:** ``sshmitm.forwarders.ssh.SSHForwarder``

**CLI argument:** ``--ssh-interface``

**Entry-point group:** ``sshmitm.SSHBaseForwarder``

SSH forwarder plugins intercept the interactive terminal session between the
SSH client and the remote server. Override the stream hooks to read or modify
data in-flight.

.. mermaid::

   classDiagram
       direction LR
       class SSHBaseForwarder["SSHBaseForwarder\n«base»"]
       class SSHForwarder["SSHForwarder\n«default»"]
       class SSHMirrorForwarder["SSHMirrorForwarder\n«built-in plugin»"]

       SSHBaseForwarder <|-- SSHForwarder
       SSHForwarder <|-- SSHMirrorForwarder

.. list-table::
   :header-rows: 1
   :widths: 45 55

   * - Method
     - Purpose
   * - ``handle_client_data(data: bytes) -> bytes``
     - Data typed by the user (client → server). Return the bytes to forward.
   * - ``handle_server_data(data: bytes) -> bytes``
     - Output from the remote server (server → client). Return the bytes to forward.
   * - ``handle_server_error(data: bytes) -> bytes``
     - Error output from the remote server. Return the bytes to forward.
   * - ``close_session(channel)``
     - Called when the session closes. Clean up resources here.

**Example — log all terminal output to a file:**

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

        def handle_server_data(self, data: bytes) -> bytes:
            self._log.write(data)
            return data

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

**Entry-point group:** ``sshmitm.SCPBaseForwarder``

SCP forwarder plugins intercept Secure Copy (SCP) file transfers. The SCP
protocol wraps file metadata and content in a simple byte stream; the base
class parses it and exposes higher-level hooks.

.. mermaid::

   classDiagram
       direction LR
       class ExecForwarder["ExecForwarder"]
       class SCPBaseForwarder["SCPBaseForwarder\n«base»"]
       class SCPForwarder["SCPForwarder\n«default»"]
       class SCPDebugForwarder["SCPDebugForwarder\n«built-in»"]
       class SCPInjectFile["SCPInjectFile\n«built-in»"]
       class SCPReplaceFile["SCPReplaceFile\n«built-in»"]
       class SCPStorageForwarder["SCPStorageForwarder\n«built-in»"]
       class SCPRewriteCommand["SCPRewriteCommand\n«built-in»"]
       class CVE202229154["CVE202229154\n«built-in»"]

       ExecForwarder <|-- SCPBaseForwarder
       SCPBaseForwarder <|-- SCPForwarder
       SCPForwarder <|-- SCPDebugForwarder
       SCPForwarder <|-- SCPInjectFile
       SCPForwarder <|-- SCPReplaceFile
       SCPForwarder <|-- SCPStorageForwarder
       SCPForwarder <|-- SCPRewriteCommand
       SCPForwarder <|-- CVE202229154

.. list-table::
   :header-rows: 1
   :widths: 45 55

   * - Method
     - Purpose
   * - ``handle_client_data(data: bytes) -> bytes``
     - Raw bytes from the client (client → server). Return the bytes to forward.
   * - ``handle_server_data(data: bytes) -> bytes``
     - Raw bytes from the server (server → client). Return the bytes to forward.
   * - ``rewrite_scp_command(command: str) -> str``
     - Modify the SCP shell command before it is executed on the server.
   * - ``handle_error(data: bytes) -> bytes``
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

        def handle_client_data(self, data: bytes) -> bytes:
            print("[SCP] client → server:")
            print(format_hex(data))
            return super().handle_client_data(data)

        def handle_server_data(self, data: bytes) -> bytes:
            print("[SCP] server → client:")
            print(format_hex(data))
            return super().handle_server_data(data)

**Registration:**

.. code-block:: toml

    [project.entry-points."sshmitm.SCPBaseForwarder"]
    debug = "mypkg.scp_debug:SCPDebugForwarder"

**Usage:**

.. code-block:: bash

    ssh-mitm server --scp-interface debug


Netconf Forwarder Plugins
^^^^^^^^^^^^^^^^^^^^^^^^^

**Base class:** ``sshmitm.forwarders.netconf.NetconfForwarder``

**CLI argument:** ``--netconf-interface``

**Entry-point group:** ``sshmitm.NetconfBaseForwarder``

NETCONF (RFC 6241) is an XML-based network management protocol that runs as an
SSH subsystem (``ssh -s netconf``). It is widely used to configure routers,
switches, and other network devices from vendors such as Cisco, Juniper, and
Nokia.

NETCONF forwarder plugins intercept the XML RPCs exchanged between the
management client and the target network device. Override the stream hooks to
inspect or modify the NETCONF messages in-flight.

.. mermaid::

   classDiagram
       direction LR
       class ExecForwarder["ExecForwarder"]
       class NetconfBaseForwarder["NetconfBaseForwarder\n«base»"]
       class NetconfForwarder["NetconfForwarder\n«default»"]

       ExecForwarder <|-- NetconfBaseForwarder
       NetconfBaseForwarder <|-- NetconfForwarder

.. list-table::
   :header-rows: 1
   :widths: 45 55

   * - Method
     - Purpose
   * - ``handle_client_data(data: bytes) -> bytes``
     - NETCONF RPC from the client (client → device). Return the bytes to forward.
   * - ``handle_server_data(data: bytes) -> bytes``
     - NETCONF response from the device (device → client). Return the bytes to forward.
   * - ``handle_error(data: bytes) -> bytes``
     - Called when the remote side sends an error response.
   * - ``close_session(channel)``
     - Called when the NETCONF session closes.

**Example — log all NETCONF RPC messages:**

.. code-block:: python

    import logging
    from sshmitm.forwarders.netconf import NetconfForwarder

    class LoggingNetconfForwarder(NetconfForwarder):
        """Logs all NETCONF RPC traffic"""

        def handle_client_data(self, data: bytes) -> bytes:
            logging.info("[NETCONF] client→device: %s", data.decode(errors="replace"))
            return super().handle_client_data(data)

        def handle_server_data(self, data: bytes) -> bytes:
            logging.info("[NETCONF] device→client: %s", data.decode(errors="replace"))
            return super().handle_server_data(data)

**Registration:**

.. code-block:: toml

    [project.entry-points."sshmitm.NetconfBaseForwarder"]
    logging = "mypkg.netconf_log:LoggingNetconfForwarder"

**Usage:**

.. code-block:: bash

    ssh-mitm server --netconf-interface logging


SFTP Handler Plugins
^^^^^^^^^^^^^^^^^^^^

**Base class:** ``sshmitm.forwarders.sftp.SFTPHandlerPlugin``

**CLI argument:** ``--sftp-handler``

**Entry-point group:** ``sshmitm.SFTPHandlerBasePlugin``

SFTP handler plugins are instantiated **per file transfer**. The plugin
receives every chunk of file data as it passes through and can inspect,
modify, or store it.

.. mermaid::

   classDiagram
       direction LR
       class SFTPHandlerBasePlugin["SFTPHandlerBasePlugin\n«base»"]
       class SFTPHandlerPlugin["SFTPHandlerPlugin\n«default»"]
       class SFTPHandlerStoragePlugin["SFTPHandlerStoragePlugin\n«built-in»"]
       class SFTPProxyReplaceHandler["SFTPProxyReplaceHandler\n«built-in»"]
       class SFTPHandlerCheckFilePlugin["SFTPHandlerCheckFilePlugin\n«built-in»"]

       SFTPHandlerBasePlugin <|-- SFTPHandlerPlugin
       SFTPHandlerPlugin <|-- SFTPHandlerStoragePlugin
       SFTPHandlerPlugin <|-- SFTPProxyReplaceHandler
       SFTPHandlerPlugin <|-- SFTPHandlerCheckFilePlugin

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

- ``sftp`` — the ``SFTPBaseHandle`` for the current file; ``sftp.session``
  gives access to the active ``Session``.
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

**CLI argument:** ``--local-port-forwarder``

**Entry-point group:** ``sshmitm.LocalPortForwardingBaseForwarder``

Local port forwarding plugins handle connections that the SSH client opens
towards the server (``ssh -L``). ``LocalPortForwardingForwarder`` uses multiple
inheritance — it combines ``TunnelForwarder`` (a bidirectional threading
forwarder) with the plugin base class.

.. mermaid::

   classDiagram
       direction LR
       class TunnelForwarder["TunnelForwarder\n(threading.Thread)"]
       class LocalPortForwardingBaseForwarder["LocalPortForwardingBaseForwarder\n«base»"]
       class LocalPortForwardingForwarder["LocalPortForwardingForwarder\n«default»"]
       class SOCKSTunnelForwarder["SOCKSTunnelForwarder\n«built-in plugin»"]

       TunnelForwarder <|-- LocalPortForwardingForwarder
       LocalPortForwardingBaseForwarder <|-- LocalPortForwardingForwarder
       LocalPortForwardingForwarder <|-- SOCKSTunnelForwarder

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

    ssh-mitm server --local-port-forwarder my-tunnel


Remote Port Forwarding Plugins
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

**Base class:** ``sshmitm.forwarders.tunnel.RemotePortForwardingForwarder``

**CLI argument:** ``--remote-port-forwarder``

**Entry-point group:** ``sshmitm.RemotePortForwardingBaseForwarder``

Remote port forwarding plugins handle connections that the SSH server opens
back towards the client (``ssh -R``). The structure mirrors the local
forwarding plugin above.

.. mermaid::

   classDiagram
       direction LR
       class RemotePortForwardingBaseForwarder["RemotePortForwardingBaseForwarder\n«base»"]
       class RemotePortForwardingForwarder["RemotePortForwardingForwarder\n«default»"]
       class InjectableRemotePortForwardingForwarder["InjectableRemotePortForwardingForwarder\n«built-in plugin»"]

       RemotePortForwardingBaseForwarder <|-- RemotePortForwardingForwarder
       RemotePortForwardingForwarder <|-- InjectableRemotePortForwardingForwarder

**Registration:**

.. code-block:: toml

    [project.entry-points."sshmitm.RemotePortForwardingBaseForwarder"]
    my-remote = "mypkg.remote_tunnel:MyRemoteTunnelPlugin"

**Usage:**

.. code-block:: bash

    ssh-mitm server --remote-port-forwarder my-remote


Authenticator Plugins
^^^^^^^^^^^^^^^^^^^^^

**Base class:** ``sshmitm.authentication.Authenticator``

**CLI argument:** ``--authenticator``

**Entry-point group:** ``sshmitm.Authenticator``

Authenticator plugins control how SSH-MITM validates client credentials and
how it connects to the upstream server. The default implementation performs a
transparent pass-through: it replays the client's credentials against the real
server and accepts if the server accepts.

.. mermaid::

   classDiagram
       direction LR
       class Authenticator["Authenticator\n«base»"]
       class AuthenticatorPassThrough["AuthenticatorPassThrough\n«default»"]
       class AuthenticatorRemote["AuthenticatorRemote\n«built-in»"]

       Authenticator <|-- AuthenticatorPassThrough
       Authenticator <|-- AuthenticatorRemote

Key attributes available in ``__init__`` (after calling ``super().__init__``):

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

**CLI argument:** ``--auth-interface``

**Entry-point group:** ``sshmitm.BaseServerInterface``

The server interface is the Paramiko ``ServerInterface`` that SSH-MITM
presents to connecting clients. Override its methods to change which channel
types and authentication methods are accepted.

.. mermaid::

   classDiagram
       direction LR
       class BaseServerInterface["BaseServerInterface\n«base»"]
       class ServerInterface["ServerInterface\n«default»"]

       BaseServerInterface <|-- ServerInterface

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

    ssh-mitm server --auth-interface my-interface


Session Plugins
^^^^^^^^^^^^^^^

**Base class:** ``sshmitm.session.Session``

**CLI argument:** ``--session-class``

**Entry-point group:** ``sshmitm.BaseSession``

Session plugins wrap the entire lifecycle of a single SSH connection. Subclass
``Session`` to add state or hooks that span all the other plugin types for a
given connection.

.. mermaid::

   classDiagram
       direction LR
       class BaseSession["BaseSession\n«base»"]
       class Session["Session\n«default»"]

       BaseSession <|-- Session

Because the ``Session`` class is large, it is usually better to hook into the
more targeted plugin types above. Only use a custom session class when you
need to track state across multiple sub-protocols (SSH + SFTP + SCP)
simultaneously.

**Registration:**

.. code-block:: toml

    [project.entry-points."sshmitm.BaseSession"]
    my-session = "mypkg.session:MySession"

**Usage:**

.. code-block:: bash

    ssh-mitm server --session-class my-session


Exec Handler Plugins
^^^^^^^^^^^^^^^^^^^^

**Entry-point group:** ``sshmitm.ExecHandler``

Exec handlers extend ``ExecForwarder`` directly and are dispatched for
specific SSH exec commands. SSH-MITM matches the command byte prefix against
registered handlers via ``SCPBaseForwarder.register_exec_handler()``.

The built-in example is ``MoshForwarder``, which intercepts Mosh server launch
commands:

.. code-block:: python

    from sshmitm.forwarders.exec import ExecForwarder
    from sshmitm.forwarders.scp import SCPBaseForwarder

    class MyExecHandler(ExecForwarder):

        def handle_client_data(self, data: bytes) -> bytes:
            # inspect or modify data sent to the exec'd process
            return data

        def handle_server_data(self, data: bytes) -> bytes:
            # inspect or modify output from the exec'd process
            return data

    SCPBaseForwarder.register_exec_handler(b"my-command", MyExecHandler)

**Registration:**

.. code-block:: toml

    [project.entry-points."sshmitm.ExecHandler"]
    my-handler = "mypkg.exec_handler:MyExecHandler"


Adding CLI Arguments
--------------------

Every plugin can expose its own command-line flags by implementing the
``parser_arguments()`` classmethod:

.. code-block:: python

    @classmethod
    def parser_arguments(cls) -> None:
        group = cls.argument_group()        # argument group named after the class
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
