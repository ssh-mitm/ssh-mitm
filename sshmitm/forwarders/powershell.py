"""PowerShell remoting (PSRP over SSH) forwarder.

PowerShell remoting over SSH is implemented as an SSH *subsystem*: the client
opens a channel and requests the ``powershell`` subsystem, which on the remote
host launches ``pwsh -sshs``.  All traffic on that channel is the binary
PowerShell Remoting Protocol (PSRP) — a bidirectional, framed-by-PowerShell
stream that must be relayed verbatim.

Unlike NETCONF, PSRP has no line/terminator framing that SSH-MITM could safely
parse, so this forwarder performs a transparent byte-for-byte relay using the
generic loop provided by :class:`~sshmitm.forwarders.exec.ExecForwarder`.

Extending this forwarder
------------------------

For pass-through the data hooks are intentionally identity functions.  To debug,
log, or modify the PSRP stream, subclass :class:`PowerShellForwarder` and
override:

* :meth:`~sshmitm.forwarders.exec.ExecForwarder.handle_client_data` -
  bytes sent from the client towards the remote ``pwsh``.
* :meth:`~sshmitm.forwarders.exec.ExecForwarder.handle_server_data` -
  bytes sent from the remote ``pwsh`` back to the client.
* :meth:`~sshmitm.forwarders.exec.ExecForwarder.handle_error` -
  bytes on the stderr stream.

Each hook receives the raw chunk and must return the (possibly modified) bytes
to forward; returning the input unchanged keeps the session transparent.
"""

import logging
from typing import ClassVar

import paramiko

from sshmitm.forwarders.exec import ExecForwarder


class PowerShellBaseForwarder(ExecForwarder):
    """Base class for PowerShell remoting (PSRP) subsystem forwarders."""

    # Name of the SSH subsystem requested by PowerShell remoting clients.
    subsystem_name: ClassVar[str] = "powershell"

    @property
    def client_channel(self) -> paramiko.Channel | None:
        return self.session.powershell_channel

    @property
    def _forwarded_command(self) -> bytes:
        return self.subsystem_name.encode("utf-8")

    def forward(self) -> None:
        raise NotImplementedError


class PowerShellForwarder(PowerShellBaseForwarder):
    """Transparent MITM forwarder for the PowerShell remoting (PSRP) subsystem.

    Relays the binary PSRP stream between the client and the remote ``pwsh -sshs``
    process without modification.  No parsing or logging is performed — all traffic
    is forwarded byte-for-byte.

    **Usage example**

    ::

        ssh-mitm server --powershell-interface base

    **Notes**

    * This is the default PowerShell forwarder; no ``--powershell-interface`` flag
      is needed unless overriding.
    * To log or inspect PSRP traffic use the ``log-session`` plugin instead.
    * See the module docstring for how to subclass and hook into the stream.
    """

    def forward(self) -> None:
        logging.debug("starting powershell subsystem relay")
        # Request the upstream "powershell" subsystem (runs ``pwsh -sshs``).
        self.server_channel.invoke_subsystem(self.subsystem_name)
        try:
            self._run_traffic_loop()
        except Exception:
            logging.exception("error relaying powershell subsystem")
            raise
        finally:
            logging.debug("powershell subsystem relay finished")
