"""NETCONF forwarder — EXPERIMENTAL

.. warning::

    This forwarder is **experimental**. It has known protocol gaps and bugs
    that can cause session failures with modern NETCONF implementations.
    Do not use in production without understanding the limitations documented
    below.

Testing
-------

Two test setups are recommended — one against a legacy RFC 4742 server to
verify baseline functionality, and one against a modern RFC 6242 server to
reproduce the chunked-framing failure described below.

**Legacy server: yuma123 / netconfd (RFC 4742, ``]]>]]>`` framing)**

Install from the distribution package manager::

    # Debian / Ubuntu
    sudo apt install yuma123

Start the server (requires root or ``CAP_NET_BIND_SERVICE`` for port 830)::

    sudo netconfd --no-startup --superuser=$USER

``netconfd`` uses RFC 4742 framing and is therefore compatible with the
current forwarder. Use this setup to test the happy path.

**Modern server: netopeer2 (RFC 6242, chunked framing)**

Build and install ``libyang``, ``sysrepo``, ``libnetconf2``, and
``netopeer2`` from source following the upstream documentation at
https://github.com/CESNET/netopeer2. This setup is more involved but
represents current real-world NETCONF deployments and will reproduce the
chunked-framing failure in this forwarder.

**Client**

``netconf-console`` is a lightweight Python client suitable for both setups::

    pip install netconf-console

    # Basic <get> request
    netconf-console --host=localhost --port=830 -u admin --get

Alternatively use ``yangcli``, which ships with yuma123::

    yangcli user=admin server=localhost

**Inserting SSH-MITM between client and server**

::

    netconf-console → SSH-MITM (10022) → netconfd / netopeer2 (830)

Start SSH-MITM::

    ssh-mitm server --remote-host localhost --remote-port 830 --listen-port 10022

Point the client at SSH-MITM::

    netconf-console --host=localhost --port=10022 -u admin --get

With the yuma123 server the session should complete successfully. With
netopeer2 the session will stall or produce garbled output, demonstrating
the RFC 6242 gap documented below.

Known limitations and bugs
--------------------------

**RFC 6242 chunked framing not implemented (critical)**
    RFC 6242 (the current standard for NETCONF-over-SSH) requires chunk-based
    message framing::

        #4\\ndata\\n##\\n

    Only the legacy ``]]>]]>`` end-of-message terminator from RFC 4742 is
    implemented. Modern NETCONF devices and clients negotiate chunked framing
    during the ``<hello>`` exchange. When either side uses chunked framing the
    forwarder will silently corrupt or drop messages, or the session will hang
    waiting for a terminator that never arrives.

**No timeout in read_netconf_data()**
    The reader loops forever until the ``]]>]]>`` terminator is seen. A
    connection that drops mid-message, or any peer that uses chunked framing,
    will cause the forwarder thread to hang indefinitely.

**Busy-loop with artificial latency**
    ``read_netconf_data()`` sleeps 50 ms *before* every ``recv()`` call. This
    adds unnecessary per-message latency and wastes CPU in a polling loop
    instead of blocking on the channel.

**No capability negotiation interception**
    The ``<hello>`` exchange where client and server negotiate capabilities
    (including the framing version) passes through unexamined. The MITM
    cannot advertise, suppress, or rewrite capabilities.

**No message-id tracking**
    NETCONF RPC messages carry a ``message-id`` attribute that correlates
    requests with responses. This forwarder does not parse message-ids, so
    audit logs cannot reliably pair requests with their responses in sessions
    with concurrent or pipelined RPCs.
"""

import logging
import time
from typing import TYPE_CHECKING

import paramiko

from sshmitm.core.netconf import NetconfBaseForwarder

if TYPE_CHECKING:
    import sshmitm


class NetconfForwarder(NetconfBaseForwarder):
    """Transparent MITM forwarder for the NETCONF SSH subsystem (RFC 6242).

    Intercepts NETCONF messages between client and server. See the module
    docstring for a full list of known limitations before using this class.
    """

    def forward(self) -> None:  # noqa: C901,PLR0915

        # pylint: disable=protected-access
        if self.session.ssh.pty_kwargs is not None:
            self.server_channel.get_pty(**self.session.ssh.pty_kwargs)

        # Guard against EOF that arrived before the loop starts.
        # NOTE: shutdown_write() may be called again inside the loop — no guard exists.
        if self.client_channel is not None and self.client_channel.eof_received:
            logging.debug("client channel eof received")
            self.server_channel.shutdown_write()
        if self.server_channel.eof_received:
            logging.debug("server channel eof received")
            if self.client_channel is not None:
                self.client_channel.shutdown_write()

        self.server_channel.invoke_subsystem("netconf")

        try:
            while self.session.running:
                if self.client_channel is None:
                    msg = "No Netconf Channel available!"
                    raise ValueError(msg)

                if self.client_channel.recv_ready():
                    buf = self.read_netconf_data(self.client_channel)
                    self.session.netconf.command = buf
                    buf = self.handle_client_data(buf)
                    self.sendall(self.server_channel, buf, self.server_channel.send)

                if self.server_channel.recv_ready():
                    buf = self.read_netconf_data(self.server_channel)
                    # NOTE: decode may raise UnicodeDecodeError on non-UTF-8 payloads.
                    logging.info(
                        "received response: %s [command=%s]",
                        buf.decode("utf-8"),
                        self.session.netconf.command,
                    )
                    buf = self.handle_server_data(buf)
                    self.sendall(self.client_channel, buf, self.client_channel.send)

                if self.client_channel.recv_stderr_ready():
                    buf = self.client_channel.recv_stderr(self.BUF_LEN)
                    buf = self.handle_error(buf)
                    self.sendall(
                        self.server_channel, buf, self.server_channel.send_stderr
                    )
                if self.server_channel.recv_stderr_ready():
                    buf = self.server_channel.recv_stderr(self.BUF_LEN)
                    buf = self.handle_error(buf)
                    self.sendall(
                        self.client_channel,
                        buf,
                        self.client_channel.send_stderr,
                    )

                if self.server_channel.exit_status_ready():
                    logging.debug("Exit from server ready")
                    status = self.server_channel.recv_exit_status()
                    self.server_exit_code_received = True
                    self.close_session_with_status(self.client_channel, status)
                    logging.info(
                        "remote netconf command '%s' exited with code: %s",
                        self.session.netconf.command.decode("utf-8"),
                        status,
                    )
                    time.sleep(0.1)
                    break
                if self.client_channel.exit_status_ready():
                    logging.debug("Exit from client ready")
                    self.client_exit_code_received = True
                    self.client_channel.recv_exit_status()
                    self.close_session(self.client_channel)
                    break

                if self._closed(self.client_channel):
                    logging.info("client channel closed")
                    self.server_channel.close()
                    self.close_session(self.client_channel)
                    break
                if self._closed(self.server_channel):
                    logging.info("server channel closed")
                    self.close_session(self.client_channel)
                    break
                if self.client_channel.eof_received:
                    logging.debug("client channel eof received")
                    self.server_channel.shutdown_write()
                if self.server_channel.eof_received:
                    logging.debug("server channel eof received")
                    self.client_channel.shutdown_write()

                time.sleep(0.1)
        except Exception:
            logging.exception("error processing netconf command")
            raise
