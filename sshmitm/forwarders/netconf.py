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

**Plugin hooks are not wired up**
    ``handle_traffic()`` and ``handle_error()`` are inherited from
    ``SCPBaseForwarder`` but are never called in the forwarding loop. Subclass
    overrides have no effect — traffic is forwarded unmodified regardless.

**Inheritance from SCPBaseForwarder is semantically wrong**
    NETCONF and SCP are unrelated protocols. Inheriting from
    ``SCPBaseForwarder`` pulls in SCP-specific methods (``handle_scp()``,
    ``handle_command()``, ``process_response()``, …) that make no sense here
    and make the class hierarchy misleading. The base class should eventually
    be ``BaseForwarder`` directly.

**UTF-8 decode without error handling**
    The server response is decoded as UTF-8 unconditionally before logging
    (``buf.decode("utf-8")``). Binary payloads or non-UTF-8 XML encodings
    will raise ``UnicodeDecodeError`` and terminate the forwarder thread.

**Double EOF shutdown**
    ``shutdown_write()`` is called on EOF both before the main loop and inside
    the loop. There is no guard against issuing the shutdown twice on an
    already-closed channel.

**Dead exec_command path**
    ``check_channel_exec_request()`` in ``interfaces/server.py`` contains a
    branch that sets ``session.netconf_command`` when ``netconf_requested`` is
    already ``True``, but exec-based invocations are never routed to this
    forwarder. The branch is dead code. Per RFC 6242 NETCONF must be invoked
    as an SSH subsystem, not via exec.

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

import paramiko

from sshmitm.forwarders.scp import SCPBaseForwarder


class NetconfBaseForwarder(SCPBaseForwarder):
    # RFC 4742 end-of-message delimiter; RFC 6242 chunked framing is not supported.
    __netconf_terminator = b"]]>]]>"

    @property
    def client_channel(self) -> paramiko.Channel | None:
        return self.session.netconf_channel

    def read_netconf_data(self, chan: paramiko.Channel, responses: int = 1) -> bytes:
        # WARNING: busy-loop with 50 ms sleep; no timeout; hangs on chunked framing.
        # Accumulates data until the expected number of ]]>]]> terminators is seen.
        response_buf = b""
        while responses:
            time.sleep(0.05)
            response = chan.recv(self.BUF_LEN)
            response_buf += response
            responses -= response.count(self.__netconf_terminator)

        return response_buf


class NetconfForwarder(NetconfBaseForwarder):
    """Transparent MITM forwarder for the NETCONF SSH subsystem (RFC 6242).

    Intercepts NETCONF messages between client and server. See the module
    docstring for a full list of known limitations before using this class.
    """

    def forward(self) -> None:  # noqa: C901,PLR0915

        # pylint: disable=protected-access
        if self.session.ssh_pty_kwargs is not None:
            self.server_channel.get_pty(**self.session.ssh_pty_kwargs)

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
                    self.session.netconf_command = buf
                    # NOTE: handle_traffic() is intentionally NOT called here — the hook
                    # is inherited from SCPBaseForwarder but was never wired up.
                    self.sendall(self.server_channel, buf, self.server_channel.send)

                if self.server_channel.recv_ready():
                    buf = self.read_netconf_data(self.server_channel)
                    # NOTE: decode may raise UnicodeDecodeError on non-UTF-8 payloads.
                    logging.info(
                        "received response: %s [isclient=%s] [command=%s]",
                        buf.decode("utf-8"),
                        False,
                        self.session.netconf_command,
                    )
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
                        self.session.netconf_command.decode("utf-8"),
                        status,
                    )
                    time.sleep(0.1)
                    break
                if self.client_channel.exit_status_ready():
                    logging.debug("Exit from client ready")
                    status = self.client_channel.recv_exit_status()
                    self.client_exit_code_received = True
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
