"""NETCONF forwarder — EXPERIMENTAL

.. warning::

    This forwarder is **experimental**. It has known protocol gaps and bugs
    that can cause session failures with modern NETCONF implementations.
    Do not use in production without understanding the limitations documented
    below.

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
