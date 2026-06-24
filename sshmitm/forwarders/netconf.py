"""NETCONF forwarder — EXPERIMENTAL

.. warning::

    This forwarder is **experimental**. Protocol gaps remain; do not use in
    production without understanding the limitations documented below.

Testing
-------

Two test setups are recommended — one against a legacy RFC 4742 server to
verify baseline functionality, and one against a modern RFC 6242 server to
confirm the chunked-framing implementation.

**Legacy server: yuma123 / netconfd (RFC 4742, ``]]>]]>`` framing)**

Install from the distribution package manager::

    # Debian / Ubuntu
    sudo apt install yuma123

Start the server (requires root or ``CAP_NET_BIND_SERVICE`` for port 830)::

    sudo netconfd --no-startup --superuser=$USER

**Modern server: netopeer2 (RFC 6242, chunked framing)**

Build and install ``libyang``, ``sysrepo``, ``libnetconf2``, and
``netopeer2`` from source following the upstream documentation at
https://github.com/CESNET/netopeer2.

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

Known limitations
-----------------

**No notification support** *(Phase 5)*
    NETCONF event notifications (RFC 5277 ``create-subscription``) are
    forwarded transparently but not tracked or intercepted.

RPC hooks (Phase 3)
-------------------

Subclasses can override :meth:`NetconfBaseForwarder.handle_rpc_request` and
:meth:`NetconfBaseForwarder.handle_rpc_reply` to inspect or rewrite individual
RPC operations without touching the framing layer.  The reference logging
plugin is :class:`sshmitm.plugins.netconf.log_session.NetconfLoggingForwarder`.
"""

import logging
import time
import xml.etree.ElementTree as ET

import paramiko

from sshmitm.forwarders.exec import ExecForwarder

_NETCONF_NS = "urn:ietf:params:xml:ns:netconf:base:1.0"
_CAP_BASE_1_0 = "urn:ietf:params:netconf:base:1.0"
_CAP_BASE_1_1 = "urn:ietf:params:netconf:base:1.1"

# Register the NETCONF base namespace as the default so ET.tostring() emits
# xmlns="..." instead of xmlns:ns0="..." when plugins rewrite RPC elements.
ET.register_namespace("", _NETCONF_NS)


def _parse_hello(raw: bytes) -> frozenset[str]:
    """Return the set of capability URNs from a raw NETCONF ``<hello>`` message.

    Strips the ``]]>]]>`` EOM terminator before parsing. Returns an empty
    frozenset if the XML is absent or malformed.
    """
    xml_bytes = raw.split(b"]]>]]>")[0].strip()
    if not xml_bytes:
        return frozenset()
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError:
        logging.warning("NETCONF: failed to parse <hello> XML")
        return frozenset()
    return frozenset(
        cap.text.strip()
        for cap in root.iter(f"{{{_NETCONF_NS}}}capability")
        if cap.text and cap.text.strip()
    )


def _reassemble_chunks(raw: bytes) -> bytes:
    r"""Extract the payload bytes from a chunked-framed NETCONF message.

    Input format (RFC 6242)::

        \n#<size>\n<data>\n#<size>\n<data>...\n##\n

    Returns the concatenated data from all chunks.
    """
    result = b""
    pos = 0
    n = len(raw)
    while pos < n - 1:
        if raw[pos : pos + 2] != b"\n#":
            break
        pos += 2
        if pos < n and raw[pos : pos + 1] == b"#":
            break
        nl = raw.find(b"\n", pos)
        if nl == -1:
            break
        try:
            size = int(raw[pos:nl])
        except ValueError:
            break
        pos = nl + 1
        result += raw[pos : pos + size]
        pos += size
    return result


class NetconfBaseForwarder(ExecForwarder):
    """Base class for NETCONF SSH-subsystem forwarders.

    Provides message framing for both RFC 4742 (EOM ``]]>]]>``) and
    RFC 6242 (chunked ``\\n#<size>\\n<data>...\\n##\\n``) framing, with
    configurable read timeouts.
    """

    _EOM_TERMINATOR: bytes = b"]]>]]>"

    #: Default timeout in seconds for reading one complete NETCONF message.
    READ_TIMEOUT: float = 30.0

    @property
    def client_channel(self) -> paramiko.Channel | None:
        return self.session.netconf_channel

    @property
    def _forwarded_command(self) -> bytes:
        return self.session.netconf.command

    # ------------------------------------------------------------------
    # Low-level receive helpers
    # ------------------------------------------------------------------

    def _recv_byte(self, chan: paramiko.Channel, deadline: float) -> bytes:
        """Read exactly one byte from *chan*, raising on timeout or EOF."""
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            msg = "Timeout reading NETCONF message"
            raise TimeoutError(msg)
        chan.settimeout(min(remaining, 1.0))
        byte = chan.recv(1)
        if not byte:
            msg = "Channel closed while reading NETCONF message"
            raise ConnectionError(msg)
        return byte

    def _recv_exactly(self, chan: paramiko.Channel, n: int, deadline: float) -> bytes:
        """Read exactly *n* bytes from *chan* before *deadline*."""
        data = b""
        while len(data) < n:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                msg = "Timeout reading NETCONF chunk data"
                raise TimeoutError(msg)
            chan.settimeout(min(remaining, 1.0))
            chunk = chan.recv(min(n - len(data), self.BUF_LEN))
            if not chunk:
                msg = "Channel closed while reading NETCONF chunk data"
                raise ConnectionError(msg)
            data += chunk
        return data

    # ------------------------------------------------------------------
    # Framing readers
    # ------------------------------------------------------------------

    def _read_eom(self, chan: paramiko.Channel, initial: bytes, deadline: float) -> bytes:
        """Read until the ``]]>]]>`` EOM terminator.

        *initial* holds bytes already read from the channel.
        """
        buf = initial
        while self._EOM_TERMINATOR not in buf:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                msg = "Timeout reading NETCONF EOM message"
                raise TimeoutError(msg)
            chan.settimeout(min(remaining, 1.0))
            chunk = chan.recv(self.BUF_LEN)
            if not chunk:
                return buf
            buf += chunk
        return buf

    def _read_chunked_after_lf_hash(self, chan: paramiko.Channel, deadline: float) -> bytes:
        r"""Read the remainder of an RFC 6242 chunked message.

        Called after the leading ``\n#`` bytes have been consumed.
        Reads and returns everything from ``<size>\n<data>`` through the
        final ``\n##\n`` end-of-chunks marker (not including the consumed
        ``\n#``).

        RFC 6242 chunk format::

            \n#<size>\n<data>\n#<size>\n<data>...\n##\n
        """
        buf = b""
        while True:
            # Next byte is either the first digit of chunk-size or '#' (end-of-chunks).
            next_byte = self._recv_byte(chan, deadline)
            buf += next_byte

            if next_byte == b"#":
                # End-of-chunks: \n##\n — consume and validate the trailing \n.
                terminator = self._recv_byte(chan, deadline)
                if terminator != b"\n":
                    msg = f"Expected \\n after ##, got {terminator!r}"
                    raise ValueError(msg)
                buf += terminator
                return buf

            if not next_byte.isdigit():
                msg = f"Invalid character in NETCONF chunk header: {next_byte!r}"
                raise ValueError(msg)

            # Read remaining digits and the terminating \n.
            size_bytes = next_byte
            while True:
                b = self._recv_byte(chan, deadline)
                buf += b
                if b == b"\n":
                    break
                if not b.isdigit():
                    msg = f"Non-digit in NETCONF chunk size: {b!r}"
                    raise ValueError(msg)
                size_bytes += b

            chunk_size = int(size_bytes)
            buf += self._recv_exactly(chan, chunk_size, deadline)

            # Read the \n# separator that precedes the next chunk header or end-of-chunks.
            lf = self._recv_byte(chan, deadline)
            buf += lf
            if lf != b"\n":
                msg = f"Expected \\n between NETCONF chunks, got {lf!r}"
                raise ValueError(msg)
            hash_byte = self._recv_byte(chan, deadline)
            buf += hash_byte
            if hash_byte != b"#":
                msg = f"Expected # in NETCONF chunk delimiter, got {hash_byte!r}"
                raise ValueError(msg)

    def read_netconf_message(self, chan: paramiko.Channel, timeout: float | None = None) -> bytes:
        r"""Read one complete NETCONF message from *chan*.

        Framing is detected automatically from the first two bytes:

        * ``\n#`` → RFC 6242 chunked framing
          (``\n#<size>\n<data>...\n##\n``)
        * anything else → RFC 4742 EOM framing (``]]>]]>``), including the
          ``<hello>`` exchange that opens every RFC 6242 session.

        Raises :exc:`TimeoutError` if no complete message arrives within
        *timeout* seconds (defaults to :attr:`READ_TIMEOUT`).
        """
        if timeout is None:
            timeout = self.READ_TIMEOUT
        deadline = time.monotonic() + timeout

        remaining = deadline - time.monotonic()
        chan.settimeout(remaining)
        first = chan.recv(1)
        if not first:
            return b""

        if first != b"\n":
            return self._read_eom(chan, first, deadline)

        # First byte is \n — peek at the second byte to distinguish
        # chunked framing (\n#…) from EOM with leading whitespace (\n<…).
        second = self._recv_byte(chan, deadline)
        if second == b"#":
            return b"\n#" + self._read_chunked_after_lf_hash(chan, deadline)

        # EOM message with a leading newline (valid XML whitespace).
        return self._read_eom(chan, first + second, deadline)

    def _handle_hello_exchange(self) -> None:
        """Read, parse, and forward the NETCONF ``<hello>`` exchange.

        Both sides always use EOM framing for the ``<hello>`` message,
        regardless of the capabilities they advertise.  After this method
        returns:

        * ``session.netconf.server_capabilities`` and
          ``session.netconf.client_capabilities`` are populated.
        * ``session.netconf.use_chunked`` is ``True`` when both sides
          advertised ``:base:1.1``, selecting RFC 6242 chunked framing for
          all subsequent messages.
        """
        if self.client_channel is None:
            msg = "No NETCONF channel available for hello exchange"
            raise ValueError(msg)

        # The server sends its <hello> immediately after the subsystem is
        # opened.  Read it first, forward to the client, then read the
        # client's <hello> and forward that to the server.
        server_hello = self.read_netconf_message(self.server_channel)
        self.session.netconf.server_capabilities = _parse_hello(server_hello)
        logging.debug(
            "NETCONF server capabilities: %s",
            self.session.netconf.server_capabilities,
        )
        self.sendall(self.client_channel, server_hello, self.client_channel.send)

        client_hello = self.read_netconf_message(self.client_channel)
        self.session.netconf.client_capabilities = _parse_hello(client_hello)
        logging.debug(
            "NETCONF client capabilities: %s",
            self.session.netconf.client_capabilities,
        )
        self.sendall(self.server_channel, client_hello, self.server_channel.send)

        self.session.netconf.use_chunked = (
            _CAP_BASE_1_1 in self.session.netconf.server_capabilities
            and _CAP_BASE_1_1 in self.session.netconf.client_capabilities
        )
        logging.info(
            "NETCONF framing negotiated: %s",
            "chunked (RFC 6242 :base:1.1)"
            if self.session.netconf.use_chunked
            else "EOM (RFC 4742 :base:1.0)",
        )

    def _read_rpc_message(self, chan: paramiko.Channel) -> bytes:
        """Read one post-hello NETCONF message using the negotiated framing.

        Uses the framing mode determined during the ``<hello>`` exchange
        (``session.netconf.use_chunked``) instead of auto-detecting per
        message.  Call :meth:`_handle_hello_exchange` before the main loop.
        """
        deadline = time.monotonic() + self.READ_TIMEOUT
        if self.session.netconf.use_chunked:
            lf = self._recv_byte(chan, deadline)
            if lf != b"\n":
                msg = f"Expected \\n for chunked framing, got {lf!r}"
                raise ValueError(msg)
            h = self._recv_byte(chan, deadline)
            if h != b"#":
                msg = f"Expected # for chunked framing, got {h!r}"
                raise ValueError(msg)
            return b"\n#" + self._read_chunked_after_lf_hash(chan, deadline)
        else:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                msg = "Timeout reading NETCONF EOM message"
                raise TimeoutError(msg)
            chan.settimeout(remaining)
            first = chan.recv(1)
            if not first:
                return b""
            return self._read_eom(chan, first, deadline)

    # ------------------------------------------------------------------
    # Framing encode/decode (Phase 3 helpers)
    # ------------------------------------------------------------------

    def _strip_framing(self, raw: bytes) -> bytes:
        """Remove framing from a complete NETCONF message and return plain XML."""
        if self.session.netconf.use_chunked:
            return _reassemble_chunks(raw)
        return raw.split(b"]]>]]>")[0].strip()

    def _apply_framing(self, xml: bytes) -> bytes:
        """Wrap plain XML bytes with the negotiated framing."""
        if self.session.netconf.use_chunked:
            return f"\n#{len(xml)}\n".encode() + xml + b"\n##\n"
        return xml + b"]]>]]>"

    # ------------------------------------------------------------------
    # RPC parsing (Phase 3)
    # ------------------------------------------------------------------

    def _parse_rpc(self, xml: bytes) -> tuple[str, str, ET.Element] | None:
        """Parse a NETCONF ``<rpc>`` element.

        Returns ``(message_id, operation, element)`` or ``None`` if *xml*
        does not contain a valid ``<rpc>`` document.
        *operation* is the local name of the first child of ``<rpc>``
        (e.g. ``"get"``, ``"get-config"``, ``"edit-config"``).
        """
        if not xml:
            return None
        try:
            root = ET.fromstring(xml)
        except ET.ParseError:
            return None
        if root.tag not in (f"{{{_NETCONF_NS}}}rpc", "rpc"):
            return None
        message_id = root.get("message-id", "")
        op_el = next(iter(root), None)
        if op_el is None:
            return None
        tag = op_el.tag
        operation = tag[tag.index("}") + 1 :] if "}" in tag else tag
        return message_id, operation, root

    def _parse_rpc_reply(self, xml: bytes) -> tuple[str, ET.Element] | None:
        """Parse a NETCONF ``<rpc-reply>`` element.

        Returns ``(message_id, element)`` or ``None`` if *xml* does not
        contain a valid ``<rpc-reply>`` document.
        """
        if not xml:
            return None
        try:
            root = ET.fromstring(xml)
        except ET.ParseError:
            return None
        if root.tag not in (f"{{{_NETCONF_NS}}}rpc-reply", "rpc-reply"):
            return None
        return root.get("message-id", ""), root

    # ------------------------------------------------------------------
    # RPC hooks — override in subclasses / plugins (Phase 3)
    # ------------------------------------------------------------------

    def handle_rpc_request(
        self,
        message_id: str,
        operation: str,
        element: ET.Element,
    ) -> ET.Element | None:
        """Called for each client RPC after the ``<hello>`` exchange.

        *message_id* is the ``message-id`` attribute of the ``<rpc>`` element.
        *operation* is the local name of the operation (e.g. ``"get-config"``).
        *element* is the parsed ``<rpc>`` :class:`~xml.etree.ElementTree.Element`.

        Return a modified element to rewrite the message, or ``None`` to
        forward the original bytes unchanged.  The default implementation
        always returns ``None``.
        """
        return None

    def handle_rpc_reply(
        self,
        message_id: str,
        element: ET.Element,
    ) -> ET.Element | None:
        """Called for each server RPC reply after the ``<hello>`` exchange.

        *message_id* is the ``message-id`` attribute of the ``<rpc-reply>``.
        *element* is the parsed ``<rpc-reply>`` element.

        Return a modified element to rewrite the reply, or ``None`` to
        forward the original bytes unchanged.  The default implementation
        always returns ``None``.
        """
        return None

    # ------------------------------------------------------------------
    # handle_client_data / handle_server_data (Phase 3 wiring)
    # ------------------------------------------------------------------

    def handle_client_data(self, data: bytes) -> bytes:
        """Parse client data as an RPC and invoke :meth:`handle_rpc_request`."""
        xml = self._strip_framing(data)
        parsed = self._parse_rpc(xml)
        if parsed is None:
            return data
        message_id, operation, element = parsed
        modified = self.handle_rpc_request(message_id, operation, element)
        if modified is None:
            return data
        return self._apply_framing(
            ET.tostring(modified, encoding="unicode").encode("utf-8")
        )

    def handle_server_data(self, data: bytes) -> bytes:
        """Parse server data as an rpc-reply and invoke :meth:`handle_rpc_reply`."""
        xml = self._strip_framing(data)
        parsed = self._parse_rpc_reply(xml)
        if parsed is None:
            return data
        message_id, element = parsed
        modified = self.handle_rpc_reply(message_id, element)
        if modified is None:
            return data
        return self._apply_framing(
            ET.tostring(modified, encoding="unicode").encode("utf-8")
        )

    def forward(self) -> None:
        msg = "Method forward is not implemented in NetconfBaseForwarder"
        raise NotImplementedError(msg)


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
        if self.client_channel is not None and self.client_channel.eof_received:
            logging.debug("client channel eof received")
            self.server_channel.shutdown_write()
        if self.server_channel.eof_received:
            logging.debug("server channel eof received")
            if self.client_channel is not None:
                self.client_channel.shutdown_write()

        self.server_channel.invoke_subsystem("netconf")
        self._handle_hello_exchange()

        try:
            while self.session.running:
                if self.client_channel is None:
                    msg = "No Netconf Channel available!"
                    raise ValueError(msg)

                if self.client_channel.recv_ready():
                    buf = self._read_rpc_message(self.client_channel)
                    if buf:
                        self.session.netconf.command = buf
                        buf = self.handle_client_data(buf)
                        self.sendall(self.server_channel, buf, self.server_channel.send)

                if self.server_channel.recv_ready():
                    buf = self._read_rpc_message(self.server_channel)
                    if buf:
                        logging.info(
                            "received response: %s [command=%s]",
                            buf.decode("utf-8", errors="replace"),
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
                        self.session.netconf.command.decode("utf-8", errors="replace"),
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
        except TimeoutError:
            logging.warning("NETCONF message read timeout — closing session")
        except Exception:
            logging.exception("error processing netconf command")
            raise
