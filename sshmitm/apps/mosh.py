import base64
import logging
import socket
import threading
from typing import List, Tuple, cast

from colored.colored import attr, fg  # type: ignore[import-untyped]
from cryptography.hazmat.primitives.ciphers.aead import AESOCB3

from sshmitm.logging import Colors
from sshmitm.session import Session
from sshmitm.utils import format_hex


class UdpProxy:
    """
    UdpProxy is a class to act as a proxy server for MOSH (Mobile shell) protocol

    This class provides the functionality of a proxy server for the MOSH protocol. MOSH is a protocol for mobile shell sessions, which helps maintain shell sessions when network connection is disrupted.

    :param key: Base64 encoded key to be used for decryption of incoming messages
    :param target_ip: IP of target server
    :param target_port: Port number of target server
    :param listen_ip: IP to bind the proxy server (default '')
    :param listen_port: Port number to bind the proxy server (default 0)
    :param buf_size: buffer size for incoming data (default 1024)
    """

    def __init__(  # pylint: disable=too-many-arguments
        self,
        key: str,
        target_ip: str,
        target_port: int,
        listen_ip: str = "",
        listen_port: int = 0,
        buf_size: int = 1024,
    ) -> None:
        self.key = base64.b64decode(key + "==")
        self.listen_ip = listen_ip
        self.listen_port = listen_port
        self.target_ip = target_ip
        self.target_port = target_port
        self.buf_size = buf_size
        self.pair_list: List[List[Tuple[str, int]]] = []
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind((self.listen_ip, self.listen_port))

    def get_bind_port(self) -> int:
        """
        Get the port number that the proxy server is bound to.

        :return: Port number
        """
        return cast(int, self.socket.getsockname()[1])

    def start(self) -> None:
        """
        Start the proxy server.
        """
        timed_thread = threading.Timer(0, self.thread_receive)
        timed_thread.daemon = True
        timed_thread.start()

    def check_pairing(self, addr: Tuple[str, int]) -> Tuple[str, int]:
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
            final_fragment_bool = final_fragment.hex() == "8000"
            payload = dec_message[14:]

            data_to_print = [
                f"{Colors.stylize('MOSH Data', attr('bold'))}",
                f"from->to: {addr} -> {destination_addr}",
                f"timestamp (ms): {int.from_bytes(timestamp, 'big')} (0x{timestamp.hex()})",
                f"timestamp_reply (ms): {int.from_bytes(timestamp_reply, 'big')} (0x{timestamp_reply.hex()})",
                f"fragment_id: 0x{fragment_id.hex()}",
                f"final_fragment:  {final_fragment_bool} (0x{final_fragment.hex()})",
                f"Payload:\n{format_hex(payload)}",
                "-" * 89,
            ]
            logging.info("\n".join(data_to_print))

            self.socket.sendto(data, destination_addr)

    def thread_receive(self) -> None:
        """
        Start a separate thread to receive incoming messages.
        """
        while True:
            self.receive(self.buf_size)


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
                        else cast(int, mosh_connect_parts[2])
                    ),
                )
                mosh_port = mosh_proxy.get_bind_port()
                mosh_proxy.start()
                logging.info("started mosh proxy with  %s", mosh_port)
                return f"MOSH CONNECT {mosh_port} {mosh_connect_parts[3]}".encode()
        except Exception:  # pylint: disable=broad-exception-caught
            logging.exception("Error starting mosh proxy")
    return traffic
