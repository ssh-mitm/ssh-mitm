import logging
import binascii
import socket
import threading
from typing import cast, List, Tuple
import base64

from cryptography.hazmat.primitives.ciphers.aead import AESOCB3  # type: ignore
from colored.colored import stylize, attr, fg  # type: ignore
from rich._emoji_codes import EMOJI

from sshmitm.session import Session


class UdpProxy:
    def __init__(self, key: str, target_ip: str, target_port: int, listen_ip: str = '', listen_port: int = 0, buf_size: int = 1024):
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
        return cast(int, self.socket.getsockname()[1])

    def start(self) -> None:
        th = threading.Timer(0, self.thread_receive)
        th.daemon = True
        th.start()

    def check_pairing(self, addr: Tuple[str, int]) -> Tuple[str, int]:
        for i in range(len(self.pair_list)):
            if addr == self.pair_list[i][0]:
                return self.pair_list[i][1]
            if addr == self.pair_list[i][1]:
                return self.pair_list[i][0]
        new_port = len(self.pair_list) + self.target_port
        destination_addr = (self.target_ip, new_port)
        self.pair_list.append([addr, destination_addr])
        return destination_addr

    @staticmethod
    def format_hex(data: bytes, hexwidth: int = 19) -> str:
        result = []
        for i in range(0, len(data), hexwidth):
            s = data[i:i + hexwidth]
            hexa = list(map(''.join, zip(*[iter(binascii.hexlify(s).decode('utf-8'))] * 2)))
            while hexwidth - len(hexa) > 0:
                hexa.append(' ' * 2)
            text = ''.join([chr(x) if 0x20 <= x < 0x7F else '.' for x in s])
            addr = '%04X:    %s    %s' % (i, " ".join(hexa), text)
            result.append(addr)

        return '\n'.join(result)

    def receive(self, buff_size: int) -> None:
        data, addr = self.socket.recvfrom(buff_size)
        if addr and data:
            destination_addr = self.check_pairing(addr)

            nonce = b"\x00\x00\x00\x00" + data[:8]
            message = data[8:]
            aesocb = AESOCB3(self.key)
            dec_message = aesocb.decrypt(nonce, message, None)

            data_to_print = [
                f"{stylize('MOSH Data', attr('bold'))}",
                f"from->to: {addr} -> {destination_addr}",
                f"timestamp (ms): {int.from_bytes(dec_message[:2], 'big')}",
                f"timestamp_reply (ms): {int.from_bytes(dec_message[2:4], 'big')}",
                f"Payload:\n{self.format_hex(dec_message[4:])}",
                "-" * 89
            ]
            logging.info("\n".join(data_to_print))

            self.socket.sendto(data, destination_addr)

    def thread_receive(self) -> None:
        while True:
            self.receive(self.buf_size)


def handle_mosh(session: Session, traffic: bytes, isclient: bool) -> bytes:
    if not isclient:
        try:
            mosh_connect = traffic.decode("utf8")
            logging.info(mosh_connect)
            mosh_connect_parts = mosh_connect.strip().split(" ")
            mosh_info = "\n".join([
                stylize(
                    EMOJI['information'] + " MOSH connection info",
                    fg('blue') + attr('bold')
                ),
                f"  * MOSH-port: {mosh_connect_parts[2]}",
                f"  * MOSH-shared-secret: {mosh_connect_parts[3]}"
            ])
            logging.info(mosh_info)

            if session.remote_address[0] is not None:
                mosh_proxy = UdpProxy(
                    key=mosh_connect_parts[3],
                    target_ip=session.remote_address[0],
                    target_port=int(mosh_connect_parts[2]),
                    listen_ip="0.0.0.0",
                    listen_port=0 if session.remote_address[0] == '127.0.0.1' else cast(int, mosh_connect_parts[2])
                )
                mosh_port = mosh_proxy.get_bind_port()
                mosh_proxy.start()
                logging.info(f"started mosh proxy with port {mosh_port}")
                return f"MOSH CONNECT {mosh_port} {mosh_connect_parts[3]}".encode()
        except Exception:
            logging.exception("Error starting mosh proxy")
    return traffic
