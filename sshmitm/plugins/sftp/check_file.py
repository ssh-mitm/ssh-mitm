import io
import logging
import os
import socket
import struct
import uuid
from typing import cast

import paramiko
from paramiko import SFTPAttributes
from paramiko.sftp_handle import SFTPHandle

from sshmitm.exceptions import MissingClient
from sshmitm.forwarders.sftp import SFTPBaseHandle, SFTPHandlerPlugin
from sshmitm.interfaces.sftp import BaseSFTPServerInterface, SFTPProxyServerInterface


class ClamAVClient:
    def __init__(
        self, socket_path: str = "/tmp/clamd.sock"  # nosec B108  # noqa: S108
    ) -> None:
        self.socket_path = socket_path

    def _connect(self) -> socket.socket:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(self.socket_path)
        return s

    def _read_response(self, sock: socket.socket) -> str:
        data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if data.endswith((b"\x00", b"\n")):
                break
        return data.decode("utf-8", errors="replace").strip()

    def instream(self, data: bytes, chunk_size: int = 1024) -> str:
        with self._connect() as sock:
            sock.sendall(b"zINSTREAM\x00")
            pos = 0
            while pos < len(data):
                chunk = data[pos : pos + chunk_size]
                sock.sendall(struct.pack(">I", len(chunk)))
                sock.sendall(chunk)
                pos += chunk_size
            sock.sendall(struct.pack(">I", 0))
            return self._read_response(sock)


class SFTPHandlerCheckFilePlugin(SFTPHandlerPlugin):
    """Buffers transferred files in memory, scans with ClamAV before forwarding"""

    @classmethod
    def parser_arguments(cls) -> None:
        plugin_group = cls.argument_group()
        plugin_group.add_argument(
            "--clamav-socket",
            dest="clamav_socket",
            default="/tmp/clamd.sock",  # nosec B108  # noqa: S108
            help="Path to the ClamAV Unix domain socket (default: /tmp/clamd.sock).",
        )

    def __init__(self, sftp: SFTPBaseHandle, filename: str) -> None:
        super().__init__(sftp, filename)
        self.file_id = str(uuid.uuid4())
        self.filename = filename

        logging.info(
            "SFTP transfer started: %s -> memory buffer (%s)", filename, self.file_id
        )

    class SFTPInterface(SFTPProxyServerInterface):

        def open(self, path: str, flags: int, attr: SFTPAttributes) -> SFTPHandle | int:
            logging.info(
                "open from check_file with: path=%s flags=%s attr=%s", path, flags, attr
            )
            try:
                self.session.sftp.client_ready.wait()
                if self.session.sftp.client is None:
                    msg = "self.session.sftp.client is None!"
                    raise MissingClient(msg)

                sftp_handler = self.session.proxyserver.sftp_handler
                sftp_file_handle = sftp_handler.get_file_handle()
                fobj = sftp_file_handle(
                    self, self.session, sftp_handler, path, flags, attr, use_buffer=True
                )

                if not flags & (os.O_WRONLY | os.O_RDWR):
                    # Download: load remote file into buffer and check before serving
                    remote_file = self.session.sftp.client.open(path, "rb")
                    fobj.buffer = io.BytesIO(remote_file.read())
                    remote_file.close()
                    fobj.readfile = fobj.buffer
                    if not cast("SFTPHandlerCheckFilePlugin", fobj.plugin).check_file():
                        logging.warning("sftp get blocked: invalid file. path=%s", path)
                        return paramiko.sftp.SFTP_PERMISSION_DENIED
                    fobj.buffer.seek(0)

            except OSError as exc:
                logging.exception("Error")
                return paramiko.SFTPServer.convert_errno(exc.errno or 0)
            except Exception:  # pylint: disable=broad-exception-caught
                logging.exception("Error")
                return paramiko.sftp.SFTP_FAILURE
            return fobj

    @classmethod
    def get_interface(cls) -> type[BaseSFTPServerInterface] | None:
        return cls.SFTPInterface

    def check_file(self) -> bool:
        """Scan the buffered file with ClamAV via INSTREAM"""
        self.sftp.buffer.seek(0)
        data = self.sftp.buffer.read()
        try:
            client = ClamAVClient(self.args.clamav_socket)
            result = client.instream(data)
        except OSError:
            logging.exception("ClamAV connection failed for %s", self.filename)
            return False
        if "FOUND" in result:
            logging.warning("ClamAV detected threat in %s: %s", self.filename, result)
            return False
        if "ERROR" in result:
            logging.error("ClamAV scan error for %s: %s", self.filename, result)
            return False
        logging.info("ClamAV scan clean for %s: %s", self.filename, result)
        return True

    def close(self) -> None:
        # Downloads are checked in open(); nothing to forward to server
        if not self.sftp.open_flags & (os.O_WRONLY | os.O_RDWR):
            super().close()
            return

        # Check the buffered file content before forwarding
        if not self.check_file():
            raise paramiko.SFTPError(
                paramiko.sftp.SFTP_FAILURE, "ClamAV scan rejected file"
            )

        self.sftp.open_remote_file()
        self.sftp.buffer.seek(0)  # Go to beginning of buffer
        if self.sftp.remote_file is not None:
            logging.info("Flushing buffered file (%s) to server", self.filename)
            chunk_size = 32768
            offset = 0
            while True:
                chunk = self.sftp.buffer.read(chunk_size)
                if not chunk:
                    break
                self.sftp.remote_file.write(chunk)
                offset += len(chunk)
            self.sftp.remote_file.flush()
        else:
            logging.warning("remote_file handle is None; data not forwarded!")
        self.sftp.buffer.close()
        super().close()

    def handle_data(
        self, data: bytes, *, offset: int | None = None, length: int | None = None
    ) -> bytes:
        del offset
        del length
        return data
