import logging
import uuid
import zipfile
from typing import Optional, Type, Union

import paramiko
from paramiko import SFTPAttributes
from paramiko.sftp_handle import SFTPHandle

from sshmitm.exceptions import MissingClient
from sshmitm.forwarders.sftp import SFTPBaseHandle, SFTPHandlerPlugin
from sshmitm.interfaces.sftp import BaseSFTPServerInterface, SFTPProxyServerInterface


class SFTPHandlerCheckFilePlugin(SFTPHandlerPlugin):
    """Buffers transferred files in memory and forwards on close,
    checks ZIP content on close"""

    def __init__(self, sftp: SFTPBaseHandle, filename: str) -> None:
        super().__init__(sftp, filename)
        self.file_id = str(uuid.uuid4())
        self.filename = filename

        logging.info(
            "SFTP transfer started: %s -> memory buffer (%s)", filename, self.file_id
        )

    class SFTPInterface(SFTPProxyServerInterface):

        def open(
            self, path: str, flags: int, attr: SFTPAttributes
        ) -> Union[SFTPHandle, int]:
            logging.info("open from check_file")
            try:
                self.session.sftp_client_ready.wait()
                if self.session.sftp_client is None:
                    msg = "self.session.sftp_client is None!"
                    raise MissingClient(msg)

                sftp_handler = self.session.proxyserver.sftp_handler
                sftp_file_handle = sftp_handler.get_file_handle()
                fobj = sftp_file_handle(
                    self, self.session, sftp_handler, path, flags, attr, use_buffer=True
                )

            except (OSError, IOError) as exc:
                logging.exception("Error")
                return paramiko.SFTPServer.convert_errno(exc.errno)
            except Exception:  # pylint: disable=broad-exception-caught
                logging.exception("Error")
                return paramiko.sftp.SFTP_FAILURE
            return fobj

    @classmethod
    def get_interface(cls) -> Optional[Type[BaseSFTPServerInterface]]:
        return cls.SFTPInterface

    def check_file(self) -> bool:
        """List the content of the buffered ZIP archive"""
        self.sftp.buffer.seek(0)
        try:
            with zipfile.ZipFile(self.sftp.buffer) as z:
                logging.info("ZIP archive contents for %s:", self.filename)
                for info in z.infolist():
                    logging.info("  %s - %d bytes", info.filename, info.file_size)
        except zipfile.BadZipFile:
            logging.error("File %s is not a valid ZIP archive", self.filename)
            return False
        return True

    def close(self) -> None:
        # Check the buffered file content before forwarding
        if not self.check_file():
            raise paramiko.SFTPError(paramiko.sftp.SFTP_FAILURE, "Invalid ZIP archive")

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
        self, data: bytes, *, offset: Optional[int] = None, length: Optional[int] = None
    ) -> bytes:
        del offset
        del length
        return data
