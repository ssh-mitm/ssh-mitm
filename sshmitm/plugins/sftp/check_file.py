import logging
import io
import uuid
from typing import Optional
from paramiko import SFTPAttributes
from sshmitm.forwarders.sftp import SFTPBaseHandle, SFTPHandlerPlugin
from sshmitm.interfaces.sftp import BaseSFTPServerInterface, SFTPProxyServerInterface


import io
import logging
import uuid
import zipfile
from typing import Optional


class SFTPHandlerCheckFilePlugin(SFTPHandlerPlugin):
    """Buffers transferred files in memory and forwards on close, 
    checks ZIP content on close"""

    def __init__(self, sftp: SFTPBaseHandle, filename: str) -> None:
        super().__init__(sftp, filename)
        self.file_id = str(uuid.uuid4())
        self.buffer = io.BytesIO()
        self.filename = filename

        logging.info("SFTP transfer started: %s -> memory buffer (%s)", filename, self.file_id)

    class SFTPInterface(SFTPProxyServerInterface):

        def open(  # noqa: C901
            self, path: str, flags: int, attr: SFTPAttributes
        ):
            logging.info("interface open")
            logging.error(flags)
            return super().open(path, flags, attr)


    @classmethod
    def get_interface(cls):
        return cls.SFTPInterface


    def check_file(self) -> bool:
        """List the content of the buffered ZIP archive"""
        self.buffer.seek(0)
        try:
            with zipfile.ZipFile(self.buffer) as z:
                logging.info("ZIP archive contents for %s:", self.filename)
                for info in z.infolist():
                    logging.info("  %s - %d bytes", info.filename, info.file_size)
            return True
        except zipfile.BadZipFile:
            logging.error("File %s is not a valid ZIP archive", self.filename)
        return False

    def close(self) -> None:
        # Check the buffered file content before forwarding
        if not self.check_file():
            raise paramiko.SFTPError(paramiko.sftp.SFTP_FAILURE, "Invalid ZIP archive")

        self.buffer.seek(0)  # Go to beginning of buffer
        if self.sftp.writefile is not None:
            logging.info("Flushing buffered file (%s) to server", self.filename)
            chunk_size = 32768
            offset = 0
            while True:
                chunk = self.buffer.read(chunk_size)
                if not chunk:
                    break
                self.sftp.writefile.write(chunk)
                offset += len(chunk)
            self.sftp.writefile.flush()
        else:
            logging.warning("writefile handle is None; data not forwarded!")
        self.buffer.close()
        super().close()

    def handle_data(
        self, data: bytes, *, offset: Optional[int] = None, length: Optional[int] = None
    ) -> bytes:
        self.buffer.write(data)
        return b""  # prevent direct forwarding to writefile
