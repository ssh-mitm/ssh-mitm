import io
import logging
import uuid
import zipfile
from typing import Optional, Type

from paramiko import SFTPAttributes, SFTPError
from paramiko.sftp import SFTP_FAILURE

from sshmitm.forwarders.sftp import SFTPBaseHandle, SFTPHandlerPlugin
from sshmitm.interfaces.sftp import SFTPProxyServerInterface


class SFTPHandlerCheckFilePlugin(SFTPHandlerPlugin):
    """Buffers transferred files in memory and forwards on close,
    checks ZIP content on close"""

    def __init__(self, sftp: SFTPBaseHandle, filename: str) -> None:
        super().__init__(sftp, filename)
        self.file_id: str = str(uuid.uuid4())
        self.buffer: io.BytesIO = io.BytesIO()
        self.filename: str = filename

        logging.info(
            "SFTP transfer started: %s -> memory buffer (%s)", filename, self.file_id
        )

    class SFTPInterface(SFTPProxyServerInterface):

        def open(self, path: str, flags: int, attr: SFTPAttributes) -> SFTPBaseHandle:
            logging.info("interface open")
            logging.error(flags)
            return super().open(path, flags, attr)

    @classmethod
    def get_interface(cls) -> Type[SFTPProxyServerInterface]:
        return cls.SFTPInterface

    def check_file(self) -> bool:
        """List the content of the buffered ZIP archive"""
        self.buffer.seek(0)
        try:
            with zipfile.ZipFile(self.buffer) as z:
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
            raise SFTPError(SFTP_FAILURE, "Invalid ZIP archive")

        self.buffer.seek(0)  # Go to beginning of buffer
        if self.sftp.writefile is not None:
            logging.info("Flushing buffered file (%s) to server", self.filename)
            chunk_size: int = 32768
            offset: int = 0
            while True:
                chunk: bytes = self.buffer.read(chunk_size)
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
        del offset
        del length
        self.buffer.write(data)
        return b""  # prevent direct forwarding to writefile
