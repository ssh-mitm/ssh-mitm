import io
import logging
import os
from typing import TYPE_CHECKING

import paramiko
from paramiko.sftp_attr import SFTPAttributes

from sshmitm.interfaces.sftp import BaseSFTPServerInterface

if TYPE_CHECKING:
    from _typeshed import ReadableBuffer

    import sshmitm
    from sshmitm.core.sftp import SFTPHandlerBasePlugin


class SFTPBaseHandle(paramiko.SFTPHandle):
    def __init__(  # pylint: disable=too-many-arguments
        self,
        server_interface: BaseSFTPServerInterface,
        session: "sshmitm.session.Session",
        plugin: "type[SFTPHandlerBasePlugin]",
        filename: str,
        open_flags: int,
        open_attr: SFTPAttributes,
        flags: int = 0,
        *,
        use_buffer: bool = False,
    ) -> None:
        super().__init__(flags)
        self.server_interface = server_interface
        self.session = session
        self.session.register_session_thread()
        self.filename = filename
        self.plugin: SFTPHandlerBasePlugin = plugin(self, filename)
        self.open_flags = open_flags
        self.open_attr = open_attr

        self.use_buffer = use_buffer
        self.buffer = io.BytesIO()
        self.writefile: paramiko.sftp_file.SFTPFile | io.BytesIO | None = (
            self.buffer if use_buffer else None
        )
        self.readfile: paramiko.sftp_file.SFTPFile | io.BytesIO | None = (
            self.buffer if use_buffer else None
        )
        self.remote_file: paramiko.sftp_file.SFTPFile | None = None

    def open_remote_file(self) -> int | None:
        # Code aus dem StubSFTPServer der Paramiko Demo auf GitHub
        if (self.open_flags & os.O_CREAT) and self.open_attr:
            self.open_attr._flags &= ~self.open_attr.FLAG_PERMISSIONS  # type: ignore[attr-defined]
        if self.open_flags & os.O_WRONLY:
            fstr = "ab" if self.open_flags & os.O_APPEND else "wb"
        elif self.open_flags & os.O_RDWR:
            fstr = "a+b" if self.open_flags & os.O_APPEND else "r+b"
        else:
            # O_RDONLY (== 0)
            fstr = "rb"

        if self.session.sftp.client is None:
            logging.error("%s - no sftp client", self.session)
            return paramiko.sftp.SFTP_FAILURE
        self.remote_file = self.session.sftp.client.open(self.filename, fstr)

        # writeonly
        if fstr in ("wb", "ab"):
            self.writefile = self.remote_file
        # readonly
        elif fstr == "rb":
            self.readfile = self.remote_file
        # read and write
        elif fstr in ("a+b", "r+b"):
            self.writefile = self.remote_file
            self.readfile = self.remote_file
        if self.writefile:
            self.server_interface.chattr(self.filename, self.open_attr)
        return None

    def close(self) -> None:
        self.plugin.close()
        super().close()

    def read(self, offset: int, length: int) -> bytes | int:
        logging.debug("R_OFFSET: %s", offset)
        if self.readfile is None:
            return paramiko.sftp.SFTP_FAILURE
        data = self.readfile.read(length)
        return self.plugin.handle_data(data, length=length)

    def write(self, offset: int, data: "ReadableBuffer") -> int:
        logging.debug("W_OFFSET: %s", offset)
        if not isinstance(data, bytes):
            logging.error("SFTPBaseHandle.write got invalid argument!")
            return paramiko.sftp.SFTP_FAILURE
        data = self.plugin.handle_data(data, offset=offset)
        if self.writefile is None:
            return paramiko.sftp.SFTP_FAILURE
        if data:
            self.writefile.write(data)
        return paramiko.sftp.SFTP_OK
