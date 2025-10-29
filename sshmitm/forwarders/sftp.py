import io
import logging
import os
from typing import TYPE_CHECKING, Optional, Type, Union, cast

import paramiko
from paramiko.sftp_attr import SFTPAttributes

from sshmitm.interfaces.sftp import BaseSFTPServerInterface
from sshmitm.moduleparser import BaseModule

if TYPE_CHECKING:
    from _typeshed import ReadableBuffer

    import sshmitm


class SFTPHandlerBasePlugin(BaseModule):
    def __init__(self, sftp: "SFTPBaseHandle", filename: str) -> None:
        super().__init__()
        self.filename: str = filename
        self.sftp: "SFTPBaseHandle" = sftp

    @classmethod
    def get_interface(cls) -> Optional[Type[BaseSFTPServerInterface]]:
        return None

    @classmethod
    def get_file_handle(cls) -> Type["SFTPBaseHandle"]:
        return cast("Type[SFTPBaseHandle]", SFTPBaseHandle)

    def close(self) -> None:
        pass

    def handle_data(
        self, data: bytes, *, offset: Optional[int] = None, length: Optional[int] = None
    ) -> bytes:
        del offset, length  # unused arguments
        return data


class SFTPHandlerPlugin(SFTPHandlerBasePlugin):
    """transfer files from/to remote sftp server"""


class SFTPBaseHandle(paramiko.SFTPHandle):
    def __init__(  # pylint: disable=too-many-arguments
        self,
        server_interface: BaseSFTPServerInterface,
        session: "sshmitm.core.session.Session",
        plugin: Type[SFTPHandlerBasePlugin],
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
        self.plugin = plugin(self, filename)
        self.open_flags = open_flags
        self.open_attr = open_attr

        self.use_buffer = use_buffer
        self.buffer = io.BytesIO()
        self.writefile: Optional[paramiko.sftp_file.SFTPFile] = (
            self.buffer if use_buffer else None
        )
        self.readfile: Optional[paramiko.sftp_file.SFTPFile] = (
            self.buffer if use_buffer else None
        )
        self.remote_file = None

    def open_remote_file(self) -> Optional[int]:
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

        if self.session.sftp_client is None:
            logging.error("%s - no sftp client", self.session)
            return paramiko.sftp.SFTP_FAILURE
        self.remote_file = self.session.sftp_client.open(self.filename, fstr)

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

    def read(self, offset: int, length: int) -> Union[bytes, int]:
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
