import logging
from typing import (
    TYPE_CHECKING,
    Optional,
    Text,
    Union, Type,
    cast
)

import paramiko
from enhancements.modules import BaseModule
from typeguard import typechecked

import sshmitm
from sshmitm.interfaces.sftp import BaseSFTPServerInterface

if TYPE_CHECKING:
    from sshmitm.session import Session


class SFTPHandlerBasePlugin(BaseModule):

    @typechecked
    def __init__(self, sftp: 'SFTPBaseHandle', filename: Text) -> None:
        super().__init__()
        self.filename: Text = filename
        self.sftp: 'SFTPBaseHandle' = sftp

    @classmethod
    @typechecked
    def get_interface(cls) -> Optional[Type[BaseSFTPServerInterface]]:
        return None

    @classmethod
    @typechecked
    def get_file_handle(cls) -> Type['SFTPBaseHandle']:
        return cast(Type[SFTPBaseHandle], SFTPBaseHandle)

    @typechecked
    def close(self) -> None:
        pass

    def handle_data(self, data: bytes, *, offset: Optional[int] = None, length: Optional[int] = None) -> bytes:
        return data


class SFTPHandlerPlugin(SFTPHandlerBasePlugin):
    """transfer files from/to remote sftp server
    """


class SFTPBaseHandle(paramiko.SFTPHandle):

    @typechecked
    def __init__(
        self,
        session: 'sshmitm.session.Session',
        plugin: Type[SFTPHandlerBasePlugin],
        filename: Text,
        flags: int = 0
    ) -> None:
        super().__init__(flags)
        self.session = session
        self.plugin = plugin(self, filename)
        self.writefile: Optional[paramiko.sftp_file.SFTPFile] = None
        self.readfile: Optional[paramiko.sftp_file.SFTPFile] = None

    @typechecked
    def close(self) -> None:
        super().close()
        self.plugin.close()

    @typechecked
    def read(self, offset: int, length: int) -> Union[bytes, int]:
        logging.debug("R_OFFSET: %s", offset)
        if self.readfile is None:
            return paramiko.sftp.SFTP_FAILURE
        data = self.readfile.read(length)
        return self.plugin.handle_data(data, length=length)

    @typechecked
    def write(self, offset: int, data: bytes) -> int:
        logging.debug("W_OFFSET: %s", offset)
        data = self.plugin.handle_data(data, offset=offset)
        if self.writefile is None:
            return paramiko.sftp.SFTP_FAILURE
        self.writefile.write(data)
        return paramiko.sftp.SFTP_OK
