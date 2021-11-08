import logging
from typing import (
    TYPE_CHECKING,
    Optional,
    Union, Type
)

import paramiko
from enhancements.modules import BaseModule
from typeguard import typechecked

import ssh_proxy_server
from ssh_proxy_server.interfaces.sftp import BaseSFTPServerInterface

if TYPE_CHECKING:
    from ssh_proxy_server.session import Session


class SFTPHandlerBasePlugin(BaseModule):

    @typechecked
    def __init__(self, sftp, filename) -> None:
        super().__init__()
        self.filename = filename
        self.sftp = sftp

    @classmethod
    @typechecked
    def get_interface(cls) -> Optional[Type[BaseSFTPServerInterface]]:
        return None

    @classmethod
    @typechecked
    def get_file_handle(cls) -> Type['SFTPBaseHandle']:
        return SFTPBaseHandle

    @typechecked
    def close(self) -> None:
        pass

    def handle_data(self, data, *, offset=None, length=None):
        return data


class SFTPHandlerPlugin(SFTPHandlerBasePlugin):
    """transfer files from/to remote sftp server
    """


class SFTPBaseHandle(paramiko.SFTPHandle):

    @typechecked
    def __init__(
        self, session: 'ssh_proxy_server.session.Session', plugin, filename, flags: int = 0
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
    def read(self, offset, length) -> Union[bytes, int]:
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
