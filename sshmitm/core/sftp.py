from typing import TYPE_CHECKING

from sshmitm.core.modules import SSHMITMBaseModule
from sshmitm.forwarders.sftp import SFTPBaseHandle
from sshmitm.interfaces.sftp import BaseSFTPServerInterface

if TYPE_CHECKING:
    import sshmitm


class SFTPHandlerBasePlugin(SSHMITMBaseModule):
    """Specifies the handler for SFTP operations, responsible for processing file transfer requests and managing file system interactions."""

    def __init__(self, sftp: "SFTPBaseHandle", filename: str) -> None:
        super().__init__()
        self.filename: str = filename
        self.sftp: SFTPBaseHandle = sftp

    @property
    def session(self) -> "sshmitm.session.Session":
        return self.sftp.session

    @classmethod
    def get_interface(cls) -> type[BaseSFTPServerInterface] | None:
        return None

    @classmethod
    def get_file_handle(cls) -> "type[SFTPBaseHandle]":
        return SFTPBaseHandle

    def close(self) -> None:
        pass

    def handle_data(
        self, data: bytes, *, offset: int | None = None, length: int | None = None
    ) -> bytes:
        del offset, length
        return data


class SFTPHandlerPlugin(SFTPHandlerBasePlugin):
    """Transparent SFTP plugin — forwards all data unchanged.

    This is the base class for all SFTP plugins. Inherit from this class
    to implement custom SFTP behaviour; override only the methods you need.
    """
