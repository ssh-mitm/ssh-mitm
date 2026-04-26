import logging
from typing import TYPE_CHECKING, cast

import paramiko
from paramiko.sftp import SFTP_NO_SUCH_FILE
from paramiko.sftp_attr import SFTPAttributes
from paramiko.sftp_handle import SFTPHandle

from sshmitm.core.modules import SSHMITMBaseModule
from sshmitm.exceptions import MissingClient
from sshmitm.interfaces.server import BaseServerInterface

if TYPE_CHECKING:
    import os


class BaseSFTPServerInterface(paramiko.SFTPServerInterface, SSHMITMBaseModule):
    """Sets the base interface for SFTP (SSH File Transfer Protocol) operations, such as file listing, uploads, and downloads."""

    def __init__(self, serverinterface: BaseServerInterface) -> None:
        super().__init__(serverinterface)
        self.session = serverinterface.session


class SFTPProxyServerInterface(BaseSFTPServerInterface):
    """sftp subsystem implementation for SSH-MITM"""

    def chattr(self, path: str, attr: SFTPAttributes) -> int:
        self.session.sftp_client_ready.wait()
        if self.session.sftp_client is None:
            msg = "self.session.sftp_client is None!"
            raise MissingClient(msg)
        if attr.st_mode:
            return self.session.sftp_client.chmod(path, attr.st_mode)
        remotestat = self.stat(path)
        if isinstance(remotestat, int):
            return remotestat
        oldattr = paramiko.SFTPAttributes.from_stat(cast("os.stat_result", remotestat))
        if not attr.st_uid:
            attr.st_uid = oldattr.st_uid
        if not attr.st_gid:
            attr.st_gid = oldattr.st_gid
        if attr.st_uid is None or attr.st_gid is None:
            return paramiko.sftp.SFTP_FAILURE
        return self.session.sftp_client.chown(path, attr.st_uid, attr.st_gid)

    def list_folder(self, path: str) -> list[SFTPAttributes] | int:
        self.session.sftp_client_ready.wait()
        if self.session.sftp_client is None:
            msg = "self.session.sftp_client is None!"
            raise MissingClient(msg)
        return cast("list[SFTPAttributes]", self.session.sftp_client.listdir_attr(path))

    def lstat(self, path: str) -> SFTPAttributes | int:
        self.session.sftp_client_ready.wait()
        if self.session.sftp_client is None:
            msg = "self.session.sftp_client is None!"
            raise MissingClient(msg)
        try:
            return cast("SFTPAttributes", self.session.sftp_client.lstat(path))
        except FileNotFoundError:
            logging.debug("File %s not found", path)
            return SFTP_NO_SUCH_FILE

    def mkdir(self, path: str, attr: SFTPAttributes) -> int:
        self.session.sftp_client_ready.wait()
        if self.session.sftp_client is None:
            msg = "self.session.sftp_client is None!"
            raise MissingClient(msg)
        if attr.st_mode is None:
            return self.session.sftp_client.mkdir(path)
        return self.session.sftp_client.mkdir(path, attr.st_mode)

    def open(self, path: str, flags: int, attr: SFTPAttributes) -> SFTPHandle | int:
        try:
            self.session.sftp_client_ready.wait()
            if self.session.sftp_client is None:
                msg = "self.session.sftp_client is None!"
                raise MissingClient(msg)

            sftp_handler = self.session.proxyserver.sftp_handler
            sftp_file_handle = sftp_handler.get_file_handle()
            fobj = sftp_file_handle(self, self.session, sftp_handler, path, flags, attr)
            fobj.open_remote_file()

        except OSError as exc:
            logging.exception("Error")
            return paramiko.SFTPServer.convert_errno(exc.errno or 0)
        except Exception:  # pylint: disable=broad-exception-caught
            logging.exception("Error")
            return paramiko.sftp.SFTP_FAILURE
        return fobj

    def readlink(self, path: str) -> str | int:
        self.session.sftp_client_ready.wait()
        if self.session.sftp_client is None:
            msg = "self.session.sftp_client is None!"
            raise MissingClient(msg)
        return cast("str", self.session.sftp_client.readlink(path))

    def remove(self, path: str) -> int:
        self.session.sftp_client_ready.wait()
        if self.session.sftp_client is None:
            msg = "self.session.sftp_client is None!"
            raise MissingClient(msg)
        return self.session.sftp_client.remove(path)

    def rename(self, oldpath: str, newpath: str) -> int:
        self.session.sftp_client_ready.wait()
        if self.session.sftp_client is None:
            msg = "self.session.sftp_client is None!"
            raise MissingClient(msg)
        return self.session.sftp_client.rename(oldpath, newpath)

    def rmdir(self, path: str) -> int:
        self.session.sftp_client_ready.wait()
        if self.session.sftp_client is None:
            msg = "self.session.sftp_client is None!"
            raise MissingClient(msg)
        return self.session.sftp_client.rmdir(path)

    def stat(self, path: str) -> SFTPAttributes | int:
        self.session.sftp_client_ready.wait()
        if self.session.sftp_client is None:
            msg = "self.session.sftp_client is None!"
            raise MissingClient(msg)
        try:
            return cast("SFTPAttributes", self.session.sftp_client.stat(path))
        except FileNotFoundError:
            logging.debug("File %s not found", path)
            return SFTP_NO_SUCH_FILE

    def symlink(self, target_path: str, path: str) -> int:
        self.session.sftp_client_ready.wait()
        if self.session.sftp_client is None:
            msg = "self.session.sftp_client is None!"
            raise MissingClient(msg)
        return self.session.sftp_client.symlink(target_path, path)
