import logging
import os
from typing import List, Union, cast

import paramiko
from paramiko.sftp_attr import SFTPAttributes
from paramiko.sftp_handle import SFTPHandle

from sshmitm.exceptions import MissingClient
from sshmitm.interfaces.server import BaseServerInterface
from sshmitm.moduleparser import BaseModule


class BaseSFTPServerInterface(paramiko.SFTPServerInterface, BaseModule):
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
        oldattr = paramiko.SFTPAttributes.from_stat(cast(os.stat_result, remotestat))
        if not attr.st_uid:
            attr.st_uid = oldattr.st_uid
        if not attr.st_gid:
            attr.st_gid = oldattr.st_gid
        if attr.st_uid is None or attr.st_gid is None:
            return paramiko.sftp.SFTP_FAILURE
        return self.session.sftp_client.chown(path, attr.st_uid, attr.st_gid)

    def list_folder(self, path: str) -> Union[List[SFTPAttributes], int]:
        self.session.sftp_client_ready.wait()
        if self.session.sftp_client is None:
            msg = "self.session.sftp_client is None!"
            raise MissingClient(msg)
        return self.session.sftp_client.listdir_attr(path)

    def lstat(self, path: str) -> Union[SFTPAttributes, int]:
        self.session.sftp_client_ready.wait()
        if self.session.sftp_client is None:
            msg = "self.session.sftp_client is None!"
            raise MissingClient(msg)
        return self.session.sftp_client.lstat(path)

    def mkdir(self, path: str, attr: SFTPAttributes) -> int:
        self.session.sftp_client_ready.wait()
        if self.session.sftp_client is None:
            msg = "self.session.sftp_client is None!"
            raise MissingClient(msg)
        if attr.st_mode is None:
            return self.session.sftp_client.mkdir(path)
        return self.session.sftp_client.mkdir(path, attr.st_mode)

    def open(  # noqa: C901
        self, path: str, flags: int, attr: SFTPAttributes
    ) -> Union[SFTPHandle, int]:
        try:
            self.session.sftp_client_ready.wait()
            if self.session.sftp_client is None:
                msg = "self.session.sftp_client is None!"
                raise MissingClient(msg)

            # Code aus dem StubSFTPServer der Paramiko Demo auf GitHub
            if (flags & os.O_CREAT) and attr:
                attr._flags &= ~attr.FLAG_PERMISSIONS  # type: ignore[attr-defined]
            if flags & os.O_WRONLY:
                fstr = "ab" if flags & os.O_APPEND else "wb"
            elif flags & os.O_RDWR:
                fstr = "a+b" if flags & os.O_APPEND else "r+b"
            else:
                # O_RDONLY (== 0)
                fstr = "rb"

            try:
                if self.session.sftp_client is None:
                    return paramiko.sftp.SFTP_FAILURE
                client_f = self.session.sftp_client.open(path, fstr)
            except Exception:  # pylint: disable=broad-exception-caught
                logging.exception("Error file")
                return paramiko.sftp.SFTP_FAILURE

            sftp_handler = self.session.proxyserver.sftp_handler
            sftp_file_handle = sftp_handler.get_file_handle()
            fobj = sftp_file_handle(self.session, sftp_handler, path)

            # writeonly
            if fstr in ("wb", "ab"):
                fobj.writefile = client_f
            # readonly
            elif fstr == "rb":
                fobj.readfile = client_f
            # read and write
            elif fstr in ("a+b", "r+b"):
                fobj.writefile = client_f
                fobj.readfile = client_f
            if fobj.writefile:
                self.chattr(path, attr)
        except (OSError, IOError) as exc:
            logging.exception("Error")
            return paramiko.SFTPServer.convert_errno(exc.errno)
        except Exception:  # pylint: disable=broad-exception-caught
            logging.exception("Error")
            return paramiko.sftp.SFTP_FAILURE
        return fobj

    def readlink(self, path: str) -> Union[str, int]:
        self.session.sftp_client_ready.wait()
        if self.session.sftp_client is None:
            msg = "self.session.sftp_client is None!"
            raise MissingClient(msg)
        return self.session.sftp_client.readlink(path)

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

    def stat(self, path: str) -> Union[SFTPAttributes, int]:
        self.session.sftp_client_ready.wait()
        if self.session.sftp_client is None:
            msg = "self.session.sftp_client is None!"
            raise MissingClient(msg)
        return self.session.sftp_client.stat(path)

    def symlink(self, target_path: str, path: str) -> int:
        self.session.sftp_client_ready.wait()
        if self.session.sftp_client is None:
            msg = "self.session.sftp_client is None!"
            raise MissingClient(msg)
        return self.session.sftp_client.symlink(target_path, path)
