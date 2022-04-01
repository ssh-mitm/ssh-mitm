import logging
import paramiko
import os
from typing import (
    cast,
    Text,
    List,
    Union
)

from enhancements.modules import BaseModule
from paramiko.sftp_attr import SFTPAttributes
from paramiko.sftp_handle import SFTPHandle
from typeguard import typechecked

from sshmitm.exceptions import MissingClient
from sshmitm.interfaces.server import BaseServerInterface


class BaseSFTPServerInterface(paramiko.SFTPServerInterface, BaseModule):

    @typechecked
    def __init__(self, serverinterface: BaseServerInterface) -> None:
        super().__init__(serverinterface)
        self.session = serverinterface.session


class SFTPProxyServerInterface(BaseSFTPServerInterface):
    """sftp subsystem implementation for SSH-MITM
    """

    @typechecked
    def chattr(self, path: Text, attr: SFTPAttributes) -> int:
        self.session.sftp_client_ready.wait()
        if self.session.sftp_client is None:
            raise MissingClient("self.session.sftp_client is None!")
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

    @typechecked
    def list_folder(self, path: Text) -> Union[List[SFTPAttributes], int]:
        self.session.sftp_client_ready.wait()
        if self.session.sftp_client is None:
            raise MissingClient("self.session.sftp_client is None!")
        return self.session.sftp_client.listdir_attr(path)

    @typechecked
    def lstat(self, path: Text) -> Union[SFTPAttributes, int]:
        self.session.sftp_client_ready.wait()
        if self.session.sftp_client is None:
            raise MissingClient("self.session.sftp_client is None!")
        return self.session.sftp_client.lstat(path)

    @typechecked
    def mkdir(self, path: Text, attr: SFTPAttributes) -> int:
        self.session.sftp_client_ready.wait()
        if self.session.sftp_client is None:
            raise MissingClient("self.session.sftp_client is None!")
        if attr.st_mode is None:
            return paramiko.sftp.SFTP_FAILURE
        return self.session.sftp_client.mkdir(path, attr.st_mode)

    @typechecked
    def open(self, path: Text, flags: int, attr: SFTPAttributes) -> Union[SFTPHandle, int]:
        try:
            self.session.sftp_client_ready.wait()
            if self.session.sftp_client is None:
                raise MissingClient("self.session.sftp_client is None!")

            # Code aus dem StubSFTPServer der Paramiko Demo auf GitHub
            if (flags & os.O_CREAT) and attr:
                attr._flags &= ~attr.FLAG_PERMISSIONS  # type: ignore
            if flags & os.O_WRONLY:
                if flags & os.O_APPEND:
                    fstr = 'ab'
                else:
                    fstr = 'wb'
            elif flags & os.O_RDWR:
                if flags & os.O_APPEND:
                    fstr = 'a+b'
                else:
                    fstr = 'r+b'
            else:
                # O_RDONLY (== 0)
                fstr = 'rb'

            try:
                if self.session.sftp_client is None:
                    return paramiko.sftp.SFTP_FAILURE
                client_f = self.session.sftp_client.open(path, fstr)
            except Exception:
                logging.exception("Error file")
                return paramiko.sftp.SFTP_FAILURE

            sftp_handler = self.session.proxyserver.sftp_handler
            sftp_file_handle = sftp_handler.get_file_handle()
            fobj = sftp_file_handle(self.session, sftp_handler, path)

            # writeonly
            if fstr in ('wb', 'ab'):
                fobj.writefile = client_f
            # readonly
            elif fstr == 'rb':
                fobj.readfile = client_f
            # read and write
            elif fstr in ('a+b', 'r+b'):
                fobj.writefile = client_f
                fobj.readfile = client_f
            if fobj.writefile:
                self.chattr(path, attr)
            return fobj
        except (OSError, IOError) as e:
            logging.exception("Error")
            return paramiko.SFTPServer.convert_errno(e.errno)
        except Exception:
            logging.exception("Error")
            return paramiko.sftp.SFTP_FAILURE

    @typechecked
    def readlink(self, path: Text) -> Union[Text, int]:
        self.session.sftp_client_ready.wait()
        if self.session.sftp_client is None:
            raise MissingClient("self.session.sftp_client is None!")
        return self.session.sftp_client.readlink(path)

    @typechecked
    def remove(self, path: Text) -> int:
        self.session.sftp_client_ready.wait()
        if self.session.sftp_client is None:
            raise MissingClient("self.session.sftp_client is None!")
        return self.session.sftp_client.remove(path)

    @typechecked
    def rename(self, oldpath: Text, newpath: Text) -> int:
        self.session.sftp_client_ready.wait()
        if self.session.sftp_client is None:
            raise MissingClient("self.session.sftp_client is None!")
        return self.session.sftp_client.rename(oldpath, newpath)

    @typechecked
    def rmdir(self, path: Text) -> int:
        self.session.sftp_client_ready.wait()
        if self.session.sftp_client is None:
            raise MissingClient("self.session.sftp_client is None!")
        return self.session.sftp_client.rmdir(path)

    @typechecked
    def stat(self, path: Text) -> Union[SFTPAttributes, int]:
        self.session.sftp_client_ready.wait()
        if self.session.sftp_client is None:
            raise MissingClient("self.session.sftp_client is None!")
        return self.session.sftp_client.stat(path)

    @typechecked
    def symlink(self, targetPath: Text, path: Text) -> int:
        self.session.sftp_client_ready.wait()
        if self.session.sftp_client is None:
            raise MissingClient("self.session.sftp_client is None!")
        return self.session.sftp_client.symlink(targetPath, path)
