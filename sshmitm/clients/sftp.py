import logging
import os
from typing import (
    Callable,
    List,
    Any,
    Optional,
    Tuple,
    Union
)

import paramiko
from paramiko.pkey import PKey
from paramiko.sftp_attr import SFTPAttributes
from paramiko.sftp_file import SFTPFile

import sshmitm
from sshmitm.clients.ssh import AuthenticationMethod, SSHClient


class SFTPClient(SSHClient):

    def __init__(
        self,
        host: str,
        port: int,
        method: AuthenticationMethod,
        password: Optional[str],
        user: str,
        key: Optional[PKey],
        session: 'sshmitm.session.Session'
    ) -> None:
        super().__init__(host, port, method, password, user, key, session)
        self._sftp: Optional[paramiko.SFTPClient] = None
        self.subsystem_count = 0

    @classmethod
    def from_client(cls, ssh_client: Optional[SSHClient]) -> Optional['SFTPClient']:
        if ssh_client is None:
            logging.error('error creating sftp client - no ssh client!')
            return None
        if not ssh_client.connected and ssh_client.connect():
            logging.error('error creating sftp client!')
            return None

        try:
            sftp = cls(
                ssh_client.host,
                ssh_client.port,
                ssh_client.method,
                ssh_client.password,
                ssh_client.user,
                ssh_client.key,
                ssh_client.session
            )
            if ssh_client.transport is None:
                logging.debug("ssh_client does not have a transport")
                return None
            sftp._sftp = paramiko.SFTPClient.from_transport(ssh_client.transport)
            sftp.connected = True
            return sftp
        except Exception:
            logging.exception('error creating sftp client')
            return None

    @property
    def running(self) -> bool:
        return self.subsystem_count > 0

    def connect(self) -> bool:
        ret = super().connect()
        if not ret:
            return False
        if self._sftp is None:
            return False
        try:
            if self.transport is None:
                return False
            self._sftp = paramiko.SFTPClient.from_transport(self.transport)
            return True
        except Exception:
            logging.exception('error creating sftp client')
        return False

    def open(self, filename: Union[str, bytes], mode: str = 'r', bufsize: int = -1) -> SFTPFile:
        if self._sftp is None:
            raise paramiko.SFTPError("Expected handle")
        return self._sftp.open(filename, mode, bufsize)

    def chmod(self, path: Union[str, bytes], mode: int) -> int:
        if self._sftp is None:
            return paramiko.sftp.SFTP_FAILURE
        self._sftp.chmod(path, mode)
        return paramiko.sftp.SFTP_OK

    def chown(self, path: Union[str, bytes], uid: int, gid: int) -> int:
        if self._sftp is None:
            return paramiko.sftp.SFTP_FAILURE
        self._sftp.chown(path, uid, gid)
        return paramiko.sftp.SFTP_OK

    def get(
        self, remotePath: Union[str, bytes], localPath: Union[str, bytes],
        callback: Optional[Callable[[int, int], Any]] = None
    ) -> int:
        if self._sftp is None:
            return paramiko.sftp.SFTP_FAILURE
        try:
            self._sftp.get(remotePath, localPath, callback)
            return paramiko.sftp.SFTP_OK
        except (IOError, OSError) as ex:
            logging.error(ex)
            os.remove(localPath)
        return paramiko.sftp.SFTP_FAILURE

    def listdir_attr(self, path: str = '.') -> Union[int, List[SFTPAttributes]]:
        if self._sftp is None:
            return paramiko.sftp.SFTP_FAILURE
        return self._sftp.listdir_attr(path)

    def lstat(self, path: Union[str, bytes]) -> Union[int, SFTPAttributes]:
        if self._sftp is None:
            return paramiko.sftp.SFTP_FAILURE
        return self._sftp.lstat(path)

    def mkdir(self, path: Union[str, bytes], mode: int = 511) -> int:
        if self._sftp is None:
            return paramiko.sftp.SFTP_FAILURE
        self._sftp.mkdir(path, mode)
        return paramiko.sftp.SFTP_OK

    def put(
        self, localPath: Union[str, bytes], remotePath: Union[str, bytes], callback: Any = None, confirm: bool = True
    ) -> None:
        raise NotImplementedError('put not implemented')

    def readlink(self, path: Union[str, bytes]) -> Union[int, str]:
        if self._sftp is None:
            return paramiko.sftp.SFTP_FAILURE
        return self._sftp.readlink(path) or paramiko.sftp.SFTP_FAILURE

    def remove(self, path: Union[str, bytes]) -> int:
        if self._sftp is None:
            return paramiko.sftp.SFTP_FAILURE
        self._sftp.remove(path)
        return paramiko.sftp.SFTP_OK

    def rename(self, oldpath: Union[str, bytes], newpath: Union[str, bytes]) -> int:
        if self._sftp is None:
            return paramiko.sftp.SFTP_FAILURE
        self._sftp.rename(oldpath, newpath)
        return paramiko.sftp.SFTP_OK

    def rmdir(self, path: Union[str, bytes]) -> int:
        if self._sftp is None:
            return paramiko.sftp.SFTP_FAILURE
        self._sftp.rmdir(path)
        return paramiko.sftp.SFTP_OK

    def stat(self, path: Union[str, bytes]) -> Union[int, SFTPAttributes]:
        if self._sftp is None:
            return paramiko.sftp.SFTP_FAILURE
        return self._sftp.stat(path)

    def utime(self, path: Union[str, bytes], times: Tuple[float, float]) -> int:
        if self._sftp is None:
            return paramiko.sftp.SFTP_FAILURE
        self._sftp.utime(path, times)
        return paramiko.sftp.SFTP_OK

    def symlink(self, source: Union[str, bytes], dest: Union[str, bytes]) -> int:
        if self._sftp is None:
            return paramiko.sftp.SFTP_FAILURE
        self._sftp.symlink(source, dest)
        return paramiko.sftp.SFTP_OK

    def close(self) -> int:
        if self._sftp is None:
            return paramiko.sftp.SFTP_FAILURE
        if not self.running:
            self._sftp.close()
            if self.session.sftp_channel is not None:
                self.session.sftp_channel.close()
        return paramiko.sftp.SFTP_OK
