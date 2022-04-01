import logging
import os
from typing import (
    TYPE_CHECKING,
    Callable,
    List,
    Any,
    Optional,
    Tuple,
    Union,
    Text
)

import paramiko
from paramiko.pkey import PKey
from paramiko.sftp_attr import SFTPAttributes
from paramiko.sftp_file import SFTPFile
from typeguard import typechecked

import sshmitm
from sshmitm.clients.ssh import AuthenticationMethod, SSHClient
if TYPE_CHECKING:
    from sshmitm.session import Session


class SFTPClient(SSHClient):

    @typechecked
    def __init__(
        self,
        host: Text,
        port: int,
        method: AuthenticationMethod,
        password: Optional[Text],
        user: Text,
        key: Optional[PKey],
        session: 'sshmitm.session.Session'
    ) -> None:
        super().__init__(host, port, method, password, user, key, session)
        self._sftp: Optional[paramiko.SFTPClient] = None
        self.subsystem_count = 0

    @classmethod
    @typechecked
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

    @typechecked
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

    @typechecked
    def open(self, filename: Union[Text, bytes], mode: Text = 'r', bufsize: int = -1) -> SFTPFile:
        if self._sftp is None:
            raise paramiko.SFTPError("Expected handle")
        return self._sftp.open(filename, mode, bufsize)

    @typechecked
    def chmod(self, path: Union[Text, bytes], mode: int) -> int:
        if self._sftp is None:
            return paramiko.sftp.SFTP_FAILURE
        self._sftp.chmod(path, mode)
        return paramiko.sftp.SFTP_OK

    @typechecked
    def chown(self, path: Union[Text, bytes], uid: int, gid: int) -> int:
        if self._sftp is None:
            return paramiko.sftp.SFTP_FAILURE
        self._sftp.chown(path, uid, gid)
        return paramiko.sftp.SFTP_OK

    @typechecked
    def get(self, remotePath: Union[Text, bytes], localPath: Union[Text, bytes], callback: Optional[Callable[[int, int], Any]] = None) -> int:
        if self._sftp is None:
            return paramiko.sftp.SFTP_FAILURE
        try:
            self._sftp.get(remotePath, localPath, callback)
            return paramiko.sftp.SFTP_OK
        except (IOError, OSError) as ex:
            logging.error(ex)
            os.remove(localPath)
        return paramiko.sftp.SFTP_FAILURE

    @typechecked
    def listdir_attr(self, path: Text = '.') -> Union[int, List[SFTPAttributes]]:
        if self._sftp is None:
            return paramiko.sftp.SFTP_FAILURE
        return self._sftp.listdir_attr(path)

    @typechecked
    def lstat(self, path: Union[Text, bytes]) -> Union[int, SFTPAttributes]:
        if self._sftp is None:
            return paramiko.sftp.SFTP_FAILURE
        return self._sftp.lstat(path)

    @typechecked
    def mkdir(self, path: Union[Text, bytes], mode: int = 511) -> int:
        if self._sftp is None:
            return paramiko.sftp.SFTP_FAILURE
        self._sftp.mkdir(path, mode)
        return paramiko.sftp.SFTP_OK

    @typechecked
    def put(self, localPath: Union[Text, bytes], remotePath: Union[Text, bytes], callback: Any = None, confirm: bool = True) -> None:
        raise NotImplementedError('put not implemented')

    @typechecked
    def readlink(self, path: Union[Text, bytes]) -> Union[int, Text]:
        if self._sftp is None:
            return paramiko.sftp.SFTP_FAILURE
        return self._sftp.readlink(path) or paramiko.sftp.SFTP_FAILURE

    @typechecked
    def remove(self, path: Union[Text, bytes]) -> int:
        if self._sftp is None:
            return paramiko.sftp.SFTP_FAILURE
        self._sftp.remove(path)
        return paramiko.sftp.SFTP_OK

    @typechecked
    def rename(self, oldpath: Union[Text, bytes], newpath: Union[Text, bytes]) -> int:
        if self._sftp is None:
            return paramiko.sftp.SFTP_FAILURE
        self._sftp.rename(oldpath, newpath)
        return paramiko.sftp.SFTP_OK

    @typechecked
    def rmdir(self, path: Union[Text, bytes]) -> int:
        if self._sftp is None:
            return paramiko.sftp.SFTP_FAILURE
        self._sftp.rmdir(path)
        return paramiko.sftp.SFTP_OK

    @typechecked
    def stat(self, path: Union[Text, bytes]) -> Union[int, SFTPAttributes]:
        if self._sftp is None:
            return paramiko.sftp.SFTP_FAILURE
        return self._sftp.stat(path)

    @typechecked
    def utime(self, path: Union[Text, bytes], times: Tuple[float, float]) -> int:
        if self._sftp is None:
            return paramiko.sftp.SFTP_FAILURE
        self._sftp.utime(path, times)
        return paramiko.sftp.SFTP_OK

    @typechecked
    def symlink(self, source: Union[Text, bytes], dest: Union[Text, bytes]) -> int:
        if self._sftp is None:
            return paramiko.sftp.SFTP_FAILURE
        self._sftp.symlink(source, dest)
        return paramiko.sftp.SFTP_OK

    @typechecked
    def close(self) -> int:
        if self._sftp is None:
            return paramiko.sftp.SFTP_FAILURE
        if not self.running:
            self._sftp.close()
            if self.session.sftp_channel is not None:
                self.session.sftp_channel.close()
        return paramiko.sftp.SFTP_OK
