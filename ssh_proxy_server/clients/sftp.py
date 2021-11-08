import logging
import os
from typing import (
    Optional
)

import paramiko

from ssh_proxy_server.clients.ssh import SSHClient


class SFTPClient(SSHClient):

    def __init__(self, host, port, method, password, user, key, session):
        super().__init__(host, port, method, password, user, key, session)
        self._sftp: Optional[paramiko.SFTPClient] = None
        self.subsystem_count = 0

    @classmethod
    def from_client(cls, ssh_client: Optional[SSHClient]):
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
    def running(self):
        return self.subsystem_count > 0

    def connect(self):
        ret = super().connect()
        if not ret:
            return False
        if self._sftp is None:
            return paramiko.sftp.SFTP_FAILURE
        try:
            self._sftp = paramiko.SFTPClient.from_transport(self.transport)
            return True
        except Exception:
            logging.exception('error creating sftp client')
        return False

    def chmod(self, path, mode):
        if self._sftp is None:
            return paramiko.sftp.SFTP_FAILURE
        self._sftp.chmod(path, mode)
        return paramiko.sftp.SFTP_OK

    def chown(self, path, uid, gid):
        if self._sftp is None:
            return paramiko.sftp.SFTP_FAILURE
        self._sftp.chown(path, uid, gid)
        return paramiko.sftp.SFTP_OK

    def get(self, remotePath, localPath, callback=None):
        if self._sftp is None:
            return paramiko.sftp.SFTP_FAILURE
        try:
            self._sftp.get(remotePath, localPath, callback)
            return paramiko.sftp.SFTP_OK
        except (IOError, OSError) as ex:
            logging.error(ex)
            os.remove(localPath)
            return paramiko.sftp.SFTP_FAILURE

    def listdir_attr(self, path='.'):
        if self._sftp is None:
            return paramiko.sftp.SFTP_FAILURE
        return self._sftp.listdir_attr(path)

    def lstat(self, path):
        if self._sftp is None:
            return paramiko.sftp.SFTP_FAILURE
        return self._sftp.lstat(path)

    def mkdir(self, path, mode=511):
        if self._sftp is None:
            return paramiko.sftp.SFTP_FAILURE
        self._sftp.mkdir(path, mode)
        return paramiko.sftp.SFTP_OK

    def put(self, localPath, remotePath, callback=None, confirm=True):
        raise NotImplementedError('put not implemented')

    def readlink(self, path):
        if self._sftp is None:
            return paramiko.sftp.SFTP_FAILURE
        return self._sftp.readlink(path)

    def remove(self, path):
        if self._sftp is None:
            return paramiko.sftp.SFTP_FAILURE
        self._sftp.remove(path)
        return paramiko.sftp.SFTP_OK

    def rename(self, oldpath, newpath):
        if self._sftp is None:
            return paramiko.sftp.SFTP_FAILURE
        self._sftp.rename(oldpath, newpath)
        return paramiko.sftp.SFTP_OK

    def rmdir(self, path):
        if self._sftp is None:
            return paramiko.sftp.SFTP_FAILURE
        self._sftp.rmdir(path)
        return paramiko.sftp.SFTP_OK

    def stat(self, path):
        if self._sftp is None:
            return paramiko.sftp.SFTP_FAILURE
        return self._sftp.stat(path)

    def utime(self, path, times):
        if self._sftp is None:
            return paramiko.sftp.SFTP_FAILURE
        return self._sftp.utime(path, times)

    def symlink(self, source, dest):
        if self._sftp is None:
            return paramiko.sftp.SFTP_FAILURE
        self._sftp.symlink(source, dest)
        return paramiko.sftp.SFTP_OK

    def close(self):
        if self._sftp is None:
            return paramiko.sftp.SFTP_FAILURE
        if not self.running:
            self._sftp.close()
            self.session.sftp_channel.close()
        return paramiko.sftp.SFTP_OK
