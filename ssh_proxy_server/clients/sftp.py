import logging
import os

import paramiko

from ssh_proxy_server.clients.ssh import SSHClient


class SFTPClient(SSHClient):

    def __init__(self, host, port, method, password, user, key, session):
        super().__init__(host, port, method, password, user, key, session)
        self._sftp = None
        self.subsystem_count = 0

    @classmethod
    def from_client(cls, ssh_client):
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
        try:
            self._sftp = paramiko.SFTPClient.from_transport(self.transport)
            return True
        except Exception:
            logging.exception('error creating sftp client')
            return False

    def chmod(self, path, mode):
        self._sftp.chmod(path, mode)
        return paramiko.SFTP_OK

    def chown(self, path, uid, gid):
        self._sftp.chown(path, uid, gid)
        return paramiko.SFTP_OK

    def get(self, remotePath, localPath, callback=None):
        try:
            self._sftp.get(remotePath, localPath, callback)
            return paramiko.SFTP_OK
        except (IOError, OSError) as ex:
            logging.error(ex)
            os.remove(localPath)
            return paramiko.SFTP_FAILURE

    def listdir_attr(self, path='.'):
        return self._sftp.listdir_attr(path)

    def lstat(self, path):
        return self._sftp.lstat(path)

    def mkdir(self, path, mode=511):
        self._sftp.mkdir(path, mode)
        return paramiko.SFTP_OK

    def put(self, localPath, remotePath, callback=None, confirm=True):
        raise NotImplementedError('put not implemented')

    def readlink(self, path):
        return self._sftp.readlink(path)

    def remove(self, path):
        self._sftp.remove(path)
        return paramiko.SFTP_OK

    def rename(self, oldpath, newpath):
        self._sftp.rename(oldpath, newpath)
        return paramiko.SFTP_OK

    def rmdir(self, path):
        self._sftp.rmdir(path)
        return paramiko.SFTP_OK

    def stat(self, path):
        return self._sftp.stat(path)

    def utime(self, path, times):
        return self._sftp.utime(path, times)

    def symlink(self, source, dest):
        self._sftp.symlink(source, dest)
        return paramiko.SFTP_OK

    def close(self):
        if not self.running:
            self._sftp.close()
            self.session.sftp_channel.close()
        return paramiko.SFTP_OK
