import logging
import paramiko
import os

from enhancements.modules import BaseModule

from ssh_proxy_server.forwarders.sftp import SFTPBaseHandle


class BaseSFTPServerInterface(paramiko.SFTPServerInterface, BaseModule):

    def __init__(self, authenticationinterface):
        super().__init__(authenticationinterface)
        self.session = authenticationinterface.session


class SFTPProxyServerInterface(BaseSFTPServerInterface):
    """sftp subsystem implementation for SSH-MITM
    """

    def chattr(self, path, attr):
        self.session.sftp_client_ready.wait()
        if attr.st_mode:
            return self.session.sftp_client.chmod(path, attr.st_mode)
        oldattr = paramiko.SFTPAttributes.from_stat(self.stat(path))
        if not attr.st_uid:
            attr.st_uid = oldattr.st_uid
        if not attr.st_gid:
            attr.st_gid = oldattr.st_gid
        return self.session.sftp_client.chown(path, attr.st_uid, attr.st_gid)

    def list_folder(self, path):
        self.session.sftp_client_ready.wait()
        return self.session.sftp_client.listdir_attr(path)

    def lstat(self, path):
        self.session.sftp_client_ready.wait()
        return self.session.sftp_client.lstat(path)

    def mkdir(self, path, attr):
        self.session.sftp_client_ready.wait()
        return self.session.sftp_client.mkdir(path, attr.st_mode)

    def open(self, remotePath, flags, attr):
        try:
            self.session.sftp_client_ready.wait()

            # Code aus dem StubSFTPServer der Paramiko Demo auf GitHub
            if (flags & os.O_CREAT) and attr:
                attr._flags &= ~attr.FLAG_PERMISSIONS
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
                client_f = self.session.sftp_client._sftp.open(remotePath, fstr)
            except Exception:
                logging.exception("Error file")
                return None

            sftp_handler = self.session.proxyserver.sftp_handler
            sftp_file_handle = sftp_handler.get_file_handle() or SFTPBaseHandle
            fobj = sftp_file_handle(sftp_handler, remotePath)

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
                self.chattr(remotePath, attr)
            return fobj
        except Exception as e:
            logging.exception("Error")
            return paramiko.SFTPServer.convert_errno(e.errno)

    def readlink(self, path):
        self.session.sftp_client_ready.wait()
        return self.session.sftp_client.readlink(path)

    def remove(self, remotePath):
        self.session.sftp_client_ready.wait()
        return self.session.sftp_client.remove(remotePath)

    def rename(self, oldpath, newpath):
        self.session.sftp_client_ready.wait()
        return self.session.sftp_client.rename(oldpath, newpath)

    def rmdir(self, path):
        self.session.sftp_client_ready.wait()
        return self.session.sftp_client.rmdir(path)

    def stat(self, remotePath):
        self.session.sftp_client_ready.wait()
        return self.session.sftp_client.stat(remotePath)

    def symlink(self, targetPath, path):
        self.session.sftp_client_ready.wait()
        return self.session.sftp_client.symlink(targetPath, path)
