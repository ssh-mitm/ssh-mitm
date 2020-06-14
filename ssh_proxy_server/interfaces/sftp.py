import logging
import paramiko


class SFTPProxyServerInterface(paramiko.SFTPServerInterface):

    def __init__(self, authenticationinterface):
        super().__init__(authenticationinterface)
        self.session = authenticationinterface.session

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
        logging.error('open not implemented')
        raise NotImplementedError('open not implemented!')

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
