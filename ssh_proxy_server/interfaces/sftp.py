import paramiko


class SFTPProxyServerInterface(paramiko.SFTPServerInterface):

    def __init__(self, authenticationinterface):
        super().__init__(authenticationinterface)
        self.session = authenticationinterface.session

    def chattr(self, path, attr):
        raise NotImplementedError('chattr not implemented')

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
