import logging
import paramiko
import os


class StubSFTPHandle(paramiko.SFTPHandle):
    def __init__(self, flags=0):
        super().__init__(flags)
        self.writefile = None
        self.readfile = None
        self.filename = None

    def stat(self):
        f = self.writefile if self.writefile else self.readfile
        try:
            return paramiko.SFTPAttributes.from_stat(os.fstat(f.fileno()))
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)

    def chattr(self, attr):
        try:
            paramiko.SFTPServer.set_file_attr(self.filename, attr)
            return paramiko.SFTP_OK
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)


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
        if not os.path.exists(self.ROOT):
            os.mkdir(self.ROOT)

        localPath = os.path.join(
            self.ROOT,
            ''.join([
                self.session.getUniquePrefix(),
                os.path.basename(remotePath)
            ])
        )
        self.session.clientReady.wait()

        # Code aus dem StubSFTPServer der Paramiko Demo auf Github
        if (flags & os.O_CREAT) and attr:
            attr._flags &= ~attr.FLAG_PERMISSIONS
            paramiko.SFTPServer.set_file_attr(localPath, attr)
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

        # alle Werte von 'fstr' außer 'wb' haben Leserechte auf die Datei
        # dh. wir müssen die Datei downloaden
        if fstr != 'wb':
            try:
                self.session.sftpClient.get(remotePath, localPath)
            except (IOError, OSError) as ex:
                logging.error('SFTP get failed!')
                logging.error(ex)
                return paramiko.SFTPServer.convert_errno(ex.errno)

        try:
            binaryFlag = getattr(os, 'O_BINARY', 0)
            flags |= binaryFlag
            mode = getattr(attr, 'st_mode', None)

            if mode:
                fd = os.open(localPath, flags, mode)
            else:
                # os.open() defaults to 0777 which is
                # an odd default mode for files
                fd = os.open(localPath, flags, 0o666)
        except OSError as ex:
            logging.error(ex)
            if not self.session.proxyserver.config.getboolean("SFTP", "keep_files"):
                os.remove(localPath)
            return paramiko.SFTPServer.convert_errno(ex.errno)

        try:
            f = os.fdopen(fd, fstr)
            fobj = StubSFTPHandle(flags)
            fobj.remotePath = remotePath

            fobj.filename = localPath

            # die Standardimplementation des SFTPHandles verwendet 'writefile'
            # und 'readfile' um zu lesen bzw. zu schreiben.
            # Wir verwenden diese Klassenmember, um zwischen readonly,
            # writeonly und read and write Dateien zu unterscheiden

            # writeonly
            if fstr in ('wb', 'ab'):
                fobj.writefile = f
            # readonly
            elif fstr == 'rb':
                fobj.readfile = f
            # read and write
            elif fstr in ('a+b', 'r+b'):
                fobj.writefile = f
                fobj.readfile = f
            return fobj
        except OSError as e:
            logging.error(e)
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
