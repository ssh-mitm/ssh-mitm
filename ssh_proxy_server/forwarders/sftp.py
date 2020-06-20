import paramiko
from enhancements.modules import Module


class SFTPBaseHandle(paramiko.SFTPHandle, Module):
    pass


class SFTPForwardHandle(SFTPBaseHandle):
    def __init__(self, flags=0):
        super().__init__(flags)
        self.writefile = None
        self.readfile = None

    def read(self, offset, length):
        return self.readfile.read(length)

    def write(self, offset, data):
        self.writefile.write(data)
        return paramiko.SFTP_OK
