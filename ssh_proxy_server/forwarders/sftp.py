import logging
import paramiko
from enhancements.modules import BaseModule


class SFTPHandlerBasePlugin(BaseModule):

    def __init__(self, sftp, filename):
        super().__init__()
        self.filename = filename
        self.sftp = sftp

    @classmethod
    def get_interface(cls):
        return None

    @classmethod
    def get_file_handle(cls):
        return None

    def close(self):
        pass

    def handle_data(self, data, *, offset=None, length=None):
        return data


class SFTPHandlerPlugin(SFTPHandlerBasePlugin):
    """transfer files from/to remote sftp server
    """


class SFTPBaseHandle(paramiko.SFTPHandle):

    def __init__(self, plugin, filename, flags=0):
        super().__init__(flags)
        self.plugin = plugin(self, filename)
        self.writefile = None
        self.readfile = None

    def close(self):
        super().close()
        self.plugin.close()

    def read(self, offset, length):
        logging.debug("R_OFFSET: %s", offset)
        data = self.readfile.read(length)
        return self.plugin.handle_data(data, length=length)

    def write(self, offset, data):
        logging.debug("W_OFFSET: %s", offset)
        data = self.plugin.handle_data(data, offset=offset)
        self.writefile.write(data)
        return paramiko.SFTP_OK
