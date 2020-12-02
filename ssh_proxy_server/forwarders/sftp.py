import uuid
import os
import logging
import paramiko
from enhancements.modules import Module


class SFTPHandlerBasePlugin(Module):

    def __init__(self, sftp, filename):
        super().__init__()
        self.filename = filename
        self.sftp = sftp

    @classmethod
    def get_interface(cls):
        return None

    def close(self):
        pass

    def handle_data(self, data):
        return data


class SFTPHandlerPlugin(SFTPHandlerBasePlugin):
    pass


class SFTPHandlerStoragePlugin(SFTPHandlerPlugin):
    @classmethod
    def parser_arguments(cls):
        cls.PARSER.add_argument(
            '--sftp-storage',
            dest='sftp_storage_dir',
            required=True,
            help='directory to store files from scp'
        )

    def __init__(self, sftp, filename):
        super().__init__(sftp, filename)
        self.file_id = str(uuid.uuid4())
        logging.info("sftp file transfer: %s -> %s", filename, self.file_id)
        self.output_path = os.path.join(self.args.sftp_storage_dir, self.file_id)
        self.out_file = open(self.output_path, 'wb')

    def close(self):
        self.out_file.close()

    def handle_data(self, data):
        self.out_file.write(data)
        return data


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
        logging.info("R_OFFSET: " + str(offset))
        data = self.readfile.read(length)
        return self.plugin.handle_data(data, length)

    def write(self, offset, data):
        logging.info("W_OFFSET: " + str(offset))
        data = self.plugin.handle_data(data)
        self.writefile.write(data)
        return paramiko.SFTP_OK
