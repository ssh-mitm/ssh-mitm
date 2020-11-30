import math
import uuid
import os
import logging
import paramiko
from enhancements.modules import Module
from paramiko import SFTPFile


class SFTPHandlerBasePlugin(Module):

    def __init__(self, sftp, filename):
        super().__init__()
        self.filename = filename
        self.sftp = sftp

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
        data = self.readfile.read(length)
        return self.plugin.handle_data(data)

    def write(self, offset, data):
        data = self.plugin.handle_data(data)
        self.writefile.write(data)
        return paramiko.SFTP_OK


class SFTPHandlerReplacePlugin(SFTPHandlerPlugin):
    """
    Replaces a SFTP transmitted File during transit
    """
    @classmethod
    def parser_arguments(cls):
        cls.PARSER.add_argument(
            '--sftp-replace',
            dest='sftp_replacement_file',
            required=True,
            help='file that is used for replacement'
        )

    def __init__(self, sftp, filename):
        super().__init__(sftp, filename)
        logging.info("sftp file transfer detected: %s", filename)
        logging.info("intercepting sftp file, replacement: %s", self.args.sftp_replacement_file)
        self.file = None
        self.replacement = open(self.args.sftp_replacement_file, "rb")
        self.buf_size = None

    def close(self):
        self.replacement.close()

    def handle_data(self, data):
        # Cannot reasonably detect given buffer size, using best guess: biggest power of 2
        # PUT cannot replace file correctly if the to-be PUT file is smaller than the to-be REPLACED file
        # --> closes file before everything can be transmitted
        if not self.buf_size and not self.file:
            self.file = self.sftp.writefile if self.sftp.readfile is None else self.sftp.readfile
            if len(data) == 0:
                self.buf_size = 1
            elif len(data) == self.file.stat().st_size:
                self.buf_size = pow(2, int(math.log(len(data)) // math.log(2)))
            else:
                self.buf_size = len(data)
        return self.replacement.read(self.buf_size)
