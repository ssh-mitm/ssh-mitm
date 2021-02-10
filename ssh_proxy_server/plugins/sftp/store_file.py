import logging
import os
import uuid

from ssh_proxy_server.forwarders.sftp import SFTPHandlerPlugin


class SFTPHandlerStoragePlugin(SFTPHandlerPlugin):
    """Stores transferred files to the file system
    """
    @classmethod
    def parser_arguments(cls):
        cls.parser().add_argument(
            '--sftp-storage',
            dest='sftp_storage_dir',
            required=True,
            help='directory to store files from scp'
        )

    def __init__(self, sftp, filename):
        super().__init__(sftp, filename)
        self.args.sftp_storage_dir = os.path.expanduser(self.args.sftp_storage_dir)

        self.file_id = str(uuid.uuid4())
        logging.info("sftp file transfer: %s -> %s", filename, self.file_id)
        self.output_path = os.path.join(self.args.sftp_storage_dir, self.file_id)
        self.out_file = open(self.output_path, 'wb')

    def close(self):
        self.out_file.close()

    def handle_data(self, data, *, offset=None, length=None):
        self.out_file.write(data)
        return data
