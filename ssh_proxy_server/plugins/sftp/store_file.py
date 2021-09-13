import logging
import os
import uuid

from ssh_proxy_server.forwarders.sftp import SFTPHandlerPlugin


class SFTPHandlerStoragePlugin(SFTPHandlerPlugin):
    """Stores transferred files to the file system
    """
    @classmethod
    def parser_arguments(cls):
        plugin_group = cls.parser().add_argument_group(cls.__name__)
        plugin_group.add_argument(
            '--store-sftp-files',
            dest='store_sftp_files',
            action='store_true',
            help='store files from sftp'
        )

    def __init__(self, sftp, filename):
        super().__init__(sftp, filename)
        self.file_id = str(uuid.uuid4())
        self.sftp_storage_dir = None
        self.output_path = None
        self.out_file = None

        if self.sftp.session.session_log_dir and self.args.store_sftp_files:
            self.sftp_storage_dir = os.path.join(self.sftp.session.session_log_dir, 'sftp')
            os.makedirs(self.sftp_storage_dir, exist_ok=True)

            self.output_path = os.path.join(self.sftp_storage_dir, self.file_id)
            self.out_file = open(self.output_path, 'wb')

        logging.info("sftp file transfer: %s -> %s", filename, self.file_id)

    def close(self):
        if self.args.store_sftp_files:
            self.out_file.close()

    def handle_data(self, data, *, offset=None, length=None):
        if self.args.store_sftp_files:
            self.out_file.write(data)
        return data
