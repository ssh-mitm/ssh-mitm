import logging
import os
import uuid

from ssh_proxy_server.forwarders.scp import SCPForwarder


class SCPStorageForwarder(SCPForwarder):
    """Stores transferred files to the file system
    """
    @classmethod
    def parser_arguments(cls):
        plugin_group = cls.parser().add_argument_group(cls.__name__)
        plugin_group.add_argument(
            '--store-scp-files',
            dest='store_scp_files',
            action='store_true',
            help='store files from scp'
        )

    def __init__(self, session):
        super().__init__(session)
        self.file_id = None
        self.scp_storage_dir = None
        if self.session.session_log_dir:
            self.scp_storage_dir = os.path.join(self.session.session_log_dir, 'scp')



    def process_data(self, traffic):
        if not self.args.store_scp_files or not self.scp_storage_dir:
            return traffic
        os.makedirs(self.scp_storage_dir, exist_ok=True)
        if not self.file_id:
            self.file_id = str(uuid.uuid4())
        output_path = os.path.join(self.scp_storage_dir, self.file_id)

        # notwendig, da im letzten Datenpaket ein NULL-Byte angehängt wird
        self.bytes_to_write = min(len(traffic), self.bytes_remaining)
        self.bytes_remaining -= self.bytes_to_write
        with open(output_path, 'a+b') as tmp_file:
            tmp_file.write(traffic[:self.bytes_to_write])

        # Dateiende erreicht
        if self.file_name and self.bytes_remaining == 0:
            logging.info("file %s -> %s", self.file_name, self.file_id)
            self.file_id = None
        return traffic
