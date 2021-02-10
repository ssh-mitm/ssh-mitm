import logging
import os
import uuid

from ssh_proxy_server.forwarders.scp import SCPForwarder


class SCPStorageForwarder(SCPForwarder):
    """Stores transferred files to the file system
    """
    @classmethod
    def parser_arguments(cls):
        cls.parser().add_argument(
            '--scp-storage',
            dest='scp_storage_dir',
            required=True,
            help='directory to store files from scp'
        )

    def __init__(self, session):
        super().__init__(session)
        self.args.scp_storage_dir = os.path.expanduser(self.args.scp_storage_dir)

        self.file_id = None
        self.tmp_file = None

    def process_data(self, traffic):
        os.makedirs(self.args.scp_storage_dir, exist_ok=True)
        if not self.file_id:
            self.file_id = str(uuid.uuid4())
        output_path = os.path.join(self.args.scp_storage_dir, self.file_id)

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
