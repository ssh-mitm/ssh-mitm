"""SCPStorageForwarder: store transferred files from SCP

SCPStorageForwarder is a class that is derived from SCPForwarder.
This class provides a capability to store the transferred files from SCP (secure copy) to the file system.

Attributes:
file_id (str): A unique identifier for each file, generated using uuid.
scp_storage_dir (str): A path to the directory where files are stored.

Methods:
parser_arguments: This method adds a command line argument '--store-scp-files' for storing SCP files to the file system.
init: This method initializes the SCPStorageForwarder class. It creates a scp_storage_dir if it doesn't exist.
process_data: This method stores the data transmitted during SCP file transfer to the file system. The files are stored in the scp_storage_dir directory.

"""

import logging
import os
import uuid
from typing import (
    Optional
)
import sshmitm
from sshmitm.forwarders.scp import SCPForwarder


class SCPStorageForwarder(SCPForwarder):
    """Stores transferred files to the file system
    """
    @classmethod
    def parser_arguments(cls) -> None:
        plugin_group = cls.parser().add_argument_group(cls.__name__)
        plugin_group.add_argument(
            '--store-scp-files',
            dest='store_scp_files',
            action='store_true',
            help='store files from scp'
        )

    def __init__(self, session: 'sshmitm.session.Session') -> None:
        super().__init__(session)
        self.file_id: Optional[str] = None
        self.scp_storage_dir = None
        if self.session.session_log_dir:
            self.scp_storage_dir = os.path.join(self.session.session_log_dir, 'scp')

    def process_data(self, traffic: bytes) -> bytes:
        if not self.args.store_scp_files or not self.scp_storage_dir:
            return traffic
        os.makedirs(self.scp_storage_dir, exist_ok=True)
        if self.file_id is None:
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
