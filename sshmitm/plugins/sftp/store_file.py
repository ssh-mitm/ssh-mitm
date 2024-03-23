import logging
import os
import uuid
from typing import BinaryIO, Optional

from sshmitm.forwarders.sftp import SFTPBaseHandle, SFTPHandlerPlugin


class SFTPHandlerStoragePlugin(SFTPHandlerPlugin):
    """Stores transferred files to the file system"""

    @classmethod
    def parser_arguments(cls) -> None:
        plugin_group = cls.argument_group()
        plugin_group.add_argument(
            "--store-sftp-files",
            dest="store_sftp_files",
            action="store_true",
            help="store files from sftp",
        )

    def __init__(self, sftp: SFTPBaseHandle, filename: str) -> None:
        super().__init__(sftp, filename)
        self.file_id = str(uuid.uuid4())
        self.sftp_storage_dir = None
        self.output_path = None
        self.out_file: Optional[BinaryIO] = None

        if self.sftp.session.session_log_dir and self.args.store_sftp_files:
            self.sftp_storage_dir = os.path.join(
                self.sftp.session.session_log_dir, "sftp"
            )
            os.makedirs(self.sftp_storage_dir, exist_ok=True)

            self.output_path = os.path.join(self.sftp_storage_dir, self.file_id)
            # open a file descriptor. this is closed when "close" is called on this plugin
            self.out_file = open(  # pylint: disable=consider-using-with # noqa: SIM115
                self.output_path, "wb"
            )

        logging.info("sftp file transfer: %s -> %s", filename, self.file_id)

    def close(self) -> None:
        if self.args.store_sftp_files and self.out_file is not None:
            self.out_file.close()

    def handle_data(
        self, data: bytes, *, offset: Optional[int] = None, length: Optional[int] = None
    ) -> bytes:
        del offset
        del length
        if self.args.store_sftp_files and self.out_file is not None:
            self.out_file.write(data)
        return data
