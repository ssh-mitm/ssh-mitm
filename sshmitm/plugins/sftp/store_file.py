import logging
import os
import uuid
from typing import BinaryIO

from sshmitm.forwarders.sftp import SFTPBaseHandle, SFTPHandlerPlugin


class SFTPHandlerStoragePlugin(SFTPHandlerPlugin):
    """Saves files transferred via SFTP to the local file system.

    For each intercepted SFTP file handle, data is written to
    ``<log-dir>/<session-id>/sftp/`` under a UUID-based filename.  The original
    transfer continues unmodified — storage is transparent to both client and server.

    **Usage example**

    ::

        ssh-mitm server --sftp-handler store_file --store-sftp-files --log-dir /tmp/sftp-logs

    **Notes**

    * ``--log-dir`` must be configured; without it no files are stored even if
      ``--store-sftp-files`` is set.
    * Each file is saved with a UUID filename.  The original filename is logged
      alongside the UUID so transfers can be correlated.
    """

    @classmethod
    def parser_arguments(cls) -> None:
        plugin_group = cls.argument_group()
        plugin_group.add_argument(
            "--store-sftp-files",
            dest="store_sftp_files",
            action="store_true",
            help="Enables the storage of files transferred via SFTP (SSH File Transfer Protocol).",
        )

    def __init__(self, sftp: SFTPBaseHandle, filename: str) -> None:
        """Creates the storage directory and opens the output file for writing.

        :param sftp: the SFTP file handle for the intercepted transfer.
        :param filename: the original filename as requested by the client.
        """
        super().__init__(sftp, filename)
        self.file_id = str(uuid.uuid4())
        self.sftp_storage_dir = None
        self.output_path = None
        self.out_file: BinaryIO | None = None

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
        self, data: bytes, *, offset: int | None = None, length: int | None = None
    ) -> bytes:
        del offset
        del length
        if self.args.store_sftp_files and self.out_file is not None:
            self.out_file.write(data)
        return data
