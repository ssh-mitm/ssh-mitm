import logging
import os
from typing import Optional, Type, Union

from paramiko import SFTPAttributes

from sshmitm.exceptions import MissingClient
from sshmitm.forwarders.sftp import SFTPBaseHandle, SFTPHandlerPlugin
from sshmitm.interfaces.sftp import BaseSFTPServerInterface, SFTPProxyServerInterface


class SFTPProxyReplaceHandler(SFTPHandlerPlugin):
    """Replaces a SFTP transmitted File during transit"""

    class SFTPInterface(SFTPProxyServerInterface):
        def lstat(self, path: str) -> Union[SFTPAttributes, int]:
            self.session.sftp_client_ready.wait()
            args, _ = SFTPProxyReplaceHandler.parser().parse_known_args()
            if self.session.sftp_client is None:
                msg = "self.session.sftp_client is None!"
                raise MissingClient(msg)
            stat_remote = self.session.sftp_client.lstat(path)
            if isinstance(stat_remote, int):
                return stat_remote
            stat_replace = SFTPAttributes.from_stat(os.stat(args.sftp_replace_file))
            stat_remote.st_size = stat_replace.st_size
            return stat_remote

        def stat(self, path: str) -> Union[SFTPAttributes, int]:
            return self.lstat(path)

    @classmethod
    def get_interface(cls) -> Optional[Type[BaseSFTPServerInterface]]:
        return cls.SFTPInterface

    @classmethod
    def parser_arguments(cls) -> None:
        plugin_group = cls.argument_group()
        plugin_group.add_argument(
            "--sftp-replace-file",
            dest="sftp_replace_file",
            required=True,
            help="file that is used for replacement",
        )

    def __init__(self, sftp: SFTPBaseHandle, filename: str) -> None:
        super().__init__(sftp, filename)
        self.args.sftp_replace_file = os.path.expanduser(self.args.sftp_replace_file)

        logging.info(
            "intercepting sftp file '%s', replacement: %s",
            filename,
            self.args.sftp_replace_file,
        )
        # open a file descriptor. this is closed when "close" is called on this plugin
        self.replacement = open(  # pylint: disable=consider-using-with # noqa:SIM115
            self.args.sftp_replace_file, "rb"
        )
        self.file_uploaded = False
        self.data_handled = False

    def close(self) -> None:
        self.replacement.close()

    def handle_data(
        self, data: bytes, *, offset: Optional[int] = None, length: Optional[int] = None
    ) -> bytes:
        del data
        del offset
        self.data_handled = True
        if self.file_uploaded:
            return b""
        if self.sftp.writefile:
            self.file_uploaded = True
            return self.replacement.read()
        if length is not None:
            return self.replacement.read(length)
        return b""
