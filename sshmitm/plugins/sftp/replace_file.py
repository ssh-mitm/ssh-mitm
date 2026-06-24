import logging
import os

from paramiko import SFTPAttributes

from sshmitm.exceptions import MissingClient
from sshmitm.forwarders.sftp import SFTPBaseHandle, SFTPHandlerPlugin
from sshmitm.interfaces.sftp import BaseSFTPServerInterface, SFTPProxyServerInterface


class SFTPProxyReplaceHandler(SFTPHandlerPlugin):
    """Replaces file content transparently during an SFTP transfer.

    For every SFTP file the client reads or writes, this plugin substitutes the
    specified replacement file instead of the real content.  The remote server
    receives the replacement on uploads; the client receives the replacement on
    downloads.  The ``stat`` / ``lstat`` response is also patched to reflect the
    size of the replacement file so the client does not notice a size mismatch.

    **Usage example**

    ::

        ssh-mitm server --sftp-handler replace_file --sftp-replace-file /path/to/replacement.bin

    **Notes**

    * The replacement file is opened once per file handle and closed when the
      handle is closed.
    * Both read and write operations are affected — every SFTP file access in
      the session serves or stores the replacement content.
    """

    class SFTPInterface(SFTPProxyServerInterface):
        def lstat(self, path: str) -> SFTPAttributes | int:
            self.session.sftp.client_ready.wait()
            args, _ = SFTPProxyReplaceHandler.parser().parse_known_args()
            if self.session.sftp.client is None:
                msg = "self.session.sftp.client is None!"
                raise MissingClient(msg)
            stat_remote = self.session.sftp.client.lstat(path)
            if isinstance(stat_remote, int):
                return stat_remote
            stat_replace = SFTPAttributes.from_stat(os.stat(args.sftp_replace_file))
            stat_remote.st_size = stat_replace.st_size
            return stat_remote

        def stat(self, path: str) -> SFTPAttributes | int:
            return self.lstat(path)

    @classmethod
    def get_interface(cls) -> type[BaseSFTPServerInterface] | None:
        return cls.SFTPInterface

    @classmethod
    def parser_arguments(cls) -> None:
        plugin_group = cls.argument_group()
        plugin_group.add_argument(
            "--sftp-replace-file",
            dest="sftp_replace_file",
            required=True,
            help="Specifies the path to the file that will be used for replacement during SFTP file transfers. This option is required.",
        )

    def __init__(self, sftp: SFTPBaseHandle, filename: str) -> None:
        """Resolves the replacement file path and opens it for reading.

        :param sftp: the SFTP file handle for the intercepted transfer.
        :param filename: the original filename as requested by the client.
        """
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
        self, data: bytes, *, offset: int | None = None, length: int | None = None
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
