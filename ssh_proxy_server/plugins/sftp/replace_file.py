import logging
import os

from paramiko import SFTPAttributes

from ssh_proxy_server.forwarders.sftp import SFTPHandlerPlugin, SFTPBaseHandle
from ssh_proxy_server.interfaces.sftp import SFTPProxyServerInterface


class SFTPProxyReplaceHandler(SFTPHandlerPlugin):
    """Replaces a SFTP transmitted File during transit
    """

    class SFTPInterface(SFTPProxyServerInterface):

        def lstat(self, path):
            self.session.sftp_client_ready.wait()
            args, _ = SFTPProxyReplaceHandler.parser().parse_known_args()
            stat_remote = self.session.sftp_client.lstat(path)
            stat_replace = SFTPAttributes.from_stat(os.stat(args.sftp_replacement_file))
            stat_remote.st_size = stat_replace.st_size
            return stat_remote

        def stat(self, remotePath):
            return self.lstat(remotePath)

    class SFTPHandle(SFTPBaseHandle):

        def close(self):
            if not self.plugin.data_handled:
                args, _ = SFTPProxyReplaceHandler.parser().parse_known_args()
                with open(args.sftp_replacement_file, "rb") as r:
                    self.writefile.write(r.read())
            super().close()

    @classmethod
    def get_interface(cls):
        return cls.SFTPInterface

    @classmethod
    def parser_arguments(cls):
        cls.parser().add_argument(
            '--sftp-replace',
            dest='sftp_replacement_file',
            required=True,
            help='file that is used for replacement'
        )

    def __init__(self, sftp, filename):
        super().__init__(sftp, filename)
        self.args.sftp_replacement_file = os.path.expanduser(self.args.sftp_replacement_file)

        logging.info("intercepting sftp file '%s', replacement: %s", filename, self.args.sftp_replacement_file)
        self.replacement = open(self.args.sftp_replacement_file, "rb")
        self.file_uploaded = False
        self.data_handled = False

    def close(self):
        self.replacement.close()

    def handle_data(self, data, *, offset=None, length=None):
        self.data_handled = True
        if self.file_uploaded:
            return b''
        if self.sftp.writefile:
            self.file_uploaded = True
            return self.replacement.read()
        return self.replacement.read(length)
