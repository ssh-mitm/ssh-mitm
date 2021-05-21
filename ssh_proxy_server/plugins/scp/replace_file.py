import os
from ssh_proxy_server.forwarders.scp import SCPForwarder


class SCPReplaceFile(SCPForwarder):
    """replace the file with another file
    """

    @classmethod
    def parser_arguments(cls):
        cls.parser().add_argument(
            '--scp-replace',
            dest='scp_replacement_file',
            required=True,
            help='file that is used for replacement'
        )

    def __init__(self, session) -> None:
        super().__init__(session)
        self.args.scp_replacement_file = os.path.expanduser(self.args.scp_replacement_file)

        self.data_sent = False
        self.file_stat = os.stat(self.args.scp_replacement_file)
        self.file_to_send = open(self.args.scp_replacement_file, 'rb')

    def handle_command(self, traffic, isclient):
        traffic = super().handle_command(traffic, isclient)
        if not self.got_c_command:
            return traffic

        self.bytes_remaining = self.file_size = self.file_stat.st_size
        traffic = "{}{} {} {}\n".format(
            self.file_command,
            self.file_mode,
            self.file_size,
            self.file_name
        )
        return traffic.encode("UTF-8")

    def process_data(self, traffic):
        if not self.data_sent:
            self.data_sent = True
            data = self.file_to_send.read()
            data += b"\x00"
            return data
        self.file_to_send.close()
        return b"\x00"
