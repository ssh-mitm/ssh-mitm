import os
from typing import (
    TYPE_CHECKING
)

from typeguard import typechecked

import sshmitm
from sshmitm.forwarders.scp import SCPForwarder
if TYPE_CHECKING:
    from sshmitm.session import Session


class SCPReplaceFile(SCPForwarder):
    """replace the file with another file
    """

    @classmethod
    @typechecked
    def parser_arguments(cls) -> None:
        plugin_group = cls.parser().add_argument_group(cls.__name__)
        plugin_group.add_argument(
            '--scp-replace',
            dest='scp_replacement_file',
            required=True,
            help='file that is used for replacement'
        )

    @typechecked
    def __init__(self, session: 'sshmitm.session.Session') -> None:
        super().__init__(session)
        self.args.scp_replacement_file = os.path.expanduser(self.args.scp_replacement_file)

        self.data_sent = False
        self.file_stat = os.stat(self.args.scp_replacement_file)
        self.file_to_send = open(self.args.scp_replacement_file, 'rb')

    @typechecked
    def handle_command(self, traffic: bytes) -> bytes:
        traffic = super().handle_command(traffic)
        if not self.got_c_command:
            return traffic

        self.bytes_remaining = self.file_size = self.file_stat.st_size
        traffic_string = f"{self.file_command}{self.file_mode} {self.file_size} {self.file_name}\n"
        return traffic_string.encode("UTF-8")

    @typechecked
    def process_data(self, traffic: bytes) -> bytes:
        if not self.data_sent:
            self.data_sent = True
            data = self.file_to_send.read()
            data += b"\x00"
            return data
        self.file_to_send.close()
        return b"\x00"
