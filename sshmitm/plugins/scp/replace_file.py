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
handle_command(data: bytes) -> bytes: Handles the incoming SCP command and returns the modified SCP command.
process_data(data: bytes) -> bytes: Processes the SCP data and returns the modified SCP data
(i.e.the replacement file).
"""

import os
from typing import TYPE_CHECKING

from sshmitm.forwarders.scp import SCPForwarder

if TYPE_CHECKING:
    import sshmitm


class SCPReplaceFile(SCPForwarder):
    """Replaces the transferred file with a different file during an SCP upload.

    When an SCP client uploads a file to the server, this plugin intercepts the
    transfer and substitutes the specified replacement file, so the server receives
    the replacement instead of the original content.

    **Usage example**

    ::

        ssh-mitm server --scp-forwarder replace_file --scp-replace-file /path/to/replacement.bin

    **Notes**

    * Only affects upload operations.  Download transfers pass through unchanged.
    * File size and permissions are taken from the replacement file, not the
      original, so the client may observe a size mismatch if it checks.
    """

    @classmethod
    def parser_arguments(cls) -> None:
        plugin_group = cls.argument_group()
        plugin_group.add_argument(
            "--scp-replace-file",
            dest="scp_replace_file",
            required=True,
            help="Specifies the path to the file that will be used for replacement during SCP file transfers. This option is required.",
        )

    def __init__(self, session: "sshmitm.session.Session") -> None:
        """Resolves the replacement file path and opens it for reading.

        :param session: the active SSH session being intercepted.
        """
        super().__init__(session)
        self.args.scp_replace_file = os.path.expanduser(self.args.scp_replace_file)

        self.data_sent = False
        self.file_stat = os.stat(self.args.scp_replace_file)

        # open a file descriptor. this is closed when file transmission is complete.
        # this is checked in another method
        self.file_to_send = open(  # pylint: disable=consider-using-with # noqa: SIM115
            self.args.scp_replace_file, "rb"
        )

    def handle_command(self, data: bytes) -> bytes:
        data = super().handle_command(data)
        if not self.got_c_command:
            return data

        self.bytes_remaining = self.file_size = self.file_stat.st_size
        traffic_string = (
            f"{self.file_command}{self.file_mode} {self.file_size} {self.file_name}\n"
        )
        return traffic_string.encode("UTF-8")

    def process_data(self, data: bytes) -> bytes:
        del data
        if not self.data_sent:
            self.data_sent = True
            data = self.file_to_send.read()
            data += b"\x00"
            return data
        self.file_to_send.close()
        return b"\x00"
