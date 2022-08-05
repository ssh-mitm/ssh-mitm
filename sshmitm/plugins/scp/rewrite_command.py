from typing import Text
from sshmitm.forwarders.scp import SCPForwarder


class SCPRewriteCommand(SCPForwarder):
    """replace the file with another file
    """

    @classmethod
    def parser_arguments(cls) -> None:
        plugin_group = cls.parser().add_argument_group(
            cls.__name__,
            "Rewrite SCP Commands (can also used for rsync and git)"
        )
        plugin_group.add_argument(
            '--scp-append-string',
            dest='scp_append_string',
            help='append a string to the existing command'
        )
        plugin_group.add_argument(
            '--scp-replace-string',
            dest='scp_replace_string',
            help='replace the command with another command'
        )

    def rewrite_scp_command(self, command: Text) -> Text:
        if self.args.scp_append_string:
            return command + self.args.scp_append_string
        if self.args.scp_replace_string:
            return self.args.scp_replace_string
        return command