"""
SCPRewriteCommand - A plugin for ssh-mitm that rewrites SCP commands.

This plugin is used to modify SCP commands, either by appending a string to
the existing command or replacing the command with a different string.
It can also be used to modify rsync and git commands.
The new command is specified using the `--scp-append-string` and `--scp-replace-string`
options, respectively.

"""
import logging
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

    def rewrite_scp_command(self, command: str) -> str:
        if self.args.scp_append_string:
            new_command = f"{command}{self.args.scp_append_string}"
            logging.info("scp command added string: %s", new_command)
            return new_command
        if self.args.scp_replace_string:
            logging.info("scp command replaced: %s", self.args.scp_replace_string)
            return f"{self.args.scp_replace_string}"
        return command
