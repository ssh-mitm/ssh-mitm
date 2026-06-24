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
    """Rewrites the SCP command before it is sent to the remote server.

    Intercepts the exec command that the SCP client sends and either appends a
    string to it or replaces it entirely.  Because SCP, rsync, and git all tunnel
    over the SSH exec channel, this plugin can manipulate any of those commands.

    **Usage example**

    Append a string to the existing command::

        ssh-mitm server --scp-forwarder replace-command --scp-append-string " --dry-run"

    Replace the command entirely::

        ssh-mitm server --scp-forwarder replace-command --scp-replace-string "echo hijacked"

    **Notes**

    * If both ``--scp-append-string`` and ``--scp-replace-string`` are set,
      append takes precedence.
    * The rewritten command is logged at INFO level.
    """

    @classmethod
    def parser_arguments(cls) -> None:
        plugin_group = cls.argument_group()
        plugin_group.add_argument(
            "--scp-append-string",
            dest="scp_append_string",
            help="Specifies a string that will be appended to the existing SCP command during execution.",
        )
        plugin_group.add_argument(
            "--scp-replace-string",
            dest="scp_replace_string",
            help="Specifies a string that will replace the original SCP command during execution.",
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
