import argparse
import sys
from pathlib import Path
from paramiko.pkey import PublicBlob
from rich import print as rich_print
from sshpubkeys import SSHKey  # type: ignore[import-untyped]
from sshmitm.moduleparser import SubCommand
from sshmitm.authentication import PublicKeyEnumerator


class Check_Publickey(SubCommand):  # pylint: disable=invalid-name
    """checks a username and publickey against a server"""

    HAS_CONFIG = False

    def register_arguments(self) -> None:
        self.parser.add_argument(
            "--host", type=str, required=True, help="Hostname or IP address"
        )
        self.parser.add_argument(
            "--port", type=int, default=22, help="port (default: 22)"
        )
        self.parser.add_argument(
            "--username", type=str, required=True, help="username to check"
        )
        self.parser.add_argument(
            "--public-keys",
            action="store",
            nargs="+",
            type=str,
            required=True,
            help="publickeys to check",
        )

    @staticmethod
    def print_valid_keys(valid_keys):
        if not valid_keys:
            rich_print("[bold red]:cross_mark: No valid keys found[/bold red]")
            return
        rich_print("[bold green]:heavy_check_mark: Valid keys found[/bold green]")
        for key in valid_keys:
            ssh_key = SSHKey(key, strict=True)
            print(
                ssh_key.key_type.decode(),
                ssh_key.bits,
                ssh_key.hash_sha256(),
                ssh_key.comment or "",
            )

    def execute(self, args: argparse.Namespace) -> None:
        """
        This function is used to check the validity of a public key file by
        using the PublicKeyEnumerator.

        :param args: Namespace object that contains the necessary parameters.
        """
        keys = []
        for file_path in args.public_keys:
            with Path(file_path).expanduser().open(
                "rt", encoding="utf-8"
            ) as key_handle:
                key = key_handle.read()
            try:
                keys.append(key)
            except ValueError:
                sys.exit("file is not a valid public key")

        try:
            valid_keys = []
            with PublicKeyEnumerator(args.host, args.port) as enumerator:
                for pubkey in keys:
                    if enumerator.check_publickey(args.username, pubkey):
                        valid_keys.append(pubkey)
            self.print_valid_keys(valid_keys)

        except Exception as exc:  # pylint: disable=broad-exception-caught
            print(exc)
            sys.exit(1)
