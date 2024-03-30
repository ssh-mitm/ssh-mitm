import argparse
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional

from rich import print as rich_print
from sshpubkeys import AuthorizedKeysFile, SSHKey  # type: ignore[import-untyped]

from sshmitm.authentication import PublicKeyEnumerator
from sshmitm.moduleparser import SubCommand


class CheckPublickey(SubCommand):
    """checks a username and publickey against a server"""

    @classmethod
    def config_section(cls) -> Optional[str]:
        return None

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
    def print_valid_keys(valid_keys: Dict[str, List[str]]) -> None:
        if not valid_keys:
            rich_print("[bold red]:cross_mark: No valid keys found[/bold red]")
            return
        rich_print("[bold green]:heavy_check_mark: Valid keys found[/bold green]")
        for filepath, keys in valid_keys.items():
            for key in keys:
                ssh_key = SSHKey(key, strict=True)
                print(
                    filepath,
                    "---",
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
        keys: Dict[str, List[str]] = defaultdict(list)
        try:
            for file_path in args.public_keys:
                with Path(file_path).expanduser().open(
                    "rt", encoding="utf-8"
                ) as key_handle:
                    key_file = AuthorizedKeysFile(key_handle, strict=False)
                for key in key_file.keys:
                    keys[file_path].append(key.keydata)
        except FileNotFoundError as exc:
            sys.exit(str(exc))

        valid_keys: Dict[str, List[str]] = defaultdict(list)
        try:
            with PublicKeyEnumerator(args.host, args.port) as enumerator:
                for filename, pubkeys in keys.items():
                    for pubkey in pubkeys:
                        if enumerator.check_publickey(args.username, pubkey):
                            valid_keys[filename].append(pubkey)
        except (  # pylint: disable=broad-exception-caught
            Exception  # noqa: BLE001
        ) as exc:
            print(exc)
            sys.exit(1)
        finally:
            self.print_valid_keys(valid_keys)
