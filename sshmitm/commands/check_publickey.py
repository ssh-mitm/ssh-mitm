import argparse
import sys
import urllib.request
from collections import defaultdict
from pathlib import Path

from rich import print as rich_print
from rich.console import Console

from sshmitm.authentication import PublicKeyEnumerator
from sshmitm.moduleparser import SubCommand
from sshmitm.utils import SSHPubKey

console = Console()


class CheckPublickey(SubCommand):
    """checks a username and publickey against a server"""

    @classmethod
    def config_section(cls) -> str | None:
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
            help="publickeys to check (file path or http/https URL)",
        )

    @staticmethod
    def print_valid_keys(valid_keys: dict[str, list[str]]) -> None:
        if not valid_keys:
            rich_print("[bold red]:cross_mark: No valid keys found[/bold red]")
            return

        rich_print("[bold green]:heavy_check_mark: Valid keys found[/bold green]")

        for filepath, keys in valid_keys.items():
            for key_line in keys:
                ssh_key = SSHPubKey.from_ssh_line(key_line)
                print(
                    filepath,
                    "---",
                    ssh_key.get_name(),
                    ssh_key.get_bits(),
                    ssh_key.hash_sha256(),
                    ssh_key.comment or "",
                )

    def execute(self, args: argparse.Namespace) -> None:
        keys: dict[str, list[str]] = defaultdict(list)
        try:
            for file_path in args.public_keys:
                if file_path.startswith("http://") or file_path.startswith("https://"):
                    with urllib.request.urlopen(file_path) as resp:  # noqa: S310
                        content = resp.read().decode("utf-8", errors="replace")
                    lines: list[str] = content.splitlines()
                else:
                    with (
                        Path(file_path)
                        .expanduser()
                        .open("rt", encoding="utf-8") as key_handle
                    ):
                        lines = list(key_handle)
                for line in lines:
                    stripped_line = line.strip()
                    if stripped_line and not stripped_line.startswith("#"):
                        keys[file_path].append(stripped_line)
        except FileNotFoundError as exc:
            sys.exit(str(exc))

        total = sum(len(v) for v in keys.values())
        rich_print(
            f"\nTesting [bold]{total}[/bold] "
            f"{'key' if total == 1 else 'keys'} for user "
            f"[bold]{args.username!r}[/bold] against "
            f"[bold]{args.host}:{args.port}[/bold]\n"
        )

        valid_keys: dict[str, list[str]] = defaultdict(list)

        # (accepted, key_info_markup, source, raw_pubkey)
        results: list[tuple[bool, str, str]] = []

        try:
            with PublicKeyEnumerator(args.host, args.port) as enumerator:
                for filename, pubkeys in keys.items():
                    for pubkey in pubkeys:
                        try:
                            ssh_key = SSHPubKey.from_ssh_line(pubkey)
                            comment = ssh_key.comment or ""
                            key_info = (
                                f"[bold]{comment}[/bold]\n"
                                f"   Type:        {ssh_key.get_name()}\n"
                                f"   Fingerprint: {ssh_key.hash_sha256()}"
                            )
                        except ValueError:
                            key_info = pubkey

                        accepted = enumerator.check_publickey(args.username, pubkey)
                        if accepted:
                            valid_keys[filename].append(pubkey)
                        results.append((accepted, key_info, filename))
        except (  # pylint: disable=broad-exception-caught
            Exception  # noqa: BLE001
        ) as exc:
            print(exc)
            sys.exit(1)
        finally:
            # print accepted keys first, then rejected — grouped with section headers
            accepted_results = [(ki, src) for ok, ki, src in results if ok]
            rejected_results = [(ki, src) for ok, ki, src in results if not ok]

            if accepted_results:
                console.rule("[bold green]Accepted[/bold green]", style="green")
                for key_info, _ in accepted_results:
                    rich_print()
                    rich_print(f"[green]:heavy_check_mark:[/green]  {key_info}")

            if rejected_results:
                rich_print()
                console.rule("[bold red]Not accepted[/bold red]", style="red")
                for key_info, _ in rejected_results:
                    rich_print()
                    rich_print(f"[red]:cross_mark:[/red]  {key_info}")

            valid_count = sum(1 for r in results if r[0])
            checked_count = len(results)
            rich_print()
            rich_print()
            if valid_count == 0:
                rich_print(
                    f"[bold red]:cross_mark: 0 of {checked_count} "
                    f"{'key' if checked_count == 1 else 'keys'} accepted[/bold red]"
                )
            else:
                rich_print(
                    f"[bold green]:heavy_check_mark: {valid_count} of {checked_count} "
                    f"{'key' if checked_count == 1 else 'keys'} accepted[/bold green]"
                )
