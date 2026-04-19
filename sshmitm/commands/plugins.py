import argparse
import os
import sys
from configparser import ConfigParser
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.syntax import Syntax
from rich.table import Table, box
from rich.text import Text
from rich.tree import Tree

from sshmitm.authentication import Authenticator
from sshmitm.forwarders.scp import SCPBaseForwarder
from sshmitm.forwarders.sftp import SFTPHandlerBasePlugin
from sshmitm.forwarders.ssh import SSHBaseForwarder
from sshmitm.forwarders.tunnel import (
    LocalPortForwardingBaseForwarder,
    RemotePortForwardingBaseForwarder,
)
from sshmitm.interfaces.server import BaseServerInterface
from sshmitm.interfaces.sftp import BaseSFTPServerInterface
from sshmitm.moduleparser import SubCommand
from sshmitm.moduleparser.modules import BaseModule
from sshmitm.session import BaseSession
from sshmitm.utils import metadata, resources


PLUGIN_TYPES: list[tuple[type[BaseModule], str, str]] = [
    (SSHBaseForwarder, "--ssh-interface", "SSH Terminal Forwarder"),
    (SCPBaseForwarder, "--scp-interface", "SCP File Transfer Forwarder"),
    (BaseSFTPServerInterface, "--sftp-interface", "SFTP Server Interface"),
    (SFTPHandlerBasePlugin, "--sftp-handler", "SFTP File Handler"),
    (RemotePortForwardingBaseForwarder, "--remote-port-forwarder", "Remote Port Forwarder"),
    (LocalPortForwardingBaseForwarder, "--local-port-forwarder", "Local Port Forwarder"),
    (BaseServerInterface, "--auth-interface", "SSH Server Interface"),
    (Authenticator, "--authenticator", "Authenticator"),
    (BaseSession, "--session-class", "Session"),
]


def _ep_value(ep: Any) -> str:
    return ep.value


def _first_line(doc: str | None) -> str:
    if not doc:
        return ""
    return doc.strip().split("\n", 1)[0]


def _find_plugin(
    name: str,
) -> tuple[type[BaseModule], str, str, Any, type[BaseModule]] | None:
    for base_class, cli_flag, type_label in PLUGIN_TYPES:
        for ep in metadata.entry_points(group=f"sshmitm.{base_class.__name__}"):
            if name in (ep.name, _ep_value(ep)):
                return base_class, type_label, cli_flag, ep, ep.load()
    return None


def _load_default_cfg() -> ConfigParser:
    cfg = ConfigParser()
    conf = resources.files("sshmitm") / "data/default.ini"
    cfg.read_string(conf.read_text())
    return cfg


def _load_user_cfg(path: str) -> ConfigParser:
    cfg = ConfigParser()
    cfg.read(os.path.expanduser(path))
    return cfg


def _get_config_path() -> str | None:
    """Read --config path directly from sys.argv (same approach as ModuleParser.add_config_arg)."""
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("--config", dest="config_path")
    parsed, _ = p.parse_known_args(sys.argv[1:])
    return parsed.config_path


class Plugins(SubCommand):
    """manage and inspect SSH-MITM plugins"""

    @classmethod
    def config_section(cls) -> str | None:
        return None

    def register_arguments(self) -> None:
        subparsers = self.parser.add_subparsers(dest="plugins_command", metavar="COMMAND")

        show_parser = subparsers.add_parser(
            "show",
            help="show available plugins or details for a specific plugin",
        )
        show_parser.add_argument(
            "plugin",
            nargs="?",
            metavar="PLUGIN",
            help=(
                "short name (e.g. 'mirrorshell') or full class path "
                "(e.g. 'sshmitm.plugins.ssh.mirrorshell:SSHMirrorForwarder')"
            ),
        )

        subparsers.add_parser(
            "tui",
            help="open interactive plugin browser (requires: pip install textual)",
        )

    def execute(self, args: argparse.Namespace) -> None:
        console = Console()
        command = getattr(args, "plugins_command", None)

        if command == "show":
            plugin_name = getattr(args, "plugin", None)
            if plugin_name:
                _show_detail(console, plugin_name, args)
            else:
                _show_all(console)
        elif command == "tui":
            try:
                from sshmitm.commands.plugins_tui import run_tui  # noqa: PLC0415
            except ImportError:
                console.print(
                    "[bold red]Textual is not installed.[/bold red]\n"
                    "Install it with:  [bold]pip install textual[/bold]"
                )
                return
            run_tui()
        else:
            self.parser.print_help()


# ---------------------------------------------------------------------------
# List view  —  ssh-mitm plugins show
# ---------------------------------------------------------------------------

def _show_all(console: Console) -> None:
    console.print()
    console.print(Rule("[bold cyan]SSH-MITM Plugins[/bold cyan]", style="cyan"))
    console.print()

    for base_class, cli_flag, type_label in PLUGIN_TYPES:
        eps = sorted(
            metadata.entry_points(group=f"sshmitm.{base_class.__name__}"),
            key=lambda ep: ep.name,
        )
        if not eps:
            continue

        tree = Tree(
            Text.assemble(
                (type_label, "bold white"),
                "  ",
                (cli_flag, "bold yellow"),
                "  ",
                (f"[sshmitm.{base_class.__name__}]", "dim"),
            ),
            guide_style="dim cyan",
        )

        for ep in eps:
            loaded = ep.load()
            desc = _first_line(loaded.__doc__)
            branch = tree.add(
                Text.assemble(
                    (ep.name, "bold green"),
                    "  ",
                    (_ep_value(ep), "dim"),
                )
            )
            if desc:
                branch.add(Text(desc, style="italic"))

        console.print(tree)
        console.print()

    console.print(
        "[dim]  Run [bold]ssh-mitm plugins show [/bold][bold cyan]<name>[/bold cyan]"
        " for detailed information.[/dim]"
    )
    console.print()


# ---------------------------------------------------------------------------
# Detail view  —  ssh-mitm plugins show <name>
# ---------------------------------------------------------------------------

def _show_detail(console: Console, name: str, args: argparse.Namespace) -> None:
    result = _find_plugin(name)
    if result is None:
        console.print(f"\n[bold red]:cross_mark:  Plugin not found:[/bold red] {name}\n")
        return

    base_class, type_label, cli_flag, ep, loaded_class = result
    config_section = f"{loaded_class.__module__}:{loaded_class.__name__}"
    doc = (loaded_class.__doc__ or "").strip()

    default_cfg = _load_default_cfg()
    config_path = _get_config_path()
    user_cfg = _load_user_cfg(config_path) if config_path else None

    console.print()
    console.print(Rule(f"[bold cyan]{ep.name}[/bold cyan]", style="cyan"))
    console.print()

    # --- info grid ---
    info = Table.grid(padding=(0, 3))
    info.add_column(style="dim", no_wrap=True)
    info.add_column()
    info.add_row("Plugin name", Text(ep.name, style="bold green"))
    info.add_row(
        "Type",
        Text.assemble((type_label, "bold white"), "  ", (cli_flag, "yellow")),
    )
    info.add_row("Class", Text(_ep_value(ep), style="cyan"))
    info.add_row("Config section", Text(config_section, style="cyan"))
    console.print(info)

    # --- description ---
    if doc:
        console.print()
        console.print(Rule("Description", style="dim"))
        console.print()
        for line in doc.splitlines():
            console.print(f"  {line}")

    # --- arguments ---
    try:
        plugin_parser = loaded_class.parser()
    except Exception:  # noqa: BLE001
        return

    actions = [
        a
        for a in plugin_parser._actions
        if not isinstance(a, argparse._HelpAction)
        and a.help != argparse.SUPPRESS
    ]

    if actions:
        console.print()
        console.print(Rule("Arguments", style="dim"))
        console.print()

        arg_table = Table(
            show_header=True,
            header_style="bold dim",
            box=box.SIMPLE_HEAD,
            expand=True,
            padding=(0, 2),
        )
        arg_table.add_column("Flag", style="bold green", no_wrap=True)
        arg_table.add_column("Default", style="yellow", no_wrap=True)
        arg_table.add_column("Req.", no_wrap=True)
        arg_table.add_column("Description")

        for action in actions:
            flags = (
                ", ".join(action.option_strings)
                if action.option_strings
                else f"<{action.dest}>"
            )
            default = action.default
            if default is None or default is argparse.SUPPRESS or default is False:
                default_str = ""
            else:
                default_str = str(default)
            required = (
                "[bold red]yes[/bold red]" if getattr(action, "required", False) else ""
            )
            arg_table.add_row(flags, default_str, required, action.help or "")

        console.print(arg_table)

    # --- config values ---
    _show_config_values(console, config_section, actions, default_cfg, user_cfg, config_path)
    console.print()


def _show_config_values(
    console: Console,
    config_section: str,
    actions: list[argparse.Action],
    default_cfg: ConfigParser,
    user_cfg: ConfigParser | None,
    config_path: str | None,
) -> None:
    has_default_section = default_cfg.has_section(config_section)
    has_user_section = user_cfg is not None and user_cfg.has_section(config_section)

    if not has_default_section and not has_user_section:
        return

    console.print()
    console.print(Rule("Configuration", style="dim"))
    console.print()

    # build key → flag mapping from actions
    dest_to_flag: dict[str, str] = {}
    for action in actions:
        if action.option_strings:
            flag = action.option_strings[0].lstrip("-")
            dest_to_flag[action.dest] = flag

    def _cfg_items(cfg: ConfigParser, section: str) -> dict[str, str]:
        if not cfg.has_section(section):
            return {}
        return dict(cfg.items(section))

    default_items = _cfg_items(default_cfg, config_section)
    user_items = _cfg_items(user_cfg, config_section) if user_cfg else {}

    show_user_col = user_cfg is not None

    cfg_table = Table(
        show_header=True,
        header_style="bold dim",
        box=box.SIMPLE_HEAD,
        expand=False,
        padding=(0, 2),
    )
    cfg_table.add_column("Key", style="bold green", no_wrap=True)
    cfg_table.add_column("default.ini", style="yellow", no_wrap=True)
    if show_user_col:
        cfg_table.add_column(
            f"{os.path.basename(config_path or '')}",
            style="bold cyan",
            no_wrap=True,
        )

    all_keys = sorted(set(default_items) | set(user_items))
    for key in all_keys:
        dval = default_items.get(key, "")
        uval = user_items.get(key, "")
        flag_str = f"--{key}"

        if show_user_col:
            # highlight when user overrides a default
            if uval and uval != dval:
                user_cell = Text(uval, style="bold cyan")
            elif uval:
                user_cell = Text(uval, style="cyan")
            else:
                user_cell = Text("", style="dim")
            cfg_table.add_row(flag_str, dval, user_cell)
        else:
            cfg_table.add_row(flag_str, dval)

    subtitle = ""
    if show_user_col:
        subtitle = f"[bold cyan]bold cyan[/bold cyan] = overrides default.ini"

    console.print(
        Panel(
            cfg_table,
            title="[bold]Config values[/bold]",
            subtitle=subtitle,
            border_style="dim",
            expand=False,
            padding=(0, 1),
        )
    )

    # --- INI snippet with real values filled in ---
    active_items = {**default_items, **user_items}
    ini_lines: list[str] = [f"[{config_section}]"]
    for action in actions:
        if not action.option_strings:
            continue
        flag = action.option_strings[0].lstrip("-")
        val = active_items.get(flag, "")
        ini_lines.append(f"{flag} = {val}")

    console.print()
    console.print(
        Panel(
            Syntax("\n".join(ini_lines), "ini", theme="ansi_dark"),
            title="[bold]Active config snippet[/bold]",
            subtitle="[dim]ssh-mitm server --config myconfig.ini[/dim]",
            border_style="dim",
            expand=False,
            padding=(0, 2),
        )
    )
