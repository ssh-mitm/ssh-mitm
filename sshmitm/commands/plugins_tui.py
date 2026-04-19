"""Textual TUI for browsing SSH-MITM plugins."""

from __future__ import annotations

import argparse
import contextlib
import os
import sys
from configparser import ConfigParser
from dataclasses import dataclass
from typing import TYPE_CHECKING

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, ScrollableContainer, Vertical
from textual.css.query import NoMatches
from textual.reactive import reactive
from textual.widgets import DataTable, Footer, Header, Label, Static, Tree

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
from sshmitm.session import BaseSession
from sshmitm.utils import metadata, resources

if TYPE_CHECKING:
    from sshmitm.moduleparser.modules import BaseModule

PLUGIN_TYPES: list[tuple[type[BaseModule], str, str]] = [
    (SSHBaseForwarder, "--ssh-interface", "SSH Terminal Forwarder"),
    (SCPBaseForwarder, "--scp-interface", "SCP File Transfer Forwarder"),
    (BaseSFTPServerInterface, "--sftp-interface", "SFTP Server Interface"),
    (SFTPHandlerBasePlugin, "--sftp-handler", "SFTP File Handler"),
    (
        RemotePortForwardingBaseForwarder,
        "--remote-port-forwarder",
        "Remote Port Forwarder",
    ),
    (
        LocalPortForwardingBaseForwarder,
        "--local-port-forwarder",
        "Local Port Forwarder",
    ),
    (BaseServerInterface, "--auth-interface", "SSH Server Interface"),
    (Authenticator, "--authenticator", "Authenticator"),
    (BaseSession, "--session-class", "Session"),
]


@dataclass
class PluginInfo:
    name: str
    ep_value: str
    type_label: str
    cli_flag: str
    base_class: type[BaseModule]
    loaded_class: type[BaseModule]

    @property
    def config_section(self) -> str:
        return f"{self.loaded_class.__module__}:{self.loaded_class.__name__}"

    @property
    def doc(self) -> str:
        return (self.loaded_class.__doc__ or "").strip()

    @property
    def actions(self) -> list[argparse.Action]:
        try:
            parser = self.loaded_class.parser()
        except Exception:  # noqa: BLE001  # pylint: disable=broad-exception-caught
            return []
        return [
            a
            for a in parser._actions  # pylint: disable=protected-access
            if not isinstance(
                a, argparse._HelpAction  # pylint: disable=protected-access
            )
            and a.help != argparse.SUPPRESS
        ]


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------


def _load_default_cfg() -> ConfigParser:
    cfg = ConfigParser()
    conf = resources.files("sshmitm") / "data/default.ini"
    cfg.read_string(conf.read_text())
    return cfg


def _get_config_path() -> str | None:
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("--config", dest="config_path")
    parsed, _ = p.parse_known_args(sys.argv[1:])
    return str(parsed.config_path) if parsed.config_path is not None else None


def _load_user_cfg(path: str) -> ConfigParser:
    cfg = ConfigParser()
    cfg.read(os.path.expanduser(path))
    return cfg


def _cfg_items(cfg: ConfigParser, section: str) -> dict[str, str]:
    if not cfg.has_section(section):
        return {}
    return dict(cfg.items(section))


# ---------------------------------------------------------------------------
# Detail panel — single scrollable view, all sections stacked
# ---------------------------------------------------------------------------

TCSS = """
Screen { layout: vertical; }

#main {
    layout: horizontal;
    height: 1fr;
}

#sidebar {
    width: 30;
    min-width: 22;
    border-right: solid $primary-darken-2;
    background: $surface;
}

#sidebar-title {
    background: $primary-darken-2;
    color: $text;
    text-align: center;
    padding: 0 1;
    text-style: bold;
}

#plugin-tree {
    height: 1fr;
    scrollbar-size: 1 1;
}

#detail {
    width: 1fr;
    height: 1fr;
    background: $panel;
}

/* Each Static inside the scroll grows with its content */
#detail Static {
    height: auto;
    padding: 0 2;
}

/* Section headers */
.section-rule {
    height: 1;
    padding: 0 2;
    color: $text-muted;
    border-bottom: solid $primary-darken-3;
    text-style: bold;
}

/* DataTables size to content, outer container scrolls */
#detail DataTable {
    height: auto;
    margin: 0 2;
}
"""


class DetailPane(ScrollableContainer):
    """Single scrollable panel: info → arguments → configuration."""

    def compose(self) -> ComposeResult:
        # placeholder
        yield Static(id="placeholder")

        # info section
        yield Static(id="sec-info")

        # arguments section
        yield Label(" Arguments ", classes="section-rule", id="lbl-args")
        yield DataTable(id="tbl-args", zebra_stripes=True, cursor_type="row")

        # configuration section
        yield Label(" Configuration ", classes="section-rule", id="lbl-cfg")
        yield DataTable(id="tbl-cfg", zebra_stripes=True, cursor_type="row")
        yield Static(id="sec-snippet")

    def on_mount(self) -> None:
        self.query_one("#tbl-args", DataTable).add_columns(
            "Flag", "Default", "Req.", "Description"
        )
        self._set_visible(False)
        self.query_one("#placeholder", Static).update(
            "[dim]Select a plugin from the tree on the left.[/dim]"
        )

    def _set_visible(self, visible: bool) -> None:
        self.query_one("#placeholder").display = not visible
        for wid_id in (
            "#sec-info",
            "#lbl-args",
            "#tbl-args",
            "#lbl-cfg",
            "#tbl-cfg",
            "#sec-snippet",
        ):
            self.query_one(wid_id).display = visible

    def show(
        self,
        plugin: PluginInfo,
        default_cfg: ConfigParser,
        user_cfg: ConfigParser | None,
        config_path: str | None,
    ) -> None:
        self._set_visible(True)
        self.scroll_home(animate=False)
        self._fill_info(plugin)
        self._fill_args(plugin)
        self._fill_cfg(plugin, default_cfg, user_cfg, config_path)

    # --- info ---

    def _fill_info(self, plugin: PluginInfo) -> None:
        lines = [
            f"[bold cyan]{plugin.name}[/bold cyan]\n",
            f"[dim]Type[/dim]            [bold white]{plugin.type_label}[/bold white]  [yellow]{plugin.cli_flag}[/yellow]",
            f"[dim]Class[/dim]           [cyan]{plugin.ep_value}[/cyan]",
            f"[dim]Config section[/dim]  [cyan]{plugin.config_section}[/cyan]",
        ]
        if plugin.doc:
            lines += ["", "[dim]─── Description ───────────────────────────[/dim]", ""]
            for line in plugin.doc.splitlines():
                lines.append(line)
        lines.append("")
        self.query_one("#sec-info", Static).update("\n".join(lines))

    # --- arguments ---

    def _fill_args(self, plugin: PluginInfo) -> None:
        table = self.query_one("#tbl-args", DataTable)
        table.clear()
        for action in plugin.actions:
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
            required = "yes" if getattr(action, "required", False) else ""
            table.add_row(flags, default_str, required, action.help or "")

    # --- configuration ---

    def _fill_cfg(
        self,
        plugin: PluginInfo,
        default_cfg: ConfigParser,
        user_cfg: ConfigParser | None,
        config_path: str | None,
    ) -> None:
        table = self.query_one("#tbl-cfg", DataTable)
        table.clear(columns=True)

        default_items = _cfg_items(default_cfg, plugin.config_section)
        user_items = _cfg_items(user_cfg, plugin.config_section) if user_cfg else {}
        all_keys = sorted(set(default_items) | set(user_items))

        has_user = user_cfg is not None
        user_col = os.path.basename(config_path or "config") if has_user else None

        cols = ["Key", "default.ini"]
        if has_user:
            cols.append(user_col or "config")
        table.add_columns(*cols)

        if not all_keys:
            self.query_one("#sec-snippet", Static).update(
                f"[dim]  No config entries for [{plugin.config_section}][/dim]\n"
            )
            return

        for key in all_keys:
            dval = default_items.get(key, "")
            uval = user_items.get(key, "")
            if has_user:
                table.add_row(f"--{key}", dval, uval)
            else:
                table.add_row(f"--{key}", dval)

        # active INI snippet
        active = {**default_items, **user_items}
        snippet_lines = ["", f"  [{plugin.config_section}]"]
        for action in plugin.actions:
            if not action.option_strings:
                continue
            key = action.option_strings[0].lstrip("-")
            snippet_lines.append(f"  {key} = {active.get(key, '')}")
        snippet_lines.append("")
        self.query_one("#sec-snippet", Static).update(
            "[dim]─── Active config snippet ───────────────────[/dim]"
            + "\n".join(snippet_lines)
        )


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------


class PluginBrowserApp(App[None]):
    """SSH-MITM Plugin Browser"""

    TITLE = "SSH-MITM Plugin Browser"
    CSS = TCSS
    BINDINGS = [  # noqa: RUF012
        Binding("q", "quit", "Quit"),
        Binding("tab", "focus_detail", "Detail"),
        Binding("escape", "focus_tree", "Tree"),
    ]

    selected_plugin: reactive[PluginInfo | None] = reactive(None)

    def __init__(
        self,
        default_cfg: ConfigParser,
        user_cfg: ConfigParser | None,
        config_path: str | None,
    ) -> None:
        super().__init__()
        self._default_cfg = default_cfg
        self._user_cfg = user_cfg
        self._config_path = config_path

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="main"):
            with Vertical(id="sidebar"):
                yield Label(" SSH-MITM Plugins ", id="sidebar-title")
                yield Tree("Plugin Types", id="plugin-tree")
            yield DetailPane(id="detail")
        yield Footer()

    def on_mount(self) -> None:
        self._populate_tree()
        self.query_one("#plugin-tree", Tree).focus()

    def _populate_tree(self) -> None:
        tree = self.query_one("#plugin-tree", Tree)
        tree.root.expand()
        for base_class, cli_flag, type_label in PLUGIN_TYPES:
            eps = sorted(
                metadata.entry_points(group=f"sshmitm.{base_class.__name__}"),
                key=lambda ep: ep.name,
            )
            if not eps:
                continue
            branch = tree.root.add(type_label, expand=True)
            for ep in eps:
                loaded = ep.load()
                branch.add_leaf(
                    ep.name,
                    data=PluginInfo(
                        name=ep.name,
                        ep_value=ep.value,
                        type_label=type_label,
                        cli_flag=cli_flag,
                        base_class=base_class,
                        loaded_class=loaded,
                    ),
                )

    def on_tree_node_selected(
        self, event: Tree.NodeSelected[PluginInfo | None]
    ) -> None:
        info: PluginInfo | None = event.node.data
        if info is not None:
            self.selected_plugin = info

    def watch_selected_plugin(self, plugin: PluginInfo | None) -> None:
        if plugin is None:
            return
        self.query_one(DetailPane).show(
            plugin, self._default_cfg, self._user_cfg, self._config_path
        )

    def action_focus_detail(self) -> None:
        with contextlib.suppress(NoMatches):
            self.query_one(DetailPane).focus()

    def action_focus_tree(self) -> None:
        with contextlib.suppress(NoMatches):
            self.query_one("#plugin-tree", Tree).focus()


def run_tui() -> None:
    default_cfg = _load_default_cfg()
    config_path = _get_config_path()
    user_cfg = _load_user_cfg(config_path) if config_path else None
    PluginBrowserApp(default_cfg, user_cfg, config_path).run()
