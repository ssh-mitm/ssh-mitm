"""SSH-MITM plugin inspection commands and TUI browser."""

from __future__ import annotations

import argparse
import contextlib
import functools
import inspect
import os
import re
import sys
from configparser import ConfigParser
from dataclasses import dataclass
from typing import TYPE_CHECKING

from textual.app import (
    App,
    ComposeResult,
)
from textual.binding import (
    Binding,
)
from textual.containers import (
    Horizontal,
    ScrollableContainer,
    Vertical,
)
from textual.css.query import (
    NoMatches,
)
from textual.reactive import (
    reactive,
)
from textual.widgets import (
    DataTable,
    Footer,
    Header,
    Label,
    Markdown,
    Static,
    Tree,
)

from sshmitm.moduleparser import SubCommand
from sshmitm.moduleparser.parser import (
    ModuleParser,
)
from sshmitm.server.cli import (
    SSHServerModules,
)
from sshmitm.utils import metadata, resources

if TYPE_CHECKING:
    from sshmitm.moduleparser.modules import BaseModule


# ---------------------------------------------------------------------------
# Dynamic plugin-type discovery
# ---------------------------------------------------------------------------


def _class_to_label(cls_name: str) -> str:
    """Derive a human-readable label from a base-class name."""
    name = cls_name.replace("Base", "")
    words = re.findall(r"[A-Z]+(?=[A-Z][a-z]|\d|\b)|[A-Z][a-z]+|\d+", name)
    return " ".join(words)


@functools.cache
def _plugin_types() -> list[tuple[type[BaseModule], str, str]]:
    """Return (base_class, cli_flag, type_label) triples, derived from SSHServerModules."""
    mp = ModuleParser(prog="sshmitm")
    sub = mp.add_subparsers()
    cmd = SSHServerModules("server", sub)
    cmd.register_arguments()

    return [
        (baseclass, action.option_strings[0], _class_to_label(baseclass.__name__))
        for action, baseclass in cmd.parser._extra_modules  # pylint: disable=protected-access
        if action.option_strings
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
    """Read --config path directly from sys.argv (same approach as ModuleParser.add_config_arg)."""
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
# Shared plugin lookup
# ---------------------------------------------------------------------------


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
        return inspect.cleandoc(self.loaded_class.__doc__ or "")

    @property
    def actions(self) -> list[argparse.Action]:
        try:
            parser = self.loaded_class.parser()
        except Exception:  # noqa: BLE001  # pylint: disable=broad-exception-caught
            return []
        return [
            a
            for a in parser._actions  # pylint: disable=protected-access
            if a.dest is not argparse.SUPPRESS and a.help != argparse.SUPPRESS
        ]


# ---------------------------------------------------------------------------
# SubCommand
# ---------------------------------------------------------------------------


class Plugins(SubCommand):
    """manage and inspect SSH-MITM plugins"""

    @classmethod
    def config_section(cls) -> str | None:
        return None

    def register_arguments(self) -> None:
        subparsers = self.parser.add_subparsers(
            dest="plugins_command", metavar="COMMAND"
        )
        subparsers.add_parser(
            "show",
            help="open interactive plugin browser",
        )

    def execute(self, args: argparse.Namespace) -> None:
        command = getattr(args, "plugins_command", None)
        if command == "show":
            _run_tui()
        else:
            self.parser.print_help()


# ---------------------------------------------------------------------------
# TUI
# ---------------------------------------------------------------------------


_TCSS = """
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

#detail Static {
    height: auto;
    padding: 0 2;
}

#sec-doc {
    height: auto;
    padding: 0 2;
}

.section-rule {
    height: 1;
    padding: 0 2;
    color: $text-muted;
    border-bottom: solid $primary-darken-3;
    text-style: bold;
}

#detail DataTable {
    height: auto;
    margin: 0 2;
}
"""


def _run_tui() -> None:  # noqa: C901

    class DetailPane(ScrollableContainer):
        def compose(self) -> ComposeResult:
            yield Static(id="placeholder")
            yield Static(id="sec-info")
            yield Markdown("", id="sec-doc")
            yield Label(" Arguments ", classes="section-rule", id="lbl-args")
            yield DataTable(id="tbl-args", zebra_stripes=True, cursor_type="row")
            yield Label(" Configuration ", classes="section-rule", id="lbl-cfg")
            yield DataTable(id="tbl-cfg", zebra_stripes=True, cursor_type="row")

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
                "#sec-doc",
                "#lbl-args",
                "#tbl-args",
                "#lbl-cfg",
                "#tbl-cfg",
            ):
                self.query_one(wid_id).display = visible

        async def show(
            self,
            plugin: PluginInfo,
            default_cfg: ConfigParser,
            user_cfg: ConfigParser | None,
            config_path: str | None,
        ) -> None:
            self._set_visible(True)
            self.scroll_home(animate=False)
            await self._fill_info(plugin)
            self._fill_args(plugin)
            self._fill_cfg(plugin, default_cfg, user_cfg, config_path)

        async def _fill_info(self, plugin: PluginInfo) -> None:
            lines = [
                f"[bold cyan]{plugin.name}[/bold cyan]\n",
                f"[dim]Type[/dim]            [bold white]{plugin.type_label}[/bold white]  [yellow]{plugin.cli_flag}[/yellow]",
                f"[dim]Class[/dim]           [cyan]{plugin.ep_value}[/cyan]",
                f"[dim]Config section[/dim]  [cyan]{plugin.config_section}[/cyan]",
                "",
            ]
            self.query_one("#sec-info", Static).update("\n".join(lines))
            await self.query_one("#sec-doc", Markdown).update(plugin.doc)

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
                default_str = (
                    ""
                    if default is None
                    or default is argparse.SUPPRESS
                    or default is False
                    else str(default)
                )
                required = "yes" if getattr(action, "required", False) else ""
                table.add_row(flags, default_str, required, action.help or "")

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

            for key in all_keys:
                dval = default_items.get(key, "")
                if has_user:
                    table.add_row(key, dval, user_items.get(key, ""))
                else:
                    table.add_row(key, dval)

    class PluginBrowserApp(App[None]):
        """SSH-MITM Plugin Browser"""

        TITLE = "SSH-MITM Plugin Browser"
        CSS = _TCSS
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
            for base_class, cli_flag, type_label in _plugin_types():
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
                            ep_value=str(ep.value),
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

        async def watch_selected_plugin(self, plugin: PluginInfo | None) -> None:
            if plugin is None:
                return
            await self.query_one(DetailPane).show(
                plugin, self._default_cfg, self._user_cfg, self._config_path
            )

        def action_focus_detail(self) -> None:
            with contextlib.suppress(NoMatches):
                self.query_one(DetailPane).focus()

        def action_focus_tree(self) -> None:
            with contextlib.suppress(NoMatches):
                self.query_one("#plugin-tree", Tree).focus()

    default_cfg = _load_default_cfg()
    config_path = _get_config_path()
    user_cfg = _load_user_cfg(config_path) if config_path else None
    PluginBrowserApp(default_cfg, user_cfg, config_path).run()
