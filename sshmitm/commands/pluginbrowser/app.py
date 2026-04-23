"""SSH-MITM Plugin Browser Textual application."""

from __future__ import annotations

import contextlib
import importlib.resources
from typing import TYPE_CHECKING, Any

from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Footer, Header, Tree

from sshmitm.commands.pluginbrowser.config import (
    get_config_path,
    load_default_cfg,
    load_user_cfg,
)
from sshmitm.commands.pluginbrowser.detail import DetailPane
from sshmitm.commands.pluginbrowser.serverinfo import server_info
from sshmitm.commands.pluginbrowser.widgets import PluginTree
from sshmitm.logger import Colors
from sshmitm.moduleparser.plugininfo import (
    GeneralActionInfo,
    GeneralGroupInfo,
    PluginInfo,
    PluginTypeInfo,
)
from sshmitm.utils import metadata

if TYPE_CHECKING:
    from configparser import ConfigParser

_TCSS = (
    importlib.resources.files("sshmitm")
    .joinpath("data/plugins_browser.tcss")
    .read_text(encoding="utf-8")
)


class PluginBrowserApp(App[None]):
    """SSH-MITM Plugin Browser"""

    TITLE = "SSH-MITM Plugin Browser"
    CSS = _TCSS
    BINDINGS = [  # noqa: RUF012
        Binding("q", "quit", "Quit"),
        Binding("tab", "focus_args", "Arguments"),
        Binding("escape", "focus_tree", "Plugins"),
        Binding("[", "shrink_desc", "< Desc"),
        Binding("]", "grow_desc", "Desc >"),
    ]

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
                yield PluginTree("SSH-MITM", id="plugin-tree")
            yield DetailPane(id="detail")
        yield Footer()

    def on_mount(self) -> None:
        self.theme = "gruvbox"
        self._populate_tree()
        tree = self.query_one("#plugin-tree", PluginTree)
        tree.show_root = False
        tree.focus()

    def _populate_tree(self) -> None:
        tree = self.query_one("#plugin-tree", PluginTree)
        tree.root.expand()

        if server_info.general_groups:
            server_branch = tree.root.add("Server Parameters", expand=True)
            for group_info in server_info.general_groups:
                server_branch.add_leaf(group_info.title, data=group_info)

        plugins_branch = tree.root.add("Plugins", expand=True)
        for type_info in server_info.plugin_types:
            eps = sorted(
                metadata.entry_points(group=f"sshmitm.{type_info.base_class.__name__}"),
                key=lambda ep: ep.name,
            )
            if not eps:
                continue
            branch = plugins_branch.add(
                type_info.type_label, data=type_info, expand=True
            )
            for ep in eps:
                loaded = ep.load()
                branch.add_leaf(
                    ep.name,
                    data=PluginInfo(
                        name=ep.name,
                        ep_value=str(ep.value),
                        type_label=type_info.type_label,
                        cli_flag=type_info.cli_flag,
                        base_class=type_info.base_class,
                        loaded_class=loaded,
                    ),
                )

    async def on_tree_node_selected(self, event: Tree.NodeSelected[Any]) -> None:
        info = event.node.data
        detail = self.query_one(DetailPane)
        if isinstance(info, PluginInfo):
            await detail.show(
                info, self._default_cfg, self._user_cfg, self._config_path
            )
        elif isinstance(info, PluginTypeInfo):
            await detail.show_plugin_type(info)
        elif isinstance(info, GeneralGroupInfo):
            await detail.show_general_group(
                info, self._default_cfg, self._user_cfg, self._config_path
            )
        elif isinstance(info, GeneralActionInfo):
            await detail.show_general_action(
                info, self._default_cfg, self._user_cfg, self._config_path
            )

    def action_focus_args(self) -> None:
        with contextlib.suppress(Exception):
            self.query_one("#groups-tree", Tree).focus()

    def action_focus_tree(self) -> None:
        with contextlib.suppress(Exception):
            self.query_one("#plugin-tree", PluginTree).focus()

    def action_shrink_desc(self) -> None:
        with contextlib.suppress(Exception):
            self.query_one(DetailPane).adjust_split(-3)

    def action_grow_desc(self) -> None:
        with contextlib.suppress(Exception):
            self.query_one(DetailPane).adjust_split(3)


def run_browser() -> None:
    """Launch the plugin browser TUI."""
    Colors.stylize_func = False
    default_cfg = load_default_cfg()
    config_path = get_config_path()
    user_cfg = load_user_cfg(config_path) if config_path else None
    PluginBrowserApp(default_cfg, user_cfg, config_path).run()
