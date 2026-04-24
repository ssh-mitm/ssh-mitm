"""SSH-MITM Plugin Browser Textual application."""

from __future__ import annotations

import contextlib
import importlib.resources
import inspect
from typing import TYPE_CHECKING, Any

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import DataTable, Footer, Header, Input, Select, TabbedContent, TabPane, Tree

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
        Binding("a", "focus_args", "Arguments"),
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
        self._all_plugin_rows: list[tuple[str, str, str | Text, str, str]] = []

    def compose(self) -> ComposeResult:
        yield Header()
        with TabbedContent(id="main-tabs"):
            with TabPane("Browser", id="tab-browser"):
                with Horizontal(id="main"):
                    with Vertical(id="sidebar"):
                        yield PluginTree("SSH-MITM", id="plugin-tree")
                    yield DetailPane(id="detail")
            with TabPane("All Plugins", id="tab-overview"):
                with Vertical(id="overview-layout"):
                    with Horizontal(id="filter-bar"):
                        yield Select(
                            [("All", "all"), ("Active", "active"), ("Inactive", "inactive")],
                            value="all",
                            id="status-filter",
                            allow_blank=False,
                        )
                        yield Input(placeholder="Filter plugins…", id="filter-input")
                    yield DataTable(
                        id="all-plugins-table",
                        zebra_stripes=True,
                        cursor_type="row",
                    )
        yield Footer()

    def on_mount(self) -> None:
        self.theme = "gruvbox"
        self._populate_tree()
        self._populate_overview_table()
        tree = self.query_one("#plugin-tree", PluginTree)
        tree.show_root = False
        tree.focus()

    def _active_ep_value(self, cli_flag: str) -> str | None:
        key = cli_flag.lstrip("-")
        section = "SSH-Server-Modules"
        if self._user_cfg and self._user_cfg.has_option(section, key):
            return self._user_cfg.get(section, key)
        if self._default_cfg.has_option(section, key):
            return self._default_cfg.get(section, key)
        return None

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
                metadata.entry_points(group=f"{type_info.base_class.entry_point_prefix}.{type_info.base_class.__name__}"),
                key=lambda ep: ep.name,
            )
            if not eps:
                continue
            branch = plugins_branch.add(
                type_info.type_label, data=type_info, expand=True
            )
            active_value = self._active_ep_value(type_info.cli_flag)
            for ep in eps:
                loaded = ep.load()
                is_active = str(ep.value) == active_value
                label: str | Text = (
                    Text(f"» {ep.name}", style="bold") if is_active else ep.name
                )
                branch.add_leaf(
                    label,
                    data=PluginInfo(
                        name=ep.name,
                        ep_value=str(ep.value),
                        type_label=type_info.type_label,
                        cli_flag=type_info.cli_flag,
                        base_class=type_info.base_class,
                        loaded_class=loaded,
                    ),
                )

    def _populate_overview_table(self) -> None:
        tbl = self.query_one("#all-plugins-table", DataTable)
        tbl.add_columns("Category", "EP-Name", "Active", "Class", "Description")

        for type_info in server_info.plugin_types:
            eps = sorted(
                metadata.entry_points(group=f"{type_info.base_class.entry_point_prefix}.{type_info.base_class.__name__}"),
                key=lambda ep: ep.name,
            )
            if not eps:
                continue
            active_value = self._active_ep_value(type_info.cli_flag)
            for ep in eps:
                loaded = ep.load()
                is_active = str(ep.value) == active_value
                doc = inspect.cleandoc(loaded.__doc__ or "")
                first_line = doc.splitlines()[0] if doc else ""
                active_cell: str | Text = Text("✓", style="bold") if is_active else ""
                self._all_plugin_rows.append((
                    type_info.type_label,
                    ep.name,
                    active_cell,
                    str(ep.value),
                    first_line,
                ))

        self._apply_filter("", "all")

    def _apply_filter(self, query: str, status: str) -> None:
        tbl = self.query_one("#all-plugins-table", DataTable)
        tbl.clear()
        needle = query.lower()
        for row in self._all_plugin_rows:
            is_active = bool(row[2])
            if status == "active" and not is_active:
                continue
            if status == "inactive" and is_active:
                continue
            searchable = f"{row[0]} {row[1]} {row[3]} {row[4]}".lower()
            if needle in searchable:
                tbl.add_row(*row)

    def _refresh_filter(self) -> None:
        query = self.query_one("#filter-input", Input).value
        status = self.query_one("#status-filter", Select).value
        self._apply_filter(query, str(status))

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "filter-input":
            self._refresh_filter()

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "status-filter":
            self._refresh_filter()

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
