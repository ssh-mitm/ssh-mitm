"""Plugin Browser Textual application."""

from __future__ import annotations

import contextlib
import importlib.resources
import inspect
from configparser import ConfigParser
from importlib import metadata
from typing import TYPE_CHECKING, Any

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import (
    DataTable,
    Footer,
    Header,
    Input,
    Select,
    TabbedContent,
    TabPane,
    Tree,
)

from sshmitm.moduleparser.colors import Colors
from sshmitm.moduleparser.pluginbrowser.config import (
    BrowserConfig,
    get_config_path,
    load_user_cfg,
)
from sshmitm.moduleparser.pluginbrowser.detail import DetailPane
from sshmitm.moduleparser.pluginbrowser.widgets import PluginTree
from sshmitm.moduleparser.plugininfo import (
    ExecHandlerInfo,
    GeneralActionInfo,
    GeneralGroupInfo,
    PluginInfo,
    PluginTypeInfo,
)

if TYPE_CHECKING:
    from sshmitm.moduleparser.parser import ModuleParser


_TCSS = (
    importlib.resources.files("sshmitm.moduleparser.pluginbrowser")
    .joinpath("plugins_browser.tcss")
    .read_text(encoding="utf-8")
)


class PluginBrowserApp(App[None]):
    """Plugin Browser"""

    CSS = _TCSS
    BINDINGS = [  # noqa: RUF012
        Binding("q", "quit", "Quit"),
        Binding("a", "focus_args", "Arguments"),
        Binding("escape", "focus_tree", "Plugins"),
        Binding("[", "shrink_desc", "< Desc"),
        Binding("]", "grow_desc", "Desc >"),
    ]

    def __init__(self, parser: ModuleParser, config: BrowserConfig) -> None:
        super().__init__()
        self._parser = parser
        self._default_cfg = config.default_cfg
        self._user_cfg = config.user_cfg
        self._config_path = config.config_path
        self._title = config.title
        self._tree_root_label = config.tree_root_label
        self._active_config_section = config.active_config_section
        self._all_plugin_rows: list[tuple[str, str, str | Text, str, str]] = []

    def compose(self) -> ComposeResult:
        yield Header()
        with TabbedContent(id="main-tabs"):
            with TabPane("Browser", id="tab-browser"), Horizontal(id="main"):
                with Vertical(id="sidebar"):
                    yield PluginTree(self._tree_root_label, id="plugin-tree")
                yield DetailPane(id="detail", resolver=self._parser.resolve_ep_name)
            with (
                TabPane("All Plugins", id="tab-overview"),
                Vertical(id="overview-layout"),
            ):
                with Horizontal(id="filter-bar"):
                    yield Select(
                        [
                            ("All", "all"),
                            ("Active", "active"),
                            ("Inactive", "inactive"),
                        ],
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
        self.title = self._title
        self.theme = "gruvbox"
        self._populate_tree()
        self._populate_overview_table()
        tree = self.query_one("#plugin-tree", PluginTree)
        tree.show_root = False
        tree.focus()

    def _active_ep_value(
        self, config_key: str, config_section: str | None = None
    ) -> str | None:
        section = (
            config_section
            if config_section is not None
            else self._active_config_section
        )
        if section is None:
            return None
        if self._user_cfg and self._user_cfg.has_option(section, config_key):
            return self._user_cfg.get(section, config_key)
        if self._default_cfg.has_option(section, config_key):
            return self._default_cfg.get(section, config_key)
        return None

    def _populate_parser_into_branch(self, branch: Any, parser: ModuleParser) -> None:
        general_groups = parser.general_groups
        if general_groups:
            params_branch = branch.add("Parameters", expand=True)
            for group_info in general_groups:
                params_branch.add_leaf(group_info.title, data=group_info)

        plugin_types = parser.plugin_types
        if not plugin_types:
            return
        plugins_branch = branch.add("Plugins", expand=True)
        config_section = parser.config_section
        for type_info in plugin_types:
            eps = sorted(
                metadata.entry_points(
                    group=f"{type_info.base_class.entry_point_prefix}.{type_info.base_class.__name__}"
                ),
                key=lambda ep: ep.name,
            )
            if not eps:
                continue
            type_branch = plugins_branch.add(
                type_info.type_label, data=type_info, expand=True
            )
            active_value = self._active_ep_value(type_info.config_key, config_section)
            for ep in eps:
                loaded = ep.load()
                is_active = str(ep.value) == active_value
                label: str | Text = (
                    Text(f"» {ep.name}", style="bold") if is_active else ep.name
                )
                type_branch.add_leaf(
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

    _SCP_CONFIG_SECTION = "sshmitm.interfaces.server:ServerInterface"

    def _exec_handler_enabled_sets(self) -> tuple[list[str], list[str]]:
        enabled_raw = self._active_ep_value("enabled_exec_handlers", self._SCP_CONFIG_SECTION) or "ALL"
        disabled_raw = self._active_ep_value("disabled_exec_handlers", self._SCP_CONFIG_SECTION) or "NONE"
        return enabled_raw.split(), disabled_raw.split()

    def _is_exec_handler_enabled(self, name: str) -> bool:
        from sshmitm.forwarders.scp import SCPBaseForwarder  # noqa: PLC0415

        enabled, disabled = self._exec_handler_enabled_sets()
        return SCPBaseForwarder._is_handler_allowed(name, enabled, disabled)  # pylint: disable=protected-access

    def _populate_exec_handlers_into_branch(self, branch: Any) -> None:
        eps = sorted(
            metadata.entry_points(group="sshmitm.ExecHandler"),
            key=lambda ep: ep.name,
        )
        if not eps:
            return
        exec_branch = branch.add("Exec Handlers", expand=True)
        for ep in eps:
            handler_class = ep.load()
            is_enabled = self._is_exec_handler_enabled(ep.name)
            label: str | Text = (
                Text(f"✓ {ep.name}", style="bold green")
                if is_enabled
                else Text(f"✗ {ep.name}", style="dim red")
            )
            command_prefix = getattr(handler_class, "command_prefix", b"")
            exec_branch.add_leaf(
                label,
                data=ExecHandlerInfo(
                    name=ep.name,
                    ep_value=str(ep.value),
                    command_prefix=command_prefix,
                    loaded_class=handler_class,
                    enabled=is_enabled,
                ),
            )

    def _populate_exec_handlers_into_table(self) -> None:
        eps = sorted(
            metadata.entry_points(group="sshmitm.ExecHandler"),
            key=lambda ep: ep.name,
        )
        for ep in eps:
            handler_class = ep.load()
            is_enabled = self._is_exec_handler_enabled(ep.name)
            doc = inspect.cleandoc(handler_class.__doc__ or "")
            first_line = doc.splitlines()[0] if doc else ""
            active_cell: str | Text = Text("✓", style="bold") if is_enabled else ""
            self._all_plugin_rows.append((
                "Exec Handler",
                ep.name,
                active_cell,
                str(ep.value),
                first_line,
            ))

    def _populate_tree(self) -> None:
        tree = self.query_one("#plugin-tree", PluginTree)
        tree.root.expand()

        subcommand_parsers = self._parser.subcommand_parsers
        if subcommand_parsers:
            sub_parser = subcommand_parsers.get("server") or next(
                iter(subcommand_parsers.values())
            )
            self._populate_parser_into_branch(tree.root, sub_parser)
        else:
            self._populate_parser_into_branch(tree.root, self._parser)
        self._populate_exec_handlers_into_branch(tree.root)

    def _populate_parser_into_table(
        self, parser: ModuleParser, category_prefix: str = ""
    ) -> None:
        config_section = parser.config_section
        for type_info in parser.plugin_types:
            eps = sorted(
                metadata.entry_points(
                    group=f"{type_info.base_class.entry_point_prefix}.{type_info.base_class.__name__}"
                ),
                key=lambda ep: ep.name,
            )
            if not eps:
                continue
            active_value = self._active_ep_value(type_info.config_key, config_section)
            category = (
                f"{category_prefix}{type_info.type_label}"
                if category_prefix
                else type_info.type_label
            )
            for ep in eps:
                loaded = ep.load()
                is_active = str(ep.value) == active_value
                doc = inspect.cleandoc(loaded.__doc__ or "")
                first_line = doc.splitlines()[0] if doc else ""
                active_cell: str | Text = Text("✓", style="bold") if is_active else ""
                self._all_plugin_rows.append(
                    (
                        category,
                        ep.name,
                        active_cell,
                        str(ep.value),
                        first_line,
                    )
                )

    def _populate_overview_table(self) -> None:
        tbl = self.query_one("#all-plugins-table", DataTable)
        tbl.add_columns("Category", "EP-Name", "Active", "Class", "Description")

        subcommand_parsers = self._parser.subcommand_parsers
        if subcommand_parsers:
            sub_parser = subcommand_parsers.get("server") or next(
                iter(subcommand_parsers.values())
            )
            self._populate_parser_into_table(sub_parser)
        else:
            self._populate_parser_into_table(self._parser)

        self._populate_exec_handlers_into_table()
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
        if isinstance(info, ExecHandlerInfo):
            await detail.show_exec_handler(
                info, self._default_cfg, self._user_cfg, self._config_path
            )
        elif isinstance(info, PluginInfo):
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


def run_browser(parser: ModuleParser) -> None:
    """Launch the plugin browser TUI."""
    Colors.stylize_func = False
    config_path = get_config_path()
    prog = parser.prog.split()[0]
    config = BrowserConfig(
        default_cfg=parser.ARGCONF if parser.ARGCONF is not None else ConfigParser(),
        user_cfg=load_user_cfg(config_path) if config_path else None,
        config_path=config_path,
        title=f"{prog} Plugin Browser",
        tree_root_label=prog,
        active_config_section=parser.config_section,
    )
    PluginBrowserApp(parser=parser, config=config).run()
