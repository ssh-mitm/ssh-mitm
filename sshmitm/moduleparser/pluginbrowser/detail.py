"""DetailPane widget for the SSH-MITM plugin browser."""

from __future__ import annotations

import argparse
import os
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from textual.containers import (
    Horizontal,
    ScrollableContainer,
    Vertical,
    VerticalScroll,
)
from textual.reactive import reactive
from textual.widget import Widget
from textual.widgets import (
    DataTable,
    Markdown,
    Static,
    TabbedContent,
    TabPane,
    Tree,
)

from sshmitm.moduleparser.baseparser import _UNSET
from sshmitm.moduleparser.pluginbrowser.config import cfg_items
from sshmitm.moduleparser.pluginbrowser.formatters import (
    ActionRenderContext,
    action_markdown,
    cli_help_to_markdown,
    flag_str,
    group_markdown,
    help_module_section,
    type_label,
)
from sshmitm.moduleparser.pluginbrowser.widgets import PluginTree
from sshmitm.moduleparser.plugininfo import (
    ExecHandlerInfo,
    GeneralActionInfo,
    GeneralGroupInfo,
    PluginInfo,
    PluginTypeInfo,
    visible_actions,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from configparser import ConfigParser

    from textual.app import ComposeResult


@dataclass
class _TableContext:
    """Rendering context shared across all rows of the config table."""

    has_actions: bool
    has_user: bool
    default_has_section: bool
    user_has_section: bool
    default_items: dict[str, str] = field(default_factory=dict)
    user_items: dict[str, str] = field(default_factory=dict)


class DetailPane(Widget):
    """Right-hand detail pane showing plugin or group information."""

    _top_lines: reactive[int] = reactive(20)

    def __init__(
        self, *args: Any, resolver: Callable[[Any], str] | None = None, **kwargs: Any
    ) -> None:
        super().__init__(*args, **kwargs)
        self._resolver: Callable[[Any], str] = (
            resolver
            if resolver is not None
            else (lambda x: str(x) if x is not None else "")
        )
        self._plugin: PluginInfo | None = None
        self._default_cfg: ConfigParser | None = None
        self._user_cfg: ConfigParser | None = None
        self._config_path: str | None = None
        self._general_cfg_section: str | None = None

    def watch__top_lines(self, value: int) -> None:
        self.query_one("#top-section").styles.height = value

    def adjust_split(self, delta: int) -> None:
        self._top_lines = max(5, min(50, self._top_lines + delta))

    def compose(self) -> ComposeResult:
        yield Static(
            "[dim]Select a plugin from the tree on the left.[/dim]",
            id="placeholder",
        )
        with Vertical(id="plugin-view"):
            with ScrollableContainer(id="top-section"):
                yield Static(id="sec-info")
                yield Markdown("", id="sec-doc")
            with TabbedContent(id="tabs"):
                with (
                    TabPane("CLI Parameters", id="tab-cli"),
                    Horizontal(id="args-split"),
                ):
                    with Vertical(id="groups-sidebar"):
                        yield PluginTree("", id="groups-tree")
                    with VerticalScroll(id="cli-scroll"):
                        yield Markdown("", id="md-cli")
                with (
                    TabPane("Config Section", id="tab-cfg"),
                    VerticalScroll(id="cfg-scroll"),
                ):
                    yield Static("", id="cfg-header")
                    yield DataTable(
                        id="tbl-config",
                        zebra_stripes=True,
                        cursor_type="row",
                    )

    def on_mount(self) -> None:
        self.query_one("#plugin-view").display = False
        self.query_one("#groups-tree", Tree).show_root = False

    # ------------------------------------------------------------------
    # Public show-methods
    # ------------------------------------------------------------------

    async def show(
        self,
        plugin: PluginInfo,
        default_cfg: ConfigParser,
        user_cfg: ConfigParser | None,
        config_path: str | None,
    ) -> None:
        self._plugin = plugin
        self._general_cfg_section = None
        self._default_cfg = default_cfg
        self._user_cfg = user_cfg
        self._config_path = config_path

        self._set_visible()
        self.query_one("#sec-info", Static).update(
            "\n".join(
                [
                    f"[bold cyan]{plugin.name}[/bold cyan]\n",
                    f"[dim]Type[/dim]            [bold white]{plugin.type_label}[/bold white]  [yellow]{plugin.cli_flag}[/yellow]",
                    f"[dim]Class[/dim]           [cyan]{plugin.ep_value}[/cyan]",
                    "",
                ]
            )
        )
        await self.query_one("#sec-doc", Markdown).update(plugin.doc)

        groups_tree = self.query_one("#groups-tree", Tree)
        groups_tree.clear()
        first: tuple[Any, argparse._ArgumentGroup, argparse.Action] | None = None
        for group in plugin.argument_groups:
            branch = groups_tree.root.add(
                group.title or "(unnamed)", data=group, expand=True
            )
            for action in visible_actions(group):
                node = branch.add_leaf(flag_str(action), data=action)
                if first is None:
                    first = (node, group, action)

        self._fill_config_tab(plugin.config_section, plugin.actions)

        if first is not None:
            groups_tree.move_cursor(first[0])
            overview = "\n".join(group_markdown(g) for g in plugin.argument_groups)
            await self.query_one("#md-cli", Markdown).update(overview)
        else:
            await self.query_one("#md-cli", Markdown).update(
                "*This plugin has no configurable arguments.*"
            )
        self.query_one("#cli-scroll").scroll_home(animate=False)

    async def show_exec_handler(
        self,
        info: ExecHandlerInfo,
        default_cfg: ConfigParser,
        user_cfg: ConfigParser | None,
        config_path: str | None,
    ) -> None:
        self._plugin = None
        self._general_cfg_section = None
        self._default_cfg = default_cfg
        self._user_cfg = user_cfg
        self._config_path = config_path

        status_style = "bold green" if info.enabled else "bold red"
        status_text = "enabled" if info.enabled else "disabled"

        self._set_visible()
        self.query_one("#sec-info", Static).update(
            "\n".join(
                [
                    f"[bold cyan]{info.name}[/bold cyan]\n",
                    f"[dim]Type[/dim]            [bold white]{info.type_label}[/bold white]  [{status_style}]{status_text}[/{status_style}]",
                    f"[dim]Command Prefix[/dim]  [yellow]{info.command_prefix.decode()}[/yellow]",
                    f"[dim]Class[/dim]           [cyan]{info.ep_value}[/cyan]",
                    "",
                ]
            )
        )
        await self.query_one("#sec-doc", Markdown).update(info.doc)

        groups_tree = self.query_one("#groups-tree", Tree)
        groups_tree.clear()
        first: tuple[Any, argparse._ArgumentGroup, argparse.Action] | None = None
        for group in info.argument_groups:
            branch = groups_tree.root.add(
                group.title or "(unnamed)", data=group, expand=True
            )
            for action in visible_actions(group):
                node = branch.add_leaf(flag_str(action), data=action)
                if first is None:
                    first = (node, group, action)

        self._fill_config_tab(info.config_section, info.actions)

        if first is not None:
            groups_tree.move_cursor(first[0])
            overview = "\n".join(group_markdown(g) for g in info.argument_groups)
            await self.query_one("#md-cli", Markdown).update(overview)
        else:
            await self.query_one("#md-cli", Markdown).update(
                "*This exec handler has no configurable arguments.*"
            )
        self.query_one("#cli-scroll").scroll_home(animate=False)

    async def show_plugin_type(self, type_info: PluginTypeInfo) -> None:
        self._plugin = None
        self._general_cfg_section = None

        self._set_visible()
        self.query_one("#sec-info", Static).update(
            "\n".join(
                [
                    f"[bold cyan]{type_info.type_label}[/bold cyan]\n",
                    f"[dim]CLI Parameter[/dim]  [yellow]{type_info.cli_flag}[/yellow]",
                    "",
                ]
            )
        )

        parts: list[str] = []
        if type_info.doc:
            parts.append(type_info.doc)
        if type_info.help_text:
            section = help_module_section(type_info.help_text)
            if section:
                parts.append(cli_help_to_markdown(section))
        await self.query_one("#sec-doc", Markdown).update("\n\n---\n\n".join(parts))

        self.query_one("#groups-tree", Tree).clear()
        tbl = self.query_one("#tbl-config", DataTable)
        tbl.clear(columns=True)
        self.query_one("#cfg-header", Static).update("")
        await self.query_one("#md-cli", Markdown).update(
            "*Select a plugin from the list to view its parameters.*"
        )
        self.query_one("#cli-scroll").scroll_home(animate=False)

    async def show_general_group(
        self,
        group_info: GeneralGroupInfo,
        default_cfg: ConfigParser,
        user_cfg: ConfigParser | None,
        config_path: str | None,
    ) -> None:
        self._plugin = None
        self._general_cfg_section = group_info.config_section
        self._default_cfg = default_cfg
        self._user_cfg = user_cfg
        self._config_path = config_path

        self._set_visible()
        self.query_one("#sec-info", Static).update(
            "\n".join(
                [
                    f"[bold cyan]{group_info.title}[/bold cyan]\n",
                    f"[dim]Config Section[/dim]  [cyan]{group_info.config_section}[/cyan]",
                    "",
                ]
            )
        )
        await self.query_one("#sec-doc", Markdown).update(group_info.description)

        groups_tree = self.query_one("#groups-tree", Tree)
        groups_tree.clear()
        branch = groups_tree.root.add(
            group_info.title or "(unnamed)", data=group_info.group, expand=True
        )
        first: tuple[Any, argparse.Action] | None = None
        for action in visible_actions(group_info.group):
            node = branch.add_leaf(flag_str(action), data=action)
            if first is None:
                first = (node, action)

        self._fill_config_tab(
            group_info.config_section, visible_actions(group_info.group)
        )

        if first is not None:
            groups_tree.move_cursor(first[0])
        await self.query_one("#md-cli", Markdown).update(
            group_markdown(group_info.group)
        )
        self.query_one("#cli-scroll").scroll_home(animate=False)

    async def show_general_action(
        self,
        action_info: GeneralActionInfo,
        default_cfg: ConfigParser,
        user_cfg: ConfigParser | None,
        config_path: str | None,
    ) -> None:
        self._plugin = None
        self._general_cfg_section = action_info.config_section
        self._default_cfg = default_cfg
        self._user_cfg = user_cfg
        self._config_path = config_path

        self._set_visible()
        self.query_one("#sec-info", Static).update(
            "\n".join(
                [
                    f"[bold cyan]{action_info.group_title}[/bold cyan]\n",
                    f"[dim]Config Section[/dim]  [cyan]{action_info.config_section}[/cyan]",
                    "",
                ]
            )
        )
        await self.query_one("#sec-doc", Markdown).update("")

        groups_tree = self.query_one("#groups-tree", Tree)
        groups_tree.clear()
        branch = groups_tree.root.add(
            action_info.group_title or "(unnamed)",
            data=action_info.group,
            expand=True,
        )
        target_node = None
        for action in visible_actions(action_info.group):
            node = branch.add_leaf(flag_str(action), data=action)
            if action is action_info.action:
                target_node = node

        self._fill_config_tab(
            action_info.config_section, visible_actions(action_info.group)
        )

        if target_node is not None:
            groups_tree.move_cursor(target_node)
        await self._show_action(action_info.action, action_info.group)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _set_visible(self) -> None:
        self.query_one("#placeholder").display = False
        self.query_one("#plugin-view").display = True

    def _table_columns(
        self,
        has_actions: bool,
        has_user: bool,
    ) -> list[str]:
        cols: list[str] = ["Key"]
        if has_actions:
            cols += ["Type", "Default"]
        cols.append("default.ini")
        if has_user:
            cols.append(os.path.basename(self._config_path or "config"))
        return cols

    def _table_row(
        self,
        key: str,
        act: argparse.Action | None,
        tctx: _TableContext,
    ) -> list[str]:
        no_cli_arg = tctx.has_actions and act is None
        row: list[str] = [f"[yellow]⚠ {key}[/yellow]" if no_cli_arg else key]
        if tctx.has_actions:
            row.append(type_label(act) if act is not None else "")
            if act is not None:
                code_default = getattr(act, "default_arg_code", _UNSET)
                if code_default is _UNSET or code_default is argparse.SUPPRESS:
                    row.append("[dim]✗[/dim]")
                else:
                    resolved = (
                        self._resolver(code_default) if code_default is not None else ""
                    )
                    row.append(f"✓ {resolved}" if resolved else "✓")
            else:
                row.append("")
        if not tctx.default_has_section or key not in tctx.default_items:
            row.append("[dim italic]⚠ not in config[/dim italic]")
        else:
            row.append(self._resolver(tctx.default_items[key]))
        if tctx.has_user:
            if not tctx.user_has_section or key not in tctx.user_items:
                row.append("")
            else:
                row.append(self._resolver(tctx.user_items[key]))
        return row

    def _fill_config_tab(
        self,
        section: str,
        actions: list[argparse.Action] | None = None,
    ) -> None:
        default_items = cfg_items(self._default_cfg, section)
        user_items = cfg_items(self._user_cfg, section)

        action_map: dict[str, argparse.Action] = {}
        action_dash_keys: set[str] = set()
        for a in actions or []:
            action_map[a.dest] = a
            action_map[a.dest.replace("_", "-")] = a
            action_dash_keys.add(a.dest.replace("_", "-"))

        tctx = _TableContext(
            has_actions=bool(action_map),
            has_user=self._user_cfg is not None,
            default_items=default_items,
            user_items=user_items,
            default_has_section=(
                self._default_cfg is not None and self._default_cfg.has_section(section)
            ),
            user_has_section=(
                self._user_cfg is not None and self._user_cfg.has_section(section)
            ),
        )

        all_keys = sorted(set(default_items) | set(user_items) | action_dash_keys)

        header = f"[bold cyan]\\[{section}][/bold cyan]"
        if not tctx.default_has_section:
            header += "  [yellow]⚠ section not in default.ini — can be added[/yellow]"
        self.query_one("#cfg-header", Static).update(header)

        tbl = self.query_one("#tbl-config", DataTable)
        tbl.clear(columns=True)
        tbl.add_columns(*self._table_columns(tctx.has_actions, tctx.has_user))
        for key in all_keys:
            act = action_map.get(key) if tctx.has_actions else None
            tbl.add_row(*self._table_row(key, act, tctx))

    async def _show_action(
        self,
        action: argparse.Action,
        group: argparse._ArgumentGroup | None = None,
    ) -> None:
        config_section: str | None = None
        add_arg = getattr(group, "add_argument", None) if group else None
        if add_arg is not None and hasattr(add_arg, "config_section"):
            config_section = add_arg.config_section
        if config_section is None and self._plugin is not None:
            config_section = self._plugin.config_section
        if config_section is None:
            config_section = self._general_cfg_section
        if config_section is None:
            return

        ctx = ActionRenderContext(
            default_items=cfg_items(self._default_cfg, config_section),
            user_items=cfg_items(self._user_cfg, config_section),
            config_label=(
                os.path.basename(self._config_path) if self._config_path else None
            ),
            config_section=config_section,
            group_title=group.title if group and group.title else None,
        )
        await self.query_one("#md-cli", Markdown).update(action_markdown(action, ctx))
        self.query_one("#cli-scroll").scroll_home(animate=False)

    async def _show_group_overview(self, group: argparse._ArgumentGroup) -> None:
        await self.query_one("#md-cli", Markdown).update(group_markdown(group))
        self.query_one("#cli-scroll").scroll_home(animate=False)

    async def on_tree_node_selected(self, event: Tree.NodeSelected[Any]) -> None:
        event.stop()
        data = event.node.data
        if isinstance(data, argparse.Action):
            parent_data = event.node.parent.data if event.node.parent else None
            group = (
                parent_data
                if isinstance(
                    parent_data,
                    argparse._ArgumentGroup,  # pylint: disable=protected-access
                )
                else None
            )
            await self._show_action(data, group)
        elif isinstance(
            data, argparse._ArgumentGroup  # pylint: disable=protected-access
        ):
            await self._show_group_overview(data)
