"""SSH-MITM plugin inspection commands and TUI browser."""

from __future__ import annotations

import argparse
import contextlib
import functools
import importlib.resources
import inspect
import os
import re
import sys
from configparser import ConfigParser
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

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
    VerticalScroll,
)
from textual.css.query import (
    NoMatches,
)
from textual.reactive import (
    reactive,
)
from textual.widget import Widget
from textual.widgets import (
    DataTable,
    Footer,
    Header,
    Markdown,
    Static,
    TabbedContent,
    TabPane,
    Tree,
)

from sshmitm.cli import create_parser as _create_main_parser
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


@dataclass
class PluginTypeInfo:
    type_label: str
    cli_flag: str
    help_text: str
    base_class: type[BaseModule]

    @property
    def doc(self) -> str:
        return inspect.cleandoc(self.base_class.__doc__ or "")


@dataclass
class GeneralGroupInfo:
    title: str
    description: str
    config_section: str
    group: argparse._ArgumentGroup


@dataclass
class GeneralActionInfo:
    action: argparse.Action
    group: argparse._ArgumentGroup
    group_title: str
    config_section: str


def _extract_groups(
    parser: argparse.ArgumentParser,
    skip: set[str | None],
) -> list[GeneralGroupInfo]:
    """Extract visible argument groups from a parser, excluding standard/skipped groups."""
    groups: list[GeneralGroupInfo] = []
    for g in parser._action_groups:  # pylint: disable=protected-access
        if g.title in skip:
            continue
        visible = [
            a
            for a in g._group_actions  # pylint: disable=protected-access
            if a.dest is not argparse.SUPPRESS and a.help != argparse.SUPPRESS
        ]
        if not visible:
            continue
        cfg_section = ""
        add_arg = getattr(g, "add_argument", None)
        if add_arg is not None and hasattr(add_arg, "config_section"):
            cfg_section = add_arg.config_section or ""
        groups.append(
            GeneralGroupInfo(
                title=g.title or "(unnamed)",
                description=g.description or "",
                config_section=cfg_section,
                group=g,
            )
        )
    return groups


@functools.cache
def _server_info() -> tuple[list[PluginTypeInfo], list[GeneralGroupInfo]]:
    """Return plugin type info and general argument groups from all SSH-MITM parsers."""
    standard_groups = {"positional arguments", "optional arguments", "options", None}

    # Main parser: provides the [SSH-MITM] config section
    main_parser = _create_main_parser()
    general_groups = _extract_groups(main_parser, standard_groups)

    # Server command parser: provides [SSH-Server-Modules] and [SSH-Server-Options]
    mp = ModuleParser(prog="sshmitm")
    sub = mp.add_subparsers()
    cmd = SSHServerModules("server", sub)
    cmd.register_arguments()

    plugin_types = [
        PluginTypeInfo(
            type_label=_class_to_label(baseclass.__name__),
            cli_flag=action.option_strings[0],
            help_text=action.help or "",
            base_class=baseclass,
        )
        for action, baseclass in cmd.parser._extra_modules  # pylint: disable=protected-access
        if action.option_strings
    ]

    # Include all server groups, including plugin_group (SSH-Server-Modules)
    general_groups += _extract_groups(cmd.parser, standard_groups)

    return plugin_types, general_groups


# ---------------------------------------------------------------------------
# Config helpers
# ---------------------------------------------------------------------------


def _load_default_cfg() -> ConfigParser:
    cfg = ConfigParser()
    conf = resources.files("sshmitm") / "data/default.ini"
    cfg.read_string(conf.read_text())
    return cfg


def _get_config_path() -> str | None:
    """Read --config path directly from sys.argv."""
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("--config", dest="config_path")
    parsed, _ = p.parse_known_args(sys.argv[1:])
    return str(parsed.config_path) if parsed.config_path is not None else None


def _load_user_cfg(path: str) -> ConfigParser:
    cfg = ConfigParser()
    cfg.read(os.path.expanduser(path))
    return cfg


def _cfg_items(cfg: ConfigParser | None, section: str) -> dict[str, str]:
    if cfg is None or not cfg.has_section(section):
        return {}
    return dict(cfg.items(section))


# ---------------------------------------------------------------------------
# Shared plugin lookup
# ---------------------------------------------------------------------------

_SKIP_GROUPS = {"positional arguments", "optional arguments", "options"}


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
    def argument_groups(self) -> list[argparse._ArgumentGroup]:
        try:
            parser = self.loaded_class.parser()
        except Exception:  # noqa: BLE001  # pylint: disable=broad-exception-caught
            return []
        return [
            g
            for g in parser._action_groups  # pylint: disable=protected-access
            if g.title not in _SKIP_GROUPS
            and any(
                a.dest is not argparse.SUPPRESS and a.help != argparse.SUPPRESS
                for a in g._group_actions  # pylint: disable=protected-access
            )
        ]

    @property
    def actions(self) -> list[argparse.Action]:
        return [
            a
            for g in self.argument_groups
            for a in g._group_actions  # pylint: disable=protected-access
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


_TCSS = (
    importlib.resources.files("sshmitm")
    .joinpath("data/plugins_browser.tcss")
    .read_text(encoding="utf-8")
)


def _run_tui() -> None:  # noqa: C901, PLR0915

    def _visible_actions(group: argparse._ArgumentGroup) -> list[argparse.Action]:
        return [
            a
            for a in group._group_actions  # pylint: disable=protected-access
            if a.dest is not argparse.SUPPRESS and a.help != argparse.SUPPRESS
        ]

    def _flag_str(action: argparse.Action) -> str:
        return (
            ", ".join(action.option_strings)
            if action.option_strings
            else f"<{action.dest}>"
        )

    def _cfg_get(items: dict[str, str], dest: str) -> str | None:
        val = items.get(dest)
        if val is None:
            val = items.get(dest.replace("_", "-"))
        return val

    def _type_label(action: argparse.Action) -> str:
        if action.type is not None:
            return getattr(action.type, "__name__", str(action.type))
        if action.__class__.__name__ in (
            "_StoreTrueAction",
            "_StoreFalseAction",
            "BooleanOptionalAction",
        ):
            return "bool"
        return "str"

    def _fmt_cfg_val(val: str | None) -> str:
        if val is None:
            return "*(not set)*"
        if val == "":
            return "*(empty)*"
        return f"`{val}`"

    def _action_markdown(  # pylint: disable=too-many-arguments
        action: argparse.Action,
        cfg_items: dict[str, str],
        user_items: dict[str, str],
        config_label: str | None,
        group_title: str | None = None,
        config_section: str | None = None,
    ) -> str:
        flags_md = (
            " / ".join(f"`{f}`" for f in action.option_strings)
            if action.option_strings
            else f"`<{action.dest}>`"
        )
        lines: list[str] = []
        if group_title:
            lines += [f"### {group_title}", ""]
        lines += [f"## {flags_md}", ""]

        if action.help:
            help_text = inspect.cleandoc(action.help)
            help_text = re.sub(r"\n(?!\n)", "  \n", help_text)
            lines += [help_text, ""]

        lines += [
            "### CLI Properties",
            "",
            "| Property | Value |",
            "|:---|:---|",
        ]

        lines.append(f"| **Type** | `{_type_label(action)}` |")

        default = action.default
        if default is None or default is argparse.SUPPRESS or default is False:
            default_str = "*(none)*"
        else:
            default_str = f"`{default}`"
        lines.append(f"| **Default** | {default_str} |")

        required_str = "**yes**" if getattr(action, "required", False) else "no"
        lines.append(f"| **Required** | {required_str} |")

        lines += [
            "",
            "### Configuration",
            "",
            "| Source | Value |",
            "|:---|:---|",
        ]
        if config_section:
            lines.append(f"| **Section** | `{config_section}` |")
        lines.append(f"| **Config key** | `{action.dest}` |")

        ini_val = _cfg_get(cfg_items, action.dest)
        lines.append(f"| **default.ini** | {_fmt_cfg_val(ini_val)} |")

        if config_label is not None:
            user_val = _cfg_get(user_items, action.dest)
            lines.append(f"| **{config_label}** | {_fmt_cfg_val(user_val)} |")

        if hasattr(action, "choices") and action.choices:
            lines += ["", "### Choices", ""]
            for choice in action.choices:
                lines.append(f"- `{choice}`")

        lines.append("")
        return "\n".join(lines)

    def _group_markdown(group: argparse._ArgumentGroup) -> str:
        lines: list[str] = [f"# {group.title}", ""]
        if group.description:
            lines += [group.description, ""]
        actions = _visible_actions(group)
        if actions:
            lines += ["| Flag | Description |", "|---|---|"]
            for action in actions:
                lines.append(f"| `{_flag_str(action)}` | {action.help or ''} |")
        lines.append("")
        return "\n".join(lines)

    class DetailPane(Widget):
        """Right-hand detail pane."""

        _top_lines: reactive[int] = reactive(20)

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
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
                            yield _PluginTree("", id="groups-tree")
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

            self.query_one("#placeholder").display = False
            self.query_one("#plugin-view").display = True

            lines = [
                f"[bold cyan]{plugin.name}[/bold cyan]\n",
                f"[dim]Type[/dim]            [bold white]{plugin.type_label}[/bold white]  [yellow]{plugin.cli_flag}[/yellow]",
                f"[dim]Class[/dim]           [cyan]{plugin.ep_value}[/cyan]",
                "",
            ]
            self.query_one("#sec-info", Static).update("\n".join(lines))
            await self.query_one("#sec-doc", Markdown).update(plugin.doc)

            groups_tree = self.query_one("#groups-tree", Tree)
            groups_tree.clear()
            first: tuple[Any, argparse._ArgumentGroup, argparse.Action] | None = None
            for group in plugin.argument_groups:
                branch = groups_tree.root.add(
                    group.title or "(unnamed)", data=group, expand=True
                )
                for action in _visible_actions(group):
                    node = branch.add_leaf(_flag_str(action), data=action)
                    if first is None:
                        first = (node, group, action)

            self._fill_config_tab_for_section(plugin.config_section, plugin.actions)

            if first is not None:
                groups_tree.move_cursor(first[0])
                overview = "\n".join(_group_markdown(g) for g in plugin.argument_groups)
                await self.query_one("#md-cli", Markdown).update(overview)
            else:
                await self.query_one("#md-cli", Markdown).update(
                    "*This plugin has no configurable arguments.*"
                )
            self.query_one("#cli-scroll").scroll_home(animate=False)

        async def show_plugin_type(self, type_info: PluginTypeInfo) -> None:
            """Show info about a plugin type category."""
            self._plugin = None
            self._general_cfg_section = None

            self.query_one("#placeholder").display = False
            self.query_one("#plugin-view").display = True

            lines = [
                f"[bold cyan]{type_info.type_label}[/bold cyan]\n",
                f"[dim]CLI Parameter[/dim]  [yellow]{type_info.cli_flag}[/yellow]",
                "",
            ]
            self.query_one("#sec-info", Static).update("\n".join(lines))

            parts: list[str] = []
            if type_info.help_text:
                parts.append(re.sub(r"\n(?!\n)", "  \n", type_info.help_text))
            if type_info.doc:
                parts.append(type_info.doc)
            await self.query_one("#sec-doc", Markdown).update("\n\n---\n\n".join(parts))

            groups_tree = self.query_one("#groups-tree", Tree)
            groups_tree.clear()

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
            """Show info about a general server argument group."""
            self._plugin = None
            self._general_cfg_section = group_info.config_section
            self._default_cfg = default_cfg
            self._user_cfg = user_cfg
            self._config_path = config_path

            self.query_one("#placeholder").display = False
            self.query_one("#plugin-view").display = True

            lines = [
                f"[bold cyan]{group_info.title}[/bold cyan]\n",
                f"[dim]Config Section[/dim]  [cyan]{group_info.config_section}[/cyan]",
                "",
            ]
            self.query_one("#sec-info", Static).update("\n".join(lines))
            await self.query_one("#sec-doc", Markdown).update(group_info.description)

            groups_tree = self.query_one("#groups-tree", Tree)
            groups_tree.clear()
            branch = groups_tree.root.add(
                group_info.title or "(unnamed)", data=group_info.group, expand=True
            )
            first: tuple[Any, argparse.Action] | None = None
            for action in _visible_actions(group_info.group):
                node = branch.add_leaf(_flag_str(action), data=action)
                if first is None:
                    first = (node, action)

            self._fill_config_tab_for_section(
                group_info.config_section, _visible_actions(group_info.group)
            )

            if first is not None:
                groups_tree.move_cursor(first[0])
            await self.query_one("#md-cli", Markdown).update(
                _group_markdown(group_info.group)
            )
            self.query_one("#cli-scroll").scroll_home(animate=False)

        async def show_general_action(
            self,
            action_info: GeneralActionInfo,
            default_cfg: ConfigParser,
            user_cfg: ConfigParser | None,
            config_path: str | None,
        ) -> None:
            """Show detail for a general server argument."""
            self._plugin = None
            self._general_cfg_section = action_info.config_section
            self._default_cfg = default_cfg
            self._user_cfg = user_cfg
            self._config_path = config_path

            self.query_one("#placeholder").display = False
            self.query_one("#plugin-view").display = True

            lines = [
                f"[bold cyan]{action_info.group_title}[/bold cyan]\n",
                f"[dim]Config Section[/dim]  [cyan]{action_info.config_section}[/cyan]",
                "",
            ]
            self.query_one("#sec-info", Static).update("\n".join(lines))
            await self.query_one("#sec-doc", Markdown).update("")

            groups_tree = self.query_one("#groups-tree", Tree)
            groups_tree.clear()
            branch = groups_tree.root.add(
                action_info.group_title or "(unnamed)",
                data=action_info.group,
                expand=True,
            )
            target_node = None
            for action in _visible_actions(action_info.group):
                node = branch.add_leaf(_flag_str(action), data=action)
                if action is action_info.action:
                    target_node = node

            self._fill_config_tab_for_section(
                action_info.config_section, _visible_actions(action_info.group)
            )

            if target_node is not None:
                groups_tree.move_cursor(target_node)
            await self._show_action(action_info.action, action_info.group)

        def _fill_config_tab_for_section(
            self,
            section: str,
            actions: list[argparse.Action] | None = None,
        ) -> None:
            cfg_items = _cfg_items(self._default_cfg, section)
            user_items = _cfg_items(self._user_cfg, section)
            all_keys = sorted(set(cfg_items) | set(user_items))
            has_user = self._user_cfg is not None

            action_map: dict[str, argparse.Action] = {}
            if actions:
                for a in actions:
                    action_map[a.dest] = a
                    action_map[a.dest.replace("_", "-")] = a

            self.query_one("#cfg-header", Static).update(
                f"[bold cyan]\\[{section}][/bold cyan]"
            )

            tbl = self.query_one("#tbl-config", DataTable)
            tbl.clear(columns=True)
            has_actions = bool(action_map)
            cols: list[str] = ["Key"]
            if has_actions:
                cols.append("Type")
            cols.append("default.ini")
            if has_user:
                cols.append(os.path.basename(self._config_path or "config"))
            tbl.add_columns(*cols)
            for key in all_keys:
                row: list[str] = [key]
                if has_actions:
                    act = action_map.get(key)
                    row.append(_type_label(act) if act is not None else "")
                row.append(cfg_items.get(key, ""))
                if has_user:
                    row.append(user_items.get(key, ""))
                tbl.add_row(*row)

        async def _show_action(
            self,
            action: argparse.Action,
            group: argparse._ArgumentGroup | None = None,
        ) -> None:
            # Resolve config section: from group, then plugin, then stored general section
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

            cfg_items = _cfg_items(self._default_cfg, config_section)
            user_items = _cfg_items(self._user_cfg, config_section)
            config_label = (
                os.path.basename(self._config_path) if self._config_path else None
            )
            group_title = group.title if group and group.title else None
            md = _action_markdown(
                action,
                cfg_items,
                user_items,
                config_label,
                group_title,
                config_section=config_section,
            )
            await self.query_one("#md-cli", Markdown).update(md)
            self.query_one("#cli-scroll").scroll_home(animate=False)

        async def _show_group_overview(self, group: argparse._ArgumentGroup) -> None:
            md = _group_markdown(group)
            await self.query_one("#md-cli", Markdown).update(md)
            self.query_one("#cli-scroll").scroll_home(animate=False)

        async def on_tree_node_selected(
            self,
            event: Tree.NodeSelected[Any],
        ) -> None:
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

    class _PluginTree(Tree[Any]):
        BINDINGS = [  # noqa: RUF012
            Binding("enter", "select_cursor", "Show Info", show=True),
            Binding("space", "toggle_node", "Expand/Collapse", show=True),
        ]

        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            self.auto_expand = False

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
                    yield _PluginTree("SSH-MITM", id="plugin-tree")
                yield DetailPane(id="detail")
            yield Footer()

        def on_mount(self) -> None:
            self.theme = "gruvbox"
            self._populate_tree()
            tree = self.query_one("#plugin-tree", _PluginTree)
            tree.show_root = False
            tree.focus()

        def _populate_tree(self) -> None:
            tree = self.query_one("#plugin-tree", _PluginTree)
            tree.root.expand()

            plugin_types, general_groups = _server_info()

            if general_groups:
                server_branch = tree.root.add("Server Parameters", expand=True)
                for group_info in general_groups:
                    server_branch.add_leaf(group_info.title, data=group_info)

            plugins_branch = tree.root.add("Plugins", expand=True)
            for type_info in plugin_types:
                eps = sorted(
                    metadata.entry_points(
                        group=f"sshmitm.{type_info.base_class.__name__}"
                    ),
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
            with contextlib.suppress(NoMatches):
                self.query_one("#groups-tree", Tree).focus()

        def action_focus_tree(self) -> None:
            with contextlib.suppress(NoMatches):
                self.query_one("#plugin-tree", _PluginTree).focus()

        def action_shrink_desc(self) -> None:
            with contextlib.suppress(NoMatches):
                self.query_one(DetailPane).adjust_split(-3)

        def action_grow_desc(self) -> None:
            with contextlib.suppress(NoMatches):
                self.query_one(DetailPane).adjust_split(3)

    default_cfg = _load_default_cfg()
    config_path = _get_config_path()
    user_cfg = _load_user_cfg(config_path) if config_path else None
    PluginBrowserApp(default_cfg, user_cfg, config_path).run()
