"""Text and Markdown formatting helpers for the plugin browser."""

from __future__ import annotations

import argparse
import inspect
from dataclasses import dataclass, field

from sshmitm.moduleparser.plugininfo import visible_actions


def help_module_section(text: str) -> str:
    """Extract only the 'default module' and 'available modules' lines from help text."""
    lines = text.split("\n")
    result: list[str] = []
    in_section = False
    for line in lines:
        if line.startswith("default module:") or line.strip() == "available modules:":
            in_section = True
        if in_section:
            result.append(line)
    return "\n".join(result)


def cli_help_to_markdown(text: str) -> str:
    """Convert CLI-formatted module help text to Markdown."""
    lines = text.split("\n")
    out: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.startswith("default module:"):
            module = line[len("default module:") :].strip()
            if out and out[-1] != "":
                out.append("")
            out.append(f"**Default module:** `{module}`")
        elif line.strip() == "available modules:":
            if out and out[-1] != "":
                out.append("")
            out.append("**Available modules:**\n")
            i += 1
            while i < len(lines):
                entry = lines[i]
                stripped = entry.lstrip("\t").lstrip()
                if not stripped.startswith("* "):
                    break
                content = stripped[2:]
                if " -> " in content:
                    name, desc = content.split(" -> ", 1)
                    out.append(f"- **{name}**" + (f" — {desc}" if desc.strip() else ""))
                else:
                    out.append(f"- **{content}**")
                i += 1
            continue
        else:
            out.append(line)
        i += 1
    return "\n".join(out)


def flag_str(action: argparse.Action) -> str:
    return (
        ", ".join(action.option_strings)
        if action.option_strings
        else f"<{action.dest}>"
    )


def type_label(action: argparse.Action) -> str:
    if action.type is not None:
        return getattr(action.type, "__name__", str(action.type))
    if action.__class__.__name__ in (
        "_StoreTrueAction",
        "_StoreFalseAction",
        "BooleanOptionalAction",
    ):
        return "bool"
    return "str"


def cfg_get(items: dict[str, str], dest: str) -> str | None:
    val = items.get(dest)
    if val is None:
        val = items.get(dest.replace("_", "-"))
    return val


def fmt_cfg_val(val: str | None, in_config: bool = True) -> str:
    if not in_config:
        return "*(not in config — can be added)*"
    if val is None:
        return "*(not set)*"
    if val == "":
        return "*(empty)*"
    return f"`{val}`"


@dataclass
class ActionRenderContext:
    """Config/display context passed to action_markdown."""

    default_items: dict[str, str] = field(default_factory=dict)
    user_items: dict[str, str] = field(default_factory=dict)
    config_label: str | None = None
    config_section: str | None = None
    group_title: str | None = None


def action_markdown(action: argparse.Action, ctx: ActionRenderContext) -> str:
    flags_md = (
        " / ".join(f"`{f}`" for f in action.option_strings)
        if action.option_strings
        else f"`<{action.dest}>`"
    )
    lines: list[str] = []
    if ctx.group_title:
        lines += [f"### {ctx.group_title}", ""]
    lines += [f"## {flags_md}", ""]

    if action.help and action.help != argparse.SUPPRESS:
        help_text = cli_help_to_markdown(inspect.cleandoc(action.help))
        lines += [help_text, ""]

    lines += [
        "### CLI Properties",
        "",
        "| Property | Value |",
        "|:---|:---|",
    ]
    lines.append(f"| **Type** | `{type_label(action)}` |")

    default = action.default
    if default is None or default is argparse.SUPPRESS or default is False:
        default_str = "*(none)*"
    else:
        default_str = f"`{default}`"
    lines.append(f"| **Default** | {default_str} |")
    lines.append(
        f"| **Required** | {'**yes**' if getattr(action, 'required', False) else 'no'} |"
    )

    lines += ["", "### Configuration", "", "| Source | Value |", "|:---|:---|"]
    if ctx.config_section:
        lines.append(f"| **Section** | `{ctx.config_section}` |")
    lines.append(f"| **Config key** | `{action.dest}` |")

    ini_val = cfg_get(ctx.default_items, action.dest)
    ini_in_cfg = (
        action.dest in ctx.default_items
        or action.dest.replace("_", "-") in ctx.default_items
    )
    lines.append(f"| **default.ini** | {fmt_cfg_val(ini_val, ini_in_cfg)} |")

    if ctx.config_label is not None:
        user_val = cfg_get(ctx.user_items, action.dest)
        lines.append(f"| **{ctx.config_label}** | {fmt_cfg_val(user_val)} |")

    if hasattr(action, "choices") and action.choices:
        lines += ["", "### Choices", ""]
        for choice in action.choices:
            lines.append(f"- `{choice}`")

    lines.append("")
    return "\n".join(lines)


def group_markdown(group: argparse._ArgumentGroup) -> str:
    lines: list[str] = [f"# {group.title}", ""]
    if group.description:
        lines += [group.description, ""]
    actions = visible_actions(group)
    if actions:
        lines += ["| Flag | Description |", "|---|---|"]
        for action in actions:
            raw = (
                ""
                if not action.help or action.help == argparse.SUPPRESS
                else action.help
            )
            help_str = raw.split("\n")[0] if raw else ""
            lines.append(f"| `{flag_str(action)}` | {help_str} |")
    lines.append("")
    return "\n".join(lines)
