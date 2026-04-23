"""Reusable Textual widgets for the SSH-MITM plugin browser."""

from __future__ import annotations

from typing import Any

from textual.binding import Binding
from textual.widgets import Tree


class PluginTree(Tree[Any]):
    """Navigation tree with keyboard bindings for the plugin browser."""

    BINDINGS = [  # noqa: RUF012
        Binding("enter", "select_cursor", "Show Info", show=True),
        Binding("space", "toggle_node", "Expand/Collapse", show=True),
    ]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.auto_expand = False
