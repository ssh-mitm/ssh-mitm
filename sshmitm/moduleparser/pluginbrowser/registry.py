"""Generic proxy registry for the plugin browser — populated by the caller."""

from __future__ import annotations

from importlib import metadata
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from sshmitm.moduleparser.plugininfo import (
        GeneralGroupInfo,
        PluginTypeInfo,
    )


class PluginRegistry:
    """Proxy that holds plugin types and argument groups registered by the caller.

    Call ``plugin_registry.register()`` before launching the browser.
    """

    def __init__(self) -> None:
        self._plugin_types: list[PluginTypeInfo] | None = None
        self._general_groups: list[GeneralGroupInfo] | None = None
        self._ep_value_to_name: dict[str, str] | None = None

    def register(
        self,
        plugin_types: list[PluginTypeInfo],
        general_groups: list[GeneralGroupInfo],
    ) -> None:
        self._plugin_types = plugin_types
        self._general_groups = general_groups
        self._ep_value_to_name = None

    @property
    def plugin_types(self) -> list[PluginTypeInfo]:
        if self._plugin_types is None:
            msg = "plugin_registry not initialized — call plugin_registry.register() first"
            raise RuntimeError(msg)
        return self._plugin_types

    @property
    def general_groups(self) -> list[GeneralGroupInfo]:
        if self._general_groups is None:
            msg = "plugin_registry not initialized — call plugin_registry.register() first"
            raise RuntimeError(msg)
        return self._general_groups

    @property
    def ep_value_to_name(self) -> dict[str, str]:
        if self._ep_value_to_name is None:
            result: dict[str, str] = {}
            for type_info in self.plugin_types:
                for ep in metadata.entry_points(
                    group=f"{type_info.base_class.entry_point_prefix}.{type_info.base_class.__name__}"
                ):
                    result[ep.value] = ep.name
            self._ep_value_to_name = result
        return self._ep_value_to_name

    def resolve_ep_name(self, val: Any) -> str:
        """Return the entry-point name for a class object or ``module:class`` string."""
        if isinstance(val, type):
            key = f"{val.__module__}:{val.__name__}"
        elif isinstance(val, str) and ":" in val:
            key = val
        else:
            return str(val) if val is not None else ""
        return self.ep_value_to_name.get(key, key)


plugin_registry = PluginRegistry()
