import argparse
import logging
import sys
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from configparser import ConfigParser


class AddArgumentMethod:
    def __init__(
        self,
        *,
        parser: "BaseModuleArgumentParser",
        container: Optional[argparse._ActionsContainer] = None,
        config_section: Optional[str] = None,
    ) -> None:
        self.parser = parser
        self.container = container or parser
        self.config_section = config_section or self.parser.config_section
        self._add_argument = self.container.add_argument

    def _get_dest(self, *args: Any, **kwargs: Any) -> Any:
        dest_1 = kwargs.get("dest")
        dest_2 = None
        if dest_1 is not None:
            dest_1 = dest_1.replace("_", "-")
        if len(args) >= 1:
            dest_2 = args[0].lstrip(self.container.prefix_chars)
            dest_2 = dest_2.replace("_", "-")
        return dest_1 or dest_2

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        default_value = kwargs.get("default")
        arg_dest = self._get_dest(*args, **kwargs)
        arg_action = kwargs.get("action", "store")

        if not self.parser.ARGCONF or (
            self.config_section
            and not self.parser.ARGCONF.has_option(self.config_section, arg_dest)
            and arg_action != "version"
            and sys.flags.debug
        ):
            logging.error(
                "Missing config value -  %s - %s (%s) = %s",
                self.config_section,
                arg_dest,
                arg_action,
                default_value,
            )

        if (
            arg_dest
            and self.parser.ARGCONF
            and self.parser.ARGCONF.has_option(self.config_section, arg_dest)
            and self.parser.ARGCONF.get(self.config_section, arg_dest)
        ):
            if arg_action in ("store", "store_const"):
                kwargs["default"] = self.parser.ARGCONF.get(
                    self.config_section, arg_dest
                )
            elif arg_action in ("store_true", "store_false"):
                kwargs["default"] = self.parser.ARGCONF.getboolean(
                    self.config_section, arg_dest
                )
        return self._add_argument(*args, **kwargs)


class BaseModuleArgumentParser(argparse.ArgumentParser):
    """Enhanced ArgumentParser to suppress warnings and error during module parsing"""

    ARGCONF = None

    def __init__(
        self, *args: Any, config: Optional["ConfigParser"] = None, **kwargs: Any
    ) -> None:
        if config:
            BaseModuleArgumentParser.ARGCONF = config
        self.config_section = kwargs.pop("config_section", None)
        super().__init__(*args, **kwargs)
        self.exit_on_error = True
        self.add_argument = AddArgumentMethod(parser=self, container=self)  # type: ignore[method-assign]

    def error(self, message: str) -> None:  # type: ignore[override]
        if self.exit_on_error:
            return
        super().error(message)

    def add_argument_group(self, *args: Any, **kwargs: Any) -> argparse._ArgumentGroup:
        config_section = kwargs.pop("config_section", None)
        group = argparse._ArgumentGroup(  # pylint:disable=protected-access
            self, *args, **kwargs
        )
        group.add_argument = AddArgumentMethod(  # type: ignore[method-assign]
            parser=self,
            container=group,
            config_section=config_section,
        )
        self._action_groups.append(group)
        return group
