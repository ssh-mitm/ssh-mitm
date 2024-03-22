import argparse
import logging
import sys
from typing import Any, Optional


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

        if (
            self.config_section
            and not self.parser.config.has_option(self.config_section, arg_dest)
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
            and self.parser.config.has_option(self.config_section, arg_dest)
            and self.parser.config.get(self.config_section, arg_dest)
        ):
            if arg_action in ("store", "store_const"):
                kwargs["default"] = self.parser.config.get(
                    self.config_section, arg_dest
                )
            elif arg_action in ("store_true", "store_false"):
                kwargs["default"] = self.parser.config.getboolean(
                    self.config_section, arg_dest
                )
        return self._add_argument(*args, **kwargs)


class BaseModuleArgumentParser(argparse.ArgumentParser):
    """Enhanced ArgumentParser to suppress warnings and error during module parsing"""

    def __init__(self, config, *args: Any, **kwargs: Any) -> None:
        self.config_section = kwargs.pop("config_section", None)
        super().__init__(*args, **kwargs)
        self.config = config
        self.exit_on_error = True
        self.add_argument = AddArgumentMethod(  # type: ignore
            parser=self, container=self
        )

    def error(self, message: str) -> None:  # type: ignore
        if self.exit_on_error:
            return
        super().error(message)

    def add_argument_group(self, *args: Any, **kwargs: Any) -> argparse._ArgumentGroup:
        config_section = kwargs.pop("config_section", None)
        group = argparse._ArgumentGroup(  # pylint:disable=protected-access
            self, *args, **kwargs
        )
        group.add_argument = AddArgumentMethod(  # type: ignore
            parser=self,
            container=group,
            config_section=config_section,
        )
        self._action_groups.append(group)
        return group
