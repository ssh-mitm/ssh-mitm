import argparse
import logging
import sys
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from configparser import ConfigParser


class AddArgumentMethod:
    """
    A wrapper class for ``argparse._ActionsContainer.add_argument``.

    This class enhances the standard ``add_argument`` method by adding support for
    configuration values from a ``ConfigParser`` instance. It automatically retrieves
    default values from the configuration file if available.

    :param parser: The ``BaseModuleArgumentParser`` instance.
    :param container: The container for the argument, defaults to the parser.
    :param config_section: The section in the configuration file to use for defaults.
    """

    def __init__(
        self,
        *,
        parser: "BaseModuleArgumentParser",
        container: Optional[argparse._ActionsContainer] = None,
        config_section: Optional[str] = None,
    ) -> None:
        """
        Initialize the ``AddArgumentMethod`` wrapper.

        :param parser: The ``BaseModuleArgumentParser`` instance.
        :param container: The container for the argument, defaults to the parser.
        :param config_section: The section in the configuration file to use for defaults.
        """
        self.parser = parser
        self.container = container or parser
        self.config_section = config_section or self.parser.config_section
        self._add_argument = self.container.add_argument

    def _get_dest(self, *args: Any, **kwargs: Any) -> Any:
        """
        Get the destination attribute name for the argument.

        This method extracts the destination name from either the ``dest`` keyword
        argument or the first positional argument.

        :param args: Positional arguments for ``add_argument``.
        :param kwargs: Keyword arguments for ``add_argument``.
        :return: The destination attribute name.
        """
        dest_1 = kwargs.get("dest")
        dest_2 = None
        if dest_1 is not None:
            dest_1 = dest_1.replace("_", "-")
        if len(args) >= 1:
            dest_2 = args[0].lstrip(self.container.prefix_chars)
            dest_2 = dest_2.replace("_", "-")
        return dest_1 or dest_2

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        """
        Call the wrapped ``add_argument`` method with enhanced functionality.

        This method checks the configuration file for default values and applies them
        to the argument if available. It also logs missing configuration values in debug mode.

        :param args: Positional arguments for ``add_argument``.
        :param kwargs: Keyword arguments for ``add_argument``.
        :return: The result of the ``add_argument`` call.
        """
        default_value = kwargs.get("default")
        arg_dest = self._get_dest(*args, **kwargs)
        arg_action = kwargs.get("action", "store")

        # Log missing configuration values in debug mode
        if not self.parser.ARGCONF or (
            self.config_section
            and not self.parser.ARGCONF.has_option(self.config_section, arg_dest)
            and arg_action != "version"
            and sys.flags.debug
        ):
            logging.error(
                "Missing config value - %s - %s (%s) = %s",
                self.config_section,
                arg_dest,
                arg_action,
                default_value,
            )

        # Set default values from configuration if available
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
    """
    Enhanced ``ArgumentParser`` for module parsing.

    This class extends ``argparse.ArgumentParser`` to suppress warnings and errors
    during module parsing. It also integrates with a ``ConfigParser`` instance to
    provide default values from configuration files.

    .. attribute:: ARGCONF

        A class attribute to store the ``ConfigParser`` instance.

    .. attribute:: exit_on_error

        A flag to control whether the parser should exit on errors.
    """

    ARGCONF = None

    def __init__(
        self,
        *args: Any,
        entry_point_prefix: Optional[str] = None,
        config: Optional["ConfigParser"] = None,
        config_section: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize the ``BaseModuleArgumentParser``.

        :param args: Positional arguments for ``ArgumentParser``.
        :param config: Optional ``ConfigParser`` instance for configuration values.
        :param kwargs: Keyword arguments for ``ArgumentParser``.
        """
        if config:
            BaseModuleArgumentParser.ARGCONF = config

        self.entry_point_prefix = entry_point_prefix
        self.config_section = config_section
        super().__init__(*args, **kwargs)
        self.exit_on_error = True

        # Override the add_argument method with our enhanced version
        self.add_argument = AddArgumentMethod(parser=self, container=self)  # type: ignore[method-assign]

    def error(self, message: str) -> None:  # type: ignore[override]
        """
        Handle parsing errors.

        This method suppresses errors if ``exit_on_error`` is ``False``.

        :param message: The error message.
        """
        if self.exit_on_error:
            return
        super().error(message)

    def add_argument_group(
        self, *args: Any, config_section: Optional[str] = None, **kwargs: Any
    ) -> argparse._ArgumentGroup:
        """
        Add an argument group to the parser.

        This method creates an argument group with enhanced ``add_argument``
        functionality, similar to the main parser.

        :param args: Positional arguments for ``add_argument_group``.
        :param config_section: config section name for default argument values.
        :param kwargs: Keyword arguments for ``add_argument_group``.
        :return: The created argument group.
        """
        group = argparse._ArgumentGroup(  # pylint:disable=protected-access
            self, *args, **kwargs
        )

        # Override the add_argument method for the group
        group.add_argument = AddArgumentMethod(  # type: ignore[method-assign]
            parser=self,
            container=group,
            config_section=config_section,
        )

        self._action_groups.append(group)
        return group
