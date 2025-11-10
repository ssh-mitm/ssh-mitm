# Module `parser` shadows a Python standard-library module
"""
BaseModule parsing library.

This module is an extension to the standard Argparse module, which offers the possibility to load classes as BaseModule.

This module contains the following public class:

    - :class:`ModuleParser` -- Entry point to parse command line parameters.
        This class provides the same functionality as the ArgumentParser
        from the argparse module. However, it is possible to specify BaseModules and Plugins,
        which extend the functionality of the parser and the application respectively.
"""

import argparse
import inspect
import logging
import os
from importlib import import_module
from typing import (
    TYPE_CHECKING,
    Any,
    Dict,
    List,
    Optional,
    Sequence,
    Set,
    Tuple,
    Type,
    cast,
)

import argcomplete

from sshmitm.core.compat import metadata
from sshmitm.moduleparser.baseparser import BaseModuleArgumentParser
from sshmitm.moduleparser.exceptions import ModuleError
from sshmitm.moduleparser.formatter import ModuleFormatter
from sshmitm.moduleparser.modules import BaseModule, SubCommand
from sshmitm.moduleparser.utils import load_module, set_module_kwargs

if TYPE_CHECKING:
    from configparser import ConfigParser


class ModuleParser(BaseModuleArgumentParser):
    """
    Main parser class for handling command-line arguments and modules.

    This class extends the functionality of the standard ``argparse.ArgumentParser``
    by allowing the registration and parsing of ``BaseModule`` classes and plugins.
    It supports loading modules from entry points, parsing configuration files,
    and executing subcommands.

    .. attribute:: CONFIG_LOADED

        A class attribute indicating whether the configuration has been loaded.
    """

    CONFIG_LOADED = False

    def __init__(
        self,
        *args: Any,
        entry_point_prefix: Optional[str] = None,
        config: Optional["ConfigParser"] = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize the ``ModuleParser``.

        :param args: Variable length argument list.
        :param config: Optional configuration parser instance.
        :param kwargs: Arbitrary keyword arguments.
        """
        # Set the formatter class to ``ModuleFormatter`` for consistent argument formatting
        kwargs["formatter_class"] = ModuleFormatter
        super().__init__(
            *args,
            add_help=False,
            entry_point_prefix=entry_point_prefix,
            config=config,
            **kwargs,
        )
        self.__kwargs = kwargs
        self._extra_modules: List[Tuple[argparse.Action, type]] = []
        self._module_parsers: Set[argparse.ArgumentParser] = {self}
        self.plugin_group = self.add_argument_group(self.config_section)
        self.subcommand: Optional["argparse._SubParsersAction[ModuleParser]"] = None
        self._registered_subcommands: Dict[str, SubCommand] = {}
        self.add_config_arg()

    def add_config_arg(self) -> None:
        """
        Add a configuration file argument to the parser.

        This method adds a ``--config`` argument to the parser, allowing users to specify
        a configuration file path. If a configuration file is provided, it is loaded.
        """
        if not self.ARGCONF:
            return

        # Add the ``--config`` argument to the parser
        self.add_argument(
            "--config", dest="config_path", help="path to a configuration file"
        )

        # Check if the configuration has already been loaded
        if ModuleParser.CONFIG_LOADED:
            return

        # Create a temporary parser to extract the config path
        config_path_parser = argparse.ArgumentParser(add_help=False)
        config_path_parser.add_argument("--config", dest="config_path")
        args, _ = config_path_parser.parse_known_args()

        # If no config path is provided, exit early
        if not args.config_path:
            return

        # Check if the config file exists
        if not os.path.isfile(args.config_path):
            logging.error("Failed to load config file: %s", args.config_path)
            return

        # Load the configuration file
        self.ARGCONF.read(os.path.expanduser(args.config_path))

    def load_subcommands(self) -> None:
        """
        Load and register subcommands from entry points.

        This method discovers and registers subcommands from the entry points
        defined in the ``sshmitm.SubCommand`` group. Each subcommand is instantiated
        and its arguments are registered with the parser.
        """
        if not self.subcommand:
            # Initialize the subparsers for subcommands
            self.subcommand = self.add_subparsers(
                title="Available commands", dest="subparser_name", metavar="subcommand"
            )
            self.subcommand.required = True

        # Iterate over all entry points in the ``sshmitm.SubCommand`` group
        for entry_point in metadata.entry_points(
            group=f"{self.entry_point_prefix}.{SubCommand.__name__}"
        ):
            # Skip if the subcommand is already registered
            if entry_point.name in self._registered_subcommands:
                continue

            # Load the subcommand class from the entry point
            subcommand_cls = cast("Type[SubCommand]", entry_point.load())
            subcommand = subcommand_cls(
                self.entry_point_prefix, entry_point.name, self.subcommand
            )
            subcommand.register_arguments()
            self._registered_subcommands[entry_point.name] = subcommand

    def execute_subcommand(self, name: str, args: argparse.Namespace) -> None:
        """
        Execute a registered subcommand with the provided arguments.

        :param name: Name of the subcommand to execute.
        :param args: Parsed arguments to pass to the subcommand.
        """
        self._registered_subcommands[name].execute(args)

    def _get_sub_modules_args(
        self,
        *,
        parsed_args: argparse.Namespace,
        args: Optional[Sequence[str]],
        namespace: Optional[argparse.Namespace],
        modules: List[Tuple[argparse.Action, Type[BaseModule]]],
    ) -> List[argparse.ArgumentParser]:
        """
        Retrieve submodule arguments from parsed arguments.

        :param parsed_args: Parsed arguments namespace.
        :param args: Optional list of command-line arguments.
        :param namespace: Optional namespace for argument parsing.
        :param modules: List of tuples containing argparse actions and ``BaseModule`` classes.

        :return: List of argument parsers for the submodules.
        """
        # Extract module names from parsed arguments
        modulelist = [
            getattr(parsed_args, m[0].dest)
            for m in modules
            if hasattr(parsed_args, m[0].dest)
        ]
        return self._get_sub_modules(args=args, namespace=namespace, modules=modulelist)

    def _get_sub_modules(
        self,
        *,
        args: Optional[Sequence[str]],
        namespace: Optional[argparse.Namespace],
        modules: Optional[List[Type[BaseModule]]],
    ) -> List[argparse.ArgumentParser]:
        """
        Retrieve argument parsers for submodules.

        :param args: Optional list of command-line arguments.
        :param namespace: Optional namespace for argument parsing.
        :param modules: Optional list of ``BaseModule`` classes.

        :return: List of argument parsers for the submodules.
        """
        moduleparsers: List[argparse.ArgumentParser] = []
        if not modules:
            return moduleparsers

        # Iterate over each module and create its parser
        for module in modules:
            if not module:
                continue
            moduleparsers.append(module.parser())

            try:
                # Parse known arguments for the current module
                parsed_known_args = module.parser().parse_known_args(
                    args=args, namespace=namespace
                )
                if parsed_known_args:
                    parsed_subargs: argparse.Namespace
                    parsed_subargs, _ = parsed_known_args
                    # Recursively get submodules for the current module
                    moduleparsers.extend(
                        self._get_sub_modules_args(
                            parsed_args=parsed_subargs,
                            args=args,
                            namespace=namespace,
                            modules=module.modules(),
                        )
                    )
            except TypeError:
                logging.exception("Unable to load modules")
        return moduleparsers

    def _create_parser(
        self,
        args: Optional[Sequence[str]] = None,
        namespace: Optional[argparse.Namespace] = None,
    ) -> "argparse.ArgumentParser":
        """
        Create and return a complete argument parser.

        :param args: Optional list of command-line arguments.
        :param namespace: Optional namespace for argument parsing.

        :return: A complete argument parser with all modules and submodules.
        """
        # Parse known arguments to load modules
        parsed_args_tuple = super().parse_known_args(args=args, namespace=namespace)

        # Load modules from the ``add_module`` method
        self._module_parsers.update(
            self._get_sub_modules_args(
                parsed_args=parsed_args_tuple[0],
                args=args,
                namespace=namespace,
                modules=self._extra_modules,
            )
        )

        # Create a complete argument parser with all module parsers as parents
        if "config_section" in self.__kwargs:
            del self.__kwargs["config_section"]
        parser = argparse.ArgumentParser(
            parents=sorted(self._module_parsers, key=lambda x: x.description or ""),
            **self.__kwargs,
        )
        argcomplete.autocomplete(parser)
        return parser

    def add_module(self, *args: Any, **kwargs: Any) -> None:
        """
        Add a module to the parser.

        :param args: Variable length argument list.
        :param kwargs: Arbitrary keyword arguments.
        """
        # Extract the baseclass from kwargs
        baseclass = kwargs.pop("baseclass", BaseModule)
        default_value = kwargs.get("default")

        # Handle the default value if provided
        if default_value:
            if isinstance(default_value, str):
                kwargs["default"] = BaseModule.load_from_entrypoint(
                    self.entry_point_prefix, default_value, baseclass
                )
        else:
            # If no default value, try to load it from the configuration
            arg_dest = self.add_argument._get_dest(  # type: ignore[attr-defined] # pylint:disable=protected-access
                *args, **kwargs
            )
            if (
                arg_dest
                and self.ARGCONF
                and self.ARGCONF.has_option(self.config_section, arg_dest)
            ):
                default_value = self.ARGCONF.get(self.config_section, arg_dest)
                if self.ARGCONF.has_section(default_value):
                    part_module, part_class = default_value.rsplit(":", 1)
                    module = import_module(part_module)
                    kwargs["default"] = getattr(module, part_class)
                else:
                    kwargs["default"] = BaseModule.load_from_entrypoint(
                        self.entry_point_prefix, default_value, baseclass
                    )

        # Validate that the baseclass is a subclass of BaseModule
        if not inspect.isclass(baseclass) or not issubclass(baseclass, BaseModule):
            logging.error(
                "Baseclass %s must be subclass of %s not %s",
                baseclass.__name__,
                BaseModule.__name__,
                type(baseclass).__name__,
            )
            raise ModuleError

        # Add the module action to the plugin group
        kwargs["action"] = load_module(self.entry_point_prefix, baseclass)
        action = self.plugin_group.add_argument(
            *args, **set_module_kwargs(self.entry_point_prefix, baseclass, **kwargs)
        )
        self._extra_modules.append((action, baseclass))
        logging.debug("Baseclass: %s", baseclass)

    def parse_args(  # type: ignore[override]
        self,
        args: Optional[Sequence[str]] = None,
        namespace: Optional[argparse.Namespace] = None,
    ) -> argparse.Namespace:
        """
        Parse command-line arguments.

        :param args: Optional list of command-line arguments.
        :param namespace: Optional namespace for argument parsing.

        :return: Parsed arguments namespace.
        """
        parser = self._create_parser(args=args, namespace=namespace)
        args_namespace = parser.parse_args(args, namespace)
        if not args_namespace:
            return argparse.Namespace()
        return args_namespace

    def parse_known_args(  # type: ignore[override]
        self,
        args: Optional[Sequence[str]] = None,
        namespace: Optional[argparse.Namespace] = None,
    ) -> Tuple[argparse.Namespace, List[str]]:
        """
        Parse known command-line arguments.

        :param args: Optional list of command-line arguments.
        :param namespace: Optional namespace for argument parsing.

        :return: Tuple of parsed arguments namespace and list of remaining arguments.
        """
        parser = self._create_parser(args=args, namespace=namespace)
        return parser.parse_known_args(args, namespace)
