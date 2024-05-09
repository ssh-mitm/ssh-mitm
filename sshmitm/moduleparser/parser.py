"""BaseModule parsing library

This module is an extension to the standard Argparse module, which offers the possibility to load to load classes as BaseModule.

This module contains the following public classes:

    - ModuleParser -- entry point to parse command line parameters.
        This class provides the same functionality as the ArgumentParser
        from the argparse module. However, it is possible to specify BaseModules and Plugins,
        which extend the functionality of the parser and the application respectively.
    - BaseModule -- base class for BaseModules that can be used in the application.
        All BaseModules must be derived from this class. If a module does not originate from this class, a ModuleError occurs.
    - ModuleError -- Exception thrown when errors occur when initializing modules or plugins.
        This exception is thrown when an error has occurred. Details can be found in the exception.

All other classes and functions in this module are either legacy or are
implementation specific and should not be used in production applications.
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

from sshmitm.moduleparser.baseparser import BaseModuleArgumentParser
from sshmitm.moduleparser.exceptions import ModuleError
from sshmitm.moduleparser.formatter import ModuleFormatter
from sshmitm.moduleparser.modules import BaseModule, SubCommand
from sshmitm.moduleparser.utils import load_module, set_module_kwargs
from sshmitm.utils import metadata

if TYPE_CHECKING:
    from configparser import ConfigParser


class ModuleParser(
    BaseModuleArgumentParser
):  # pylint: disable=too-many-instance-attributes

    CONFIG_LOADED = False

    def __init__(
        self, *args: Any, config: Optional["ConfigParser"] = None, **kwargs: Any
    ) -> None:  # pylint: disable=too-many-arguments
        kwargs["formatter_class"] = ModuleFormatter
        super().__init__(*args, add_help=False, config=config, **kwargs)
        self.__kwargs = kwargs
        self._extra_modules: List[Tuple[argparse.Action, type]] = []
        self._module_parsers: Set[argparse.ArgumentParser] = {self}
        self.plugin_group = self.add_argument_group(self.config_section)
        self.subcommand: Optional["argparse._SubParsersAction[ModuleParser]"] = None
        self._registered_subcommands: Dict[str, SubCommand] = {}
        self.add_config_arg()

    def add_config_arg(self) -> None:
        if not self.ARGCONF:
            return
        self.add_argument(
            "--config", dest="config_path", help="path to a configuration file"
        )
        if ModuleParser.CONFIG_LOADED:
            return
        config_path_parser = argparse.ArgumentParser(add_help=False)
        config_path_parser.add_argument("--config", dest="config_path")
        args, _ = config_path_parser.parse_known_args()
        if not args.config_path:
            return
        if not os.path.isfile(args.config_path):
            logging.error("failed to load config file: %s", args.config_path)
            return
        self.ARGCONF.read(os.path.expanduser(args.config_path))

    def load_subcommands(self) -> None:
        if not self.subcommand:
            self.subcommand = self.add_subparsers(
                title="Available commands", dest="subparser_name", metavar="subcommand"
            )
            self.subcommand.required = True

        for entry_point in metadata.entry_points(
            group=f"sshmitm.{SubCommand.__name__}"
        ):
            if entry_point.name in self._registered_subcommands:
                continue
            subcommand_cls = cast(Type[SubCommand], entry_point.load())
            subcommand = subcommand_cls(entry_point.name, self.subcommand)
            subcommand.register_arguments()
            self._registered_subcommands[entry_point.name] = subcommand

    def execute_subcommand(self, name: str, args: argparse.Namespace) -> None:
        self._registered_subcommands[name].execute(args)

    def _get_sub_modules_args(
        self,
        *,
        parsed_args: argparse.Namespace,
        args: Optional[Sequence[str]],
        namespace: Optional[argparse.Namespace],
        modules: List[Tuple[argparse.Action, Type[BaseModule]]],
    ) -> List[argparse.ArgumentParser]:
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
        moduleparsers: List[argparse.ArgumentParser] = []
        if not modules:
            return moduleparsers

        for module in modules:
            if not module:
                continue
            moduleparsers.append(module.parser())

            try:
                parsed_known_args = module.parser().parse_known_args(
                    args=args, namespace=namespace
                )
                if parsed_known_args:
                    parsed_subargs: argparse.Namespace
                    parsed_subargs, _ = parsed_known_args
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
        parsed_args_tuple = super().parse_known_args(args=args, namespace=namespace)

        # load modules from add_module method
        self._module_parsers.update(
            self._get_sub_modules_args(
                parsed_args=parsed_args_tuple[0],
                args=args,
                namespace=namespace,
                modules=self._extra_modules,
            )
        )

        # create complete argument parser and return arguments

        if "config_section" in self.__kwargs:
            del self.__kwargs["config_section"]
        parser = argparse.ArgumentParser(
            parents=sorted(self._module_parsers, key=lambda x: x.description or ""),
            **self.__kwargs,
        )
        argcomplete.autocomplete(parser)
        return parser

    def add_module(self, *args: Any, **kwargs: Any) -> None:
        # remove "baseclass" from arguments
        baseclass = kwargs.pop("baseclass", BaseModule)
        default_value = kwargs.get("default")
        if default_value:
            if isinstance(default_value, str):
                kwargs["default"] = BaseModule.load_from_entrypoint(
                    default_value, baseclass
                )
        else:
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
                        default_value, baseclass
                    )

        if not inspect.isclass(baseclass) or not issubclass(baseclass, BaseModule):
            logging.error(
                "Baseclass %s must be subclass of %s not %s",
                baseclass.__name__,
                BaseModule.__name__,
                type(baseclass).__name__,
            )
            raise ModuleError
        # add "action" to new arguments
        kwargs["action"] = load_module(baseclass)
        action = self.plugin_group.add_argument(
            *args, **set_module_kwargs(baseclass, **kwargs)
        )
        self._extra_modules.append((action, baseclass))
        logging.debug("Baseclass: %s", baseclass)

    def parse_args(  # type: ignore[override]
        self,
        args: Optional[Sequence[str]] = None,
        namespace: Optional[argparse.Namespace] = None,
    ) -> argparse.Namespace:
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
        parser = self._create_parser(args=args, namespace=namespace)
        return parser.parse_known_args(args, namespace)
