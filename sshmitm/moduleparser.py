# -*- coding: utf-8 -*-

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

import logging
import argparse
import inspect
from importlib import import_module

from typing import (
    cast,
    Any,
    List,
    Optional,
    Sequence,
    Tuple,
    Dict,
    Type,
    Set,
    Union
)

import argcomplete
import pkg_resources
from colored.colored import attr, fg  # type: ignore
from sshmitm.config import CONFIGFILE
from sshmitm.logging import Colors


def load_module_from_entrypoint(name: str, entry_point_class: Type['BaseModule']) -> Optional[Type['BaseModule']]:
    for entry_point in pkg_resources.iter_entry_points(entry_point_class.__name__):
        if name in (entry_point.name, entry_point.module_name):
            return cast(Type[BaseModule], entry_point.load())
    return None


def load_module(entry_point_class: Type['BaseModule']) -> Type['argparse.Action']:
    """Action to be able to define BaseModule with the "add_module" method of the ModuleParser as command line parameter
    """
    class ModuleLoaderAction(argparse.Action):
        def __call__(self, parser: argparse.ArgumentParser, namespace: argparse.Namespace, values: Union[str, Sequence[Any], None], option_string: Optional[str] = None) -> None:
            if values:
                for entry_point in pkg_resources.iter_entry_points(entry_point_class.__name__):
                    if values in (entry_point.name, entry_point.module_name):
                        values = [entry_point.load()]
                        setattr(namespace, self.dest, values[0] if values else None)
                        break
    return ModuleLoaderAction


def set_module_kwargs(entry_point_class: Type['BaseModule'], **kwargs: Any) -> Dict[str, Any]:

    entry_points = sorted(
        pkg_resources.iter_entry_points(entry_point_class.__name__),
        key=lambda x: x.name
    )
    if not entry_points:
        return kwargs

    choices = []
    descriptions = []
    default_value = kwargs.get('default', None)
    default_name = None
    for entry_point in entry_points:
        choices.append(entry_point.name)

        loaded_class = entry_point.load()
        if default_value is loaded_class:
            default_name = entry_point.name
        entry_point_desc = "" if not loaded_class.__doc__ else loaded_class.__doc__.split("\n")[0]
        if entry_point_desc:
            entry_point_description = f"\t* {Colors.stylize(entry_point.name, fg('blue'))} -> {entry_point_desc}"
        else:
            entry_point_description = f"\t* {Colors.stylize(entry_point.name, fg('blue'))}"
        descriptions.append(entry_point_description)

    kwargs['choices'] = sorted(choices)
    kwargs['help'] = kwargs.get('help') or ""
    if default_name:
        kwargs['help'] += f"\ndefault module: {Colors.stylize(default_name, fg('blue') + attr('bold'))}"
    kwargs['help'] += "\navailable modules:\n{}".format("\n".join(descriptions))
    return kwargs


class BaseModuleError(Exception):
    pass


class ModuleError(BaseModuleError):

    def __init__(
        self,
        moduleclass: Optional[Union[Type['BaseModule'], Tuple[Type['BaseModule'], ...]]] = None,
        baseclass: Optional[Union[Type['BaseModule'], Tuple[Type['BaseModule'], ...]]] = None,
        message: Optional[str] = None
    ):
        super().__init__()
        self.moduleclass = moduleclass
        self.baseclass = baseclass
        self.message = message


class InvalidModuleArguments(BaseModuleError):
    pass


class AddArgumentMethod:

    def __init__(
        self,
        parser: "_ModuleArgumentParser",
        container: Optional[argparse._ActionsContainer] = None,
        config_section: Optional[str] = None
    ) -> None:
        self.parser = parser
        self.container = container or parser
        self.config_section = config_section or self.parser.config_section
        self._add_argument = self.container.add_argument

    def _get_dest(self, *args: Any, **kwargs: Any) -> Any:
        dest_1 = kwargs.get('dest')
        dest_2 = None
        if dest_1 is not None:
            dest_1 = dest_1.replace('_', '-')
        if len(args) >= 1:
            dest_2 = args[0].lstrip(self.container.prefix_chars)
            dest_2 = dest_2.replace('_', '-')
        return dest_1 or dest_2

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        default_value = kwargs.get('default')
        arg_dest = self._get_dest(*args, **kwargs)
        arg_action = kwargs.get('action', 'store')

        if self.config_section and not CONFIGFILE.has_option(self.config_section, arg_dest) and arg_action != 'version':
            logging.error("Missing config value -  %s - %s (%s) = %s", self.config_section, arg_dest, arg_action, default_value)

        if arg_dest and CONFIGFILE.has_option(self.config_section, arg_dest) and CONFIGFILE.get(self.config_section, arg_dest):
            if arg_action in ('store', 'store_const'):
                kwargs['default'] = CONFIGFILE.get(self.config_section, arg_dest)
            elif arg_action in ('store_true', 'store_false'):
                kwargs['default'] = CONFIGFILE.getboolean(self.config_section, arg_dest)
        return self._add_argument(*args, **kwargs)


class _ModuleArgumentParser(argparse.ArgumentParser):
    """Enhanced ArgumentParser to suppress warnings and error during module parsing"""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.config_section = kwargs.pop('config_section', None)
        super().__init__(*args, **kwargs)
        self.exit_on_error = True
        self.add_argument = AddArgumentMethod(self, self)  # type: ignore

    def error(self, message: str) -> None:  # type: ignore
        if self.exit_on_error:
            return
        super().error(message)

    def add_argument_group(self, *args: Any, **kwargs: Any) -> argparse._ArgumentGroup:
        config_section = kwargs.pop('config_section', None)
        group = argparse._ArgumentGroup(self, *args, **kwargs)  # pylint:disable=protected-access
        group.add_argument = AddArgumentMethod(self, group, config_section)  # type: ignore
        self._action_groups.append(group)
        return group


class BaseModule():
    _parser: Optional[_ModuleArgumentParser] = None
    _modules: Optional[List[Tuple[argparse.Action, Any]]] = None

    def __init__(
        self,
        args: Optional[Sequence[str]] = None,
        namespace: Optional[argparse.Namespace] = None,
        **kwargs: Any
    ) -> None:
        self.args: argparse.Namespace
        parser_retval = self.parser().parse_known_args(args, namespace)
        if parser_retval is None:
            raise InvalidModuleArguments()
        self.args, _ = parser_retval

        actions = {action.dest: action for action in self.parser()._actions}
        for param_name, param_value in kwargs.items():
            action = actions.get(param_name)
            if not action:
                raise KeyError(f'keyword argument {param_name} has no param')
            # check if it is an instance of the argument type, ignore mypy error because of false positive
            if hasattr(action, 'type') and not isinstance(param_value, action.type):  # type: ignore
                raise ValueError(f'Value {param_value} for parameter is not an instance of {action.type}')
            setattr(self.args, param_name, param_value)

    @classmethod
    def add_module(cls, *args: Any, **kwargs: Any) -> None:
        # remove "baseclass" from arguments
        baseclass: Type[BaseModule] = kwargs.pop('baseclass', BaseModule)
        if not inspect.isclass(baseclass) or not issubclass(baseclass, BaseModule):
            logging.error('Baseclass %s mast be subclass of %s not %s', baseclass, BaseModule, type(baseclass))
            raise ModuleError()
        # add "action" to new arguments
        kwargs['action'] = load_module(baseclass)
        if cls.modules() is not None and cls.parser() is not None:
            cls.modules().append((cls.parser().add_argument(*args, **set_module_kwargs(baseclass, **kwargs)), baseclass))

    @classmethod
    def parser_arguments(cls) -> None:
        pass

    @classmethod
    def modules(cls) -> List[Tuple[argparse.Action, Any]]:
        if '_modules' not in cls.__dict__ or cls._modules is None:
            cls._modules = []
        return cls._modules

    @classmethod
    def parser(cls) -> _ModuleArgumentParser:
        if '_parser' not in cls.__dict__:
            cls._parser = _ModuleArgumentParser(
                add_help=False,
                description=cls.__name__,
                config_section=f"{cls.__module__}:{cls.__name__}"
            )
            cls.parser_arguments()
        if not cls._parser:
            raise ValueError(f'failed to create ModuleParser for {cls}')
        return cls._parser


class ModuleFormatter(argparse.HelpFormatter):
    """Help message formatter which retains formatting of all help text.
    Only the name of this class is considered a public API. All the methods
    provided by the class are considered an implementation detail.
    """

    class _Section():  # pylint: disable=too-few-public-methods

        def __init__(self, formatter: argparse.HelpFormatter, parent: Any, heading: Optional[str] = None) -> None:
            self.formatter = formatter
            self.parent = parent
            self.heading = heading
            self.items = []  # type: ignore

        def format_help(self) -> str:
            # pylint: disable=protected-access
            # format the indented section
            if self.parent is not None:
                self.formatter._indent()  # pylint: disable=protected-access
            join = self.formatter._join_parts  # pylint: disable=protected-access
            item_help = join([func(*args) for func, args in self.items])
            if self.parent is not None:
                self.formatter._dedent()  # pylint: disable=protected-access

            # return nothing if the section was empty
            if not item_help:
                return ''

            # add the heading if the section was non-empty
            if self.heading is not argparse.SUPPRESS and self.heading is not None:
                current_indent = self.formatter._current_indent  # pylint: disable=protected-access
                heading = '%*s%s:\n' % (current_indent, '', Colors.stylize(self.heading, fg('red') + attr('bold')))  # pylint: disable=consider-using-f-string
            else:
                heading = ''

            # join the section-initial newline, the heading and the help
            return join(['\n', heading, item_help, '\n'])

    def _split_lines(self, text: str, width: int) -> List[str]:
        return text.splitlines()


class ModuleParser(_ModuleArgumentParser):  # pylint: disable=too-many-instance-attributes

    def __init__(  # pylint: disable=too-many-arguments
        self,
        **kwargs: Any
    ) -> None:
        kwargs['formatter_class'] = ModuleFormatter
        super().__init__(add_help=False, **kwargs)
        self.__kwargs = kwargs
        self._extra_modules: List[Tuple[argparse.Action, type]] = []
        self._module_parsers: Set[argparse.ArgumentParser] = {self}
        self.plugin_group = self.add_argument_group(
            self.config_section
        )

    def _get_sub_modules_args(
        self,
        *,
        parsed_args: argparse.Namespace,
        args: Optional[Sequence[str]],
        namespace: Optional[argparse.Namespace],
        modules: List[Tuple[argparse.Action, Type[BaseModule]]],
    ) -> List[argparse.ArgumentParser]:
        modulelist = [getattr(parsed_args, m[0].dest) for m in modules if hasattr(parsed_args, m[0].dest)]
        return self._get_sub_modules(
            args=args,
            namespace=namespace,
            modules=modulelist
        )

    def _get_sub_modules(
        self,
        *,
        args: Optional[Sequence[str]],
        namespace: Optional[argparse.Namespace],
        modules: Optional[List[Type[BaseModule]]]
    ) -> List[argparse.ArgumentParser]:
        moduleparsers: List[argparse.ArgumentParser] = []
        if not modules:
            return moduleparsers

        for module in modules:
            moduleparsers.append(module.parser())

            try:
                parsed_known_args = module.parser().parse_known_args(args=args, namespace=namespace)
                if parsed_known_args:
                    parsed_subargs: argparse.Namespace
                    parsed_subargs, _ = parsed_known_args
                    moduleparsers.extend(self._get_sub_modules_args(
                        parsed_args=parsed_subargs,
                        args=args,
                        namespace=namespace,
                        modules=module.modules()
                    ))
            except TypeError:
                logging.exception("Unable to load modules")
        return moduleparsers

    def _create_parser(
        self,
        args: Optional[Sequence[str]] = None,
        namespace: Optional[argparse.Namespace] = None
    ) -> 'argparse.ArgumentParser':
        parsed_args_tuple = super().parse_known_args(args=args, namespace=namespace)

        # load modules from add_module method
        self._module_parsers.update(
            self._get_sub_modules_args(
                parsed_args=parsed_args_tuple[0],
                args=args,
                namespace=namespace,
                modules=self._extra_modules
            )
        )

        # create complete argument parser and return arguments

        if 'config_section' in self.__kwargs:
            del self.__kwargs['config_section']
        parser = argparse.ArgumentParser(
            parents=sorted(
                self._module_parsers,
                key=lambda x: x.description or ''
            ),
            **self.__kwargs
        )
        argcomplete.autocomplete(parser)
        return parser

    def add_module(self, *args: Any, **kwargs: Any) -> None:
        # remove "baseclass" from arguments
        baseclass = kwargs.pop('baseclass', BaseModule)
        default_value = kwargs.get('default')
        if default_value:
            if isinstance(default_value, str):
                kwargs['default'] = load_module_from_entrypoint(default_value, baseclass)
        else:
            arg_dest = self.add_argument._get_dest(*args, **kwargs)  # type: ignore # pylint:disable=protected-access
            if arg_dest and CONFIGFILE.has_option(
                self.config_section,
                arg_dest
            ):
                default_value = CONFIGFILE.get(self.config_section, arg_dest)
                if CONFIGFILE.has_section(default_value):
                    part_module, part_class = default_value.rsplit(":", 1)
                    module = import_module(part_module)
                    kwargs['default'] = getattr(module, part_class)
                else:
                    kwargs['default'] = load_module_from_entrypoint(
                        default_value,
                        baseclass
                    )

        if not inspect.isclass(baseclass) or not issubclass(baseclass, BaseModule):
            logging.error(
                'Baseclass %s must be subclass of %s not %s',
                baseclass.__name__, BaseModule.__name__, type(baseclass).__name__
            )
            raise ModuleError()
        # add "action" to new arguments
        kwargs['action'] = load_module(baseclass)
        action = self.plugin_group.add_argument(*args, **set_module_kwargs(baseclass, **kwargs))
        self._extra_modules.append((action, baseclass))
        logging.debug("Baseclass: %s", baseclass)

    def parse_args(  # type: ignore
        self,
        args: Optional[Sequence[str]] = None,
        namespace: Optional[argparse.Namespace] = None
    ) -> argparse.Namespace:
        parser = self._create_parser(args=args, namespace=namespace)
        args_namespace = parser.parse_args(args, namespace)
        if not args_namespace:
            return argparse.Namespace()
        return args_namespace

    def parse_known_args(  # type: ignore
        self,
        args: Optional[Sequence[str]] = None,
        namespace: Optional[argparse.Namespace] = None
    ) -> Tuple[argparse.Namespace, List[str]]:
        parser = self._create_parser(args=args, namespace=namespace)
        return parser.parse_known_args(args, namespace)
