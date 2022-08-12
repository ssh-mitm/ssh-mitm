# -*- coding: utf-8 -*-

"""BaseModule parsing library

Dieses Modul ist eine Erweiterung zum Standard-Argparse Modul, welches die Möglichkeit bietet
Klassen als BaseModule zu laden.

Dieses Modul beinhaltet folgende öffentliche Klassen:

    - ModuleParser -- Einstiegspunkt um Kommandozeilenparameter zu parsen.
        Diese Klasse bietet die gleiche Funktionalität wie der ArgumentParser
        aus dem argparse Modul. Jedoch ist es möglich BaseModule und Plugins anzugeben,
        die die Funktionalität des Parsers bzw. der Applikation erweitern
    - BaseModule -- Basisklasse für BaseModule, die in der Applikation verwendet werden können.
        Alle BaseModule müssen von dieser Klasse abstammen. Stammt ein Modul nicht von dieser Klasse ab, kommt es zu
        einem ModuleError.
    - ModuleError -- Exception, die geworfen wird, wenn es beim initialisieren von Modulen oder Plugins zu Fehlern kommt.
        Diese Exception wird geworfen, wenn es zu einem Fehler gekommen ist. Details sind der Exception zu entnehmen.

Alle anderen Klassen und Funktionen in diesem Modul sind entweder aus Legacy Gründen vorhanden oder sind
implemntationsspezifisch und sollten in Produktivanwendungen nicht verwendet werden.
"""

import logging
import argparse
import inspect

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
    Text,
    Union
)

import argcomplete  # type: ignore
import pkg_resources
from colored.colored import attr, fg, stylize  # type: ignore


def load_entry_point(entrypoint: str, name: str) -> Optional[Type['BaseModule']]:
    for entry_point in pkg_resources.iter_entry_points(entrypoint):
        if name in (entry_point.name, entry_point.module_name):
            return cast(Type['BaseModule'], entry_point.load())
    return None


def load_module(entry_point_class: Type['BaseModule']) -> Type['argparse.Action']:
    """Action, um BaseModule mit der Methode "add_module" des ModuleParsers als Kommandozeilenparameter definieren zu können
    """
    class ModuleLoaderAction(argparse.Action):
        def __call__(self, parser: argparse.ArgumentParser, namespace: argparse.Namespace, values: Union[Text, Sequence[Any], None], option_string: Optional[Text] = None) -> None:
            if values:
                entry_point_list = []
                for entry_point in pkg_resources.iter_entry_points(entry_point_class.__name__):
                    entry_point_list.append(entry_point.name)
                    if values in (entry_point.name, entry_point.module_name):
                        values = [entry_point.load()]
                        setattr(namespace, self.dest, values[0] if values else None)
                        break
    return ModuleLoaderAction


def get_entrypoint_modules(entry_point_name: Text) -> Dict[Text, Text]:
    entrypoints = {}
    for entry_point in pkg_resources.iter_entry_points(entry_point_name):
        entry_point_cls = entry_point.load()
        entry_point_desc = "" if entry_point_cls.__doc__ is None else entry_point_cls.__doc__.split("\n")[0]
        if entry_point_desc:
            entry_point_description = f"\t* {stylize(entry_point.name, fg('blue'))} -> {entry_point_desc}"
        else:
            entry_point_description = f"\t* {stylize(entry_point.name, fg('blue'))}"
        entrypoints[entry_point.name] = entry_point_description
    return entrypoints


def set_module_kwargs(entry_point_class: Type['BaseModule'], **kwargs: Any) -> Dict[Text, Any]:
    entrypoints = get_entrypoint_modules(entry_point_class.__name__)
    entrypoint_classes = {
        entry_point.load(): entry_point.name
        for entry_point
        in pkg_resources.iter_entry_points(entry_point_class.__name__)
    }
    if entrypoints:
        kwargs['choices'] = entrypoints.keys()
        kwargs['help'] = kwargs.get('help') or ""
        default_value = kwargs.get('default', None)
        if default_value in entrypoint_classes:
            default_name = entrypoint_classes[default_value]
            kwargs['help'] += f"\ndefault module: {stylize(default_name, fg('blue') + attr('bold'))}"
        kwargs['help'] += "\navailable modules:\n{}".format("\n".join(entrypoints.values()))
    return kwargs


class ModuleError(Exception):

    def __init__(
        self,
        moduleclass: Optional[Union[Type['BaseModule'], Tuple[Type['BaseModule'], ...]]] = None,
        baseclass: Optional[Union[Type['BaseModule'], Tuple[Type['BaseModule'], ...]]] = None,
        message: Optional[Text] = None
    ):
        super().__init__()
        self.moduleclass = moduleclass
        self.baseclass = baseclass
        self.message = message


class InvalidModuleArguments(Exception):
    pass


class _ModuleArgumentParser(argparse.ArgumentParser):
    """Enhanced ArgumentParser to suppress warnings and error during module parsing"""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.exit_on_error = True

    def error(self, message: Text) -> None:  # type: ignore
        if self.exit_on_error:
            return
        super().error(message)


class BaseModule():
    _parser: Optional[_ModuleArgumentParser] = None
    _modules: Optional[List[Tuple[argparse.Action, Any]]] = None

    def __init__(
        self,
        args: Optional[Sequence[Text]] = None,
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
            cls._parser = _ModuleArgumentParser(add_help=False, description=cls.__name__)
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

        def __init__(self, formatter: argparse.HelpFormatter, parent: Any, heading: Optional[Text] = None) -> None:
            self.formatter = formatter
            self.parent = parent
            self.heading = heading
            self.items = []  # type: ignore

        def format_help(self) -> Text:
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
                heading = '%*s%s:\n' % (current_indent, '', stylize(self.heading, fg('red') + attr('bold')))  # pylint: disable=consider-using-f-string
            else:
                heading = ''

            # join the section-initial newline, the heading and the help
            return join(['\n', heading, item_help, '\n'])

    def _split_lines(self, text: Text, width: int) -> List[Text]:
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

    def _add_parser(self, parser: argparse.ArgumentParser) -> None:
        for module_parser in self._module_parsers:
            if module_parser.description == parser.description:
                return
        # remove help action from parser
        parser._actions[:] = [x for x in parser._actions if not isinstance(x, argparse._HelpAction)]  # pylint: disable=protected-access
        # append parser to list
        self._module_parsers.add(parser)

    def _get_sub_modules_args(
        self,
        *,
        parsed_args: argparse.Namespace,
        args: Optional[Sequence[Text]],
        namespace: Optional[argparse.Namespace],
        modules: List[Tuple[argparse.Action, Type[BaseModule]]],
    ) -> List[argparse.ArgumentParser]:
        modulelist = [getattr(parsed_args, m[0].dest) for m in modules if hasattr(parsed_args, m[0].dest)]
        modulebasecls: List[Tuple[Type[BaseModule], ...]] = [(m[1], ) for m in modules]
        return self._get_sub_modules(
            args=args,
            namespace=namespace,
            modules=modulelist,
            baseclasses=modulebasecls
        )

    def _get_sub_modules(
        self,
        *,
        args: Optional[Sequence[Text]],
        namespace: Optional[argparse.Namespace],
        modules: Optional[List[Type[BaseModule]]],
        baseclasses: List[Tuple[Type[BaseModule], ...]],
    ) -> List[argparse.ArgumentParser]:
        moduleparsers: List[argparse.ArgumentParser] = []
        if not modules:
            return moduleparsers

        for module, baseclass in zip(modules, baseclasses):
            if not issubclass(module, baseclass):
                logging.error('module %s is not an instance of baseclass %s', module, baseclass)
                raise ModuleError(module, baseclass)
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
        args: Optional[Sequence[Text]] = None,
        namespace: Optional[argparse.Namespace] = None
    ) -> 'argparse.ArgumentParser':
        parsed_args_tuple = super().parse_known_args(args=args, namespace=namespace)
        if not parsed_args_tuple:
            self.exit_on_error = False
            super().parse_known_args(args=args, namespace=namespace)

        # load modules from add_module method
        moduleparsers = self._get_sub_modules_args(
            parsed_args=parsed_args_tuple[0],
            args=args,
            namespace=namespace,
            modules=self._extra_modules
        )
        for moduleparser in moduleparsers:
            self._add_parser(moduleparser)

        # create complete argument parser and return arguments
        parser = argparse.ArgumentParser(parents=list(self._module_parsers), **self.__kwargs)
        argcomplete.autocomplete(parser)
        return parser

    def add_module(self, *args: Any, **kwargs: Any) -> None:
        # remove "baseclass" from arguments
        baseclass = kwargs.pop('baseclass', BaseModule)
        if not inspect.isclass(baseclass) or not issubclass(baseclass, BaseModule):
            logging.error('Baseclass %s mast be subclass of %s not %s', baseclass, BaseModule, type(baseclass))
            raise ModuleError()
        # add "action" to new arguments
        kwargs['action'] = load_module(baseclass)

        self._extra_modules.append((self.add_argument(*args, **set_module_kwargs(baseclass, **kwargs)), baseclass))
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

    def parse_known_args(
        self,
        args: Optional[Sequence[str]] = None,
        namespace: Optional[argparse.Namespace] = None
    ) -> Tuple[argparse.Namespace, List[str]]:
        parser = self._create_parser(args=args, namespace=namespace)
        return parser.parse_known_args(args, namespace)
