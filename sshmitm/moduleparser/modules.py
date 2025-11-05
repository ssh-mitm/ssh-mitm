import argparse
import inspect
import logging
from abc import ABC, abstractmethod
from typing import (
    TYPE_CHECKING,
    Any,
    ClassVar,
    Dict,
    List,
    Optional,
    Sequence,
    Tuple,
    Type,
    cast,
)

from sshmitm.project_metadata import MODULE_NAME
from sshmitm.core.compat import metadata
from sshmitm.moduleparser.baseparser import BaseModuleArgumentParser
from sshmitm.moduleparser.exceptions import InvalidModuleArguments, ModuleError
from sshmitm.moduleparser.utils import load_module, set_module_kwargs

if TYPE_CHECKING:
    from sshmitm.moduleparser import ModuleParser


class BaseModule(ABC):  # noqa: B024
    """
    Abstract base class for all modules in the application.

    This class provides the core functionality for parsing arguments,
    managing submodules, and handling configuration for derived modules.

    .. attribute:: _parser

        A class-level argument parser instance for the module.

    .. attribute:: _modules

        A list of tuples containing argument actions and associated module classes.

    .. attribute:: _argument_groups

        A dictionary of argument groups for organizing related arguments.
    """

    _parser: Optional[BaseModuleArgumentParser] = None
    _modules: Optional[List[Tuple[argparse.Action, Any]]] = None
    _argument_groups: ClassVar[Dict[str, argparse._ArgumentGroup]] = {}

    def __init__(
        self,
        args: Optional[Sequence[str]] = None,
        namespace: Optional[argparse.Namespace] = None,
        **kwargs: Any,
    ) -> None:
        """
        Initialize the module with parsed arguments and optional keyword arguments.

        :param args: Optional list of command-line arguments.
        :param namespace: Optional namespace for argument parsing.
        :param kwargs: Additional keyword arguments to set as attributes.
        :raises InvalidModuleArguments: If argument parsing fails.
        :raises KeyError: If a keyword argument has no corresponding parameter.
        :raises ValueError: If a keyword argument value is of the wrong type.
        """
        # Parse known arguments using the module's parser
        parser_retval = self.parser().parse_known_args(args, namespace)
        if parser_retval is None:
            raise InvalidModuleArguments
        self.args, _ = parser_retval

        # Map argument actions to their destinations for validation
        actions = {action.dest: action for action in self.parser()._actions}

        # Set keyword arguments as attributes on the parsed arguments namespace
        for param_name, param_value in kwargs.items():
            action = actions.get(param_name)
            if not action:
                msg = f"Keyword argument {param_name} has no corresponding parameter."
                raise KeyError(msg)

            # Check if the provided value matches the expected type
            if hasattr(action, "type") and not isinstance(param_value, action.type):  # type: ignore[arg-type]
                msg = f"Value {param_value} for parameter {param_name} is not an instance of {action.type}."
                raise ValueError(msg)

            setattr(self.args, param_name, param_value)

    @classmethod
    def add_module(cls, *args: Any, **kwargs: Any) -> None:
        """
        Add a submodule to the module's parser.

        :param args: Positional arguments for the module.
        :param kwargs: Keyword arguments for the module.
        :raises ModuleError: If the baseclass is not a subclass of ``BaseModule``.
        """
        # Extract the baseclass from kwargs
        baseclass: Type[BaseModule] = kwargs.pop("baseclass", BaseModule)

        # Validate that the baseclass is a subclass of BaseModule
        if not inspect.isclass(baseclass) or not issubclass(baseclass, BaseModule):
            logging.error(
                "Baseclass %s must be a subclass of %s, not %s.",
                baseclass,
                BaseModule,
                type(baseclass),
            )
            raise ModuleError

        # Set the action to load the module
        kwargs["action"] = load_module(baseclass)

        # Add the module to the module list if parser and modules are initialized
        if cls.modules() is not None and cls.parser() is not None:
            cls.modules().append(
                (
                    cls.parser().add_argument(
                        *args, **set_module_kwargs(baseclass, **kwargs)
                    ),
                    baseclass,
                )
            )

    @classmethod  # noqa: B027
    def parser_arguments(cls) -> None:
        """
        Define the arguments for the module's parser.

        This method should be overridden by subclasses to add custom arguments.
        """

    @classmethod
    def modules(cls) -> List[Tuple[argparse.Action, Any]]:
        """
        Get the list of submodules for this module.

        :return: List of tuples containing argument actions and module classes.
        """
        if "_modules" not in cls.__dict__ or cls._modules is None:
            cls._modules = []
        return cls._modules

    @classmethod
    def parser(cls) -> BaseModuleArgumentParser:
        """
        Get the argument parser for this module.

        :return: The module's argument parser.
        :raises ValueError: If the parser cannot be created.
        """
        if "_parser" not in cls.__dict__:
            cls._parser = BaseModuleArgumentParser(
                add_help=False,
                description=cls.__name__,
                config_section=f"{cls.__module__}:{cls.__name__}",
            )
            cls.parser_arguments()
        if not cls._parser:
            msg = f"Failed to create ModuleParser for {cls}."
            raise ValueError(msg)
        return cls._parser

    @classmethod
    def argument_group(
        cls,
        title: Optional[str] = None,
        *,
        description: Optional[str] = None,
    ) -> argparse._ArgumentGroup:
        """
        Create or retrieve an argument group for the module.

        :param title: Title of the argument group.
        :param description: Description of the argument group.
        :return: The argument group.
        """
        group_title = title or cls.__name__
        if not description and cls.__doc__:
            description = cls.__doc__.strip().split("\n", maxsplit=1)[0]

        if group_title not in cls._argument_groups:
            cls._argument_groups[group_title] = cls.parser().add_argument_group(
                group_title, description
            )

        return cls._argument_groups[group_title]

    @staticmethod
    def load_from_entrypoint(
        name: str, entry_point_class: Type["BaseModule"]
    ) -> Optional[Type["BaseModule"]]:
        """
        Load a module class from an entry point.

        :param name: Name of the entry point.
        :param entry_point_class: Base class for the module.
        :return: The loaded module class, or ``None`` if not found.
        """
        for entry_point in metadata.entry_points(
            group=f"{MODULE_NAME}.{entry_point_class.__name__}"
        ):
            if name in (entry_point.name, entry_point.module):
                return cast("Type[BaseModule]", entry_point.load())
        return None


class SubCommand(ABC):
    """
    Abstract base class for subcommands.

    Subcommands are used to extend the functionality of the main parser
    by adding specific commands with their own arguments and execution logic.
    """

    def __init__(
        self, name: str, subcommand: "argparse._SubParsersAction[ModuleParser]"
    ) -> None:
        """
        Initialize the subcommand with a name and subparser action.

        :param name: Name of the subcommand.
        :param subcommand: Subparsers action to add the subcommand to.
        """
        self.parser = subcommand.add_parser(  # type: ignore[call-arg]
            name,
            allow_abbrev=False,
            help=self.docs(),
            config_section=self.config_section(),
        )

    def register_arguments(self) -> None:  # noqa: B027
        """
        Register arguments for the subcommand.

        This method should be overridden by subclasses to add custom arguments.
        """

    @abstractmethod
    def execute(self, args: argparse.Namespace) -> None:
        """
        Execute the subcommand with the provided arguments.

        :param args: Parsed arguments for the subcommand.
        """

    @classmethod
    def docs(cls) -> Optional[str]:
        """
        Get the documentation string for the subcommand.

        :return: The first line of the class docstring, or ``None`` if no docstring exists.
        """
        if not cls.__doc__:
            return None
        return cls.__doc__.strip().split("\n", maxsplit=1)[0]

    @classmethod
    def config_section(cls) -> Optional[str]:
        """
        Get the configuration section name for the subcommand.

        :return: The configuration section name, derived from the class name.
        """
        return cls.__name__.replace("_", "-")
