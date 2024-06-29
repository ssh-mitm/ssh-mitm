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

from sshmitm.moduleparser.baseparser import BaseModuleArgumentParser
from sshmitm.moduleparser.exceptions import InvalidModuleArguments, ModuleError
from sshmitm.moduleparser.utils import load_module, set_module_kwargs
from sshmitm.utils import metadata

if TYPE_CHECKING:
    from sshmitm.moduleparser import ModuleParser


class BaseModule(ABC):  # noqa: B024
    _parser: Optional[BaseModuleArgumentParser] = None
    _modules: Optional[List[Tuple[argparse.Action, Any]]] = None
    _argument_groups: ClassVar[Dict[str, argparse._ArgumentGroup]] = {}

    def __init__(
        self,
        args: Optional[Sequence[str]] = None,
        namespace: Optional[argparse.Namespace] = None,
        **kwargs: Any,
    ) -> None:
        self.args: argparse.Namespace
        parser_retval = self.parser().parse_known_args(args, namespace)
        if parser_retval is None:
            raise InvalidModuleArguments
        self.args, _ = parser_retval

        actions = {action.dest: action for action in self.parser()._actions}
        for param_name, param_value in kwargs.items():
            action = actions.get(param_name)
            if not action:
                msg = f"keyword argument {param_name} has no param"
                raise KeyError(msg)
            # check if it is an instance of the argument type, ignore mypy error because of false positive
            if hasattr(action, "type") and not isinstance(param_value, action.type):  # type: ignore[arg-type]
                msg = f"Value {param_value} for parameter is not an instance of {action.type}"
                raise ValueError(msg)
            setattr(self.args, param_name, param_value)

    @classmethod
    def add_module(cls, *args: Any, **kwargs: Any) -> None:
        # remove "baseclass" from arguments
        baseclass: Type[BaseModule] = kwargs.pop("baseclass", BaseModule)
        if not inspect.isclass(baseclass) or not issubclass(baseclass, BaseModule):
            logging.error(
                "Baseclass %s mast be subclass of %s not %s",
                baseclass,
                BaseModule,
                type(baseclass),
            )
            raise ModuleError
        # add "action" to new arguments
        kwargs["action"] = load_module(baseclass)
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
        pass

    @classmethod
    def modules(cls) -> List[Tuple[argparse.Action, Any]]:
        if "_modules" not in cls.__dict__ or cls._modules is None:
            cls._modules = []
        return cls._modules

    @classmethod
    def parser(cls) -> BaseModuleArgumentParser:
        if "_parser" not in cls.__dict__:
            cls._parser = BaseModuleArgumentParser(
                add_help=False,
                description=cls.__name__,
                config_section=f"{cls.__module__}:{cls.__name__}",
            )
            cls.parser_arguments()
        if not cls._parser:
            msg = f"failed to create ModuleParser for {cls}"
            raise ValueError(msg)
        return cls._parser

    @classmethod
    def argument_group(
        cls,
        title: Optional[str] = None,
        *,
        description: Optional[str] = None,
    ) -> argparse._ArgumentGroup:
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
        for entry_point in metadata.entry_points(
            group=f"sshmitm.{entry_point_class.__name__}"
        ):
            if name in (entry_point.name, entry_point.module):
                return cast(Type[BaseModule], entry_point.load())
        return None


class SubCommand(ABC):
    def __init__(
        self, name: str, subcommand: "argparse._SubParsersAction[ModuleParser]"
    ) -> None:
        self.parser = subcommand.add_parser(  # type: ignore[call-arg]
            name,
            allow_abbrev=False,
            help=self.docs(),
            config_section=self.config_section(),
        )

    def register_arguments(self) -> None:  # noqa: B027
        pass

    @abstractmethod
    def execute(self, args: argparse.Namespace) -> None:
        pass

    @classmethod
    def docs(cls) -> Optional[str]:
        if not cls.__doc__:
            return None
        return cls.__doc__.strip().split("\n", maxsplit=1)[0]

    @classmethod
    def config_section(cls) -> Optional[str]:
        return cls.__name__.replace("_", "-")
