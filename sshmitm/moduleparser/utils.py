import argparse
from typing import TYPE_CHECKING, Any, Dict, Optional, Sequence, Type, Union

from colored.colored import attr, fg  # type: ignore[import-untyped]

from sshmitm.logging import Colors
from sshmitm.utils import metadata

if TYPE_CHECKING:
    from sshmitm.moduleparser.modules import BaseModule


def load_module(entry_point_class: Type["BaseModule"]) -> Type["argparse.Action"]:
    """Action to be able to define BaseModule with the "add_module" method of the ModuleParser as command line parameter"""

    class ModuleLoaderAction(argparse.Action):
        def __call__(
            self,
            parser: argparse.ArgumentParser,
            namespace: argparse.Namespace,
            values: Union[str, Sequence[Any], None],
            option_string: Optional[str] = None,
        ) -> None:
            del parser
            del option_string
            if values:
                for entry_point in metadata.entry_points(
                    group=f"sshmitm.{entry_point_class.__name__}"
                ):
                    if values in (entry_point.name, entry_point.module):
                        values = [entry_point.load()]
                        setattr(namespace, self.dest, values[0] if values else None)
                        break

    return ModuleLoaderAction


def set_module_kwargs(
    entry_point_class: Type["BaseModule"], **kwargs: Any
) -> Dict[str, Any]:
    entry_points = sorted(
        metadata.entry_points(group=f"sshmitm.{entry_point_class.__name__}"),
        key=lambda x: x.name,
    )
    if not entry_points:
        return kwargs

    choices = []
    descriptions = []
    default_value = kwargs.get("default", None)
    default_name = None
    for entry_point in entry_points:
        choices.append(entry_point.name)

        loaded_class = entry_point.load()
        if default_value is loaded_class:
            default_name = entry_point.name
        entry_point_desc = (
            "" if not loaded_class.__doc__ else loaded_class.__doc__.split("\n")[0]
        )
        if entry_point_desc:
            entry_point_description = f"\t* {Colors.stylize(entry_point.name, fg('blue'))} -> {entry_point_desc}"
        else:
            entry_point_description = (
                f"\t* {Colors.stylize(entry_point.name, fg('blue'))}"
            )
        descriptions.append(entry_point_description)

    kwargs["choices"] = sorted(choices)
    if len(choices) > 1:
        kwargs["help"] = kwargs.get("help") or ""
        if default_name:
            kwargs[
                "help"
            ] += f"\ndefault module: {Colors.stylize(default_name, fg('blue') + attr('bold'))}"
        kwargs["help"] += "\navailable modules:\n{}".format("\n".join(descriptions))
    else:
        kwargs["help"] = argparse.SUPPRESS
    return kwargs
