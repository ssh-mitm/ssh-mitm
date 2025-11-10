import argparse
from typing import TYPE_CHECKING, Any, Dict, Optional, Sequence, Type, Union

from colored.colored import attr, fg  # type: ignore[import-untyped]

from sshmitm.core.compat import metadata
from sshmitm.core.logger import Colors

if TYPE_CHECKING:
    from sshmitm.moduleparser.modules import BaseModule


def load_module(
    entry_point_prefix: str, entry_point_class: Type["BaseModule"]
) -> Type["argparse.Action"]:
    """
    Create an action class to load a ``BaseModule`` from an entry point.

    This function returns a custom ``argparse.Action`` class that can be used
    to load a ``BaseModule`` based on a command-line argument. The action searches
    for the specified module in the entry points and loads it if found.

    :param entry_point_class: The base class of the module to load.
    :return: A custom ``argparse.Action`` class for loading modules.
    """

    class ModuleLoaderAction(argparse.Action):
        """
        Custom action to load a ``BaseModule`` from an entry point.

        This action is called when the corresponding command-line argument is parsed.
        It searches for the specified module in the entry points and loads it.
        """

        def __call__(
            self,
            parser: argparse.ArgumentParser,
            namespace: argparse.Namespace,
            values: Union[str, Sequence[Any], None],
            option_string: Optional[str] = None,
        ) -> None:
            """
            Execute the action to load the module.

            :param parser: The argument parser.
            :param namespace: The namespace to store the loaded module.
            :param values: The value(s) provided for the argument.
            :param option_string: The option string used to invoke the action.
            """
            del parser
            del option_string
            if values:
                # Search for the module in the entry points
                for entry_point in metadata.entry_points(
                    group=f"{entry_point_prefix}.{entry_point_class.__name__}"
                ):
                    if values in (entry_point.name, entry_point.module):
                        values = [entry_point.load()]
                        setattr(namespace, self.dest, values[0] if values else None)
                        break

    return ModuleLoaderAction


def set_module_kwargs(
    entry_point_prefix: str, entry_point_class: Type["BaseModule"], **kwargs: Any
) -> Dict[str, Any]:
    """
    Set keyword arguments for a module, including choices and help text.

    This function configures the keyword arguments for a module argument,
    including the available choices and help text. It retrieves the available
    modules from the entry points and formats the help text with descriptions.

    :param entry_point_class: The base class of the module.
    :param kwargs: Additional keyword arguments for the module.
    :return: Updated keyword arguments with choices and help text.
    """
    # Retrieve and sort entry points for the module
    entry_points = sorted(
        metadata.entry_points(
            group=f"{entry_point_prefix}.{entry_point_class.__name__}"
        ),
        key=lambda x: x.name,
    )

    # Return kwargs unchanged if no entry points are found
    if not entry_points:
        return kwargs

    choices = []
    descriptions = []
    default_value = kwargs.get("default")
    default_name = None

    # Iterate over entry points to collect choices and descriptions
    for entry_point in entry_points:
        choices.append(entry_point.name)
        loaded_class = entry_point.load()

        # Set the default name if the default value matches the loaded class
        if default_value is loaded_class:
            default_name = entry_point.name

        # Extract the first line of the docstring as the description
        entry_point_desc = (
            "" if not loaded_class.__doc__ else loaded_class.__doc__.split("\n")[0]
        )

        # Format the description with color styling
        if entry_point_desc:
            entry_point_description = f"\t* {Colors.stylize(entry_point.name, fg('blue'))} -> {entry_point_desc}"
        else:
            entry_point_description = (
                f"\t* {Colors.stylize(entry_point.name, fg('blue'))}"
            )

        descriptions.append(entry_point_description)

    # Update kwargs with choices and help text
    kwargs["choices"] = sorted(choices)

    if len(choices) > 0:
        kwargs["help"] = kwargs.get("help") or ""

        # Add default module to help text if a default is set
        if default_name:
            kwargs[
                "help"
            ] += f"\ndefault module: {Colors.stylize(default_name, fg('blue') + attr('bold'))}"

        # Add available modules to help text
        kwargs["help"] += "\navailable modules:\n{}".format("\n".join(descriptions))
    else:
        # Suppress help if no choices are available
        kwargs["help"] = argparse.SUPPRESS

    return kwargs
