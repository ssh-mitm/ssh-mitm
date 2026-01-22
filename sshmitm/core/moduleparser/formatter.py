# Module `formatter` shadows a Python standard-library module
import argparse
from typing import Any, List, Optional

from colored.colored import attr, fg  # type: ignore[import-untyped]

from sshmitm.core.logger import Colors


class ModuleFormatter(argparse.HelpFormatter):
    """
    Custom help message formatter that retains formatting of all help text.

    This formatter extends ``argparse.HelpFormatter`` to provide enhanced formatting
    for help messages, including colored headings and proper indentation.
    Only the name of this class is considered part of the public API.
    All methods are implementation details and may change without notice.

    .. note::
        This class is designed to work with the ``sshmitm`` module system.
    """

    class _Section:  # pylint: disable=too-few-public-methods
        """
        Internal class representing a section of help text.

        This class is used internally by ``ModuleFormatter`` to manage and format
        sections of help text, including headings and indented content.

        :param formatter: The parent ``HelpFormatter`` instance.
        :param parent: The parent section, if any.
        :param heading: The heading for this section.
        """

        def __init__(
            self,
            formatter: argparse.HelpFormatter,
            parent: Any,
            heading: Optional[str] = None,
        ) -> None:
            """
            Initialize a help text section.

            :param formatter: The parent ``HelpFormatter`` instance.
            :param parent: The parent section, if any.
            :param heading: The heading for this section.
            """
            self.formatter = formatter
            self.parent = parent
            self.heading = heading
            self.items = []  # type: ignore[var-annotated]

        def format_help(self) -> str:
            """
            Format the help text for this section.

            This method formats the section's items with proper indentation and heading.
            If the section is empty, it returns an empty string.

            :return: The formatted help text for this section.
            """
            # pylint: disable=protected-access
            # Format the indented section
            if self.parent is not None:
                self.formatter._indent()  # pylint: disable=protected-access

            join = self.formatter._join_parts  # pylint: disable=protected-access
            item_help = join([func(*args) for func, args in self.items])

            if self.parent is not None:
                self.formatter._dedent()  # pylint: disable=protected-access

            # Return nothing if the section was empty
            if not item_help:
                return ""

            # Add the heading if the section was non-empty
            if self.heading is not argparse.SUPPRESS and self.heading is not None:
                current_indent = (
                    self.formatter._current_indent
                )  # pylint: disable=protected-access
                heading = f"{' ' * current_indent}{Colors.stylize(self.heading, fg('red') + attr('bold'))}:\n"
            else:
                heading = ""

            # Join the section-initial newline, the heading, and the help text
            return join(["\n", heading, item_help, "\n"])

    def _split_lines(self, text: str, width: int) -> List[str]:
        """
        Split text into lines without considering width.

        This method overrides the default behavior to split text by existing
        newlines, ignoring the width parameter. This preserves the original
        formatting of the text.

        :param text: The text to split.
        :param width: The maximum line width (ignored in this implementation).
        :return: A list of lines from the input text.
        """
        del width  # Width is ignored in this implementation
        return text.splitlines()
