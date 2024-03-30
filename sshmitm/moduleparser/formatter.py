import argparse
from typing import Any, List, Optional

from colored.colored import attr, fg  # type: ignore[import-untyped]

from sshmitm.logging import Colors


class ModuleFormatter(argparse.HelpFormatter):
    """Help message formatter which retains formatting of all help text.
    Only the name of this class is considered a public API. All the methods
    provided by the class are considered an implementation detail.
    """

    class _Section:  # pylint: disable=too-few-public-methods
        def __init__(
            self,
            formatter: argparse.HelpFormatter,
            parent: Any,
            heading: Optional[str] = None,
        ) -> None:
            self.formatter = formatter
            self.parent = parent
            self.heading = heading
            self.items = []  # type: ignore[var-annotated]

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
                return ""

            # add the heading if the section was non-empty
            if self.heading is not argparse.SUPPRESS and self.heading is not None:
                current_indent = (
                    self.formatter._current_indent
                )  # pylint: disable=protected-access
                heading = "%*s%s:\n" % (  # pylint: disable=consider-using-f-string
                    current_indent,
                    "",
                    Colors.stylize(self.heading, fg("red") + attr("bold")),
                )
            else:
                heading = ""

            # join the section-initial newline, the heading and the help
            return join(["\n", heading, item_help, "\n"])

    def _split_lines(self, text: str, width: int) -> List[str]:
        del width
        return text.splitlines()
