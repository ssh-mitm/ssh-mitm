import argparse
from typing import (
    Optional,
    Sequence,
    Text
)
import argcomplete  # type: ignore
from enhancements.modules import ModuleParser


class SshMitmParser(ModuleParser):

    def _create_parser(self, args: Optional[Sequence[Text]] = None, namespace: Optional[argparse.Namespace] = None) -> 'argparse.ArgumentParser':
        parser = super()._create_parser(args, namespace)
        argcomplete.autocomplete(parser)
        return parser
