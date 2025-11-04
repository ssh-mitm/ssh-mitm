"""
Module for exposing the public API of the SSH-MITM module parser.

This module provides access to the main classes used for parsing command-line arguments
and managing modules in the SSH-MITM framework. It serves as the public interface
to the module parser functionality.

.. py:data:: __all__
   :type: list[str]
   :value: ["BaseModule", "ModuleParser", "SubCommand"]

   A list of public objects available from this module.
"""

from sshmitm.moduleparser.modules import BaseModule, SubCommand
from sshmitm.moduleparser.parser import ModuleParser

__all__ = [
    "BaseModule",
    "ModuleParser",
    "SubCommand",
]
