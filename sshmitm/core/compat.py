"""
compat.py - Python Import Compatibility Layer
=============================================

This module provides a unified interface for importing `metadata` and `resources`
from `importlib` across different Python versions. It ensures compatibility
between Python 3.10+ (where these are built-in) and earlier versions
(where they are provided by the `importlib_metadata` and `importlib_resources` packages).

Usage
-----
Import `metadata` and `resources` directly from this module:

    from compat import metadata, resources

    # Example usage:
    version = metadata.version("your_package")
    file_path = resources.files("your_package").joinpath("data.json")

Background
----------
- In Python 3.10+, `importlib.metadata` and `importlib.resources` are part of the standard library.
- For Python < 3.10, the backported packages `importlib_metadata` and `importlib_resources` must be installed.

Dependencies
------------
- Python 3.7+
- For Python < 3.10:
    - `importlib_metadata` (pip install importlib_metadata)
    - `importlib_resources` (pip install importlib_resources)

Notes
-----
- This module is designed to be lightweight and transparent.
- If you need to support Python versions below 3.7, additional logic may be required.
"""

import sys

__all__ = ["metadata", "resources"]

if sys.version_info >= (3, 10):
    from importlib import metadata, resources
else:
    import importlib_metadata as metadata
    import importlib_resources as resources
