"""Load tutorial definitions via the ``sshmitm.Tutorial`` entry point group.

Any package can contribute tutorials by adding entries to its
``pyproject.toml``::

    [project.entry-points."sshmitm.Tutorial"]
    my-tutorial = "mypkg.tutorials.my_tutorial:MyTutorial"

The value must be an importable :class:`~sshmitm.tutorial._definitions.Tutorial`
subclass.  Built-in tutorials are registered the same way in
``sshmitm``'s own ``pyproject.toml``.
"""

from __future__ import annotations

import logging
from importlib.metadata import entry_points

from sshmitm.tutorial._definitions import Tutorial

_log = logging.getLogger(__name__)


def load_all() -> list[Tutorial]:
    """Load all registered tutorials and return one instance each, sorted by id."""
    tutorials: list[Tutorial] = []

    for ep in entry_points(group="sshmitm.Tutorial"):
        try:
            cls = ep.load()
        except Exception:
            _log.warning("Failed to load tutorial entry point %r", ep.name, exc_info=True)
            continue

        if not (isinstance(cls, type) and issubclass(cls, Tutorial)):
            _log.warning(
                "Entry point %r does not point to a Tutorial subclass: %r",
                ep.name, cls,
            )
            continue

        tutorials.append(cls())

    return sorted(tutorials, key=lambda t: t.id)
