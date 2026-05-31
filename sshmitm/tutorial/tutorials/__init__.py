"""All available tutorials, discovered via the ``sshmitm.Tutorial`` entry point."""

from sshmitm.tutorial._loader import load_all

ALL_TUTORIALS = load_all()
