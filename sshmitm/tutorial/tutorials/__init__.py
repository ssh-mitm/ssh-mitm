"""All available tutorials, loaded from the tutorials package directory."""

from sshmitm.tutorial._loader import load_all

ALL_TUTORIALS = load_all("sshmitm.tutorial.tutorials")
