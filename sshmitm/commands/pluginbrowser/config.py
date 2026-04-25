"""Configuration file helpers for the plugin browser."""

from __future__ import annotations

import argparse
import os
import sys
from configparser import ConfigParser
from importlib import resources


def load_default_cfg() -> ConfigParser:
    cfg = ConfigParser()
    conf = resources.files("sshmitm") / "data/default.ini"
    cfg.read_string(conf.read_text())
    return cfg


def get_config_path() -> str | None:
    """Read --config path directly from sys.argv without side effects."""
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("--config", dest="config_path")
    parsed, _ = p.parse_known_args(sys.argv[1:])
    return str(parsed.config_path) if parsed.config_path is not None else None


def load_user_cfg(path: str) -> ConfigParser:
    cfg = ConfigParser()
    cfg.read(os.path.expanduser(path))
    return cfg


def cfg_items(cfg: ConfigParser | None, section: str) -> dict[str, str]:
    if cfg is None or not cfg.has_section(section):
        return {}
    return dict(cfg.items(section))
