import inspect
import logging
from dataclasses import dataclass, field
from importlib.metadata import entry_points
from typing import Any, ClassVar

from sshmitm.moduleparser.utils import is_handler_allowed


@dataclass
class ExecHandlerEntry:
    """Registry entry for a command-prefix-based exec handler."""

    handler: type[Any]
    name: str = field(default="")
    disable_pty: bool = False
    disable_ssh: bool = False

    def __post_init__(self) -> None:
        if not self.name:
            self.name = self.handler.__name__


class ExecHandlerRegistry:
    """Protocol-independent registry for exec-command handlers.

    Handlers are discovered via the ``sshmitm.ExecHandler`` entry point group
    and matched against incoming commands by longest-prefix.
    """

    _exec_handlers: ClassVar[dict[bytes, ExecHandlerEntry]] = {}
    _handlers_loaded: ClassVar[bool] = False

    @classmethod
    def register_exec_handler(cls, prefix: bytes, entry: ExecHandlerEntry) -> None:
        cls._exec_handlers[prefix] = entry
        cls._exec_handlers = dict(
            sorted(
                cls._exec_handlers.items(), key=lambda item: len(item[0]), reverse=True
            )
        )

    @staticmethod
    def is_handler_allowed(
        name: str,
        enabled: list[str],
        disabled: list[str],
    ) -> bool:
        return is_handler_allowed(name, enabled, disabled)

    @classmethod
    def get_exec_handler(
        cls,
        command: bytes,
        enabled: list[str] | None = None,
        disabled: list[str] | None = None,
    ) -> ExecHandlerEntry | None:
        cls._ensure_handlers_loaded()
        _enabled = enabled if enabled is not None else ["ALL"]
        _disabled = disabled if disabled is not None else ["NONE"]
        for prefix, entry in cls._exec_handlers.items():
            if command.startswith(prefix):
                if cls.is_handler_allowed(entry.name, _enabled, _disabled):
                    return entry
                return None
        return None

    @classmethod
    def _ensure_handlers_loaded(cls) -> None:
        if cls._handlers_loaded:
            return
        cls._handlers_loaded = True
        cls.load_exec_handlers()

    @classmethod
    def load_exec_handlers(cls) -> None:
        """Load exec handlers registered via the ``sshmitm.ExecHandler`` entry point group."""
        handlers: dict[bytes, ExecHandlerEntry] = {}
        try:
            for ep in entry_points(group="sshmitm.ExecHandler"):
                try:
                    handler_class = ep.load()
                    if inspect.isclass(handler_class) and hasattr(
                        handler_class, "command_prefix"
                    ):
                        handlers[handler_class.command_prefix] = ExecHandlerEntry(
                            handler=handler_class,
                            name=ep.name,
                            disable_pty=getattr(handler_class, "disable_pty", False),
                            disable_ssh=getattr(handler_class, "disable_ssh", False),
                        )
                except Exception:  # pylint: disable=broad-exception-caught
                    logging.exception("Failed to load exec handler %s", ep.name)
        except Exception:  # pylint: disable=broad-exception-caught
            logging.exception("Failed to load exec handlers")
        cls._exec_handlers = dict(
            sorted(handlers.items(), key=lambda item: len(item[0]), reverse=True)
        )
