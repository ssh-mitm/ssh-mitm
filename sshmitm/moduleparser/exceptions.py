from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from sshmitm.moduleparser.modules import BaseModule


class BaseModuleError(Exception):
    pass


class ModuleError(BaseModuleError):
    def __init__(
        self,
        moduleclass: type["BaseModule"] | tuple[type["BaseModule"], ...] | None = None,
        baseclass: type["BaseModule"] | tuple[type["BaseModule"], ...] | None = None,
        message: str | None = None,
    ) -> None:
        super().__init__()
        self.moduleclass = moduleclass
        self.baseclass = baseclass
        self.message = message


class InvalidModuleArguments(BaseModuleError):
    pass
