from typing import TYPE_CHECKING, Optional, Tuple, Type, Union

if TYPE_CHECKING:
    from sshmitm.moduleparser.modules import BaseModule


class BaseModuleError(Exception):
    pass


class ModuleError(BaseModuleError):
    def __init__(
        self,
        moduleclass: Optional[
            Union[Type["BaseModule"], Tuple[Type["BaseModule"], ...]]
        ] = None,
        baseclass: Optional[
            Union[Type["BaseModule"], Tuple[Type["BaseModule"], ...]]
        ] = None,
        message: Optional[str] = None,
    ) -> None:
        super().__init__()
        self.moduleclass = moduleclass
        self.baseclass = baseclass
        self.message = message


class InvalidModuleArguments(BaseModuleError):
    pass
