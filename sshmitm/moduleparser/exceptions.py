from typing import TYPE_CHECKING, Optional, Tuple, Type, Union

if TYPE_CHECKING:
    from sshmitm.moduleparser.modules import BaseModule


class BaseModuleError(Exception):
    """
    Base exception class for module-related errors.

    This class serves as the base for all exceptions related to module handling.
    """


class ModuleError(BaseModuleError):
    """
    Exception raised when errors occur during module initialization or usage.

    This exception is raised when there is an issue with module classes or their base classes.
    It stores information about the problematic module class, base class, and an optional error message.

    :param moduleclass: The module class or tuple of module classes that caused the error.
    :param baseclass: The base class or tuple of base classes that the module class should inherit from.
    :param message: An optional error message providing additional details.
    """

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
        """
        Initialize the ``ModuleError`` exception.

        :param moduleclass: The module class or tuple of module classes that caused the error.
        :param baseclass: The base class or tuple of base classes that the module class should inherit from.
        :param message: An optional error message providing additional details.
        """
        super().__init__()
        self.moduleclass = moduleclass
        self.baseclass = baseclass
        self.message = message


class InvalidModuleArguments(BaseModuleError):
    """
    Exception raised when invalid arguments are provided to a module.

    This exception is raised when the arguments passed to a module are invalid or cannot be parsed.
    """
