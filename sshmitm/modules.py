from typing import ClassVar

from sshmitm.moduleparser.modules import BaseModule


class SSHMITMBaseModule(BaseModule):
    """Base class for all SSH-MITM plugin modules."""

    entry_point_prefix: ClassVar[str] = "sshmitm"
