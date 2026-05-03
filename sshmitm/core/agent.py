from typing import TYPE_CHECKING

from sshmitm.core.modules import SSHMITMBaseModule

if TYPE_CHECKING:
    from sshmitm.forwarders.agent import AgentProxy
    from sshmitm.session import Session


class AgentBaseForwarder(SSHMITMBaseModule):
    """Specifies the interface for managing SSH agent forwarding and optional agent breakin."""

    def __init__(self, session: "Session") -> None:
        super().__init__()
        self.session = session

    def request(self, existing_agent: "AgentProxy | None" = None) -> "AgentProxy | None":
        raise NotImplementedError
