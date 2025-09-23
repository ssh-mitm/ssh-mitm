from abc import abstractmethod
from typing import TYPE_CHECKING, Optional

import paramiko

from sshmitm.exceptions import MissingClient
from sshmitm.moduleparser import BaseModule

if TYPE_CHECKING:
    import sshmitm
    from sshmitm.session import Session


class BaseForwarder(BaseModule):
    """
    base class for all forwarders.
    """

    # Slow file transmission
    BUF_LEN = 65536 * 100

    def __init__(self, session: "sshmitm.session.Session") -> None:
        import logging
        logging.debug("DEBUG: BaseForwarder.__init__() starting")
        super().__init__()
        
        logging.debug("DEBUG: Checking ssh_client state - ssh_client=%s", session.ssh_client)
        if session.ssh_client is not None:
            logging.debug("DEBUG: ssh_client exists, checking transport - transport=%s", session.ssh_client.transport)
            if session.ssh_client.transport is not None:
                logging.debug("DEBUG: transport exists, checking if active - active=%s", session.ssh_client.transport.is_active())
            else:
                logging.error("DEBUG: ssh_client.transport is None!")
        else:
            logging.error("DEBUG: session.ssh_client is None!")
            
        if session.ssh_client is None or session.ssh_client.transport is None:
            msg = "SSH session not active"
            logging.error("DEBUG: Raising MissingClient: %s", msg)
            raise MissingClient(msg)
            
        # Handle ConfD/network device servers that drop connections after auth
        if not session.ssh_client.transport.is_active():
            logging.warning("DEBUG: Transport inactive, attempting to reconnect for ConfD/network device compatibility")
            try:
                # Try to reconnect using stored credentials
                from sshmitm.clients.ssh import SSHClient, AuthenticationMethod
                logging.debug("DEBUG: Reconnecting to %s:%s", session.remote_address[0], session.remote_address[1])
                
                # Recreate SSH client with same credentials
                new_ssh_client = SSHClient(
                    host=session.remote_address[0],
                    port=session.remote_address[1],
                    method=AuthenticationMethod.PASSWORD,  # ConfD typically uses password auth
                    password=session.password_provided,
                    user=session.username_provided,
                    key=None,
                    session=session
                )
                
                if new_ssh_client.connect():
                    logging.debug("DEBUG: Reconnection successful")
                    session.ssh_client = new_ssh_client
                else:
                    logging.error("DEBUG: Reconnection failed")
                    msg = "Failed to reconnect to ConfD server"
                    raise MissingClient(msg)
                    
            except Exception as reconnect_error:
                logging.error("DEBUG: Reconnection attempt failed: %s", reconnect_error)
                msg = "SSH session not active and reconnection failed"
                raise MissingClient(msg)
            
        logging.debug("DEBUG: Opening server channel session")
        try:
            self.server_channel: paramiko.Channel = (
                session.ssh_client.transport.open_session()
            )
            logging.debug("DEBUG: Server channel opened successfully: %s", self.server_channel)
        except Exception as e:
            logging.error("DEBUG: Failed to open server channel: %s", e)
            raise
            
        if session.agent is not None:
            logging.debug("DEBUG: Forwarding agent")
            session.agent.forward_agent(self.server_channel)
        else:
            logging.debug("DEBUG: No agent to forward")
            
        self.session: "Session" = session
        self.session.register_session_thread()

        # pass environment variables from client to server
        logging.debug("DEBUG: Setting environment variables: %s", session.env_requests)
        for env_name, env_value in self.session.env_requests.items():
            self.server_channel.set_environment_variable(env_name, env_value)
        
        logging.debug("DEBUG: BaseForwarder.__init__() completed successfully")

    @property
    @abstractmethod
    def client_channel(self) -> Optional[paramiko.Channel]:
        """Returns the client channel for the current plugin type"""

    @abstractmethod
    def forward(self) -> None:
        """Forwards data between the client and the server"""

    def close_session(self, channel: paramiko.Channel) -> None:
        channel.lock.acquire()
        if not channel.closed:
            channel.lock.release()
            channel.close()
        if channel.lock.locked():
            channel.lock.release()

    def _closed(self, channel: paramiko.Channel) -> bool:
        # return channel.closed or channel.eof_received or channel.eof_sent or not channel.active  # noqa: ERA001
        return channel.closed or not channel.active
