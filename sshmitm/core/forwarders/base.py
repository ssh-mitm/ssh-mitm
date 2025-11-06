import logging
import threading
from typing import TYPE_CHECKING, Optional

import paramiko

from sshmitm.core.exceptions import MissingClient
from sshmitm.moduleparser import BaseModule

if TYPE_CHECKING:
    import sshmitm
    from sshmitm.core.session import Session


class BaseForwarder(BaseModule):
    """
    base class for all forwarders.
    """

    # Slow file transmission
    BUF_LEN = 65536 * 100
    IS_THREADED: bool = False

    def __init__(
        self,
        session: "sshmitm.core.session.Session",
        *,
        client_channel: Optional[paramiko.Channel] = None,
    ) -> None:
        super().__init__()

        self._thread_lock = threading.Lock()
        self._thread = None  # Referenz auf den Thread speichern
        self._forwarding_started: bool = False
        self._forwarding_running: bool = False

        self.session: "Session" = session
        self._client_channel: Optional[paramiko.Channel] = client_channel
        self._server_channel: Optional[paramiko.Channel] = None
        self.session.register_session_thread()

    @property
    def client_channel(self) -> Optional[paramiko.Channel]:
        """Returns the client channel for the current plugin type"""
        return self._client_channel

    @property
    def server_channel(self) -> Optional[paramiko.Channel]:
        return self._server_channel

    def start(self) -> None:
        if self.IS_THREADED:
            self._start_threaded_forwarding()
        else:
            self._start_forwarding()

    def _start_forwarding(self) -> None:
        try:
            with self._thread_lock:
                if self._forwarding_started:
                    return
                self._forwarding_started = True
                self._forwarding_running = True
            self.forward()
        finally:
            with self._thread_lock:
                self._forwarding_running = False

    def _start_threaded_forwarding(self) -> None:
        with self._thread_lock:
            if self._forwarding_started:
                return
        self._thread = threading.Thread(target=self._start_forwarding)
        self._thread.start()

    @property
    def is_active(self) -> bool:
        if self.client_channel.closed:
            return False
        if self._thread is not None and self._thread.is_alive():
            return True
        with self._thread_lock:
            return self._forwarding_running

    def forward(self) -> None:
        """Forwards data between the client and the server"""
        logging.debug("BaseForwarder.forward called")
        if self.session.ssh_client is None or self.session.ssh_client.transport is None:
            msg = "session.ssh_client is None"
            raise MissingClient(msg)
        self._server_channel = self.session.ssh_client.transport.open_session()
        self.session.authenticator.forward_agent_to_remote(self._server_channel)

        # pass environment variables from client to server
        for env_name, env_value in self.session.env_requests.items():
            self._server_channel.set_environment_variable(env_name, env_value)

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
