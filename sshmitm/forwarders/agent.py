import logging
import os
import select
import socket
import tempfile
import threading
import time
import uuid

import paramiko.agent
from paramiko.agent import Agent, AgentClientProxy, AgentKey, AgentServerProxy
from paramiko.channel import Channel
from paramiko.transport import Transport


class AgentProxy:
    def __init__(self, transport: Transport) -> None:
        self.agents: list[Agent | AgentClientProxy] = []
        self.transport = transport
        self.local_socket: AgentLocalSocket | None = None
        agent_proxy = AgentServerProxy(self.transport)
        os.environ.update(agent_proxy.get_env())
        agent_proxy.connect()
        self.agent = Agent()
        self.keys = self.agent.get_keys()[:]
        self.agents.append(self.agent)
        # should be able to be closed now, but for some reason there is a race
        # agent is still sending over the channel
        # agent.close()  # noqa: ERA001

    def get_keys(self) -> tuple[AgentKey, ...]:
        return self.keys

    def forward_agent(self, client_channel: Channel) -> bool:
        return client_channel.request_forward_agent(self._forward_agent_handler)

    def _forward_agent_handler(self, remote_channel: Channel) -> None:
        agent = AgentServerProxy(self.transport)
        os.environ.update(agent.get_env())
        time.sleep(0.1)
        self.agents.append(AgentClientProxy(remote_channel))

    def close(self) -> None:
        if self.local_socket is not None:
            self.local_socket.close()
        for agent_proxy in self.agents:
            agent_proxy.close()


class AgentLocalSocket:
    """Exposes the client's forwarded SSH agent as a local Unix domain socket.

    Opens a server socket under ``/tmp`` and, for each incoming connection,
    opens a fresh agent-forwarding channel through the SSH transport.  The two
    sides are bridged at the raw byte level so any standard agent client
    (ssh-add, ssh-keygen, …) can use it by pointing SSH_AUTH_SOCK at the path.
    """

    def __init__(self, transport: Transport) -> None:
        self.transport = transport
        self.socket_path = os.path.join(
            tempfile.gettempdir(), f"ssh-mitm-{uuid.uuid4().hex[:8]}.agent"
        )
        self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server.bind(self.socket_path)
        self._server.listen(5)
        self._running = True
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def _accept_loop(self) -> None:
        while self._running:
            try:
                readable = select.select([self._server], [], [], 0.5)[0]
                if not readable:
                    continue
                client_sock, _ = self._server.accept()
                threading.Thread(
                    target=self._handle, args=(client_sock,), daemon=True
                ).start()
            except OSError:
                break

    def _handle(self, client_sock: socket.socket) -> None:
        proxy = AgentServerProxy(self.transport)
        sock_path = proxy.get_env()["SSH_AUTH_SOCK"]
        proxy.connect()
        agent_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            agent_sock.connect(sock_path)
            self._bridge(client_sock, agent_sock)
        except Exception:
            logging.debug("agent local socket: connection error", exc_info=True)
        finally:
            agent_sock.close()
            client_sock.close()

    def _bridge(self, a: socket.socket, b: socket.socket) -> None:
        while True:
            try:
                readable, _, err = select.select([a, b], [], [a, b], 5.0)
                if err:
                    break
                for src in readable:
                    dst = b if src is a else a
                    data = src.recv(4096)
                    if not data:
                        return
                    dst.sendall(data)
            except OSError:
                return

    def close(self) -> None:
        self._running = False
        try:
            self._server.close()
        except OSError:
            pass
        try:
            os.unlink(self.socket_path)
        except OSError:
            pass
