import logging
import os
import select
import socket
import tempfile
import threading
import time
import uuid
from typing import TYPE_CHECKING

import paramiko
import paramiko.agent
from paramiko.agent import Agent, AgentClientProxy, AgentKey, AgentServerProxy
from paramiko.channel import Channel
from paramiko.common import byte_chr
from paramiko.message import Message
from paramiko.transport import Transport

if TYPE_CHECKING:
    from paramiko.pkey import PKey

# SSH agent protocol constants (RFC 4254 + OpenSSH extensions)
_SSH2_AGENTC_ADD_IDENTITY = byte_chr(17)
_SSH2_AGENTC_REMOVE_IDENTITY = byte_chr(18)
_SSH2_AGENTC_REMOVE_ALL_IDENTITIES = byte_chr(19)
_SSH_AGENTC_LOCK = byte_chr(22)
_SSH_AGENT_SUCCESS = 6


class AgentProxy:
    def __init__(self, transport: Transport) -> None:
        self.agents: list[Agent | AgentClientProxy] = []
        self.transport = transport
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

    def _send(self, msg: Message) -> tuple[int, Message]:
        """Send a raw agent protocol message and return (type, response)."""
        conn = getattr(self.agent, "_conn", None)
        if conn is not None:
            conn.settimeout(10.0)
        return self.agent._send_message(bytes(msg))  # type: ignore[attr-defined]

    def remove_all_keys(self) -> bool:
        """Remove all identities from the forwarded agent."""
        try:
            msg = Message()
            msg.add_byte(_SSH2_AGENTC_REMOVE_ALL_IDENTITIES)
            ptype, _ = self._send(msg)
            return ptype == _SSH_AGENT_SUCCESS
        except Exception:
            logging.exception("agent: error removing all keys")
            return False

    def remove_key(self, key: AgentKey) -> bool:
        """Remove a specific identity from the forwarded agent."""
        try:
            msg = Message()
            msg.add_byte(_SSH2_AGENTC_REMOVE_IDENTITY)
            msg.add_string(key.asbytes())
            ptype, _ = self._send(msg)
            return ptype == _SSH_AGENT_SUCCESS
        except Exception:
            logging.exception("agent: error removing key")
            return False

    def lock(self, password: str) -> bool:
        """Lock the forwarded agent with a password.

        Note: most agents reject an empty password.
        """
        try:
            msg = Message()
            msg.add_byte(_SSH_AGENTC_LOCK)
            msg.add_string(password.encode())
            ptype, _ = self._send(msg)
            return ptype == _SSH_AGENT_SUCCESS
        except Exception:
            logging.exception("agent: error locking agent")
            return False

    def inject_key(self, key: "PKey", comment: str = "") -> bool:
        """Inject a private key into the forwarded agent."""
        try:
            msg = self._build_add_identity(key, comment)
        except Exception:
            logging.exception("agent: could not serialize key for injection")
            return False
        if msg is None:
            return False
        try:
            ptype, _ = self._send(msg)
            return ptype == _SSH_AGENT_SUCCESS
        except Exception:
            logging.exception("agent: error injecting key")
            return False

    def inject_key_from_file(self, path: str, comment: str = "") -> bool:
        """Load a private key file and inject it into the forwarded agent."""
        key = _load_private_key(path)
        if key is None:
            logging.error("agent: could not load key from %s", path)
            return False
        return self.inject_key(key, comment or path)

    @staticmethod
    def _build_add_identity(key: "PKey", comment: str) -> "Message | None":
        msg = Message()
        msg.add_byte(_SSH2_AGENTC_ADD_IDENTITY)

        if isinstance(key, paramiko.Ed25519Key):
            # nacl.signing.SigningKey: bytes(sk) = 32-byte seed, bytes(sk.verify_key) = 32-byte public
            sk = key._signing_key  # type: ignore[attr-defined]
            pub = bytes(sk.verify_key)
            priv = bytes(sk)
            msg.add_string("ssh-ed25519")
            msg.add_string(pub)
            msg.add_string(priv + pub)  # agent format: seed || public
            msg.add_string(comment)
            return msg

        if isinstance(key, paramiko.RSAKey):
            # cryptography RSAPrivateKey
            nums = key.key.private_numbers()  # type: ignore[attr-defined]
            pub = nums.public_numbers
            msg.add_string("ssh-rsa")
            msg.add_mpint(pub.n)
            msg.add_mpint(pub.e)
            msg.add_mpint(nums.d)
            msg.add_mpint(nums.iqmp)
            msg.add_mpint(nums.p)
            msg.add_mpint(nums.q)
            msg.add_string(comment)
            return msg

        if isinstance(key, paramiko.ECDSAKey):
            # cryptography EllipticCurvePrivateKey
            from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

            ec_key = key.signing_key  # type: ignore[attr-defined]
            curve_name = _ecdsa_curve_name(ec_key)
            if curve_name is None:
                logging.warning("agent: unsupported ECDSA curve for injection")
                return None
            pub_bytes = ec_key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
            priv_num = ec_key.private_numbers().private_value
            key_type = f"ecdsa-sha2-{curve_name}"
            msg.add_string(key_type)
            msg.add_string(curve_name)
            msg.add_string(pub_bytes)
            msg.add_mpint(priv_num)
            msg.add_string(comment)
            return msg

        logging.warning("agent: unsupported key type for injection: %s", type(key).__name__)
        return None

    def close(self) -> None:
        for agent_proxy in self.agents:
            agent_proxy.close()


def _load_private_key(path: str) -> "PKey | None":
    for cls in (paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey):
        try:
            return cls.from_private_key_file(path)  # type: ignore[return-value]
        except Exception:
            continue
    return None


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


def _ecdsa_curve_name(ec_key: object) -> "str | None":
    try:
        from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, SECP384R1, SECP521R1

        curve = ec_key.curve  # type: ignore[union-attr]
        if isinstance(curve, SECP256R1):
            return "nistp256"
        if isinstance(curve, SECP384R1):
            return "nistp384"
        if isinstance(curve, SECP521R1):
            return "nistp521"
    except Exception:
        pass
    return None
