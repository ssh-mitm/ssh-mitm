"""Standalone SSH mock server — run with: python -m sshmitm.mockserver"""

from __future__ import annotations

import argparse
import dataclasses
import logging
import os
import secrets
import string
import sys
import tempfile

import paramiko
import rich.box
from rich import print as rich_print
from rich.logging import RichHandler
from rich.table import Table
from rich.text import Text

from sshmitm.console import sshconsole
from sshmitm.mockserver._agent import MockAgent
from sshmitm.mockserver._interfaces import KbdintRound, MultiUserMockServer, _UserConfig
from sshmitm.mockserver._runner import start_server_thread
from sshmitm.utils import SSHPubKey

_log = logging.getLogger("sshmitm.mockserver")


# ---------------------------------------------------------------------------
# Credential generation
# ---------------------------------------------------------------------------

def _random_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


# ---------------------------------------------------------------------------
# Observable server — logs auth events via standard logging
# ---------------------------------------------------------------------------

class _ObservableServer(MultiUserMockServer):
    """Logs every auth attempt at INFO (success) or WARNING (failure)."""

    def _emit(self, method: str, username: str, result: int, extra: str = "") -> None:
        ok = result == paramiko.common.AUTH_SUCCESSFUL
        icon = "✓" if ok else "✗"
        suffix = f"  {extra}" if extra else ""
        msg = f"{icon}  {method:<20} user={username!r}{suffix}"
        (_log.info if ok else _log.warning)(msg)

    def check_auth_none(self, username: str) -> int:
        result = super().check_auth_none(username)
        self._emit("none", username, result)
        return result

    def check_auth_password(self, username: str, password: str) -> int:
        result = super().check_auth_password(username, password)
        self._emit("password", username, result)
        return result

    def check_auth_publickey(self, username: str, key: paramiko.PKey) -> int:
        result = super().check_auth_publickey(username, key)
        self._emit("publickey", username, result, extra=f"key={key.get_name()}")
        return result

    def check_auth_interactive_response(
        self, responses: list[str]
    ) -> "int | paramiko.server.InteractiveQuery":
        result = super().check_auth_interactive_response(responses)
        if isinstance(result, int):
            self._emit("keyboard-interactive", self._kbdint_username or "?", result)
        return result


# ---------------------------------------------------------------------------
# Server configuration
# ---------------------------------------------------------------------------

@dataclasses.dataclass
class _ServerConfig:
    address: str
    port: int
    host_key: paramiko.PKey
    host_key_source: str          # "generated temporary" or "loaded"
    users: dict[str, _UserConfig]
    key_file: str | None
    agent_sock: str | None
    agent: MockAgent | None


# ---------------------------------------------------------------------------
# Startup display
# ---------------------------------------------------------------------------

def _print_serverinfo(cfg: _ServerConfig) -> None:
    pub = SSHPubKey(cfg.host_key)

    sshconsole.rule("[bold]SSH Mock Server", style="bold blue")
    rich_print(
        f"[bold]\U0001f4bb listen on[/bold] {cfg.address} on port {cfg.port}"
    )
    sshconsole.rule(characters=".", style="bright_black")

    rich_print("[bold blue]:key: SSH-Host-Keys:")
    print(
        f"   {cfg.host_key_source} {cfg.host_key.get_name()} key "
        f"with {cfg.host_key.get_bits()} bit length\n"
        f"   {pub.hash_md5()}\n"
        f"   {pub.hash_sha256()}\n"
        f"   {pub.hash_sha512()}"
    )
    sshconsole.rule(characters=".", style="bright_black")

    rich_print("[bold blue]:bust_in_silhouette: Users:")
    table = Table(box=rich.box.SIMPLE, show_header=True, header_style="bold", padding=(0, 1))
    table.add_column("Method", no_wrap=True)
    table.add_column("User", style="green", no_wrap=True)
    table.add_column("Credential")

    for username, ucfg in cfg.users.items():
        if ucfg.allow_none:
            table.add_row("none", username, "—")

        elif ucfg.password is not None and not ucfg.kbdint_prompts:
            table.add_row("password", username, Text(ucfg.password, style="yellow"))

        elif ucfg.pubkeys:
            cred = Text()
            if cfg.key_file:
                cred.append(f"ssh -i {cfg.key_file} {username}@{cfg.address} -p {cfg.port}",
                            style="blue")
            if cfg.agent_sock:
                if cfg.key_file:
                    cred.append("\n")
                cred.append(f"export SSH_AUTH_SOCK={cfg.agent_sock}", style="blue")
            table.add_row("publickey", username, cred)

        elif ucfg.kbdint_prompts:
            cred = Text()
            if ucfg.kbdint_name:
                cred.append(f"[{ucfg.kbdint_name}]\n", style="dim")
            if ucfg.kbdint_instructions:
                cred.append(f"{ucfg.kbdint_instructions}\n", style="dim italic")
            for (label, echo), answer in zip(ucfg.kbdint_prompts, ucfg.kbdint_answers):
                echo_hint = Text("  (echo)", style="dim") if echo else Text("")
                cred.append(f"{label.strip()} ", style="dim")
                cred.append(answer, style="yellow")
                cred.append_text(echo_hint)
                cred.append("\n")
            table.add_row("keyboard-interactive", username, cred)

        elif ucfg.kbdint_rounds:
            cred = Text()
            for i, round_ in enumerate(ucfg.kbdint_rounds, 1):
                header = f"  [{round_.name}]" if round_.name else ""
                cred.append(f"round {i}{header}\n", style="dim")
                if round_.instructions:
                    cred.append(f"  {round_.instructions}\n", style="dim italic")
                for (label, echo), answer in zip(round_.prompts, round_.answers):
                    echo_hint = Text("  (echo)", style="dim") if echo else Text("")
                    cred.append(f"  {label.strip()} ", style="dim")
                    cred.append(answer, style="yellow")
                    cred.append_text(echo_hint)
                    cred.append("\n")
            table.add_row("keyboard-interactive\n(iterative)", username, cred)

    sshconsole.print(table)
    sshconsole.rule("[red]waiting for connections", style="red")


# ---------------------------------------------------------------------------
# Pubkey user setup
# ---------------------------------------------------------------------------

def _setup_pubkey_user() -> tuple[_UserConfig, str, str, MockAgent]:
    key = paramiko.RSAKey.generate(2048)

    fd, key_path = tempfile.mkstemp(suffix=".pem", prefix="ssh-mock-key-")
    os.close(fd)
    os.chmod(key_path, 0o600)
    with open(key_path, "w") as f:
        key.write_private_key(f)

    fd, sock_path = tempfile.mkstemp(suffix=".sock", prefix="ssh-mock-agent-")
    os.close(fd)
    os.unlink(sock_path)

    agent = MockAgent(key)
    agent.start(sock_path)

    return MultiUserMockServer.pubkey_user([key]), key_path, sock_path, agent


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=sshconsole, show_path=False, rich_tracebacks=False)],
    )

    parser = argparse.ArgumentParser(
        prog="python -m sshmitm.mockserver",
        description="Minimal SSH mock server with per-method usernames.",
    )
    parser.add_argument(
        "--listen-port", dest="port", type=int, default=2200, metavar="PORT",
        help="port to listen on (default: 2200)",
    )
    parser.add_argument(
        "--listen-address", dest="address", default="127.0.0.1", metavar="ADDRESS",
        help="address to listen on (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--host-key", dest="host_key_file", default=None, metavar="FILE",
        help="PEM host key file (default: generate temporary RSA key)",
    )
    parser.add_argument(
        "--none-user", dest="none_user", default="none", metavar="NAME",
        help="username for none auth (default: none, empty to disable)",
    )
    parser.add_argument(
        "--password-user", dest="password_user", default="password", metavar="NAME",
        help="username for password auth (default: password, empty to disable)",
    )
    parser.add_argument(
        "--pubkey-user", dest="pubkey_user", default="pubkey", metavar="NAME",
        help="username for publickey auth (default: pubkey, empty to disable)",
    )
    parser.add_argument(
        "--kbdint-user", dest="kbdint_user", default="kbdint", metavar="NAME",
        help="username for keyboard-interactive, all prompts in one round (default: kbdint, empty to disable)",
    )
    parser.add_argument(
        "--kbdint-iter-user", dest="kbdint_iter_user", default="kbdint-iter", metavar="NAME",
        help="username for iterative keyboard-interactive, one prompt per round (default: kbdint-iter, empty to disable)",
    )
    args = parser.parse_args()

    if args.host_key_file:
        host_key: paramiko.PKey = paramiko.RSAKey.from_private_key_file(args.host_key_file)
        host_key_source = "loaded"
    else:
        host_key = paramiko.RSAKey.generate(2048)
        host_key_source = "generated temporary"

    users: dict[str, _UserConfig] = {}
    key_file: str | None = None
    agent_sock: str | None = None
    agent: MockAgent | None = None

    if args.none_user:
        users[args.none_user] = MultiUserMockServer.none_user()
    if args.password_user:
        users[args.password_user] = MultiUserMockServer.password_user(_random_password())
    if args.pubkey_user:
        ucfg, key_file, agent_sock, agent = _setup_pubkey_user()
        users[args.pubkey_user] = ucfg
    if args.kbdint_user:
        users[args.kbdint_user] = MultiUserMockServer.kbdint_user(
            prompts=[("OTP Token: ", True), ("Password: ", False)],
            answers=[_random_password(), _random_password()],
            name="Two-Factor Authentication",
            instructions="Enter your OTP token and password.",
        )
    if args.kbdint_iter_user:
        users[args.kbdint_iter_user] = MultiUserMockServer.kbdint_iterative_user([
            KbdintRound(
                prompts=[("OTP Token: ", True)],
                answers=[_random_password()],
                name="Step 1 of 2",
                instructions="Enter your OTP token.",
            ),
            KbdintRound(
                prompts=[("Password: ", False)],
                answers=[_random_password()],
                name="Step 2 of 2",
            ),
        ])

    cfg = _ServerConfig(
        address=args.address,
        port=args.port,
        host_key=host_key,
        host_key_source=host_key_source,
        users=users,
        key_file=key_file,
        agent_sock=agent_sock,
        agent=agent,
    )

    _print_serverinfo(cfg)

    _, stop, _ = start_server_thread(
        lambda: _ObservableServer(cfg.users),
        host_key=host_key,
        bind=args.address,
        port=args.port,
    )

    try:
        while not stop.is_set():
            stop.wait(timeout=1.0)
    except KeyboardInterrupt:
        _log.info("shutting down")
    finally:
        stop.set()
        if agent:
            agent.stop()
        for path in filter(None, [key_file, agent_sock]):
            try:
                os.unlink(path)
            except OSError:
                pass

    sys.exit(0)


if __name__ == "__main__":
    main()
