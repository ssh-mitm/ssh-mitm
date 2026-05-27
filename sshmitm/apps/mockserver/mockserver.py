"""Minimal SSH mock server for testing SSH-MITM auth passthrough."""

from __future__ import annotations

import argparse
import logging
import shlex
import socket
import subprocess
import threading
from typing import TYPE_CHECKING

import paramiko
import paramiko.common
import paramiko.server

from sshmitm.moduleparser import SubCommand

if TYPE_CHECKING:
    pass


class _MockServerInterface(paramiko.ServerInterface):
    """Handles all four auth methods for a single configured user."""

    def __init__(
        self,
        username: str,
        password: str | None,
        pubkeys: list[paramiko.PKey],
        allow_none: bool,
    ) -> None:
        self._username = username
        self._password = password
        self._pubkeys = pubkeys
        self._allow_none = allow_none
        self._kbd_username: str | None = None

    def get_allowed_auths(self, username: str) -> str:
        if username != self._username:
            return "publickey"
        methods: list[str] = []
        if self._allow_none:
            methods.append("none")
        if self._pubkeys:
            methods.append("publickey")
        if self._password is not None:
            methods += ["password", "keyboard-interactive"]
        return ",".join(methods) if methods else "publickey"

    def check_auth_none(self, username: str) -> int:
        if username == self._username and self._allow_none:
            return paramiko.common.AUTH_SUCCESSFUL
        return paramiko.common.AUTH_FAILED

    def check_auth_password(self, username: str, password: str) -> int:
        if username == self._username and self._password is not None and password == self._password:
            return paramiko.common.AUTH_SUCCESSFUL
        return paramiko.common.AUTH_FAILED

    def check_auth_publickey(self, username: str, key: paramiko.PKey) -> int:
        if username != self._username:
            return paramiko.common.AUTH_FAILED
        for authorized in self._pubkeys:
            if key.get_base64() == authorized.get_base64():
                return paramiko.common.AUTH_SUCCESSFUL
        return paramiko.common.AUTH_FAILED

    def check_auth_interactive(
        self, username: str, submethods: bytes | str
    ) -> int | paramiko.server.InteractiveQuery:
        if username != self._username or self._password is None:
            return paramiko.common.AUTH_FAILED
        self._kbd_username = username
        query = paramiko.server.InteractiveQuery("", "")
        query.add_prompt("Password: ", False)
        return query

    def check_auth_interactive_response(self, responses: list[str]) -> int:
        if responses and self._password is not None and responses[0] == self._password:
            return paramiko.common.AUTH_SUCCESSFUL
        return paramiko.common.AUTH_FAILED

    def check_channel_request(self, kind: str, chanid: int) -> int:
        return paramiko.common.OPEN_SUCCEEDED

    def check_channel_pty_request(
        self,
        channel: paramiko.Channel,
        term: bytes,
        width: int,
        height: int,
        pixelwidth: int,
        pixelheight: int,
        modes: bytes,
    ) -> bool:
        return True

    def check_channel_shell_request(self, channel: paramiko.Channel) -> bool:
        threading.Thread(target=_run_shell, args=(channel,), daemon=True).start()
        return True

    def check_channel_exec_request(self, channel: paramiko.Channel, command: bytes) -> bool:
        threading.Thread(target=_run_exec, args=(channel, command), daemon=True).start()
        return True

    def check_channel_forward_agent_request(self, channel: paramiko.Channel) -> bool:
        return True


def _run_exec(channel: paramiko.Channel, command: bytes) -> None:
    try:
        result = subprocess.run(  # noqa: S603
            shlex.split(command.decode("utf-8", errors="replace")),
            capture_output=True,
            timeout=30,
        )
        channel.sendall(result.stdout)
        if result.stderr:
            channel.sendall_stderr(result.stderr)
        channel.send_exit_status(result.returncode)
    except Exception as exc:  # noqa: BLE001
        channel.sendall_stderr(f"mock-server exec error: {exc}\n".encode())
        channel.send_exit_status(1)
    finally:
        channel.close()


def _run_shell(channel: paramiko.Channel) -> None:
    try:
        channel.sendall(b"$ ")
        buf = b""
        while True:
            data = channel.recv(256)
            if not data:
                break
            channel.sendall(data)
            buf += data
            if b"\n" in buf or b"\r" in buf:
                cmd = buf.strip()
                buf = b""
                if cmd in (b"exit", b"logout", b"quit"):
                    break
                if not cmd:
                    channel.sendall(b"$ ")
                    continue
                try:
                    result = subprocess.run(  # noqa: S603
                        shlex.split(cmd.decode("utf-8", errors="replace")),
                        capture_output=True,
                        timeout=10,
                    )
                    if result.stdout:
                        channel.sendall(result.stdout)
                    if result.stderr:
                        channel.sendall(result.stderr)
                except Exception as exc:  # noqa: BLE001
                    channel.sendall(f"error: {exc}\n".encode())
                channel.sendall(b"$ ")
    except Exception:  # noqa: BLE001
        pass
    finally:
        channel.send_exit_status(0)
        channel.close()


def _load_pubkeys(paths: list[str]) -> list[paramiko.PKey]:
    keys: list[paramiko.PKey] = []
    for path in paths:
        try:
            key_data = open(path).read().strip()  # noqa: WPS515
            parts = key_data.split()
            if len(parts) < 2:
                logging.warning("mock-server: cannot parse key file %s", path)
                continue
            key_type, b64 = parts[0], parts[1]
            import base64
            raw = base64.b64decode(b64)
            msg = paramiko.Message(raw)
            key = paramiko.PKey.from_type_string(key_type, msg)
            keys.append(key)
        except Exception as exc:  # noqa: BLE001
            logging.warning("mock-server: failed to load key %s: %s", path, exc)
    return keys


def _handle_connection(
    conn: socket.socket,
    host_key: paramiko.PKey,
    interface: _MockServerInterface,
) -> None:
    transport = paramiko.Transport(conn)
    transport.add_server_key(host_key)
    try:
        transport.start_server(server=interface)
        transport.join(timeout=60)
    except Exception:  # noqa: BLE001
        pass


class MockServer(SubCommand):
    """minimal SSH server for testing auth passthrough through SSH-MITM"""

    def register_arguments(self) -> None:
        self.parser.add_argument(
            "--listen-port",
            dest="listen_port",
            type=int,
            default=2200,
            metavar="PORT",
            help="port to listen on (default: 2200)",
        )
        self.parser.add_argument(
            "--listen-address",
            dest="listen_address",
            default="127.0.0.1",
            metavar="ADDRESS",
            help="address to listen on (default: 127.0.0.1)",
        )
        self.parser.add_argument(
            "--username",
            dest="username",
            default="testuser",
            metavar="NAME",
            help="username to accept (default: testuser)",
        )
        self.parser.add_argument(
            "--password",
            dest="password",
            default=None,
            metavar="PASSWORD",
            help="password for password/keyboard-interactive auth (omit to disable)",
        )
        self.parser.add_argument(
            "--authorized-key",
            dest="authorized_keys",
            action="append",
            default=[],
            metavar="PUBKEY_FILE",
            help="public key file to accept for publickey auth (repeatable)",
        )
        self.parser.add_argument(
            "--allow-none-auth",
            dest="allow_none_auth",
            action="store_true",
            help="accept none authentication for the configured user",
        )
        self.parser.add_argument(
            "--host-key",
            dest="host_key_file",
            default=None,
            metavar="FILE",
            help="path to PEM host key file (default: generate temporary RSA key)",
        )

    def execute(self, args: argparse.Namespace) -> None:
        if args.host_key_file:
            host_key: paramiko.PKey = paramiko.RSAKey.from_private_key_file(args.host_key_file)
        else:
            host_key = paramiko.RSAKey.generate(2048)
            logging.info(
                "mock-server: generated temporary host key %s",
                host_key.get_fingerprint().hex(":"),
            )

        pubkeys = _load_pubkeys(args.authorized_keys)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((args.listen_address, args.listen_port))
        sock.listen(10)
        logging.info(
            "mock-server: listening on %s:%d  user=%r  password=%s  pubkeys=%d  none-auth=%s",
            args.listen_address,
            args.listen_port,
            args.username,
            "yes" if args.password is not None else "no",
            len(pubkeys),
            "yes" if args.allow_none_auth else "no",
        )

        try:
            while True:
                conn, addr = sock.accept()
                logging.debug("mock-server: connection from %s", addr)
                interface = _MockServerInterface(
                    username=args.username,
                    password=args.password,
                    pubkeys=pubkeys,
                    allow_none=args.allow_none_auth,
                )
                threading.Thread(
                    target=_handle_connection,
                    args=(conn, host_key, interface),
                    daemon=True,
                ).start()
        except KeyboardInterrupt:
            logging.info("mock-server: shutting down")
        finally:
            sock.close()
