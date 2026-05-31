"""Automated victim-client actions for tutorial scenarios.

A :class:`ClientAction` is run in a background thread by the runner when
its step becomes active.  It simulates the SSH/SFTP/SCP client whose
traffic the user is meant to intercept with ssh-mitm.

Example usage in a tutorial step::

    Step("intercept", "Intercept the password",
         condition=UserInput("password_value", prompt="Enter the intercepted password:"),
         victim_action=SSHPasswordAction()),

    Step("intercept-sftp", "Intercept the file transfer",
         condition=SFTPEvent("write"),
         victim_action=SFTPUploadAction("secret.txt", b"sensitive data")),
"""

from __future__ import annotations

import logging
import os
import subprocess
import tempfile
import time
from typing import TYPE_CHECKING, Protocol, runtime_checkable

import paramiko

if TYPE_CHECKING:
    from sshmitm.tutorial._context import TutorialContext

_log = logging.getLogger(__name__)

_RETRIES = 5
_RETRY_DELAY = 1.0
_INITIAL_DELAY = 1.0


@runtime_checkable
class ClientAction(Protocol):
    """Protocol for automated victim-client actions."""

    def run(self, ctx: "TutorialContext") -> None: ...


# ---------------------------------------------------------------------------
# SSH actions
# ---------------------------------------------------------------------------

class SSHPasswordAction:
    """Connect via SSH with password authentication through the MITM proxy.

    Reads ``password_user``, ``password_value``, and ``sshmitm_port`` from
    *ctx.credentials*.
    """

    def run(self, ctx: TutorialContext) -> None:
        time.sleep(_INITIAL_DELAY)
        for attempt in range(_RETRIES):
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(
                    "127.0.0.1",
                    port=int(ctx.credentials["sshmitm_port"]),
                    username=str(ctx.credentials["password_user"]),
                    password=str(ctx.credentials["password_value"]),
                    timeout=10.0,
                    allow_agent=False,
                    look_for_keys=False,
                )
                client.close()
                return
            except Exception:
                if attempt < _RETRIES - 1:
                    time.sleep(_RETRY_DELAY)
                else:
                    _log.debug("SSHPasswordAction failed after %d attempts", attempt + 1, exc_info=True)


class SSHPublicKeyAction:
    """Connect via SSH with public key auth + agent forwarding through the MITM proxy.

    Reads ``pubkey_user``, ``_client_key`` (paramiko.PKey), and
    ``sshmitm_port`` from *ctx.credentials*.
    """

    def run(self, ctx: TutorialContext) -> None:
        time.sleep(_INITIAL_DELAY)
        key: paramiko.PKey | None = ctx.credentials.get("_client_key")  # type: ignore[assignment]
        if key is None:
            _log.error("SSHPublicKeyAction: no _client_key in credentials")
            return
        keyfile = tempfile.mktemp(prefix="sshmitm-tutorial-key-", suffix=".pem")
        agent_env: dict[str, str] = {}
        try:
            key.write_private_key_file(keyfile)
            os.chmod(keyfile, 0o600)
            result = subprocess.run(
                ["ssh-agent", "-s"], capture_output=True, text=True, check=True
            )
            for line in result.stdout.splitlines():
                for var in ("SSH_AUTH_SOCK", "SSH_AGENT_PID"):
                    if line.startswith(var + "="):
                        agent_env[var] = line.split("=", 1)[1].split(";")[0]
            env = {**os.environ, **agent_env}
            subprocess.run(["ssh-add", keyfile], env=env, capture_output=True, check=True)
            for attempt in range(_RETRIES):
                try:
                    subprocess.run(
                        [
                            "ssh", "-A",
                            "-o", "StrictHostKeyChecking=no",
                            "-o", "UserKnownHostsFile=/dev/null",
                            "-o", "BatchMode=yes",
                            "-o", "ConnectTimeout=10",
                            "-p", str(int(ctx.credentials["sshmitm_port"])),
                            f"{ctx.credentials['pubkey_user']}@127.0.0.1",
                            "exit",
                        ],
                        env=env,
                        capture_output=True,
                        timeout=15,
                    )
                    return
                except Exception:
                    if attempt < _RETRIES - 1:
                        time.sleep(_RETRY_DELAY)
                    else:
                        _log.debug("SSHPublicKeyAction failed after %d attempts", attempt + 1, exc_info=True)
        finally:
            if "SSH_AGENT_PID" in agent_env:
                subprocess.run(["kill", agent_env["SSH_AGENT_PID"]], capture_output=True)
            try:
                os.unlink(keyfile)
            except OSError:
                pass


class SSHKeyboardInteractiveAction:
    """Connect via SSH with keyboard-interactive auth through the MITM proxy.

    *answers* are sent in order in response to the server's prompts.
    Reads ``kbdint_user`` and ``sshmitm_port`` from *ctx.credentials*.
    """

    def __init__(self, answers: list[str]) -> None:
        self.answers = answers

    def run(self, ctx: TutorialContext) -> None:
        time.sleep(_INITIAL_DELAY)
        answers = iter(self.answers)

        def handler(title: str, instructions: str, prompts: list) -> list[str]:
            return [next(answers, "") for _ in prompts]

        for attempt in range(_RETRIES):
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(
                    "127.0.0.1",
                    port=int(ctx.credentials["sshmitm_port"]),
                    username=str(ctx.credentials["kbdint_user"]),
                    auth_strategy=None,
                    allow_agent=False,
                    look_for_keys=False,
                )
                client.close()
                return
            except Exception:
                if attempt < _RETRIES - 1:
                    time.sleep(_RETRY_DELAY)
                    answers = iter(self.answers)
                else:
                    _log.debug("SSHKeyboardInteractiveAction failed after %d attempts", attempt + 1, exc_info=True)


class ShellAction:
    """Open an SSH shell and run *commands* in sequence.

    Connects via SSH with password auth, opens an interactive shell channel,
    sends each command, and closes the session.  Useful for tutorials that
    demonstrate shell-session interception.
    """

    def __init__(self, commands: list[str]) -> None:
        self.commands = commands

    def run(self, ctx: TutorialContext) -> None:
        time.sleep(_INITIAL_DELAY)
        for attempt in range(_RETRIES):
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(
                    "127.0.0.1",
                    port=int(ctx.credentials["sshmitm_port"]),
                    username=str(ctx.credentials["password_user"]),
                    password=str(ctx.credentials["password_value"]),
                    timeout=10.0,
                    allow_agent=False,
                    look_for_keys=False,
                )
                chan = client.invoke_shell()
                time.sleep(0.5)
                for cmd in self.commands:
                    chan.send(cmd.encode() + b"\n")
                    time.sleep(0.3)
                chan.send(b"exit\n")
                time.sleep(0.5)
                client.close()
                return
            except Exception:
                if attempt < _RETRIES - 1:
                    time.sleep(_RETRY_DELAY)
                else:
                    _log.debug("ShellAction failed after %d attempts", attempt + 1, exc_info=True)


# ---------------------------------------------------------------------------
# SFTP actions
# ---------------------------------------------------------------------------

class SFTPUploadAction:
    """Upload *filename* via SFTP through the MITM proxy.

    *content* defaults to a small placeholder.  Reads ``password_user``,
    ``password_value``, and ``sshmitm_port`` from *ctx.credentials*.
    """

    def __init__(self, filename: str, content: bytes = b"tutorial test file\n") -> None:
        self.filename = filename
        self.content = content

    def run(self, ctx: TutorialContext) -> None:
        time.sleep(_INITIAL_DELAY)
        for attempt in range(_RETRIES):
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(
                    "127.0.0.1",
                    port=int(ctx.credentials["sshmitm_port"]),
                    username=str(ctx.credentials["password_user"]),
                    password=str(ctx.credentials["password_value"]),
                    timeout=10.0,
                    allow_agent=False,
                    look_for_keys=False,
                )
                sftp = client.open_sftp()
                with sftp.file(self.filename, "wb") as f:
                    f.write(self.content)
                sftp.close()
                client.close()
                return
            except Exception:
                if attempt < _RETRIES - 1:
                    time.sleep(_RETRY_DELAY)
                else:
                    _log.debug("SFTPUploadAction failed after %d attempts", attempt + 1, exc_info=True)


class SFTPDownloadAction:
    """Download *remote_path* via SFTP through the MITM proxy."""

    def __init__(self, remote_path: str) -> None:
        self.remote_path = remote_path

    def run(self, ctx: TutorialContext) -> None:
        time.sleep(_INITIAL_DELAY)
        for attempt in range(_RETRIES):
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(
                    "127.0.0.1",
                    port=int(ctx.credentials["sshmitm_port"]),
                    username=str(ctx.credentials["password_user"]),
                    password=str(ctx.credentials["password_value"]),
                    timeout=10.0,
                    allow_agent=False,
                    look_for_keys=False,
                )
                sftp = client.open_sftp()
                sftp.getfo(self.remote_path, open(os.devnull, "wb"))
                sftp.close()
                client.close()
                return
            except Exception:
                if attempt < _RETRIES - 1:
                    time.sleep(_RETRY_DELAY)
                else:
                    _log.debug("SFTPDownloadAction failed after %d attempts", attempt + 1, exc_info=True)


# ---------------------------------------------------------------------------
# SCP actions
# ---------------------------------------------------------------------------

class SCPUploadAction:
    """Upload *filename* via SCP through the MITM proxy (uses the ``scp`` binary)."""

    def __init__(self, filename: str, content: bytes = b"tutorial test file\n") -> None:
        self.filename = filename
        self.content = content

    def run(self, ctx: TutorialContext) -> None:
        time.sleep(_INITIAL_DELAY)
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=f"_{self.filename}")
        try:
            tmp.write(self.content)
            tmp.close()
            for attempt in range(_RETRIES):
                try:
                    subprocess.run(
                        [
                            "scp",
                            "-o", "StrictHostKeyChecking=no",
                            "-o", "UserKnownHostsFile=/dev/null",
                            "-P", str(int(ctx.credentials["sshmitm_port"])),
                            tmp.name,
                            f"{ctx.credentials['password_user']}@127.0.0.1:{self.filename}",
                        ],
                        input=f"{ctx.credentials['password_value']}\n".encode(),
                        capture_output=True,
                        timeout=15,
                    )
                    return
                except Exception:
                    if attempt < _RETRIES - 1:
                        time.sleep(_RETRY_DELAY)
                    else:
                        _log.debug("SCPUploadAction failed after %d attempts", attempt + 1, exc_info=True)
        finally:
            os.unlink(tmp.name)


class SCPDownloadAction:
    """Download *remote_path* via SCP through the MITM proxy."""

    def __init__(self, remote_path: str) -> None:
        self.remote_path = remote_path

    def run(self, ctx: TutorialContext) -> None:
        time.sleep(_INITIAL_DELAY)
        for attempt in range(_RETRIES):
            try:
                subprocess.run(
                    [
                        "scp",
                        "-o", "StrictHostKeyChecking=no",
                        "-o", "UserKnownHostsFile=/dev/null",
                        "-P", str(int(ctx.credentials["sshmitm_port"])),
                        f"{ctx.credentials['password_user']}@127.0.0.1:{self.remote_path}",
                        os.devnull,
                    ],
                    input=f"{ctx.credentials['password_value']}\n".encode(),
                    capture_output=True,
                    timeout=15,
                )
                return
            except Exception:
                if attempt < _RETRIES - 1:
                    time.sleep(_RETRY_DELAY)
                else:
                    _log.debug("SCPDownloadAction failed after %d attempts", attempt + 1, exc_info=True)
