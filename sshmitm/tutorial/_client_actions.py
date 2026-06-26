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
import re
import subprocess
import tempfile
import time
from typing import TYPE_CHECKING, Protocol, runtime_checkable

import paramiko

from sshmitm.plugins.session.cve202014145 import SERVER_HOST_KEY_ALGORITHMS as _OPENSSH_KEY_ALGO_LISTS

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
    *ctx.tutorial_session_data*.
    """

    def run(self, ctx: TutorialContext) -> None:
        time.sleep(_INITIAL_DELAY)
        for attempt in range(_RETRIES):
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(
                    "127.0.0.1",
                    port=int(ctx.tutorial_session_data["sshmitm_port"]),
                    username=str(ctx.tutorial_session_data["password_user"]),
                    password=str(ctx.tutorial_session_data["password_value"]),
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
    ``sshmitm_port`` from *ctx.tutorial_session_data*.
    """

    def run(self, ctx: TutorialContext) -> None:
        time.sleep(_INITIAL_DELAY)
        key: paramiko.PKey | None = ctx.tutorial_session_data.get("_client_key")  # type: ignore[assignment]
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
                            "-p", str(int(ctx.tutorial_session_data["sshmitm_port"])),
                            f"{ctx.tutorial_session_data['pubkey_user']}@127.0.0.1",
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
    Reads ``kbdint_user`` and ``sshmitm_port`` from *ctx.tutorial_session_data*.
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
                    port=int(ctx.tutorial_session_data["sshmitm_port"]),
                    username=str(ctx.tutorial_session_data["kbdint_user"]),
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
                    port=int(ctx.tutorial_session_data["sshmitm_port"]),
                    username=str(ctx.tutorial_session_data["password_user"]),
                    password=str(ctx.tutorial_session_data["password_value"]),
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


class KeepAliveShellAction:
    """Open an interactive SSH shell via key auth + agent and keep it alive.

    Uses the same key + ssh-agent pattern as :class:`SSHPublicKeyAction` so
    that the session includes proper PTY negotiation.  This matters for
    mirrorshell: SSH-MITM only requests a PTY from the backend server when
    the victim itself requested one.

    Reads ``pubkey_user`` and ``_client_key`` from *ctx.tutorial_session_data*.
    The tutorial must therefore use :class:`~sshmitm.tutorial._server_config.PublicKeyAuth`.
    """

    def __init__(self, duration: float = 600.0) -> None:
        self.duration = duration

    def run(self, ctx: TutorialContext) -> None:
        time.sleep(_INITIAL_DELAY)
        key: paramiko.PKey | None = ctx.tutorial_session_data.get("_client_key")  # type: ignore[assignment]
        if key is None:
            _log.error("KeepAliveShellAction: no _client_key in tutorial_session_data")
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
                    proc = subprocess.Popen(
                        [
                            "ssh", "-A",
                            "-o", "StrictHostKeyChecking=no",
                            "-o", "UserKnownHostsFile=/dev/null",
                            "-o", "BatchMode=yes",
                            "-o", "ConnectTimeout=10",
                            "-p", str(int(ctx.tutorial_session_data["sshmitm_port"])),
                            f"{ctx.tutorial_session_data['pubkey_user']}@127.0.0.1",
                        ],
                        env=env,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                    try:
                        proc.wait(timeout=self.duration)
                    except subprocess.TimeoutExpired:
                        proc.terminate()
                    return
                except Exception:
                    if attempt < _RETRIES - 1:
                        time.sleep(_RETRY_DELAY)
                    else:
                        _log.debug("KeepAliveShellAction failed after %d attempts", attempt + 1, exc_info=True)
        finally:
            if "SSH_AGENT_PID" in agent_env:
                subprocess.run(["kill", agent_env["SSH_AGENT_PID"]], capture_output=True)
            try:
                os.unlink(keyfile)
            except OSError:
                pass


class ShellSessionAction:
    """Open an SSH shell and run the command stored in ``tutorial_session_data[cred_key]``.

    The command is resolved from the session data at run time so it can be
    randomised via :meth:`~sshmitm.tutorial._definitions.Tutorial.generate_tutorial_session_data`.
    """

    def __init__(self, cred_key: str = "shell_command") -> None:
        self.cred_key = cred_key

    def run(self, ctx: TutorialContext) -> None:
        command = str(ctx.tutorial_session_data.get(self.cred_key, ""))
        if not command:
            _log.error("ShellSessionAction: %r not in tutorial_session_data", self.cred_key)
            return
        time.sleep(_INITIAL_DELAY)
        for attempt in range(_RETRIES):
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(
                    "127.0.0.1",
                    port=int(ctx.tutorial_session_data["sshmitm_port"]),
                    username=str(ctx.tutorial_session_data["password_user"]),
                    password=str(ctx.tutorial_session_data["password_value"]),
                    timeout=10.0,
                    allow_agent=False,
                    look_for_keys=False,
                )
                chan = client.invoke_shell()
                time.sleep(0.5)
                chan.send(command.encode() + b"\n")
                time.sleep(0.5)
                chan.send(b"exit\n")
                time.sleep(0.3)
                client.close()
                return
            except Exception:
                if attempt < _RETRIES - 1:
                    time.sleep(_RETRY_DELAY)
                else:
                    _log.debug("ShellSessionAction failed after %d attempts", attempt + 1, exc_info=True)


# ---------------------------------------------------------------------------
# SFTP actions
# ---------------------------------------------------------------------------

class SFTPUploadAction:
    """Upload *filename* via SFTP through the MITM proxy.

    *content* defaults to a small placeholder.  Reads ``password_user``,
    ``password_value``, and ``sshmitm_port`` from *ctx.tutorial_session_data*.
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
                    port=int(ctx.tutorial_session_data["sshmitm_port"]),
                    username=str(ctx.tutorial_session_data["password_user"]),
                    password=str(ctx.tutorial_session_data["password_value"]),
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
                    port=int(ctx.tutorial_session_data["sshmitm_port"]),
                    username=str(ctx.tutorial_session_data["password_user"]),
                    password=str(ctx.tutorial_session_data["password_value"]),
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
# CVE-2020-14145 simulation (for fingerprint / host-key tutorials)
# ---------------------------------------------------------------------------

class SimulatedCVE2020Action:
    """Simulate CVE-2020-14145 fingerprint state via a Paramiko client connection.

    The CVE is about the ORDER of ``server_host_key_algorithms`` in the SSH
    client's KEXINIT: when a client has a cached host key it moves the
    matching algorithm type to the front of its proposal.

    Rather than relying on the OpenSSH binary and parsing ``-vvv`` output
    (which differs across versions), this action uses Paramiko as the SSH
    client and sets ``transport._preferred_keys`` to a controlled order
    before connecting.  The first algorithm is therefore known in advance
    and SSH-MITM will log exactly that value under
    "Preferred server host key algorithm:".

    *fingerprint_state* must be ``"new"`` or ``"cached"``:

    * ``"new"``    — known OpenSSH default order (cert types first); SSH-MITM
                     recognises this as "client connecting for the first time".
    * ``"cached"`` — same list but with the plain ``ecdsa-sha2-nistp256`` key
                     (the type SSH-MITM generates) moved to the front; SSH-MITM
                     recognises this as "client has a cached remote fingerprint".

    Both *fingerprint_state* and *algorithm_var* are written to
    ``ctx.tutorial_session_data`` so that :class:`FingerprintState` and
    :class:`UserInput` conditions can validate them.
    """

    # Use the known OpenSSH 8.9 default list.  SSH-MITM compares the full list
    # against _OPENSSH_KEY_ALGO_LISTS and reports "first time" when it matches.
    _DEFAULT_KEY_ORDER: list[str] = list(_OPENSSH_KEY_ALGO_LISTS[0])

    # Same list with the plain ECDSA key (the type SSH-MITM generates) moved
    # to the front.  The list no longer matches any known default → SSH-MITM
    # reports "client has a locally cached remote fingerprint".
    _CACHED_KEY_ORDER: list[str] = [
        "ecdsa-sha2-nistp256",
        *[k for k in _OPENSSH_KEY_ALGO_LISTS[0] if k != "ecdsa-sha2-nistp256"],
    ]

    def __init__(
        self,
        fingerprint_state: str,
        algorithm_var: str = "preferred_algorithm",
    ) -> None:
        if fingerprint_state not in ("new", "cached"):
            msg = "fingerprint_state must be 'new' or 'cached'"
            raise ValueError(msg)
        self.fingerprint_state = fingerprint_state
        self.algorithm_var = algorithm_var

    def run(self, ctx: TutorialContext) -> None:
        key_order = (
            self._DEFAULT_KEY_ORDER
            if self.fingerprint_state == "new"
            else self._CACHED_KEY_ORDER
        )
        host = "127.0.0.1"
        port = int(ctx.tutorial_session_data["sshmitm_port"])
        username = str(ctx.tutorial_session_data.get("none_user", "user"))

        time.sleep(_INITIAL_DELAY)

        for attempt in range(_RETRIES):
            try:
                transport = paramiko.Transport((host, port))
                # Simulate OpenSSH: match banner to algorithm list version.
                transport.local_version = "SSH-2.0-OpenSSH_8.9p1"  # type: ignore[attr-defined]
                # Override the instance's preferred key order so KEXINIT
                # carries exactly the algorithms we want at the front.
                transport._preferred_keys = list(key_order)  # type: ignore[attr-defined]
                transport.start_client(timeout=10)
                try:
                    transport.auth_none(username)
                except Exception:  # noqa: BLE001
                    pass
                try:
                    transport.close()
                except Exception:  # noqa: BLE001
                    pass
                ctx.tutorial_session_data["fingerprint_state"] = self.fingerprint_state
                ctx.tutorial_session_data[self.algorithm_var] = key_order[0]
                return
            except Exception:
                if attempt < _RETRIES - 1:
                    time.sleep(_RETRY_DELAY)
                else:
                    _log.debug("SimulatedCVE2020Action failed", exc_info=True)


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
                            "-P", str(int(ctx.tutorial_session_data["sshmitm_port"])),
                            tmp.name,
                            f"{ctx.tutorial_session_data['password_user']}@127.0.0.1:{self.filename}",
                        ],
                        input=f"{ctx.tutorial_session_data['password_value']}\n".encode(),
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
                        "-P", str(int(ctx.tutorial_session_data["sshmitm_port"])),
                        f"{ctx.tutorial_session_data['password_user']}@127.0.0.1:{self.remote_path}",
                        os.devnull,
                    ],
                    input=f"{ctx.tutorial_session_data['password_value']}\n".encode(),
                    capture_output=True,
                    timeout=15,
                )
                return
            except Exception:
                if attempt < _RETRIES - 1:
                    time.sleep(_RETRY_DELAY)
                else:
                    _log.debug("SCPDownloadAction failed after %d attempts", attempt + 1, exc_info=True)


# ---------------------------------------------------------------------------
# Session-data-driven actions (filename/command chosen at runtime)
# ---------------------------------------------------------------------------

class SFTPDownloadSessionAction:
    """Download the file named by ``tutorial_session_data[cred_key]`` via SFTP.

    The filename is resolved from the session data at run time, so it can be
    randomised via :meth:`~sshmitm.tutorial._definitions.Tutorial.generate_tutorial_session_data`.
    """

    def __init__(self, cred_key: str = "sftp_filename") -> None:
        self.cred_key = cred_key

    def run(self, ctx: TutorialContext) -> None:
        remote_path = str(ctx.tutorial_session_data.get(self.cred_key, ""))
        if not remote_path:
            _log.error("SFTPDownloadSessionAction: %r not in tutorial_session_data", self.cred_key)
            return
        time.sleep(_INITIAL_DELAY)
        for attempt in range(_RETRIES):
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(
                    "127.0.0.1",
                    port=int(ctx.tutorial_session_data["sshmitm_port"]),
                    username=str(ctx.tutorial_session_data["password_user"]),
                    password=str(ctx.tutorial_session_data["password_value"]),
                    timeout=10.0,
                    allow_agent=False,
                    look_for_keys=False,
                )
                sftp = client.open_sftp()
                sftp.getfo(remote_path, open(os.devnull, "wb"))
                sftp.close()
                client.close()
                return
            except Exception:
                if attempt < _RETRIES - 1:
                    time.sleep(_RETRY_DELAY)
                else:
                    _log.debug("SFTPDownloadSessionAction failed after %d attempts", attempt + 1, exc_info=True)


class SSHExecAction:
    """Execute the command stored in ``tutorial_session_data[cred_key]`` via SSH exec.

    Uses paramiko's ``exec_command`` channel — equivalent to ``ssh user@host "cmd"``.
    The command is resolved from the session data at run time so it can be
    randomised via :meth:`~sshmitm.tutorial._definitions.Tutorial.generate_tutorial_session_data`.
    """

    def __init__(self, cred_key: str = "exec_command") -> None:
        self.cred_key = cred_key

    def run(self, ctx: TutorialContext) -> None:
        command = str(ctx.tutorial_session_data.get(self.cred_key, ""))
        if not command:
            _log.error("SSHExecAction: %r not in tutorial_session_data", self.cred_key)
            return
        time.sleep(_INITIAL_DELAY)
        for attempt in range(_RETRIES):
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(
                    "127.0.0.1",
                    port=int(ctx.tutorial_session_data["sshmitm_port"]),
                    username=str(ctx.tutorial_session_data["password_user"]),
                    password=str(ctx.tutorial_session_data["password_value"]),
                    timeout=10.0,
                    allow_agent=False,
                    look_for_keys=False,
                )
                _, stdout, _ = client.exec_command(command)
                stdout.read()
                client.close()
                return
            except Exception:
                if attempt < _RETRIES - 1:
                    time.sleep(_RETRY_DELAY)
                else:
                    _log.debug("SSHExecAction failed after %d attempts", attempt + 1, exc_info=True)
