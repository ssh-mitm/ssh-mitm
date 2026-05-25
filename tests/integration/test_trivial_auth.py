"""Integration tests for trivial auth using a real OpenSSH client.

Stack:
  ssh (OpenSSH subprocess, -A)
    ↓  trivial auth: probe → AUTH_FAILED → kbd-interactive (empty) → SUCCESS
  ssh-mitm (subprocess)
    ↓  agent forwarding via Unix socket → FakeAgent → paramiko signing
  Mock SSH target (paramiko, in-process)
"""

from __future__ import annotations

import subprocess
from pathlib import Path


_SSH_OPTS = [
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "PreferredAuthentications=publickey,keyboard-interactive",
    "-o", "BatchMode=no",
]


def _ssh(mitm_port: int, command: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            "ssh", *_SSH_OPTS,
            "-A",                  # forward agent — MITM uses it to reach the target
            "-p", str(mitm_port),
            "testuser@127.0.0.1",
            command,
        ],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=15,
    )


def test_trivial_auth_full_session(mitm_trivial_auth):
    """Client authenticates via trivial auth; MITM proxies exec to mock target
    using the forwarded agent — full three-way connection established."""
    mitm_port, _ = mitm_trivial_auth

    result = _ssh(mitm_port, "echo integration-test")

    assert result.returncode == 0, (
        f"ssh exited with {result.returncode}\n"
        f"stdout: {result.stdout.decode()}\n"
        f"stderr: {result.stderr.decode()}"
    )
    assert b"REMOTE_OK" in result.stdout


def test_trivial_auth_publickeys_log(mitm_trivial_auth):
    """Verify the publickeys log for the trivial-auth session.

    Expected entries:
    - saved-from-pk-lookup: the key was identified during the probe phase
    - saved-from-agent: the MITM used the forwarded agent to authenticate
      to the real target server, confirming the three-way connection

    Note: OpenSSH may also send a sig_attached=True attempt after the probe
    fails (as allowed by RFC 4252). The MITM correctly rejects it via
    check_auth_publickey_authenticate (trivial auth active → AUTH_FAILED),
    so the session still completes via keyboard-interactive. The presence of
    a saved-from-auth-signature entry is therefore not an error.
    """
    mitm_port, log_dir = mitm_trivial_auth

    result = _ssh(mitm_port, "echo log-check")
    assert result.returncode == 0, result.stderr.decode()

    pubkeys_files = list(log_dir.rglob("publickeys"))
    assert len(pubkeys_files) == 1, f"Expected 1 publickeys file, found: {pubkeys_files}"
    content = pubkeys_files[0].read_text()

    assert "saved-from-pk-lookup" in content, f"Missing pk-lookup entry:\n{content}"
    assert "saved-from-agent" in content, (
        f"Missing agent entry — MITM did not connect to target via forwarded agent:\n{content}"
    )
