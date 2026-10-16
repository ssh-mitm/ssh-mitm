"""Integration tests for the honeypot fallback (--enable-auth-fallback).

Regression coverage for a reused upstream transport pointing at the wrong
host (sshmitm/authentication.py, Authenticator.connect()):

ssh-mitm pre-connects to --remote-host immediately on an incoming
connection, for banner passthrough (Session._preconnect_upstream /
finalize_upstream_transport). That pre-connected transport used to be
reused unconditionally by Authenticator.connect() for *any* subsequent
connect() call in the session - including auth_fallback()'s connect() to
--fallback-host/--fallback-port, a different server entirely. A client
that authenticates via publickey without forwarding its agent cannot be
replayed against the real target, so ssh-mitm falls back to the honeypot;
with the stale transport reused, that fallback silently authenticated (or
tried to) against the real target instead of the honeypot, and failed.

Stack:
  ssh (OpenSSH subprocess, no -A — no agent forwarded)
    ↓ publickey auth, accepted by the real target's pk_lookup probe
  ssh-mitm (subprocess, --enable-auth-fallback)
    ↓ no agent available to replay pubkey auth to the real target
    ↓ falls back to the honeypot over a *fresh* connection
  Honeypot mock target (paramiko, in-process, password auth)
"""

from __future__ import annotations

import subprocess


_SSH_OPTS = [
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "BatchMode=yes",
]


def _ssh_no_agent(mitm_port: int, key_file, command: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            "ssh", *_SSH_OPTS,
            "-i", str(key_file),
            "-o", "IdentitiesOnly=yes",
            # No -A: the client deliberately does not forward its agent, so
            # the real target cannot be reached and the fallback must fire.
            "-p", str(mitm_port),
            "testuser@127.0.0.1",
            command,
        ],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=15,
    )


def test_fallback_redirects_to_honeypot_not_real_target(
    mitm_fallback_honeypot, client_key_file
):
    """Without a forwarded agent, the exec reply must come from the
    honeypot (HONEYPOT_OK), never from the real target (REMOTE_OK) and
    never a hang/timeout - reproducibly, not just on a lucky timing run."""
    mitm_port = mitm_fallback_honeypot

    result = _ssh_no_agent(mitm_port, client_key_file, "echo fallback-test")

    assert result.returncode == 0, (
        f"ssh exited with {result.returncode}\n"
        f"stdout: {result.stdout.decode()}\n"
        f"stderr: {result.stderr.decode()}"
    )
    assert b"HONEYPOT_OK:echo fallback-test" in result.stdout, (
        "expected the honeypot's reply, got:\n"
        f"stdout: {result.stdout!r}\n"
        f"stderr: {result.stderr!r}"
    )
    assert b"REMOTE_OK" not in result.stdout, (
        "exec reply came from the real target instead of the honeypot — "
        "the fallback reused a transport connected to the wrong host"
    )


def test_fallback_redirects_to_honeypot_repeatedly(mitm_fallback_honeypot, client_key_file):
    """The race this guards against is timing-dependent: run it several
    times in the same session to rule out a fix that only works 80% of the
    time."""
    mitm_port = mitm_fallback_honeypot

    for i in range(5):
        result = _ssh_no_agent(mitm_port, client_key_file, f"echo fallback-test-{i}")
        assert result.returncode == 0, (
            f"attempt {i}: ssh exited with {result.returncode}\n"
            f"stdout: {result.stdout.decode()}\n"
            f"stderr: {result.stderr.decode()}"
        )
        assert f"HONEYPOT_OK:echo fallback-test-{i}".encode() in result.stdout, (
            f"attempt {i}: expected the honeypot's reply, got "
            f"stdout={result.stdout!r} stderr={result.stderr!r}"
        )


def test_fallback_key_redirects_to_honeypot(mitm_fallback_honeypot_key, client_key_file):
    """--fallback-key: the honeypot is reached with a private key ssh-mitm
    holds locally instead of a password, using a key distinct from the
    client's own (mitm_fallback_honeypot_key's honeypot_pubkey_target only
    accepts the honeypot's key, never the client's)."""
    mitm_port = mitm_fallback_honeypot_key

    result = _ssh_no_agent(mitm_port, client_key_file, "echo fallback-key-test")

    assert result.returncode == 0, (
        f"ssh exited with {result.returncode}\n"
        f"stdout: {result.stdout.decode()}\n"
        f"stderr: {result.stderr.decode()}"
    )
    assert b"HONEYPOT_OK:echo fallback-key-test" in result.stdout, (
        "expected the honeypot's reply, got:\n"
        f"stdout: {result.stdout!r}\n"
        f"stderr: {result.stderr!r}"
    )
