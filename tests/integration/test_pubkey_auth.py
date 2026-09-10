"""Integration tests for standard (non-trivial) public-key authentication.

Regression coverage for publickey-hostbound-v00@openssh.com
(sshmitm/workarounds/auth_handler.py): OpenSSH 9.x+ clients negotiate this
extension automatically for *any* pubkey auth attempt whenever the server
advertises support for it - not just when the key is actually host-restricted
via `ssh-add -h`. A broken hostbound path therefore breaks pubkey auth for
most real-world clients, not just an edge case.

`_check_pubkey_auth` must keep `sig_attached` bound as a local variable so
that `ServerInterface.check_auth_publickey`'s frame introspection (which
reads `sig_attached` out of its caller's locals to interoperate with
paramiko's own calling convention) can find it. This has regressed twice
before via mechanical "fix unused arguments" lint sweeps that replaced the
`# noqa: ARG001` marker with `del sig_attached` - which silently deletes the
variable the frame introspection depends on.

Stack:
  ssh (OpenSSH subprocess, -A)
    ↓ publickey-hostbound-v00@openssh.com (negotiated automatically)
  ssh-mitm (subprocess)
    ↓ agent forwarding via Unix socket → FakeAgent → paramiko signing
  Mock SSH target (paramiko, in-process)
"""

from __future__ import annotations

import subprocess


_SSH_OPTS = [
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "BatchMode=yes",
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


def test_pubkey_auth_full_session(mitm_pubkey_auth):
    """Client authenticates via pubkey (hostbound extension if the local
    OpenSSH client negotiates it); MITM proxies exec to the mock target
    using the forwarded agent - full three-way connection established."""
    mitm_port = mitm_pubkey_auth

    result = _ssh(mitm_port, "echo integration-test")

    assert result.returncode == 0, (
        f"ssh exited with {result.returncode}\n"
        f"stdout: {result.stdout.decode()}\n"
        f"stderr: {result.stderr.decode()}"
    )
    assert b"REMOTE_OK" in result.stdout
