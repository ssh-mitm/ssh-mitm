"""In-process SSH agent implementing the SSH agent protocol over a Unix socket."""

from __future__ import annotations

import socket
import struct
import threading

import paramiko
from paramiko.message import Message


class MockAgent:
    """Minimal SSH agent protocol server backed by a single paramiko key.

    Starts a Unix-socket listener and handles SSH_AGENTC_REQUEST_IDENTITIES
    and SSH_AGENTC_SIGN_REQUEST messages so that any SSH client that reads
    ``SSH_AUTH_SOCK`` can authenticate with the key without needing a key file.

    Usage::

        agent = MockAgent(key)
        agent.start("/tmp/mock-agent.sock")
        # set SSH_AUTH_SOCK=/tmp/mock-agent.sock in the client environment
        agent.stop()
    """

    _AGENTC_REQUEST_IDENTITIES = 11
    _AGENT_IDENTITIES_ANSWER = 12
    _AGENTC_SIGN_REQUEST = 13
    _AGENT_SIGN_RESPONSE = 14
    _AGENT_FAILURE = 5

    def __init__(self, key: paramiko.PKey) -> None:
        self._key = key
        self._stop = threading.Event()
        self._sock: socket.socket | None = None

    def start(self, path: str) -> None:
        """Start listening on *path* (Unix socket)."""
        self._sock = socket.socket(socket.AF_UNIX)
        self._sock.bind(path)
        self._sock.listen(5)
        self._sock.settimeout(0.5)
        threading.Thread(target=self._serve, daemon=True).start()

    def stop(self) -> None:
        """Stop the agent."""
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass

    def _serve(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
                threading.Thread(
                    target=self._handle, args=(conn,), daemon=True
                ).start()
            except (OSError, socket.timeout):
                continue

    @staticmethod
    def _recv(conn: socket.socket) -> bytes | None:
        hdr = b""
        while len(hdr) < 4:
            chunk = conn.recv(4 - len(hdr))
            if not chunk:
                return None
            hdr += chunk
        length = struct.unpack(">I", hdr)[0]
        buf = b""
        while len(buf) < length:
            chunk = conn.recv(length - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    @staticmethod
    def _send(conn: socket.socket, data: bytes) -> None:
        conn.sendall(struct.pack(">I", len(data)) + data)

    def _handle(self, conn: socket.socket) -> None:
        try:
            while True:
                msg = self._recv(conn)
                if msg is None:
                    break
                msg_type = msg[0]

                if msg_type == self._AGENTC_REQUEST_IDENTITIES:
                    key_blob = self._key.asbytes()
                    comment = b"ssh-mitm-mock-server"
                    body = (
                        bytes([self._AGENT_IDENTITIES_ANSWER])
                        + struct.pack(">I", 1)
                        + struct.pack(">I", len(key_blob)) + key_blob
                        + struct.pack(">I", len(comment)) + comment
                    )
                    self._send(conn, body)

                elif msg_type == self._AGENTC_SIGN_REQUEST:
                    off = 1
                    kb_len = struct.unpack(">I", msg[off:off + 4])[0]
                    off += 4 + kb_len
                    data_len = struct.unpack(">I", msg[off:off + 4])[0]
                    off += 4
                    data_to_sign = msg[off:off + data_len]
                    off += data_len
                    flags = struct.unpack(">I", msg[off:off + 4])[0] if off + 4 <= len(msg) else 0

                    # Paramiko 5.x dropped SHA-1 for RSA — always request SHA-2.
                    algorithm: str | None = None
                    if self._key.get_name() == "ssh-rsa":
                        algorithm = "rsa-sha2-512" if (flags & 4) else "rsa-sha2-256"

                    sig: Message = self._key.sign_ssh_data(data_to_sign, algorithm=algorithm)
                    sig_blob = sig.asbytes()
                    body = (
                        bytes([self._AGENT_SIGN_RESPONSE])
                        + struct.pack(">I", len(sig_blob)) + sig_blob
                    )
                    self._send(conn, body)

                else:
                    self._send(conn, bytes([self._AGENT_FAILURE]))
        except Exception:  # noqa: BLE001
            pass
        finally:
            conn.close()
