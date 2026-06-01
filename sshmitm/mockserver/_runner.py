"""Generic SSH server runner for in-process mock servers."""

from __future__ import annotations

import socket
import stat
import threading
import time
from typing import Callable

import paramiko


class _MockSFTPHandle(paramiko.SFTPHandle):
    """SFTP file handle backed by an in-memory bytes payload."""

    def __init__(self, content: bytes, flags: int = 0) -> None:
        super().__init__(flags)
        self._content = content

    def read(self, offset: int, length: int) -> bytes:
        return self._content[offset: offset + length]

    def stat(self) -> paramiko.SFTPAttributes:
        attr = paramiko.SFTPAttributes()
        attr.st_size = len(self._content)
        attr.st_mtime = int(time.time())
        attr.st_mode = stat.S_IFREG | 0o644
        return attr


class _MockSFTPInterface(paramiko.SFTPServerInterface):
    """SFTP server backed by an explicit {path: content} dict.

    Only files registered in *files* are accessible; all other paths return
    ``SFTP_NO_SUCH_FILE``.
    """

    def __init__(self, server: object, files: dict[str, bytes]) -> None:
        super().__init__(server)  # type: ignore[call-arg]
        self._files = files

    def open(self, path: str, flags: int, attr: paramiko.SFTPAttributes) -> "paramiko.SFTPHandle | int":
        content = self._files.get(path)
        if content is None:
            return paramiko.SFTP_NO_SUCH_FILE
        return _MockSFTPHandle(content, flags)

    def stat(self, path: str) -> "paramiko.SFTPAttributes | int":
        content = self._files.get(path)
        if content is None:
            return paramiko.SFTP_NO_SUCH_FILE
        attr = paramiko.SFTPAttributes()
        attr.st_size = len(content)
        attr.st_mtime = int(time.time())
        attr.st_mode = stat.S_IFREG | 0o644
        return attr

    def lstat(self, path: str) -> "paramiko.SFTPAttributes | int":
        return self.stat(path)

    def canonicalize(self, path: str) -> str:
        return path

    def list_folder(self, path: str) -> int:
        return paramiko.SFTP_OP_UNSUPPORTED  # type: ignore[return-value]


def start_server_thread(
    interface_factory: Callable[[], paramiko.ServerInterface],
    host_key: paramiko.PKey | None = None,
    bind: str = "127.0.0.1",
    port: int = 0,
    connection_timeout: float = 30.0,
    sftp_files: dict[str, bytes] | None = None,
) -> tuple[int, threading.Event, threading.Event]:
    """Start an SSH server in a background thread.

    Args:
        interface_factory: called once per connection to produce a ServerInterface
        host_key: server host key; a temporary RSA-2048 key is generated if None
        bind: address to listen on
        port: port to listen on; 0 picks a free port
        connection_timeout: per-connection transport join timeout in seconds
        sftp_files: optional in-memory filesystem ``{path: content}`` exposed via
            the SFTP subsystem.  When *None*, SFTP is not supported.

    Returns:
        ``(actual_port, stop_event, closed_event)``
        Call ``stop_event.set()`` to request shutdown.
        ``closed_event`` is set once the listening socket is fully closed.
    """
    if host_key is None:
        host_key = paramiko.RSAKey.generate(2048)

    _host_key = host_key
    _sftp_files = sftp_files
    stop = threading.Event()
    closed = threading.Event()
    ready = threading.Event()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((bind, port))
    actual_port: int = sock.getsockname()[1]
    sock.listen(5)
    sock.settimeout(0.5)

    def _handle(conn: socket.socket) -> None:
        transport = paramiko.Transport(conn)
        transport.add_server_key(_host_key)
        if _sftp_files is not None:
            transport.set_subsystem_handler(
                "sftp", paramiko.SFTPServer, _MockSFTPInterface, _sftp_files
            )
        try:
            transport.start_server(server=interface_factory())
            transport.join(timeout=connection_timeout)
        except Exception:  # noqa: BLE001
            pass

    def _serve() -> None:
        ready.set()
        while not stop.is_set():
            try:
                conn, _ = sock.accept()
                threading.Thread(target=_handle, args=(conn,), daemon=True).start()
            except socket.timeout:
                continue
        sock.close()
        closed.set()

    threading.Thread(target=_serve, daemon=True).start()
    ready.wait(timeout=2.0)
    return actual_port, stop, closed
