"""Generic SSH server runner for in-process mock servers."""

from __future__ import annotations

import socket
import threading
from typing import Callable

import paramiko


def start_server_thread(
    interface_factory: Callable[[], paramiko.ServerInterface],
    host_key: paramiko.PKey | None = None,
    bind: str = "127.0.0.1",
    port: int = 0,
    connection_timeout: float = 30.0,
) -> tuple[int, threading.Event, threading.Event]:
    """Start an SSH server in a background thread.

    Args:
        interface_factory: called once per connection to produce a ServerInterface
        host_key: server host key; a temporary RSA-2048 key is generated if None
        bind: address to listen on
        port: port to listen on; 0 picks a free port
        connection_timeout: per-connection transport join timeout in seconds

    Returns:
        ``(actual_port, stop_event, closed_event)``
        Call ``stop_event.set()`` to request shutdown.
        ``closed_event`` is set once the listening socket is fully closed.
    """
    if host_key is None:
        host_key = paramiko.RSAKey.generate(2048)

    _host_key = host_key
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
