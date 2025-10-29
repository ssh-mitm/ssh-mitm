"""
Utility functions to create server sockets able to listen on both
IPv4 and IPv6.
"""

import contextlib
import os
import socket
import sys
from typing import Optional, Tuple

__author__ = "Giampaolo Rodola' <g.rodola [AT] gmail [DOT] com>"
__license__ = "MIT"


def has_dual_stack(sock: Optional[socket.socket] = None) -> bool:
    """Return True if kernel allows creating a socket which is able to
    listen for both IPv4 and IPv6 connections.
    If *sock* is provided the check is made against it.
    """
    if (
        not hasattr(socket, "AF_INET6")
        or not hasattr(socket, "IPPROTO_IPV6")
        or not hasattr(socket, "IPV6_V6ONLY")
    ):
        return False
    try:
        if sock is not None:
            return not sock.getsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY)
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        with contextlib.closing(sock):
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, False)
            return True
    except socket.error:
        return False


def create_server_sock(  # pylint: disable=too-many-arguments # noqa: C901
    address: Tuple[str, int],
    family: Optional[socket.AddressFamily] = None,  # pylint: disable=no-member
    reuse_addr: Optional[bool] = None,
    transparent: bool = False,
    queue_size: int = 5,
    dual_stack: bool = has_dual_stack(),
) -> socket.socket:
    """Convenience function which creates a TCP server bound to
    *address* and return the socket object.

    Internally it takes care of choosing the right address family
    (IPv4 or IPv6) depending on the host specified in *address*
    (a (host, port) tuple.
    If host is an empty string or None all interfaces are assumed
    and if dual stack is supported by kernel the socket will be
    able to listen for both IPv4 and IPv6 connections.

    *family* can be set to either AF_INET or AF_INET6 to force the
    socket to use IPv4 or IPv6. If not set it will be determined
    from host.

    *reuse_addr* tells the kernel to reuse a local socket in TIME_WAIT
    state, without waiting for its natural timeout to expire.
    If not set will default to True on POSIX.

    *queue_size* is the maximum number of queued connections passed to
    listen() (defaults to 5).

    If *dual_stack* if True it will force the socket to listen on both
    IPv4 and IPv6 connections (defaults to True on all platforms
    natively supporting this functionality).

    The returned socket can be used to accept() new connections as in:

    >>> server = create_server_sock((None, 8000))
    >>> while True:
    ...     sock, addr = server.accept()
    ...     # handle new sock connection
    """
    AF_INET6 = getattr(  # pylint: disable=invalid-name # noqa: N806
        socket, "AF_INET6", 0
    )
    host: Optional[str]
    port: int
    host, port = address
    if host in ("", "0.0.0.0"):  # nosec
        # http://mail.python.org/pipermail/python-ideas/2013-March/019937.html
        host = None
    if host is None and dual_stack:
        host = "::"
    if family is None:
        family = socket.AF_UNSPEC
    if reuse_addr is None:
        reuse_addr = os.name == "posix" and sys.platform != "cygwin"
    err = None
    info = socket.getaddrinfo(
        host, port, family, socket.SOCK_STREAM, 0, socket.AI_PASSIVE
    )
    if not dual_stack:
        # in case dual stack is not supported we want IPv4 to be
        # preferred over IPv6
        info.sort(key=lambda x: x[0] == socket.AF_INET, reverse=True)
    for res in info:
        res_address_family, socktype, proto, _, res_socket_address = res
        sock = None
        try:
            sock = socket.socket(res_address_family, socktype, proto)
            if reuse_addr:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if transparent:
                if hasattr(socket, "IP_TRANSPARENT"):
                    sock.setsockopt(socket.SOL_IP, socket.IP_TRANSPARENT, 1)
                else:
                    ip_transparent = 19
                    sock.setsockopt(socket.SOL_IP, ip_transparent, 1)
            if res_address_family == AF_INET6:
                if dual_stack:
                    # enable
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                elif has_dual_stack(sock):
                    # disable
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            sock.bind(res_socket_address)
            sock.listen(queue_size)
        except socket.error as _:
            err = _
            if sock is not None:
                sock.close()
        else:
            return sock
    if err is not None:
        raise err
    msg = "getaddrinfo returns an empty list"
    raise socket.error(msg)
