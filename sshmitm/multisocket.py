"""
Utility functions to create server sockets able to listen on both
IPv4 and IPv6.

Source: https://code.activestate.com/recipes/578504-server-supporting-ipv4-and-ipv6/
Inspired by: http://bugs.python.org/issue17561

Expected usage:

>>> sock = create_server_sock(("", 8000))
>>> if not has_dual_stack(sock):
...     sock.close()
...     sock = MultipleSocketsListener([("0.0.0.0", 8000), ("::", 8000)])
>>>

From here on you have a socket which listens on port 8000,
all interfaces, serving both IPv4 and IPv6.
You can start accepting new connections as usual:

>>> while True:
...     conn, addr = sock.accept()
...     # handle new connection

Supports UNIX, Windows, non-blocking sockets and socket timeouts.
Works with Python >= 2.6 and 3.X.
"""


import os
import sys
import socket
import select
import contextlib

from typing import (
    Any,
    Dict,
    Tuple,
    Optional,
    List,
    Union,
    overload
)


__author__ = "Giampaolo Rodola' <g.rodola [AT] gmail [DOT] com>"
__license__ = "MIT"


def has_dual_stack(sock: Optional[socket.socket] = None) -> bool:
    """Return True if kernel allows creating a socket which is able to
    listen for both IPv4 and IPv6 connections.
    If *sock* is provided the check is made against it.
    """
    if not hasattr(socket, 'AF_INET6') or not hasattr(socket, 'IPPROTO_IPV6') or not hasattr(socket, 'IPV6_V6ONLY'):
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


def create_server_sock(
    address: Tuple[str, int],
    family: Optional[socket.AddressFamily] = None,  # pylint: disable=no-member
    reuse_addr: Optional[bool] = None,
    transparent: bool = False,
    queue_size: int = 5,
    dual_stack: bool = has_dual_stack()
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
    AF_INET6 = getattr(socket, 'AF_INET6', 0)  # pylint: disable=invalid-name
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
        reuse_addr = os.name == 'posix' and sys.platform != 'cygwin'
    err = None
    info = socket.getaddrinfo(host, port, family, socket.SOCK_STREAM,
                              0, socket.AI_PASSIVE)
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
                if hasattr(socket, 'IP_TRANSPARENT'):
                    sock.setsockopt(socket.SOL_IP, socket.IP_TRANSPARENT, 1)
                else:
                    IP_TRANSPARENT = 19  # pylint: disable=invalid-name
                    sock.setsockopt(socket.SOL_IP, IP_TRANSPARENT, 1)
            if res_address_family == AF_INET6:
                if dual_stack:
                    # enable
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
                elif has_dual_stack(sock):
                    # disable
                    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            sock.bind(res_socket_address)
            sock.listen(queue_size)
            return sock
        except socket.error as _:
            err = _
            if sock is not None:
                sock.close()
    if err is not None:
        raise err
    raise socket.error("getaddrinfo returns an empty list")


class MultipleSocketsListener:
    """Listen on multiple addresses specified as a list of
    (host, port) tuples.
    Useful to listen on both IPv4 and IPv6 on those systems where
    a dual stack is not supported natively (Windows and many UNIXes).

    The returned instance is a socket-like object which can be used to
    accept() new connections, as with a common socket.
    Calls like settimeout() and setsockopt() will be applied to all
    sockets.
    Calls like gettimeout() or getsockopt() will refer to the first
    socket in the list.
    """

    def __init__(
        self,
        addresses: List[Tuple[str, int]],
        family: Optional[socket.AddressFamily] = None,  # pylint: disable=no-member
        reuse_addr: Optional[bool] = None,
        transparent: bool = False,
        queue_size: int = 5
    ) -> None:
        self._pollster: Optional[select.poll]
        self._socks: List[socket.socket] = []
        self._sockmap: Dict[int, socket.socket] = {}
        if hasattr(select, 'poll'):
            self._pollster = select.poll()
        else:
            self._pollster = None
        completed = False
        try:
            for addr in addresses:
                sock = create_server_sock(
                    addr,
                    family=family,
                    reuse_addr=reuse_addr,
                    transparent=transparent,
                    queue_size=queue_size,
                    dual_stack=False
                )
                self._socks.append(sock)
                socket_file_descriptor = sock.fileno()
                if self._pollster is not None:
                    self._pollster.register(socket_file_descriptor, select.POLLIN)
                self._sockmap[socket_file_descriptor] = sock
            completed = True
        finally:
            if not completed:
                self.close()

    def __enter__(self) -> 'MultipleSocketsListener':
        return self

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
        self.close()

    def __repr__(self) -> str:
        addrs = []
        for sock in self._socks:
            try:
                addrs.append(sock.getsockname())
            except socket.error:
                addrs.append(())
        return '<%s (%r) at %#x>' % (self.__class__.__name__, addrs, id(self))  # pylint: disable=consider-using-f-string

    def _poll(self) -> Optional[Any]:
        """Return the first readable socket_file_descriptor."""
        fds_select: Optional[Tuple[List[Any], List[Any], List[Any]]] = None
        fds_poll: Optional[List[Tuple[int, int]]] = None
        timeout = self.gettimeout()
        if self._pollster is None:
            fds_select = select.select(self._sockmap.keys(), [], [], timeout)
            if timeout and fds_select == ([], [], []):
                raise TimeoutError('timed out')
        else:
            if timeout is not None:
                timeout *= 1000
            fds_poll = self._pollster.poll(timeout)
            if timeout and fds_poll == []:
                raise TimeoutError('timed out')
        try:
            if fds_select is not None:
                return fds_select[0][0]
            if fds_poll is not None:
                return fds_poll[0][0]
        except IndexError:
            pass  # non-blocking socket
        return None

    def _multicall(self, name: str, *args: Any, **kwargs: Any) -> None:
        for sock in self._socks:
            meth = getattr(sock, name)
            meth(*args, **kwargs)

    def accept(self) -> Tuple[socket.socket, Any]:
        """Accept a connection from the first socket which is ready
        to do so.
        """
        socket_file_descriptor = self._poll()
        sock = self._sockmap[socket_file_descriptor] if socket_file_descriptor else self._socks[0]
        return sock.accept()

    def filenos(self) -> List[int]:
        """Return sockets' file descriptors as a list of integers.
        This is useful with select().
        """
        return list(self._sockmap.keys())

    def getsockname(self) -> Any:
        """Return first registered socket's own address."""
        return self._socks[0].getsockname()

    @overload
    def getsockopt(self, level: int, optname: int) -> int:
        ...

    @overload
    def getsockopt(self, level: int, optname: int, buflen: int) -> bytes:
        ...

    def getsockopt(self, level: int, optname: int, buflen: int = 0) -> Union[int, bytes]:
        """Return first registered socket's options."""
        return self._socks[0].getsockopt(level, optname, buflen)

    def gettimeout(self) -> Optional[float]:
        """Return first registered socket's timeout."""
        return self._socks[0].gettimeout()

    def settimeout(self, timeout: float) -> None:
        """Set timeout for all registered sockets."""
        self._multicall('settimeout', timeout)

    def setblocking(self, flag: bool) -> None:
        """Set non/blocking mode for all registered sockets."""
        self._multicall('setblocking', flag)

    @overload
    def setsockopt(self, level: int, optname: int, value: Union[int, bytes], optlen: None) -> None:
        ...

    @overload
    def setsockopt(self, level: int, optname: int, value: None, optlen: int) -> None:
        ...

    def setsockopt(self, level: int, optname: int, value: Optional[Union[int, bytes]], optlen: Optional[int]) -> None:
        """Set option for all registered sockets."""
        self._multicall('setsockopt', level, optname, value, optlen)

    def shutdown(self, how: int) -> None:
        """Shut down all registered sockets."""
        self._multicall('shutdown', how)

    def close(self) -> None:
        """Close all registered sockets."""
        self._multicall('close')
        self._socks = []
        self._sockmap.clear()
