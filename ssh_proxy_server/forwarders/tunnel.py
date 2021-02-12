# TunnelServern - A SSH Tunnel implementation for and based on Paramiko.
#
# Copyright (C) 2014 Pier Angelo Vendrame <vogliadifarniente@gmail.com>
#
# This file is based on some of Paramiko examples: demo_server.py, forward.py,
# rforward.py.
# Original copyright (C) 2003-2007  Robey Pointer <robeypointer@gmail.com>
#
# This is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko and TunnelServer are distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
# for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this software; if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.
#
# This is an implementation of the tunnel handler for a SSH server based on
# Paramiko.
#
# Please note that this isn't a complete server: it won't accept any connection,
# as standard Paramiko ServerInterface.
# Furthermore it accepts shell requests, but it only sends a message which tells
# that actually shell access is not premitted.
#
# Another note about terminology:
# * forward is Third-Party --> SSH Server --> SSH Client (-R on OpenSSH client);
# * direct is SSH Client --> SSH Server --> Third-Party (-L on OpenSSH client).
# You should use forward when the SSH Client wants to provide a service, whereas
# you should use direct to bypass firewall when connecting to another service.


import logging
import socket
import select
import threading
import socketserver


class ForwardServer(socketserver.ThreadingTCPServer, threading.Thread):
    """
    When forwarding a port, we have to act as a server.
    Therefore we use Python standard TCP Server and threads to listen for
    connections to forward, which is what we do with this class.
    """
    daemon = True  # This is for Thread
    daemon_threads = daemon  # This is for ThreadingTCPServer
    allow_reuse_address = True

    def __init__(self, server_address, RequestHandlerClass, transport, bind_and_activate=True):
        """
        Initializes the forwarder.
        We actually save the parameters.
        """
        socketserver.ThreadingTCPServer.__init__(self, server_address, RequestHandlerClass, bind_and_activate)
        threading.Thread.__init__(self)

        # Save the original server address, otherwise OpenSSH will complain.
        # We have some freedom on port, so make sure it is correct.
        self.bind_address = (server_address[0], self.socket.getsockname()[1])

        self.transport = transport

    def run(self):
        """
        Start serving.
        This method actually have been defined to comply threading.Thread.
        """
        self.serve_forever()

    def shutdown(self, join=True):
        """
        Shutdowns the forwarding and by default join the thread.
        """
        socketserver.ThreadingTCPServer.shutdown(self)
        if join:
            self.join()

    def __del__(self):
        """
        The destructor: makes sure the forwarding is closed.
        """
        self.shutdown()


def tunnel(sock, chan, chunk_size=1024):
    """
    Connect a socket and a SSH channel.
    """
    while True:
        r, w, x = select.select([sock, chan], [], [])

        if sock in r:
            data = sock.recv(chunk_size)
            if len(data) == 0:
                break
            chan.send(data)

        if chan in r:
            data = chan.recv(chunk_size)
            if len(data) == 0:
                break
            sock.send(data)

    chan.close()
    sock.close()


class Handler(socketserver.BaseRequestHandler):
    """
    Handler for Python standard SocketServer.
    Note that we need our server class (i. e. ForwardServer), otherwise we don't
    handle the request
    """

    def handle(self):
        """
        Handles a request.
        """
        if not isinstance(self.server, ForwardServer):
            # We only want our server!
            return False

        transport = self.server.transport
        peer = self.request.getpeername()
        logging.debug(
            "Forward request by peer %s, username: %s.", peer,
            transport.get_username()
        )

        try:
            # bind_address is a custom variable, but if somebody else used this
            # handler, an exception will be raised.
            # The same if the SSH client denies the permission to open the channel.
            chan = transport.open_forwarded_tcpip_channel(
                self.client_address, self.server.bind_address
            )
            logging.debug("Opened channel %i.", chan.get_id())
        except Exception:
            logging.exception("Could not open the new channel.")

        try:
            logging.debug("Start tunnelling for %s.", peer)
            tunnel(self.request, chan)
            logging.debug("Tunnel for %s ended correctly.", peer)
        except Exception:
            logging.exception("An error occurred during tunneling for %s.", peer)


class ForwardClient(threading.Thread):
    """
    This class handles the direct TCP-IP connection feature of SSH.
    It implements a thread to do so, however it should be closed by a cleaner.
    """

    daemon = True
    chanid = 0
    active = False
    lock = threading.Lock()
    cleaner = None

    def __init__(self, address, transport, chanid, logger, cleaner):
        threading.Thread.__init__(self)

        self.socket = socket.create_connection(address)
        self.transport = transport
        self.chanid = chanid
        self.cleaner = cleaner

        cleaner.add_thread(self)

    def run(self):
        """
        Waits for the SSH direct connection channel and start redirect.
        After that it has handled its channel, it will return and the thread will
        wait to be joined.
        """
        self.lock.acquire()
        self.active = True
        self.lock.release()

        while self.active:
            chan = self.transport.accept(10)
            if chan is None:
                continue
            if chan.get_id() == self.chanid:
                break

        peer = self.socket.getpeername()
        try:
            tunnel(self.socket, chan)
        except Exception:
            logging.exception("Tunnel exception with peer %s.", peer)

        self.lock.acquire()
        self.active = False
        self.lock.release()

        self.cleaner.set_event()

    def shutdown(self, join=True):
        """
        Shutdown the thread as soon as possible.
        Note that if it is sending data, it will wait for the channel or to
        socket to be closed, and it will block the caller!
        By default this method joins the thread, too.
        """
        logging.debug(
            "Shutting down ForwardClient for channel %i.",
            self.chanid
        )

        self.lock.acquire()
        self.active = False
        self.lock.release()

        if join:
            self.join()


class Cleaner(threading.Thread):
    """
    Cleans unused threads.
    """
    # The lock used to add and delete threads
    lock = threading.Lock()

    # The event to set to ask thread deletion
    event = threading.Event()

    # The threads to monitor
    threads = []

    # We run as a demon thread
    daemon = True

    def run(self):
        """
        Wait for an event to clean
        """
        while True:
            self.event.wait()

            for thread in self.threads:
                if not thread.active:
                    thread.shutdown()

                    self.lock.acquire()
                    try:
                        # It seems that it is removed afer the next connection...
                        # Misteries of GC...
                        self.threads.remove(thread)
                    except Exception:
                        logging.debug('unable to remove port forward thread')
                    self.lock.release()

            self.event.clear()

    def add_thread(self, thread):
        """
        Add a thread to the threads list.
        """
        self.lock.acquire()
        self.threads.append(thread)
        self.lock.release()

    def set_event(self):
        """
        Ask for deletion by setting the event.
        """
        self.event.set()
