# -*- coding: utf-8 -*-

"""
This is a simple port-forward / proxy, written using only the default python library.
"""
import socket
from select import select
import time
import logging
import traceback
import ssl
import threading

from tcp_proxy_server.forwarders import TcpProxyForwarder
from tcp_proxy_server.exceptions import TcpProxyModuleError, TcpProxyPubKeyPinError, TcpProxyHandlerException


class TcpProxy(object):

    def __init__(self, modules, forwarder, chain, listenaddress, sslcertificate=None, forwardssl=False, buffer_size=4096, delay=0.0001):

        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        self.handlers = modules
        if not self.handlers:
            raise TcpProxyModuleError("Handler Module error")

        self.forwarder = None
        if isinstance(forwarder, TcpProxyForwarder):
            self.forwarder = forwarder
            self.forwarder.server = self
        else:
            if not forwarder:
                raise TcpProxyModuleError("Forwarder Module error")
            self.forwarder = forwarder(self)

        if not self.forwarder:
            raise TcpProxyModuleError("Unexpected forwarder module error")

        if not chain:
            raise TcpProxyModuleError("Chain Module error")
        self.chainclass = chain

        self.listenaddress = listenaddress

        self.sslcertificate = sslcertificate
        self.forwardssl = forwardssl
        self.ssl_pubkey_pin = None
        self.ssl_verify = True
        self.buffer_size = buffer_size
        self.delay = delay

        self.socksproxy = None
        self.socksproxyport = 1080
        self.socksusername = None
        self.sockspassword = None

        self.server.bind(self.listenaddress)
        self.server.listen(200)

    def start(self):
        logging.info("%s: starting proxy server", self.listenaddress)
        try:
            while True:
                clientsock, clientaddr = self.server.accept()
                connectionthreat = threading.Thread(target=self.on_accept, args=(clientsock, clientaddr))
                connectionthreat.daemon = True
                connectionthreat.start()
        except Exception:
            logging.debug("%s: proxy stoped", self.listenaddress)

    def stop(self):
        if self.server.fileno() >= 0:
            self.server.close()
            print(self.server.fileno())

    def on_accept(self, clientsock, clientaddr):
        logging.debug("%s: client connected on %s", clientaddr, clientsock.getsockname())
        moduleschain = self.chainclass(self, clientsock, clientaddr)
        try:
            moduleschain.connect()
            while True:
                time.sleep(self.delay)
                for s in select(moduleschain.get_sockets(), [], [])[0]:
                    logging.debug("Selected Socket: %s", s)
                    if s.type == socket.SOCK_DGRAM:
                        data, remote_address = s.recvfrom(self.buffer_size)
                    else:
                        data = s.recv(self.buffer_size)
                    if not data:
                        break
                    moduleschain.process(s, data)
                else:
                    continue
                break

        except (TcpProxyPubKeyPinError, ssl.SSLError, ConnectionRefusedError, TcpProxyHandlerException) as error:
            if isinstance(error, TcpProxyPubKeyPinError):
                logging.error("%s: public key pin does not match! Closing client connection", clientaddr)
            elif isinstance(error, ssl.SSLError):
                traceback.print_exc()
                logging.error("%s: SSL Verification Error! Connection closed", clientaddr)
            elif isinstance(error, ConnectionRefusedError):
                logging.error("%s: connection to %s refused!", clientaddr, moduleschain.serveraddress)
            elif isinstance(error, OSError):
                logging.error("%s: %s %s", clientaddr, error.args[1], moduleschain.serveraddress)
            else:
                logging.error("%s: failed to connect to remote server %s! Connection closed. Reason: %s", clientaddr, moduleschain.serveraddress, error)
                # traceback.print_exc()
        except Exception as error:
            logging.exception("%s: failed to connect to remote server %s! General Exception. Connection closed. Reason: %s", clientaddr, moduleschain.serveraddress, error)
            # traceback.print_exc()

        moduleschain.close()
