# -*- coding: utf-8 -*-

import logging
import os
import ssl
import socket
import base64
import hashlib

from enhancements.modules import BaseModule

from tcp_proxy_server import socks
from tcp_proxy_server.forwarders import TcpProxyForwardAddress
from tcp_proxy_server.exceptions import TcpProxyPubKeyPinError


class TcpProxyChain(BaseModule):

    def __init__(self, proxyserver, clientsock, clientaddr):
        super().__init__()
        self.proxyserver = proxyserver
        self.clientsock = clientsock
        self.clientaddr = clientaddr
        self.serversock = None
        self.serveraddress = None
        self.modules = None

    def get_sockets(self):
        socketlist = []
        if self.clientsock.fileno() >= 0:
            socketlist.append(self.clientsock)
        if self.serversock.fileno() >= 0:
            socketlist.append(self.serversock)
        return socketlist

    def connect(self):
        self.modules = [m() for m in self.proxyserver.handlers]
        return True

    def process_chain(self, insocket, data):
        for module in self.modules:
            data = module.process(self.clientsock == insocket, data)
            if not data:  # exit chain, if no data is left
                return None
        return data

    def process(self, insocket, data):
        raise NotImplementedError()

    def close(self):
        for module in self.modules:
            module.on_close()
        # TODO: Better error handling!!!
        if self.serveraddress:
            logging.debug("%s: disconnecting from %s", self.clientaddr, self.serveraddress)
        else:
            logging.debug("%s: client disconnected", self.clientaddr)
        for sock in self.get_sockets():
            try:
                if sock.fileno() >= 0:
                    sock.close()
            except Exception:
                logging.error("%s: failed closing connection to %s", self.clientaddr, self.serveraddress)


class TcpProxyForwardChain(TcpProxyChain):
    """creates socket and handle modules for transferred data"""

    @classmethod
    def parser_arguments(cls):
        cls.parser().add_argument(
            '--close-after-send',
            dest='closeaftersend',
            action='store_true',
            default=False,
            help='close connection after sending data'
        )
        cls.parser().add_argument(
            '--udp',
            dest='udp',
            action='store_true',
            default=False,
            help='close connection after sending data'
        )

    def connect(self):
        super().connect()
        if self.proxyserver.sslcertificate and os.path.isfile(self.proxyserver.sslcertificate):
            server_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            server_context.load_cert_chain(certfile=self.proxyserver.sslcertificate)
            server_context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
            # server_context.set_ciphers('EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH')
            self.clientsock = server_context.wrap_socket(self.clientsock, server_side=True)

        forwardaddress = self.proxyserver.forwarder.get_address(self.clientsock, self.clientaddr)
        if not isinstance(forwardaddress, TcpProxyForwardAddress):
            logging.error('Forwarder "%s" does not return a TcpProxyForwarderAddress object', self.proxyserver.forwarder.__class__.__name__)
            return False

        self.serveraddress = forwardaddress.address
        self.serversock = forwardaddress.socket
        if not self.serveraddress and not self.serversock:
            logging.error('Forwarder "%s" does not set a forward address or forwardsock!', self.proxyserver.forwarder.__class__.__name__)
            return False

        if self.serveraddress and not self.serveraddress[0] and not self.serveraddress[1]:
            logging.error('Forwarder "%s" does not set a remotehost or remoteport %s!', self.proxyserver.forwarder.__class__.__name__, self.serveraddress)
            return False

        if not self.serversock:
            self.create_socket()

        return True

    def create_socket(self):
        # forward = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        proxysocket = socks.socksocket if self.proxyserver.socksproxy else socket.socket

        if self.args.udp:
            self.serversock = proxysocket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            self.serversock = proxysocket(socket.AF_INET, socket.SOCK_STREAM)

        if self.proxyserver.forwardssl:
            forward_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            forward_context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
            if not self.proxyserver.ssl_verify:
                forward_context.check_hostname = False
                forward_context.verify_mode = ssl.CERT_NONE
            self.serversock = forward_context.wrap_socket(self.serversock, server_hostname=self.serveraddress[0])

        if self.proxyserver.socksproxy:
            self.serversock.set_proxy(socks.SOCKS5, self.proxyserver.socksproxy, self.proxyserver.socksproxyport, False, self.proxyserver.socksusername, self.proxyserver.sockspassword)

        self.serversock.connect(self.serveraddress)

        if self.proxyserver.forwardssl and self.proxyserver.ssl_pubkey_pin:

            der_cert_bin = self.serversock.getpeercert(binary_form=True)
            pem_cert = ssl.DER_cert_to_PEM_cert(der_cert_bin)
            pk_base64 = ''.join(pem_cert.split("\n")[1:-2])
            pk_raw = base64.b64decode(pk_base64)
            thumb_md5 = hashlib.md5(pk_raw).hexdigest()  # nosec
            thumb_sha1 = hashlib.sha1(pk_raw).hexdigest()  # nosec
            thumb_sha256 = hashlib.sha256(pk_raw).hexdigest()  # nosec

            if self.proxyserver.ssl_pubkey_pin not in [thumb_md5, thumb_sha1, thumb_sha256]:
                logging.warning('Pluplic Key Error! Publickey Pin: %s, Pin provided: %s', thumb_sha256, self.proxyserver.ssl_pubkey_pin)
                raise TcpProxyPubKeyPinError()

    def process(self, insocket, data):
        data = self.process_chain(insocket, data)
        if data:
            # if clientsock then send data to server
            if self.clientsock == insocket:
                if self.args.udp:
                    self.serversock.sendto(data, self.serveraddress)
                else:
                    self.serversock.send(data)
            else:
                self.clientsock.send(data)
            if self.args.closeaftersend:
                self.proxyserver.close_hanlder(self.clientsock)
