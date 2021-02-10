import logging
import sys
import os

from enhancements.modules import BaseModule as BaseModule

from tcp_proxy_server.chains import TcpProxyForwardChain, TcpProxyChain
from tcp_proxy_server.exceptions import TcpProxyModuleError, CertificateMissingException
from tcp_proxy_server.forwarders import (
    SimpleForwarder,
    TcpProxyForwarder
)
from tcp_proxy_server.proxy import TcpProxy


class TcpProxyManager(BaseModule):

    DEFAULTFORWARDER = SimpleForwarder

    def __init__(self):
        super().__init__()
        logging.info("Using proxy manager: %s", self.__class__.__name__)
        forwarder = self.args.forwarder
        if not forwarder:
            raise TcpProxyModuleError("Forwarder Module error")
        self.forwarder = forwarder

    @classmethod
    def parser_arguments(cls):
        cls.parser().add_argument(
            '-li', '--listenip',
            dest='listen_ip',
            default='0.0.0.0',  # nosec
            help='IP address to listen for incoming data'
        )
        cls.parser().add_argument(
            '--ssl-certificate',
            dest='sslcertificate',
            help='use SSL with certificate'
        )
        cls.parser().add_argument(
            '--ssl-forward',
            dest='sslforward',
            default=False,
            action='store_true',
            help='connect to the forwarded server with ssl'
        )
        cls.parser().add_argument(
            '--ssl-pubkey-pin',
            dest='sslpubkeypin',
            help='set public key pin of remote host (SHA256)'
        )
        cls.parser().add_argument(
            '--no-ssl-verify',
            dest='nosslverify',
            default=False,
            action='store_true',
            help='disable ssl verification'
        )
        cls.parser().add_argument(
            '--socks-proxy',
            dest='socksproxy',
            default=None,
            help="connect to socks proxy"
        )
        cls.parser().add_argument(
            '--socks-proxy-port',
            dest='socksproxyport',
            default=1080,
            type=int,
            help="socks proxy port (default 1080)"
        )
        cls.parser().add_argument(
            '--socks-proxy-username',
            dest='socksproxyusername',
            default=None,
            help="username for socks proxy"
        )
        cls.parser().add_argument(
            '--socks-proxy-password',
            dest='socksproxypassword',
            default=None,
            required='--socks-proxy-user' in sys.argv,
            help="password for socks proxy"
        )

        cls.add_module(
            '--chain',
            dest='chain',
            default=TcpProxyForwardChain,
            help='Chain to handle modules',
            baseclass=TcpProxyChain
        )
        cls.add_module(
            '--forwarder',
            dest='forwarder',
            default=cls.DEFAULTFORWARDER,
            help='Forwarder to send data to remote server',
            baseclass=TcpProxyForwarder
        )

    @staticmethod
    def get_instance(proxymanager):
        if not proxymanager:
            raise TcpProxyModuleError("ProxyManager Module error")
        return proxymanager()

    def get_proxy_instance(self, proxyargs):
        if proxyargs.sslcertificate and not os.path.isfile(proxyargs.sslcertificate):
            raise CertificateMissingException(proxyargs.sslcertificate)
        proxy = TcpProxy(
            proxyargs.modules,
            proxyargs.forwarder,
            proxyargs.chain,
            (proxyargs.listen_ip, proxyargs.listen_port),
            proxyargs.sslcertificate,
            proxyargs.sslforward
        )
        proxy.ssl_verify = not proxyargs.nosslverify
        proxy.ssl_pubkey_pin = proxyargs.sslpubkeypin
        proxy.socksproxy = proxyargs.socksproxy
        proxy.socksproxyport = proxyargs.socksproxyport
        proxy.socksusername = proxyargs.socksproxyusername
        proxy.sockspassword = proxyargs.socksproxypassword
        return proxy

    def start(self, proxyargs):
        raise NotImplementedError

    def stop(self):
        raise NotImplementedError


class SingleProxyManager(TcpProxyManager):
    """start a single proxy instance"""

    def __init__(self):
        super().__init__()
        self.proxy = None

    @classmethod
    def parser_arguments(cls):
        super().parser_arguments()
        cls.parser().add_argument(
            '-lp',
            '--listenport',
            dest='listen_port',
            type=int,
            required=True,
            help='port to listen on'
        )

    def start(self, proxyargs):
        self.get_proxy_instance(proxyargs).start()
