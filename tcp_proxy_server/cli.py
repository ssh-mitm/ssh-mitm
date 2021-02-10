import argparse
import base64
import hashlib
import logging
import ssl
import socket
import sys

from enhancements.modules import ModuleParser, ModuleError
from enhancements.plugins import LogModule

from tcp_proxy_server.handlers import TcpProxyHandler
from tcp_proxy_server.exceptions import (
    TooManyForwarders,
    CertificateMissingException,
    TcpProxyModuleError
)
from tcp_proxy_server.proxymanager import (
    SingleProxyManager,
    TcpProxyManager
)


def main():
    moduleloader = ModuleParser(baseclass=TcpProxyHandler, description='TCP Proxy Server')

    moduleloader.add_plugin(LogModule)

    moduleloader.add_module(
        '--proxymanager',
        dest='tcp_proxymanager',
        default=SingleProxyManager,
        help='ProxyManager to manage the Proxy',
        baseclass=TcpProxyManager
    )

    try:
        args = moduleloader.parse_args()
    except ModuleError as error:
        logging.error('Module error! Module %s is not subclass of %s', error.moduleclass, error.baseclass)
        sys.exit(1)

    if args.nosslverify and not args.sslpubkeypin:
        logging.warning("SSL certificate verification disabled, but publickey pinning not used! You should consider to enable piblickey pinning.")

    if args.sslforward and args.socksproxy:
        logging.warning("TCPProxy does not support Socks5 with SSL!")

    try:
        proxymanager = TcpProxyManager.get_instance(args.tcp_proxymanager)
        proxymanager.start(args)

    except TcpProxyModuleError:
        logging.error("Failed to load module %s", args.modules)
    except TooManyForwarders:
        logging.error("Too many forwarders!")
    except CertificateMissingException as cert_error:
        logging.error("Certificate %s is missing - ssl disabled", cert_error.certificate_path)
    except KeyboardInterrupt:
        sys.exit(1)


def certificate_hash_values():
    """Get certificate pins from ssl certificate"""

    parser = argparse.ArgumentParser()
    parser.add_argument(
        'host',
        help='server to connect to'
    )
    parser.add_argument(
        'port',
        type=int,
        help='port'
    )
    args = parser.parse_args()

    remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    remote_socket_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    remote_socket_context.options |= ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
    remote_socket_context.check_hostname = False
    remote_socket_context.verify_mode = ssl.CERT_NONE
    remote_socket = remote_socket_context.wrap_socket(remote_socket, server_hostname=args.host)

    try:
        remote_socket.connect((args.host, args.port))
    except ssl.SSLError:
        logging.error('Remote server does not support SSL')
        sys.exit(1)

    der_cert_bin = remote_socket.getpeercert(binary_form=True)
    pem_cert = ssl.DER_cert_to_PEM_cert(der_cert_bin)
    pk_base64 = ''.join(pem_cert.split("\n")[1:-2])
    pk_raw = base64.b64decode(pk_base64)

    print("MD5: {}".format(hashlib.md5(pk_raw).hexdigest()))  # nosec
    print("SHA1: {}".format(hashlib.sha1(pk_raw).hexdigest()))  # nosec
    print("SHA256: {}".format(hashlib.sha256(pk_raw).hexdigest()))
