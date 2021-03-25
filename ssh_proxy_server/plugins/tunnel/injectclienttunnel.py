import logging
import re

from ssh_proxy_server.forwarders.tunnel import TunnelForwarder, ClientTunnelForwarder
from ssh_proxy_server.plugins.session.tcpserver import TCPServerThread


class ClientTunnelHandler:

    def __init__(self, session, destination):
        self.session = session
        self.destination = destination

    def handle_request(self, client, addr):
        remote_ch = self.session.ssh_client.transport.open_channel("direct-tcpip", self.destination, addr)
        TunnelForwarder(client, remote_ch)


class InjectableClientTunnelForwarder(ClientTunnelForwarder):
    """
    Serve out direct-tcpip connections over a session on local ports
    """

    # Init should occur after master channel establishment

    @classmethod
    def parser_arguments(cls):
        cls.parser().add_argument(
            '--tunnel-client-dest',
            dest='client_tunnel_dest',
            help='multiple direct-tcpip address/port combination to forward to (e.g. google.com:80, youtube.com:80)',
            required=True,
            nargs='+'
        )
        cls.parser().add_argument(
            '--tunnel-client-net',
            dest='client_tunnel_net',
            default='127.0.0.1',
            help='network on which to serve the client tunnel injector'
        )

    session = None
    args = None
    tcpservers = []

    @classmethod
    def setup_injector(cls, session):
        parser_retval = cls.parser().parse_known_args(None, None)
        args, _ = parser_retval
        cls.session = session
        cls.args = args
        format = re.compile('.*:\d{1,5}')

        logging.debug(cls.args.client_tunnel_dest)
        for target in cls.args.client_tunnel_dest:
            logging.debug(target)
            if not format.match(target):
                logging.warning("--tunnel-client-dest %s does not match format host:port (e.g. google.com:80)", target)
                break
            destnet, destport = target.split(":")
            t = TCPServerThread(
                ClientTunnelHandler(session, (destnet, int(destport))).handle_request,
                run_status=cls.session.running,
                network=cls.args.client_tunnel_net
            )
            t.start()
            cls.tcpservers.append(t)
            logging.info(
                "created client tunnel injector for host {host} on port {port} to destination {dest}".format(
                    host=t.network,
                    port=t.port,
                    dest=target
                )
            )


