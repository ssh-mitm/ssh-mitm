import logging
import re

import paramiko

from ssh_proxy_server.forwarders.tunnel import TunnelForwarder, ClientTunnelForwarder
from ssh_proxy_server.plugins.session.tcpserver import TCPServerThread


class ClientTunnelHandler:
    """
    Similar to the ServerTunnelForwarder
    """

    def __init__(self, session, destination):
        self.session = session
        self.destination = destination

    def handle_request(self, client, addr):
        try:
            logging.debug("Injecting direct-tcpip channel (%s -> %s) to client", addr, self.destination)
            remote_ch = self.session.ssh_client.transport.open_channel("direct-tcpip", self.destination, addr)
            TunnelForwarder(client, remote_ch)
        except paramiko.ssh_exception.ChannelException:
            client.close()
            logging.error("Could not setup forward from %s to %s.", addr, self.destination)


class InjectableClientTunnelForwarder(ClientTunnelForwarder):
    """Serve out direct-tcpip connections over a session on local ports
    """

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

    # Setup should occur after master channel establishment

    @classmethod
    def setup_injector(cls, session):
        parser_retval = cls.parser().parse_known_args(None, None)
        args, _ = parser_retval
        cls.session = session
        cls.args = args
        form = re.compile('.*:\d{1,5}')

        for target in cls.args.client_tunnel_dest:
            if not form.match(target):
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
                "{session} created client tunnel injector for host {host} on port {port} to destination {dest}".format(
                    host=t.network,
                    port=t.port,
                    dest=target,
                    session=session
                )
            )
