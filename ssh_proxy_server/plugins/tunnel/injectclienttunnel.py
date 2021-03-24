import logging
import re

from ssh_proxy_server.forwarders.tunnel import TunnelForwarder, ClientTunnelForwarder
from ssh_proxy_server.interfaces import ServerInterface
from ssh_proxy_server.plugins.session.tcpserver import TCPServerThread


class InjectableClientTunnelForwarder(ClientTunnelForwarder):
    """
    Serve out direct-tcpip connections over a session on local ports
    TODO: Pretty up code, look @ master channel not rdy, logging
    """

    class ClientTunnelServerInterface(ServerInterface):

        def __init__(self, session):
            super().__init__(session)
            self.session.proxyserver.client_tunnel_interface.setup_injector(session)

    # Init should occur after master channel establishment

    @classmethod
    def parser_arguments(cls):
        cls.parser().add_argument(
            '--tunnel-client-dest',
            dest='client_tunnel_dest',
            help='direct-tcpip address/port combination to forward to (e.g. google.com:80)',
            required=True
        )
        cls.parser().add_argument(
            '--tunnel-client-net',
            dest='client_tunnel_net',
            default='127.0.0.1',
            help='network on which to serve the client tunnel injector'
        )

    session = None
    args = None
    tcpserver = None

    @classmethod
    def setup_injector(cls, session):
        parser_retval = cls.parser().parse_known_args(None, None)
        args, _ = parser_retval
        cls.session = session
        cls.args = args
        if not re.compile('.*:\d{1,5}').match(cls.args.client_tunnel_dest):
            logging.warning("--tunnel-client-dest does not match format host:port (e.g. google.com:80)")
            return
        cls.tcpserver = TCPServerThread(
            cls.handle_request,
            run_status=cls.session.running,
            network=cls.args.client_tunnel_net
        )
        cls.tcpserver.start()
        logging.info(
            "created client tunnel injector for host {host} on port {port} to destination {dest}".format(
                host=cls.tcpserver.network,
                port=cls.tcpserver.port,
                dest=cls.args.client_tunnel_dest
            )
        )

    @classmethod
    def handle_request(cls, client, addr):
        destnet, destport = cls.args.client_tunnel_dest.split(':')
        remote_ch = cls.session.ssh_client.transport.open_channel(
            "direct-tcpip",
            (destnet, int(destport)),
            addr
        )
        TunnelForwarder(client, remote_ch)

    @classmethod
    def get_interface(cls):
        return cls.ClientTunnelServerInterface



