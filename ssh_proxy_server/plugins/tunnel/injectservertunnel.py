import logging

import paramiko

from ssh_proxy_server.forwarders.tunnel import ServerTunnelForwarder, TunnelForwarder
from ssh_proxy_server.plugins.session.tcpserver import TCPServerThread


class InjectableServerTunnelForwarder(ServerTunnelForwarder):
    """For each server port forwarding request open a local port to inject traffic into the port-forward

    The Handler is still the same as the ServerTunnelForwarder, only a tcp server is added

    """

    @classmethod
    def parser_arguments(cls):
        cls.parser().add_argument(
            '--tunnel-server-net',
            dest='server_tunnel_net',
            default='127.0.0.1',
            help='local address/interface where injector sessions are served'
        )

    def __init__(self, session, server_interface, destination):
        super().__init__(session, server_interface, destination)
        self.tcpserver = TCPServerThread(
            self.serve,
            network=self.args.server_tunnel_net,
            run_status=self.session.running
        )
        logging.info(
            "created server tunnel injector for host {host} on port {port} to destination {dest}".format(
                host=self.tcpserver.network,
                port=self.tcpserver.port,
                dest=self.destination
            )
        )
        self.tcpserver.start()

    def serve(self, client, addr):
        try:
            f = TunnelForwarder(
                self.session.transport.open_channel("forwarded-tcpip", self.destination, addr),
                client
            )
            self.server_interface.forwarders.append(f)
        except (paramiko.SSHException, OSError):
            logging.warning("injector connection suffered an unexpected error")
            self.tcpserver.close()
