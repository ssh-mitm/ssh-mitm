import logging
import select
import socket
import threading
import time

import paramiko

from ssh_proxy_server.forwarders.tunnel import ServerTunnelForwarder, TunnelForwarder


class InjectableServerTunnelForwarder(ServerTunnelForwarder):
    """
    For each server port forwarding request open a local port to inject traffic into the port-forward
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
        super(InjectableServerTunnelForwarder, self).__init__(session, server_interface, destination)

        # TODO: Extract common tcp socket server
        self.injector_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.injector_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.injector_sock.bind((self.args.server_tunnel_net, 0))
        self.injector_sock.listen(5)

        self.thread = threading.Thread(target=self.serve)
        self.thread.start()

    def serve(self):
        inject_host, inject_port = self.injector_sock.getsockname()
        logging.info(
            "created server tunnel injector on port {port} for destination {dest}".format(
                host=inject_host,
                port=inject_port,
                dest=self.destination
            )
        )
        try:
            while self.session.running:
                readable = select.select([self.injector_sock], [], [], 0.5)[0]
                if len(readable) == 1 and readable[0] is self.injector_sock:
                    client, addr = self.injector_sock.accept()
                    f = TunnelForwarder(
                        self.session.transport.open_channel("forwarded-tcpip", self.destination, addr),
                        client
                    )
                    self.server_interface.forwarders.append(f)
                time.sleep(0.1)
        except (paramiko.SSHException, OSError) as e:
            logging.warning("injector connection suffered an unexpected error")
            logging.exception(e)
            self.injector_sock.close()
