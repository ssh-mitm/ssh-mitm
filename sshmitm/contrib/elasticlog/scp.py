import logging

from sshmitm.core.forwarders.scp import SCPForwarder


class SCPForwarderElasticLog(SCPForwarder):
    """Logs messages to an elastic server"""

    def rewrite_scp_command(self, command: str) -> str:
        logging.info("got remote command: %s", command)
        self.session.log_forwarder.forward_client_msg(
            client_msg=command,
        )
        return command

    def handle_error(self, traffic: bytes, isclient: bool) -> bytes:
        if isclient:
            self.session.log_forwarder.forward_client_error_message(
                client_msg_err=self.session.scp_command.decode("utf-8"),
                server_msg=traffic.decode("utf-8"),
            )
        else:
            self.session.log_forwarder.forward_server_error_message(
                client_msg=self.session.scp_command.decode("utf-8"),
                server_msg_err=traffic.decode("utf-8"),
            )
        return traffic

    def handle_traffic(self, traffic: bytes, isclient: bool) -> bytes:
        if not isclient:
            self.session.log_forwarder.forward_server_msg(
                client_msg=self.session.scp_command.decode("utf-8"),
                server_msg=traffic.decode("utf-8"),
            )
        return super().handle_traffic(traffic, isclient)
