from sshmitm.core.forwarders.netconf import NetconfForwarder


class NetconfForwarderElasticLog(NetconfForwarder):
    """forwards a netconf message from or to the remote server"""

    def handle_initial_message(self, message: bytes) -> bytes:
        self.session.log_forwarder.forward_client_msg(
            client_msg=message.decode("utf8"),
        )
        return message

    def handle_traffic(self, traffic: bytes, isclient: bool) -> bytes:
        if isclient:
            self.session.log_forwarder.forward_client_msg(
                client_msg=traffic.decode("utf-8"),
            )
        else:
            self.session.log_forwarder.forward_server_msg(
                client_msg=self.session.netconf_command.decode("utf-8"),
                server_msg=traffic.decode("utf-8"),
            )
        return traffic

    def handle_error(self, traffic: bytes, *, isclient: bool) -> bytes:
        if isclient:
            self.session.log_forwarder.forward_client_error_message(
                client_msg_err=self.session.netconf_command.decode("utf-8"),
                server_msg=traffic.decode("utf-8"),
            )
        else:
            self.session.log_forwarder.forward_server_error_message(
                client_msg=self.session.netconf_command.decode("utf-8"),
                server_msg_err=traffic.decode("utf-8"),
            )
        return traffic
