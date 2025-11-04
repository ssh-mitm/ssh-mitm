from sshmitm.core.forwarders.ssh import SSHForwarder


class SSHForwarderElasticLog(SSHForwarder):
    """Logs ssh sessions to an elastic server"""

    def stdin(self, text: bytes) -> bytes:
        self.session.log_forwarder.forward_client_msg(
            client_msg=text.decode("utf-8"),
        )
        return text

    def stdout(self, text: bytes) -> bytes:
        self.session.log_forwarder.forward_server_msg(
            client_msg=None,
            server_msg=text.decode("utf-8"),
        )
        return text

    def stderr(self, text: bytes) -> bytes:
        self.session.log_forwarder.forward_server_error_message(
            client_msg=None,
            server_msg_err=text.decode("utf-8"),
        )
        return text
