import logging

import paramiko
from enhancements.modules import BaseModule


class BaseServerInterface(paramiko.ServerInterface, BaseModule):

    def __init__(self, session):
        super().__init__()
        self.session = session


class ServerInterface(BaseServerInterface):
    """ssh server implementation for SSH-MITM
    """

    @classmethod
    def parser_arguments(cls):
        cls.parser().add_argument(
            '--disable-ssh',
            dest='disable_ssh',
            action='store_true',
            help='disable ssh'
        )
        cls.parser().add_argument(
            '--disable-scp',
            dest='disable_scp',
            action='store_true',
            help='disable scp'
        )
        cls.parser().add_argument(
            '--disable-password-auth',
            dest='disable_password_auth',
            action='store_true',
            help='disable password authentication'
        )
        cls.parser().add_argument(
            '--disable-pubkey-auth',
            dest='disable_pubkey_auth',
            action='store_true',
            help='disable public key authentication'
        )

    def check_channel_exec_request(self, channel, command):
        if self.args.disable_scp:
            logging.warning('scp command not allowed!')
            return False
        if command.decode('utf8').startswith('scp'):
            logging.debug("got scp command: %s", command.decode('utf8'))
            self.session.scp = True
            self.session.scp_command = command
            self.session.scp_channel = channel
            return True

        if not self.args.disable_ssh:
            # we can use the scp forwarder for command executions
            logging.info("got ssh command: %s", command.decode('utf8'))
            self.session.scp = True
            self.session.scp_command = command
            self.session.scp_channel = channel
            self.session.proxyserver.scp_interface(self.session).forward()
            return True
        logging.warning('ssh command not allowed!')
        return False

    def check_channel_forward_agent_request(self, channel):
        self.session.agent_requested.set()
        logging.debug("check_channel_forward_agent_request")
        return True

    def check_channel_shell_request(self, channel):
        if not self.args.disable_ssh:
            self.session.ssh = True
            self.session.ssh_channel = channel
            return True
        return False

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        logging.debug(
            "check_channel_pty_request: term=%s, width=%s, height=%s, pixelwidth=%s, pixelheight=%s, modes=%s",
            term, width, height, pixelwidth, pixelheight, modes
        )
        if not self.args.disable_ssh:
            self.session.ssh = True
            self.session.sshPtyKArgs = {
                'term': term,
                'width': width,
                'height': height,
                'width_pixels': pixelwidth,
                'height_pixels': pixelheight
            }
            return True
        return False

    def get_allowed_auths(self, username):
        allowed_auths = []
        if not self.args.disable_pubkey_auth:
            allowed_auths.append('publickey')
        if not self.args.disable_password_auth:
            allowed_auths.append('password')
        if allowed_auths:
            return ','.join(allowed_auths)
        logging.warning('Allowed authentication is none!')
        return 'none'

    def check_auth_publickey(self, username, key):
        if self.args.disable_pubkey_auth:
            logging.warning("Public key login attempt, but public key auth was disabled!")
            return paramiko.AUTH_FAILED
        return self.session.authenticator.authenticate(username, key=key)

    def check_auth_password(self, username, password):
        if self.args.disable_password_auth:
            logging.warning("Password login attempt, but password auth was disabled!")
            return paramiko.AUTH_FAILED
        return self.session.authenticator.authenticate(username, password=password)

    def check_channel_request(self, kind, chanid):
        logging.debug("check_channel_request: %s , %s", kind, chanid)
        return paramiko.OPEN_SUCCEEDED

    def check_channel_env_request(self, channel, name, value):
        logging.debug("check_channel_env_request: %s=%s", name, value)
        return False

    def check_channel_subsystem_request(self, channel, name):
        logging.debug("check_channel_subsystem_request: name=%s", name)
        if name.upper() == 'SFTP':
            self.session.sftp = True
            self.session.sftp_channel = channel
        return super().check_channel_subsystem_request(channel, name)

    def check_port_forward_request(self, address, port):
        logging.info(
            "check_port_forward_request: address=%s, port=%s",
            address, port
        )
        return True

    def cancel_port_forward_request(self, address, port):
        logging.info(
            "cancel_port_forward_request: address=%s, port=%s",
            address, port
        )

    def check_channel_direct_tcpip_request(self, chanid, origin, destination):
        logging.info(
            "channel_direct_tcpip_request: chanid=%s, origin=%s, destination=%s",
            chanid, origin, destination
        )
        return paramiko.OPEN_SUCCEEDED

    def check_channel_window_change_request(self, channel, width, height, pixelwidth, pixelheight):
        logging.debug(
            "check_channel_window_change_request: width=%s, height=%s, pixelwidth=%s, pixelheight=%s",
            width, height, pixelwidth, pixelheight
        )
        return False

    def check_channel_x11_request(self, channel, single_connection, auth_protocol, auth_cookie, screen_number):
        logging.info(
            "check_channel_x11_request: single_connection=%s, auth_protocol=%s, auth_cookie=%s, screen_number=%s",
            single_connection, auth_protocol, auth_cookie, screen_number
        )
        return False

    def check_global_request(self, msg):
        logging.debug(
            "check_global_request: msg=%s", msg
        )


class ProxySFTPServer(paramiko.SFTPServer):
    def start_subsystem(self, name, transport, channel):
        self.server.session.sftp_client_ready.wait()
        self.server.session.sftp_client.subsystem_count += 1
        super().start_subsystem(name, transport, channel)

    def finish_subsystem(self):
        super().finish_subsystem()
        self.server.session.sftp_client.subsystem_count -= 1
        self.server.session.sftp_client.close()
