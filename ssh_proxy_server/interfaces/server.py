import logging

import paramiko
from sshpubkeys import SSHKey

from enhancements.modules import BaseModule
from ssh_proxy_server.clients.sftp import SFTPClient


class BaseServerInterface(paramiko.ServerInterface, BaseModule):

    def __init__(self, session):
        super().__init__()
        self.session = session


class ServerInterface(BaseServerInterface):
    """ssh server implementation for SSH-MITM
    """

    def __init__(self, session):
        super().__init__(session)
        self.forwarders = []

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
        cls.parser().add_argument(
            '--enable-none-auth',
            dest='enable_none_auth',
            action='store_true',
            help='enable "none" authentication'
        )
        cls.parser().add_argument(
            '--enable-keyboard-interactive-auth',
            dest='enable_keyboard_interactive_auth',
            action='store_true',
            help='enable "keyboard-interactive" authentication'
        )
        cls.parser().add_argument(
            '--disable-keyboard-interactive-prompts',
            dest='disable_keyboard_interactive_prompts',
            action='store_true',
            help='disable prompts for keyboard-interactive'
        )
        cls.parser().add_argument(
            '--extra-auth-methods',
            dest='extra_auth_methods',
            help='extra authentication mehtod names'
        )

    def check_channel_exec_request(self, channel, command):
        logging.debug("check_channel_exec_request: channel=%s, command=%s", channel, command.decode('utf8'))
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
            return True
        logging.warning('ssh command not allowed!')
        return False

    def check_channel_forward_agent_request(self, channel):
        logging.debug("check_channel_forward_agent_request: channel=%s", channel)
        self.session.agent_requested.set()
        return True

    def check_channel_shell_request(self, channel):
        logging.debug("check_channel_shell_request: channel=%s", channel)
        if not self.args.disable_ssh:
            self.session.ssh = True
            self.session.ssh_channel = channel
            return True
        return False

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        logging.debug(
            "check_channel_pty_request: channel=%s, term=%s, width=%s, height=%s, pixelwidth=%s, pixelheight=%s, modes=%s",
            channel, term, width, height, pixelwidth, pixelheight, modes
        )
        if not self.args.disable_ssh:
            self.session.ssh = True
            self.session.ssh_pty_kwargs = {
                'term': term,
                'width': width,
                'height': height,
                'width_pixels': pixelwidth,
                'height_pixels': pixelheight
            }
            return True
        return False

    def get_allowed_auths(self, username):
        logging.debug("get_allowed_auths: username=%s", username)
        allowed_auths = []
        if self.args.extra_auth_methods:
            allowed_auths.extend(self.args.extra_auth_methods.split(','))
        if self.args.enable_keyboard_interactive_auth:
            allowed_auths.append('keyboard-interactive')
        if not self.args.disable_pubkey_auth:
            allowed_auths.append('publickey')
        if not self.args.disable_password_auth:
            allowed_auths.append('password')
        if allowed_auths or self.args.enable_none_auth:
            allowed_authentication_methods = ','.join(allowed_auths)
            logging.debug("Allowed authentication methods: %s", allowed_authentication_methods)
            return allowed_authentication_methods
        logging.warning('Authentication is set to "none", but logins are disabled!')
        return 'none'

    def check_auth_none(self, username):
        logging.debug("check_auth_none: username=%s", username)
        if self.args.enable_none_auth:
            self.session.authenticator.authenticate(username, key=None)
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_auth_interactive(self, username, submethods):
        logging.debug("check_auth_interactive: username=%s, submethods=%s", username, submethods)
        if not self.args.enable_keyboard_interactive_auth:
            return paramiko.AUTH_FAILED
        self.session.username = username
        iq = paramiko.server.InteractiveQuery()
        if not self.args.disable_keyboard_interactive_prompts:
            iq.add_prompt("Password (kb-interactive): ", False)
        return iq

    def check_auth_interactive_response(self, responses):
        logging.debug("check_auth_interactive_response: responses=%s", responses)
        if self.args.disable_keyboard_interactive_prompts:
            self.session.authenticator.authenticate(self.session.username, key=None)
            return paramiko.AUTH_SUCCESSFUL
        if not responses:
            return paramiko.AUTH_FAILED
        return self.session.authenticator.authenticate(self.session.username, password=responses[0])

    def check_auth_publickey(self, username, key):
        ssh_pub_key = SSHKey("{} {}".format(key.get_name(), key.get_base64()))
        ssh_pub_key.parse()
        logging.info("check_auth_publickey: username=%s, key=%s %s %sbits", username, key.get_name(), ssh_pub_key.hash_sha256(), ssh_pub_key.bits)
        if self.args.disable_pubkey_auth:
            logging.debug("Publickey login attempt, but publickey auth was disabled!")
            return paramiko.AUTH_FAILED
        return self.session.authenticator.authenticate(username, key=key)

    def check_auth_password(self, username, password):
        logging.debug("check_auth_password: username=%s, password=%s", username, password)
        if self.args.disable_password_auth:
            logging.warning("Password login attempt, but password auth was disabled!")
            return paramiko.AUTH_FAILED
        return self.session.authenticator.authenticate(username, password=password)

    def check_channel_request(self, kind, chanid):
        logging.debug("check_channel_request: kind=%s , chanid=%s", kind, chanid)
        return paramiko.OPEN_SUCCEEDED

    def check_channel_env_request(self, channel, name, value):
        logging.debug("check_channel_env_request: channel=%s, name=%s, value=%s", channel, name, value)
        self.session.env_requests[name] = value
        return True

    def check_channel_subsystem_request(self, channel, name):
        logging.debug("check_channel_subsystem_request: channel=%s, name=%s", channel, name)
        if name.lower() == 'sftp':
            self.session.sftp = True
            self.session.sftp_channel = channel
        return super().check_channel_subsystem_request(channel, name)

    def check_port_forward_request(self, address, port):
        """
        Note that the if the client requested the port, we must handle it or
        return false.
        Only if it requested 0 as port we can open a random port (actually the
        OS will tell us which port).
        If it can't be opened, we just return false.
        """
        logging.info(
            "check_port_forward_request: address=%s, port=%s",
            address, port
        )
        try:
            return self.session.ssh_client.transport.request_port_forward(
                address,
                port,
                self.session.proxyserver.server_tunnel_interface(self.session, self, (address, port)).handler
            )
        except paramiko.ssh_exception.SSHException:
            logging.info("TCP forwarding request denied")
            return False

    def cancel_port_forward_request(self, address, port):
        logging.info(
            "cancel_port_forward_request: address=%s, port=%s",
            address, port
        )
        username = self.session.transport.get_username()
        logging.info(
            "Cancel port forward request on %s:%i by %s.", address,
            port, username, extra={'username': username}
        )
        self.session.ssh_client.transport.cancel_port_forward(address, port)

    def check_channel_direct_tcpip_request(self, chanid, origin, destination):
        username = self.session.transport.get_username()
        logging.info(
            "channel_direct_tcpip_request: chanid=%s, origin=%s, destination=%s, username=%s",
            chanid, origin, destination, username
        )

        try:
            f = self.session.proxyserver.client_tunnel_interface(self.session, chanid, origin, destination)
            self.forwarders.append(f)
        except paramiko.ssh_exception.ChannelException:
            logging.error("Could not setup forward from %s to %s.", origin, destination)
            return paramiko.OPEN_FAILED_CONNECT_FAILED

        return paramiko.OPEN_SUCCEEDED

    def check_channel_window_change_request(self, channel, width, height, pixelwidth, pixelheight):
        logging.debug(
            "check_channel_window_change_request: channel=%s, width=%s, height=%s, pixelwidth=%s, pixelheight=%s",
            channel, width, height, pixelwidth, pixelheight
        )
        if self.session.ssh_channel:
            self.session.ssh_channel.resize_pty(width, height, pixelwidth, pixelheight)
            return True
        return False

    def check_channel_x11_request(self, channel, single_connection, auth_protocol, auth_cookie, screen_number):
        logging.debug(
            "check_channel_x11_request: channel=%s, single_connection=%s, auth_protocol=%s, auth_cookie=%s, screen_number=%s",
            channel, single_connection, auth_protocol, auth_cookie, screen_number
        )
        return False

    def check_global_request(self, msg):
        logging.debug(
            "check_global_request: msg=%s", msg
        )


class ProxySFTPServer(paramiko.SFTPServer):
    def start_subsystem(self, name, transport, channel):
        self.server.session.sftp_client = SFTPClient.from_client(self.server.session.ssh_client)
        if not self.server.session.sftp_client:
            return
        self.server.session.sftp_client.subsystem_count += 1
        super().start_subsystem(name, transport, channel)

    def finish_subsystem(self):
        super().finish_subsystem()
        if not self.server.session.sftp_client:
            return
        self.server.session.sftp_client.subsystem_count -= 1
        self.server.session.sftp_client.close()
