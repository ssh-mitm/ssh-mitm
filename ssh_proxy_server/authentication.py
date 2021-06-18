import logging

from enhancements.modules import BaseModule
import paramiko
from sshpubkeys import SSHKey

from ssh_proxy_server.clients.ssh import SSHClient, AuthenticationMethod
from ssh_proxy_server.exceptions import MissingHostException


class Authenticator(BaseModule):

    REQUEST_AGENT = False
    REQUEST_AGENT_BREAKIN = False

    @classmethod
    def parser_arguments(cls):
        cls.parser().add_argument(
            '--remote-host',
            dest='remote_host',
            help='remote host to connect to (default 127.0.0.1)'
        )
        cls.parser().add_argument(
            '--remote-port',
            dest='remote_port',
            type=int,
            help='remote port to connect to (default 22)'
        )
        cls.parser().add_argument(
            '--auth-username',
            dest='auth_username',
            help='username for remote authentication'
        )
        cls.parser().add_argument(
            '--auth-password',
            dest='auth_password',
            help='password for remote authentication'
        )
        cls.parser().add_argument(
            '--hide-credentials',
            dest='auth_hide_credentials',
            action='store_true',
            help='do not log credentials (usefull for presentations)'
        )
        cls.parser().add_argument(
            '--forward-agent',
            dest='forward_agent',
            action='store_true',
            help='enables agent forwarding through the proxy'
        )

    def __init__(self, session):
        super().__init__()
        self.session = session

    def get_remote_host_credentials(self, username, password=None, key=None):
        if self.session.proxyserver.transparent:
            return (
                self.args.auth_username or username,
                self.args.auth_password or password,
                key,
                self.args.remote_host or self.session.socket_remote_address[0],
                self.args.remote_port or self.session.socket_remote_address[1]
            )
        return (
            self.args.auth_username or username,
            self.args.auth_password or password,
            key,
            self.args.remote_host or '127.0.0.1',
            self.args.remote_port or 22
        )

    def authenticate(self, username=None, password=None, key=None):
        if username:
            remote_credentials = self.get_remote_host_credentials(username, password, key)
            self.session.username = remote_credentials[0]
            self.session.password = remote_credentials[1]
            self.session.key = remote_credentials[2]
            self.session.remote_address = (remote_credentials[3], remote_credentials[4])
        if key and not self.session.key:
            self.session.key = key

        try:
            if self.session.agent:
                return self.auth_agent(
                    self.session.username,
                    self.session.remote_address[0],
                    self.session.remote_address[1]
                )
            if self.session.password:
                return self.auth_password(
                    self.session.username,
                    self.session.remote_address[0],
                    self.session.remote_address[1],
                    self.session.password
                )
            if self.session.key:
                return self.auth_publickey(
                    self.session.username,
                    self.session.remote_address[0],
                    self.session.remote_address[1],
                    self.session.key
                )
        except MissingHostException:
            logging.error("no remote host")
        except Exception:
            logging.exception("internal error, abort authentication!")
        return paramiko.AUTH_FAILED

    def auth_agent(self, username, host, port):
        raise NotImplementedError("authentication must be implemented")

    def auth_password(self, username, host, port, password):
        raise NotImplementedError("authentication must be implemented")

    def auth_publickey(self, username, host, port, key):
        raise NotImplementedError("authentication must be implemented")

    def connect(self, user, host, port, method, password=None, key=None):
        def get_agent_pubkeys():
            keys = self.session.agent.get_keys()
            keys_parsed = []
            for k in keys:
                ssh_pub_key = SSHKey("{} {}".format(k.get_name(), k.get_base64()))
                ssh_pub_key.parse()
                keys_parsed.append((k.get_name(), ssh_pub_key, k.can_sign()))
            return keys_parsed

        if not self.args.auth_hide_credentials:
            ssh_keys = None
            keys_formatted = ""
            if self.session.agent:
                ssh_keys = get_agent_pubkeys()
                keys_formatted = "\n".join(["\t\tAgent-Key: {} {} {}bits, can sign: {}".format(k[0], k[1].hash_sha256(), k[1].bits, k[2]) for k in ssh_keys])

            logging.info(
                "\n".join((
                    "Client connection established with parameters:",
                    "\tRemote Address: %s",
                    "\tPort: %s",
                    "\tUsername: %s",
                    "\tPassword: %s",
                    "\tKey: %s",
                    "\tAgent: %s",
                    "%s"
                )),
                host,
                port,
                user,
                password,
                ('None' if key is None else 'not None'),
                "available keys: {}".format(len(ssh_keys)) if ssh_keys else 'no agent',
                keys_formatted
            )

        if not host:
            raise MissingHostException()

        sshclient = SSHClient(
            host,
            port,
            method,
            password,
            user,
            key,
            self.session
        )
        if sshclient.connect():
            self.session.ssh_client = sshclient
            return paramiko.AUTH_SUCCESSFUL
        logging.warning('connection failed!')
        return paramiko.AUTH_FAILED


class AuthenticatorPassThrough(Authenticator):
    """pass the authentication to the remote server (reuses the credentials)
    """

    def auth_agent(self, username, host, port):
        return self.connect(username, host, port, AuthenticationMethod.agent)

    def auth_password(self, username, host, port, password):
        return self.connect(username, host, port, AuthenticationMethod.password, password=password)

    def auth_publickey(self, username, host, port, key):
        if key.can_sign():
            ssh_pub_key = SSHKey("{} {}".format(key.get_name(), key.get_base64()))
            ssh_pub_key.parse()
            logging.info("AuthenticatorPassThrough.auth_publickey: username=%s, key=%s %s %sbits", username, key.get_name(), ssh_pub_key.hash_sha256(), ssh_pub_key.bits)
            return self.connect(username, host, port, AuthenticationMethod.publickey, key=key)
        if self.REQUEST_AGENT:
            # Ein Publickey wird nur direkt von check_auth_publickey
            # übergeben. In dem Fall müssen wir den Client authentifizieren,
            # damit wir auf den Agent warten können!
            logging.debug("authentication failed. accept connection and wait for agent.")
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED
