import argparse
import logging
import os
import sys
import socket
import re
from colored.colored import stylize, attr, fg
from rich._emoji_codes import EMOJI

from enhancements.modules import BaseModule
import paramiko
from sshpubkeys import SSHKey

from ssh_proxy_server.clients.ssh import SSHClient, AuthenticationMethod
from ssh_proxy_server.exceptions import MissingHostException


def probe_host(hostname_or_ip, port, username, public_key):

    def valid(self, msg):
        self.auth_event.set()
        self.authenticated = True

    def parse_service_accept(self, m):
        # https://tools.ietf.org/html/rfc4252#section-7
        service = m.get_text()
        if not (service == "ssh-userauth" and self.auth_method == "publickey"):
            return self._parse_service_accept(m)
        m = paramiko.message.Message()
        m.add_byte(paramiko.common.cMSG_USERAUTH_REQUEST)
        m.add_string(self.username)
        m.add_string("ssh-connection")
        m.add_string(self.auth_method)
        m.add_boolean(False)
        m.add_string(self.private_key.public_blob.key_type)
        m.add_string(self.private_key.public_blob.key_blob)
        self.transport._send_message(m)

    valid_key = False
    try:
        client_handler_table = paramiko.auth_handler.AuthHandler._client_handler_table
        client_handler_table[paramiko.common.MSG_USERAUTH_INFO_REQUEST] = valid
        client_handler_table[paramiko.common.MSG_SERVICE_ACCEPT] = parse_service_accept

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((hostname_or_ip, port))
        transport = paramiko.transport.Transport(sock)
        transport.start_client()

        # For compatibility with paramiko, we need to generate a random private key and replace
        # the public key with our data.
        key = paramiko.RSAKey.generate(2048)
        #key.public_blob =
        key.public_blob = public_key
        transport.auth_publickey(username, key)
        valid_key = True
    except paramiko.ssh_exception.AuthenticationException:
        pass
    finally:
        client_handler_table[paramiko.common.MSG_USERAUTH_INFO_REQUEST] = paramiko.auth_handler.AuthHandler._parse_userauth_info_request
        client_handler_table[paramiko.common.MSG_SERVICE_ACCEPT] = paramiko.auth_handler.AuthHandler._parse_service_accept
    return valid_key


def validate_remote_host(remote_host):
    if re.match(r"^[\w.]+(:[0-9]+)?$", remote_host):
        return remote_host
    raise argparse.ArgumentTypeError('remot host must be in format hostname:port')


def validate_honeypot(remote_host):
    if re.match(r"^[\S]+:[\S]+@[\w.]+(:[0-9]+)?$", remote_host):
        return remote_host
    raise argparse.ArgumentTypeError('honeypot address must be in format username_password@hostname:port')


class Authenticator(BaseModule):

    REQUEST_AGENT_BREAKIN = False

    @classmethod
    def parser_arguments(cls):
        plugin_group = cls.parser().add_argument_group(
            cls.__name__,
            "options for remote authentication"
        )
        plugin_group.add_argument(
            '--remote-host',
            dest='remote_host',
            type=validate_remote_host,
            help='remote host to connect to (default 127.0.0.1:22)'
        )
        plugin_group.add_argument(
            '--auth-username',
            dest='auth_username',
            help='username for remote authentication'
        )
        plugin_group.add_argument(
            '--auth-password',
            dest='auth_password',
            help='password for remote authentication'
        )

        plugin_group.add_argument(
            '--fallback-host',
            dest='fallback_host',
            required='--enable-auth-fallback' in sys.argv,
            type=validate_honeypot,
            help='fallback host for the honeypot (format username:password@hostname:port)'
        )

        plugin_group.add_argument(
            '--hide-credentials',
            dest='auth_hide_credentials',
            action='store_true',
            help='do not log credentials (usefull for presentations)'
        )
        plugin_group.add_argument(
            '--disallow-publickey-auth',
            dest='disallow_publickey_auth',
            action='store_true',
            help='disallow public key authentication but still checks if publickey authentication would be possible'
        )
        plugin_group.add_argument(
            '--accept-first-publickey',
            dest='accept_first_publickey',
            action='store_true',
            help='accepts the first key - does not check if user is allowed to login with publickey authentication'
        )

    def __init__(self, session):
        super().__init__()
        self.session = session

    def get_remote_host_credentials(self, username, password=None, key=None):
        remote_host = None
        remote_port = None
        if self.args.remote_host:
            if ':' in self.args.remote_host:
                remote_host = self.args.remote_host[:self.args.remote_host.rfind(':')]
                remote_port = int(self.args.remote_host[self.args.remote_host.rfind(':') + 1:])
        if self.session.proxyserver.transparent:
            return (
                self.args.auth_username or username,
                self.args.auth_password or password,
                key,
                remote_host or self.session.socket_remote_address[0],
                remote_port or self.session.socket_remote_address[1]
            )
        return (
            self.args.auth_username or username,
            self.args.auth_password or password,
            key,
            remote_host or '127.0.0.1',
            remote_port or 22
        )

    def authenticate(self, username=None, password=None, key=None, store_credentials=True):
        if store_credentials:
            self.session.username_provided = username
            self.session.password_provided = password
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

    def auth_fallback(self, username):
        def parse_host(connectionurl):
            username = None
            password = None
            hostname = None
            port = 22
            if '@' in connectionurl:
                username = connectionurl[:connectionurl.rfind('@')]
                print(username)
                if ':' in username:
                    password = username[username.rfind(':') + 1:]
                    username = username[:username.rfind(':')]
                hostname = connectionurl[connectionurl.rfind('@') + 1:]
            if ':' in hostname:
                port = int(hostname[hostname.rfind(':') + 1:])
                hostname = hostname[:hostname.rfind(':')]
            return username, password, hostname, port

        if not self.args.fallback_host:
            logging.error("\n".join([
                stylize(EMOJI['exclamation'] + " ssh agent not forwarded. Login to remote host not possible with publickey authentication.", fg('red') + attr('bold')),
                stylize(EMOJI['information'] + " To intercept clients without a forwarded agent, you can provide credentials for a honeypot.", fg('yellow') + attr('bold'))
            ]))
            return paramiko.AUTH_FAILED
        try:
            fallback_username, fallback_password, fallback_host, fallback_port = parse_host(self.args.fallback_host)
        except Exception:
            logging.error(stylize(EMOJI['exclamation'] + " failed to parse connection string for honeypot - publickey authentication failed", fg('red') + attr('bold')))
            return paramiko.AUTH_FAILED
        auth_status = self.connect(
            user=fallback_username or username,
            password=fallback_password,
            host=fallback_host,
            port=int(fallback_port),
            method=AuthenticationMethod.password
        )
        if auth_status == paramiko.AUTH_SUCCESSFUL:
            logging.warning(
                stylize(EMOJI['warning'] + " publickey authentication failed - no agent forwarded - connecting to honeypot!", fg('yellow') + attr('bold')),
            )
        else:
            logging.error(
                stylize(EMOJI['exclamation'] + " Authentication against honeypot failed!", fg('red') + attr('bold')),
            )
        return auth_status

    def connect(self, user, host, port, method, password=None, key=None):
        if not host:
            raise MissingHostException()

        auth_status = paramiko.AUTH_FAILED
        self.session.ssh_client = SSHClient(
            host,
            port,
            method,
            password,
            user,
            key,
            self.session
        )
        self.pre_auth_action()
        try:
            if self.session.ssh_client.connect():
                auth_status = paramiko.AUTH_SUCCESSFUL
        except paramiko.SSHException:
            logging.error(stylize("Connection to remote server refused", fg('red') + attr('bold')))
            return paramiko.AUTH_FAILED
        self.post_auth_action(auth_status == paramiko.AUTH_SUCCESSFUL)
        return auth_status

    def pre_auth_action(self):
        pass

    def post_auth_action(self, success):
        pass


class AuthenticatorPassThrough(Authenticator):
    """pass the authentication to the remote server (reuses the credentials)
    """

    def auth_agent(self, username, host, port):
        return self.connect(username, host, port, AuthenticationMethod.agent)

    def auth_password(self, username, host, port, password):
        return self.connect(username, host, port, AuthenticationMethod.password, password=password)

    def auth_publickey(self, username, host, port, key):
        ssh_pub_key = SSHKey(f"{key.get_name()} {key.get_base64()}")
        ssh_pub_key.parse()
        if key.can_sign():
            logging.debug("AuthenticatorPassThrough.auth_publickey: username=%s, key=%s %s %sbits", username, key.get_name(), ssh_pub_key.hash_sha256(), ssh_pub_key.bits)
            return self.connect(username, host, port, AuthenticationMethod.publickey, key=key)
        if self.args.accept_first_publickey:
            logging.debug('host probing disabled - first key accepted')
            if self.args.disallow_publickey_auth:
                logging.debug('ignoring argument --disallow-publickey-auth, first key still accepted')
            return paramiko.AUTH_SUCCESSFUL
        # Ein Publickey wird nur direkt von check_auth_publickey
        # übergeben. In dem Fall müssen wir den Client authentifizieren,
        # damit wir auf den Agent warten können!
        publickey = paramiko.pkey.PublicBlob(key.get_name(), key.asbytes())
        if probe_host(host, port, username, publickey):
            logging.debug(f"Found valid key for host {host}:{port} username={username}, key={key.get_name()} {ssh_pub_key.hash_sha256()} {ssh_pub_key.bits}bits")
            if not self.args.disallow_publickey_auth:
                return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def post_auth_action(self, success):
        def get_agent_pubkeys():
            pubkeyfile_path = None

            keys = self.session.agent.get_keys()
            keys_parsed = []
            for k in keys:
                ssh_pub_key = SSHKey(f"{k.get_name()} {k.get_base64()}")
                ssh_pub_key.parse()
                keys_parsed.append((k.get_name(), ssh_pub_key, k.can_sign(), k.get_base64()))

            if self.session.session_log_dir:
                os.makedirs(self.session.session_log_dir, exist_ok=True)
                pubkeyfile_path = os.path.join(self.session.session_log_dir, 'publickeys')
                with open(pubkeyfile_path, 'a+') as pubkeyfile:
                    pubkeyfile.write("".join([
                        f"{k[0]} {k[3]} saved-from-agent\n"
                        for k in keys_parsed
                    ]))

            return keys_parsed


        logmessage = []
        if success:
            logmessage.append(stylize("Remote authentication succeeded", fg('green') + attr('bold')))
        else:
            logmessage.append(stylize("Remote authentication failed", fg('red')))

        logmessage.append(f"\tRemote Address: {self.session.ssh_client.host}:{self.session.ssh_client.port}")
        logmessage.append(f"\tUsername: {self.session.username_provided}")

        if self.session.password_provided:
            display_password = None
            if not self.args.auth_hide_credentials:
                display_password = self.session.password_provided
            logmessage.append(f"\tPassword: {display_password or stylize('*******', fg('dark_gray'))}")

        if self.session.key is not None:
            ssh_pub_key = SSHKey(f"{self.session.key.get_name()} {self.session.key.get_base64()}")
            ssh_pub_key.parse()
            logmessage.append(f"\tLogin-Key: {self.session.key.get_name()} {ssh_pub_key.hash_sha256()} {ssh_pub_key.bits}bits")

        ssh_keys = None
        if self.session.agent:
            ssh_keys = get_agent_pubkeys()

        logmessage.append(f"\tAgent: {f'available keys: {len(ssh_keys)}' if ssh_keys else 'no agent'}")
        if ssh_keys is not None:
            logmessage.append("\n".join(
                [f"\t\tAgent-Key: {k[0]} {k[1].hash_sha256()} {k[1].bits}bits, can sign: {k[2]}" for k in ssh_keys]
            ))

        logging.info("\n".join(logmessage))
