import logging
from enum import Enum

import paramiko
import paramiko.hostkeys

from enhancements.modules import Module
from ssh_proxy_server.exceptions import NoAgentKeys, InvalidHostKey


class AuthenticationMethod(Enum):
    password = "password"  # nosec
    publickey = "publickey"
    agent = "agent"


class BaseSSHClient(Module):
    pass


class SSHClient(BaseSSHClient):

    CIPHERS = None

    def __init__(self, host, port, method, password, user, key, session):
        self.session = session
        self.host = host
        self.port = port
        self.method = method
        self.user = user
        self.password = password
        self.agent = session.agent
        self.key = key
        self.transport = None
        self.connected = False

    def connect(self):
        message = None

        self.transport = paramiko.Transport("{}:{}".format(self.host, str(self.port)))
        if self.CIPHERS:
            if not isinstance(self.CIPHERS, tuple):
                raise ValueError('client ciphers must be a tuple')
            self.transport.get_security_options().ciphers = self.CIPHERS

        try:
            if self.method is AuthenticationMethod.password:
                self.transport.connect(username=self.user, password=self.password)
            elif self.method is AuthenticationMethod.publickey:
                self.transport.connect(username=self.user, password=self.password, pkey=self.key)
            elif self.method is AuthenticationMethod.agent:
                keys = self.agent.get_keys()
                if not keys:
                    raise NoAgentKeys()
                for k in keys:
                    try:
                        self.transport.connect(username=self.user, password=self.password, pkey=k)
                        break
                    except paramiko.AuthenticationException:
                        self.transport.close()
                        self.transport = paramiko.Transport("{}:{}".format(self.host, str(self.port)))

            else:
                logging.error('authentication method "%s" not supported!', self.method.value)
                return False

            remotekey = self.transport.get_remote_server_key()
            if not self.check_host_key("{}:{}".format(self.host, self.port), remotekey.get_name(), remotekey):
                raise InvalidHostKey()
            self.connected = True
            return True

        except paramiko.SSHException:
            message = "general ssh error"
        except NoAgentKeys:
            message = "no agent keys found"
        except InvalidHostKey:
            message = "Hostkey is invalid"

        userstring = "{}:{}@{}:{}".format(self.user, self.password, self.host, self.port)
        logging.debug('Authentication failed: %s, User: %s, Message: %s', self.method.value, userstring, message or "")

        return False

    def check_host_key(self, hostname, keytype, key):
        """checks the host key, default always returns true"""
        return True
