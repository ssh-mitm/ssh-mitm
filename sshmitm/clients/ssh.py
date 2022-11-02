import logging
from enum import Enum

from typing import (
    TYPE_CHECKING,
    Optional
)
from paramiko.pkey import PKey

import paramiko
import paramiko.hostkeys
from sshpubkeys import SSHKey  # type: ignore

import sshmitm
from sshmitm.moduleparser import BaseModule
from sshmitm.forwarders.agent import AgentProxy
from sshmitm.exceptions import NoAgentKeys, InvalidHostKey

if TYPE_CHECKING:
    from sshmitm.session import Session  # noqa


class AuthenticationMethod(Enum):
    password = "password"  # nosec
    publickey = "publickey"
    agent = "agent"


class BaseSSHClient(BaseModule):
    pass


class SSHClient(BaseSSHClient):

    CIPHERS = None

    def __init__(
        self,
        host: str,
        port: int,
        method: AuthenticationMethod,
        password: Optional[str],
        user: str,
        key: Optional[PKey],
        session: 'sshmitm.session.Session'
    ) -> None:
        self.session: 'sshmitm.session.Session' = session
        self.host: str = host
        self.port: int = port
        self.method: AuthenticationMethod = method
        self.user: str = user
        self.password: Optional[str] = password
        self.agent: Optional[AgentProxy] = self.session.agent
        self.key: Optional[PKey] = key
        self.transport: Optional[paramiko.Transport] = None
        self.connected: bool = False

    def connect(self) -> bool:
        message = None

        self.transport = paramiko.Transport((self.host, self.port))
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
                if self.agent is not None:
                    keys = self.agent.get_keys()
                    if not keys:
                        raise NoAgentKeys()
                    for k in keys:
                        try:
                            self.transport.connect(username=self.user, password=self.password, pkey=k)
                            ssh_pub_key = SSHKey(f"{k.get_name()} {k.get_base64()}")
                            ssh_pub_key.parse()
                            logging.debug(
                                "ssh-mitm connected to remote host with username=%s, key=%s %s %sbits",
                                self.user, k.get_name(), ssh_pub_key.hash_sha256(), ssh_pub_key.bits
                            )
                            break
                        except paramiko.AuthenticationException:
                            self.transport.close()
                            self.transport = paramiko.Transport((self.host, self.port))

            else:
                logging.error('authentication method "%s" not supported!', self.method.value)
                return False

            remotekey = self.transport.get_remote_server_key()
            if not self.check_host_key(f"{self.host}:{self.port}", remotekey.get_name(), remotekey):
                raise InvalidHostKey()
            self.connected = True
            return True

        except paramiko.SSHException:
            message = "general ssh error"
        except NoAgentKeys:
            message = "no agent keys found"
        except InvalidHostKey:
            message = "Hostkey is invalid"

        userstring = f"{self.user}:{self.password}@{self.host}:{self.port}"
        logging.debug('Authentication failed: %s, User: %s, Message: %s', self.method.value, userstring, message or "")

        return False

    def check_host_key(self, hostname: str, keytype: str, key: PKey) -> bool:
        """checks the host key, default always returns true"""
        del hostname, keytype, key  # unused arguments
        return True
