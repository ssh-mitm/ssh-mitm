import logging
import socket
import threading
from types import TracebackType
from typing import Any, Optional, Type, Union

import paramiko
from paramiko import PKey

PATCH_LOCK = threading.Lock()
ORIGINAL_PARSE_SERVICE_ACCEPT = paramiko.auth_handler.AuthHandler._parse_service_accept  # type: ignore[attr-defined] # pylint:disable=protected-access
ORIGINAL_PARSE_USERAUTH_INFO_REQUEST = paramiko.auth_handler.AuthHandler._parse_userauth_info_request  # type: ignore[attr-defined] # pylint:disable=protected-access


def patched_parse_service_accept(
    self: paramiko.auth_handler.AuthHandler, msg: paramiko.message.Message
) -> None:
    logging.debug("wait for lock to execute original _parse_service_accept")
    with PATCH_LOCK:
        ORIGINAL_PARSE_SERVICE_ACCEPT(self, msg)


def patched_parse_userauth_info_request(
    self: paramiko.auth_handler.AuthHandler, msg: paramiko.message.Message
) -> None:
    logging.debug("wait for lock to execute original _parse_userauth_info_request")
    with PATCH_LOCK:
        ORIGINAL_PARSE_USERAUTH_INFO_REQUEST(self, msg)


paramiko.auth_handler.AuthHandler._parse_service_accept = patched_parse_service_accept  # type: ignore[attr-defined] # pylint:disable=protected-access
paramiko.auth_handler.AuthHandler._parse_userauth_info_request = patched_parse_userauth_info_request  # type: ignore[attr-defined] # pylint:disable=protected-access


class PublicKeyEnumerationError(Exception):
    pass


class PublicKeyEnumerator:
    """Probe a remote host to determine if the provided public key is authorized for the provided username.

    The PublicKeyEnumerator takes four arguments: hostname_or_ip (a string representing hostname
    or IP address), port (an integer representing the port number), username (a string
    representing the username), and public_key (a public key in paramiko.pkey.PublicBlob format).
    The function returns a boolean indicating if the provided public key is authorized or not.

    The PublicKeyEnumerator uses the paramiko library to perform the probe by creating a secure shell (SSH)
    connection to the remote host and performing authentication using the provided username and
    public key. Two helper functions, valid and parse_service_accept, are defined inside the
    check_publickey function to assist with the authentication process.

    The PublicKeyEnumerator function opens a socket connection to the remote host and starts an
    SSH transport using the paramiko library. The function then generates a random private
    key, replaces the public key with the provided key, and performs the public key
    using transport.auth_publickey. The result of the authentication is stored in the
    valid_key variable. If the authentication fails, an exception of type
    paramiko.ssh_exception.AuthenticationException is raised and caught, leaving the
    valid_key variable as False. Finally, the function returns the value of valid_key,
    which indicates whether the provided public key is authorized or not.
    """

    def __init__(self, hostname_or_ip: str, port: int) -> None:
        self.remote_address = (hostname_or_ip, port)
        self.sock: Optional[socket.socket] = None
        self.transport: Optional[paramiko.transport.Transport] = None
        self.connected: bool = False

    def connect(self) -> None:
        if self.connected:
            return
        self.connected = True
        self.sock = socket.create_connection(self.remote_address)
        self.transport = paramiko.transport.Transport(self.sock)
        self.transport.start_client()

    def close(self) -> None:
        self.connected = False
        if self.transport is not None:
            self.transport.close()
        if self.sock is not None:
            self.sock.close()

    def __enter__(self) -> "PublicKeyEnumerator":
        self.connect()
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        self.close()

    def check_publickey(
        self, username: str, public_key: Union[str, paramiko.pkey.PublicBlob]
    ) -> bool:
        # pylint: disable=protected-access
        def valid(self, msg: paramiko.message.Message) -> None:  # type: ignore[no-untyped-def] # noqa: ANN001
            """
            A helper function that is called when authentication is successful.

            Args:
                msg (paramiko.message.Message): The message that was sent.
            """
            del msg  # unused arguments
            logging.debug("execute patched _parse_userauth_info_request")
            self.auth_event.set()
            self.authenticated = True

        def parse_service_accept(self, message: paramiko.message.Message) -> Optional[Any]:  # type: ignore[no-untyped-def] # noqa: ANN001
            """
            A helper function that parses the service accept message.

            Args:
                message (paramiko.message.Message): The message to parse.
            """
            # https://tools.ietf.org/html/rfc4252#section-7
            logging.debug("execute patched _parse_service_accept")
            service = message.get_text()
            if not (service == "ssh-userauth" and self.auth_method == "publickey"):
                return self._parse_service_accept(message)
            message = paramiko.message.Message()
            message.add_byte(paramiko.common.cMSG_USERAUTH_REQUEST)
            message.add_string(self.username)
            message.add_string("ssh-connection")
            message.add_string(self.auth_method)
            message.add_boolean(False)
            if self.private_key.public_blob.key_type == "ssh-rsa":
                message.add_string("rsa-sha2-512")
            else:
                message.add_string(self.private_key.public_blob.key_type)
            message.add_string(self.private_key.public_blob.key_blob)
            self.transport._send_message(message)
            return None

        if not self.connected:
            self.connect()
        if not self.sock or not self.transport:
            msg = "enumerator not connected! use connect() method before enumeration."
            raise PublicKeyEnumerationError(msg)

        valid_key = False
        with PATCH_LOCK:
            paramiko.auth_handler.AuthHandler._parse_service_accept = parse_service_accept  # type: ignore[attr-defined]
            paramiko.auth_handler.AuthHandler._parse_userauth_info_request = valid  # type: ignore[attr-defined]
            try:
                # For compatibility with paramiko, we need to generate a random private key and replace
                # the public key with our data.
                key: PKey = paramiko.RSAKey.generate(2048)
                key.public_blob = (
                    public_key
                    if isinstance(public_key, paramiko.pkey.PublicBlob)
                    else paramiko.pkey.PublicBlob.from_string(public_key)
                )
                self.transport.auth_publickey(username, key)
                valid_key = True
            except (ValueError, paramiko.ssh_exception.AuthenticationException):
                valid_key = False
            finally:
                paramiko.auth_handler.AuthHandler._parse_service_accept = ORIGINAL_PARSE_SERVICE_ACCEPT  # type: ignore[attr-defined]
                paramiko.auth_handler.AuthHandler._parse_userauth_info_request = ORIGINAL_PARSE_USERAUTH_INFO_REQUEST  # type: ignore[attr-defined]
        return valid_key
