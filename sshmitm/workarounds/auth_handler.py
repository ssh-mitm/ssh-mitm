# pylint: disable=protected-access
import logging
from typing import cast

from paramiko.auth_handler import AuthHandler
from paramiko.common import (
    AUTH_FAILED,
    INFO,
    cMSG_EXT_INFO,
    cMSG_SERVICE_ACCEPT,
    cMSG_USERAUTH_BANNER,
    cMSG_USERAUTH_PK_OK,
    cMSG_USERAUTH_REQUEST,
)
from paramiko.message import Message
from paramiko.pkey import PKey
from paramiko.ssh_exception import SSHException

HOSTBOUND_METHOD = "publickey-hostbound-v00@openssh.com"

_original_parse_userauth_request = AuthHandler._parse_userauth_request  # type: ignore[attr-defined]


def _get_hostbound_session_blob(  # pylint: disable=too-many-arguments
    handler: AuthHandler,
    key: PKey,
    service: str,
    username: str,
    algorithm: str,
    server_key_blob: bytes,
) -> bytes:
    if handler.transport.session_id is None:
        msg = "session_id is not set"
        raise SSHException(msg)
    m = Message()
    m.add_string(handler.transport.session_id)
    m.add_byte(cMSG_USERAUTH_REQUEST)
    m.add_string(username)
    m.add_string(service)
    m.add_string(HOSTBOUND_METHOD)
    m.add_boolean(True)
    _, bits = handler._get_key_type_and_bits(key)  # type: ignore[attr-defined]
    m.add_string(algorithm)
    m.add_string(bits)
    m.add_string(server_key_blob)
    return m.asbytes()


def _load_hostbound_key(
    handler: AuthHandler, algorithm: str, keyblob: bytes
) -> PKey | None:
    try:
        return cast("PKey", handler._generate_key_from_request(algorithm, keyblob))  # type: ignore[attr-defined]
    except SSHException as e:
        handler._log(INFO, f"Auth rejected: public key: {e}")  # type: ignore[attr-defined]
    except Exception as e:  # pylint: disable=broad-exception-caught  # noqa: BLE001
        handler._log(INFO, f"Auth rejected: unsupported or mangled public key ({type(e).__name__}: {e})")  # type: ignore[attr-defined]
    return None


def _check_pubkey_auth(
    handler: AuthHandler, username: str, key: PKey, sig_attached: bool = True
) -> int:
    del sig_attached
    if handler.transport.server_object is None:
        return AUTH_FAILED
    return handler.transport.server_object.check_auth_publickey(username, key)


def auth_handler_parse_service_request(self: AuthHandler, m: Message) -> None:
    """
    Extends _parse_service_request to send a second EXT_INFO after
    SSH_MSG_SERVICE_ACCEPT. OpenSSH uses this to repeat server-sig-algs
    for the auth phase (RFC 8308 permits a second message here).
    """
    service = m.get_text()
    if self.transport.server_mode and service == "ssh-userauth":
        resp = Message()
        resp.add_byte(cMSG_SERVICE_ACCEPT)
        resp.add_string(service)
        self.transport._send_message(resp)  # type: ignore[attr-defined]

        if getattr(self.transport, "_remote_ext_info", None) == "ext-info-c":
            extensions = {"server-sig-algs": ",".join(self.transport.preferred_pubkeys)}
            ext_msg = Message()
            ext_msg.add_byte(cMSG_EXT_INFO)
            ext_msg.add_int(len(extensions))
            for name, value in sorted(extensions.items()):
                ext_msg.add_string(name)
                ext_msg.add_string(value)
            self.transport._send_message(ext_msg)  # type: ignore[attr-defined]

        if self.transport.server_object is None:
            return
        banner, language = self.transport.server_object.get_banner()
        if banner and language is not None:
            banner_msg = Message()
            banner_msg.add_byte(cMSG_USERAUTH_BANNER)
            banner_msg.add_string(banner)
            banner_msg.add_string(language)
            self.transport._send_message(banner_msg)  # type: ignore[attr-defined]
        return

    self._disconnect_service_not_available()  # type: ignore[attr-defined]


def auth_handler_parse_userauth_request(self: AuthHandler, m: Message) -> None:
    """
    Wraps _parse_userauth_request to additionally handle
    publickey-hostbound-v00@openssh.com.
    """
    username = m.get_text()
    service = m.get_text()
    method = m.get_text()
    m.rewind()

    if method != HOSTBOUND_METHOD:
        _original_parse_userauth_request(self, m)
        return

    logging.info("Auth request using %s for user %s", HOSTBOUND_METHOD, username)

    # Re-read after rewind
    username = m.get_text()
    service = m.get_text()
    m.get_text()  # method, already known

    if self.authenticated:
        return

    if service != "ssh-connection":
        self._disconnect_service_not_available()  # type: ignore[attr-defined]
        return

    if self.auth_username is not None and self.auth_username != username:
        self._disconnect_no_more_auth()  # type: ignore[attr-defined]
        return
    self.auth_username = username

    sig_attached = m.get_boolean()
    algorithm = m.get_text()
    keyblob = m.get_binary()
    server_key_blob = m.get_binary()

    server_key = self.transport.get_server_key()
    if server_key is None or server_key.asbytes() != server_key_blob:
        logging.info("Auth rejected: %s - server host key mismatch", HOSTBOUND_METHOD)
        self._send_auth_result(username, HOSTBOUND_METHOD, AUTH_FAILED)  # type: ignore[attr-defined]
        return

    key = _load_hostbound_key(self, algorithm, keyblob)
    if key is None:
        self._disconnect_no_more_auth()  # type: ignore[attr-defined]
        return

    result = _check_pubkey_auth(self, username, key, sig_attached=sig_attached)

    if result != AUTH_FAILED:
        if not sig_attached:
            pk_ok = Message()
            pk_ok.add_byte(cMSG_USERAUTH_PK_OK)
            pk_ok.add_string(algorithm)
            pk_ok.add_string(keyblob)
            self.transport._send_message(pk_ok)  # type: ignore[attr-defined]
            return

        sig = Message(m.get_binary())
        blob = _get_hostbound_session_blob(
            self, key, service, username, algorithm, server_key_blob
        )
        if not key.verify_ssh_sig(blob, sig):
            self._log(INFO, f"Auth rejected: invalid {HOSTBOUND_METHOD} signature")  # type: ignore[attr-defined]
            result = AUTH_FAILED

    self._send_auth_result(username, HOSTBOUND_METHOD, result)  # type: ignore[attr-defined]
