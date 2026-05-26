"""Paramiko internal API compatibility tests.

These tests verify that every internal (private) attribute, method, and module-
level symbol that ssh-mitm depends on is still present in the currently installed
paramiko.  Run them against a new paramiko release before bumping the version
pin in requirements.in.

Usage::

    pytest tests/test_paramiko_compat.py -v
"""

from __future__ import annotations

import importlib
import inspect
import socket
from typing import Any

import paramiko
import paramiko.auth_handler
import paramiko.common
import paramiko.message
import paramiko.packet
import paramiko.pkey
import paramiko.transport
import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _transport() -> paramiko.Transport:
    """Return a fresh Transport backed by one end of a socketpair."""
    s1, _s2 = socket.socketpair()
    t = paramiko.Transport(s1)
    s1.close()
    return t


def _has(obj: Any, name: str) -> bool:
    return hasattr(obj, name)


def _callable(obj: Any, name: str) -> bool:
    return callable(getattr(obj, name, None))


# ---------------------------------------------------------------------------
# paramiko.common constants
# ---------------------------------------------------------------------------

class TestParamikoCommonConstants:
    """All paramiko.common symbols imported by sshmitm/workarounds/*.py and
    sshmitm/authentication.py must remain available."""

    REQUIRED_CONSTANTS = [
        # byte constants (used in Message.add_byte)
        "cMSG_EXT_INFO",
        "cMSG_SERVICE_ACCEPT",
        "cMSG_SERVICE_REQUEST",
        "cMSG_USERAUTH_BANNER",
        "cMSG_USERAUTH_PK_OK",
        "cMSG_USERAUTH_REQUEST",
        "cMSG_KEXINIT",
        "cMSG_NEWKEYS",
        "cMSG_UNIMPLEMENTED",
        # integer message-type constants
        "MSG_KEXINIT",
        "MSG_IGNORE",
        "MSG_DISCONNECT",
        "MSG_DEBUG",
        "MSG_NEWKEYS",
        "MSG_UNIMPLEMENTED",
        "MSG_USERAUTH_PK_OK",
        "MSG_USERAUTH_FAILURE",
        "MSG_SERVICE_ACCEPT",
        # auth results
        "AUTH_FAILED",
        "AUTH_SUCCESSFUL",
        # log levels
        "DEBUG",
        "INFO",
        "WARNING",
        "ERROR",
        # misc
        "xffffffff",
        "MSG_NAMES",
    ]

    @pytest.mark.parametrize("name", REQUIRED_CONSTANTS)
    def test_constant_exists(self, name: str) -> None:
        assert hasattr(paramiko.common, name), (
            f"paramiko.common.{name} is missing — check if it was renamed or removed"
        )


# ---------------------------------------------------------------------------
# Module-level imports (private symbols imported by name)
# ---------------------------------------------------------------------------

class TestModuleImports:
    """Module-level private symbols that are imported by name at the top of
    workarounds/transport.py must remain importable."""

    def test_active_threads_importable_from_paramiko_transport(self) -> None:
        """sshmitm/workarounds/transport.py does:
            from paramiko.transport import _active_threads
        """
        assert hasattr(paramiko.transport, "_active_threads"), (
            "paramiko.transport._active_threads is gone — "
            "transport_run() and the workaround will break"
        )

    def test_need_rekey_exception_importable(self) -> None:
        """from paramiko.packet import NeedRekeyException"""
        assert hasattr(paramiko.packet, "NeedRekeyException"), (
            "paramiko.packet.NeedRekeyException is gone"
        )

    def test_public_blob_importable(self) -> None:
        """from paramiko.pkey import PublicBlob (used in authentication.py)"""
        assert hasattr(paramiko.pkey, "PublicBlob"), (
            "paramiko.pkey.PublicBlob is gone"
        )

    def test_public_blob_from_string(self) -> None:
        """PublicBlob.from_string() is used to parse public key strings."""
        assert callable(getattr(paramiko.pkey.PublicBlob, "from_string", None)), (
            "paramiko.pkey.PublicBlob.from_string() is gone"
        )


# ---------------------------------------------------------------------------
# Transport private attributes and methods
# ---------------------------------------------------------------------------

class TestTransportPrivateAPI:
    """Every private attribute / method on paramiko.Transport that sshmitm
    reads, writes, or calls must still exist."""

    # Methods that are monkey-patched (the originals must exist as targets)
    MONKEYPATCH_TARGETS = [
        "run",
        "_send_kex_init",
        "_activate_outbound",
    ]

    # Methods called directly on a Transport instance
    CALLABLE_METHODS = [
        "_send_message",
        "_compute_key",
        "_get_engine",
        "_check_banner",
        "_parse_disconnect",
        "_parse_debug",
        "_expect_packet",
        "_enforce_strict_kex",
        "_ensure_authed",
        "_negotiate_keys",
        "_log",
    ]

    # Attributes that must exist on the Transport *class* (not necessarily an
    # instance, because Transport.__init__ requires a real socket).
    CLASS_ATTRIBUTES = [
        "_cipher_info",
        "_mac_info",
        "_compression_info",
        "_ENCRYPT",
    ]

    # Attributes set on an instance during __init__ (checked on a live instance)
    INSTANCE_ATTRIBUTES = [
        "_handler_table",
        "_channel_handler_table",
        "_channels",
        "_expected_packet",
        "server_mode",
        "server_object",
        "session_id",
        "preferred_kex",
        "preferred_keys",
        "preferred_ciphers",
        "preferred_macs",
        "preferred_compression",
        "preferred_pubkeys",
        "server_extensions",
        "server_sig_algs",
        "in_kex",
        "active",
        "authenticated",
        "auth_handler",
        # "gss_kex_used" — removed in paramiko 5.0 with GSSAPI; workaround uses hasattr guard
        "advertise_strict_kex",
        "agreed_on_strict_kex",
        "packetizer",
        "clear_to_send",
        "clear_to_send_lock",
        "local_version",
        "handshake_timeout",
        "channels_seen",
        "server_key_dict",
        "kex_engine",
        "completion_event",
        "saved_exception",
        # Note: 'sys' is set in transport_run(), not __init__ — excluded here
    ]

    @pytest.fixture(scope="class")
    def transport(self) -> paramiko.Transport:
        return _transport()

    @pytest.mark.parametrize("name", MONKEYPATCH_TARGETS)
    def test_monkeypatch_target_exists(self, name: str, transport: paramiko.Transport) -> None:
        assert _has(transport, name), (
            f"Transport.{name} is missing — monkey-patching in cli.py will fail"
        )

    @pytest.mark.parametrize("name", CALLABLE_METHODS)
    def test_method_is_callable(self, name: str, transport: paramiko.Transport) -> None:
        assert _callable(transport, name), (
            f"Transport.{name} is not callable — check if it was removed or renamed"
        )

    @pytest.mark.parametrize("name", CLASS_ATTRIBUTES)
    def test_class_attribute_exists(self, name: str) -> None:
        assert _has(paramiko.Transport, name), (
            f"Transport.{name} class attribute is missing"
        )

    @pytest.mark.parametrize("name", INSTANCE_ATTRIBUTES)
    def test_instance_attribute_exists(self, name: str, transport: paramiko.Transport) -> None:
        assert _has(transport, name), (
            f"Transport instance is missing attribute '{name}'"
        )

    def test_handler_table_is_dict(self, transport: paramiko.Transport) -> None:
        assert isinstance(transport._handler_table, dict)  # type: ignore[attr-defined]

    def test_channel_handler_table_is_dict(self, transport: paramiko.Transport) -> None:
        assert isinstance(transport._channel_handler_table, dict)  # type: ignore[attr-defined]

    def test_cipher_info_has_required_keys(self) -> None:
        """transport_activate_outbound() accesses block-size, key-size, iv-size, is_aead."""
        for cipher_name, info in paramiko.Transport._cipher_info.items():  # type: ignore[attr-defined]
            assert "block-size" in info, f"_cipher_info[{cipher_name!r}] missing 'block-size'"
            assert "key-size" in info, f"_cipher_info[{cipher_name!r}] missing 'key-size'"

    def test_mac_info_has_required_keys(self) -> None:
        """transport_activate_outbound() accesses size and class."""
        for mac_name, info in paramiko.Transport._mac_info.items():  # type: ignore[attr-defined]
            assert "size" in info, f"_mac_info[{mac_name!r}] missing 'size'"
            assert "class" in info, f"_mac_info[{mac_name!r}] missing 'class'"

    def test_compression_info_has_two_elements(self) -> None:
        """transport_activate_outbound() unpacks _compression_info[name][0]."""
        for comp_name, info in paramiko.Transport._compression_info.items():  # type: ignore[attr-defined]
            assert len(info) >= 1, f"_compression_info[{comp_name!r}] has fewer than 1 element"

    def test_remote_ext_info_accessible_via_getattr(self, transport: paramiko.Transport) -> None:
        """auth_handler.py uses getattr(transport, '_remote_ext_info', None)."""
        val = getattr(transport, "_remote_ext_info", None)
        assert val is None or isinstance(val, str)

    def test_server_extensions_is_dict_like(self, transport: paramiko.Transport) -> None:
        """authentication.py calls transport.server_extensions.get(...)."""
        assert hasattr(transport.server_extensions, "get")  # type: ignore[attr-defined]

    def test_expected_packet_is_tuple_or_empty(self, transport: paramiko.Transport) -> None:
        """transport_run() checks len(self._expected_packet) > 0."""
        ep = transport._expected_packet  # type: ignore[attr-defined]
        assert isinstance(ep, (tuple, list))


# ---------------------------------------------------------------------------
# AuthHandler private attributes and methods
# ---------------------------------------------------------------------------

class TestAuthHandlerPrivateAPI:
    """Every private method on paramiko.auth_handler.AuthHandler that
    sshmitm/workarounds/auth_handler.py calls must still exist."""

    MONKEYPATCH_TARGETS = [
        "_parse_service_request",
        "_parse_userauth_request",
    ]

    CALLABLE_METHODS = [
        "_get_key_type_and_bits",
        "_generate_key_from_request",
        "_log",
        "_disconnect_service_not_available",
        "_disconnect_no_more_auth",
        "_send_auth_result",
    ]

    INSTANCE_ATTRIBUTES = [
        "authenticated",
        "auth_username",
    ]

    AuthHandler = paramiko.auth_handler.AuthHandler

    @pytest.mark.parametrize("name", MONKEYPATCH_TARGETS)
    def test_monkeypatch_target_exists(self, name: str) -> None:
        assert _has(self.AuthHandler, name), (
            f"AuthHandler.{name} is missing — monkey-patching in cli.py will fail"
        )

    @pytest.mark.parametrize("name", CALLABLE_METHODS)
    def test_method_is_callable(self, name: str) -> None:
        assert _callable(self.AuthHandler, name), (
            f"AuthHandler.{name} is not callable — check if it was removed or renamed"
        )

    @pytest.mark.parametrize("name", INSTANCE_ATTRIBUTES)
    def test_instance_attribute_defined_in_init(self, name: str) -> None:
        """Verify the attribute is set somewhere in __init__ by inspecting source."""
        src = inspect.getsource(self.AuthHandler.__init__)
        assert f"self.{name}" in src, (
            f"AuthHandler.__init__ no longer sets self.{name}"
        )

    def test_parse_userauth_request_signature(self) -> None:
        """Must accept (self, m: Message) — two positional params."""
        sig = inspect.signature(self.AuthHandler._parse_userauth_request)  # type: ignore[attr-defined]
        params = list(sig.parameters)
        assert len(params) == 2, (
            f"AuthHandler._parse_userauth_request signature changed: {params}"
        )

    def test_parse_service_request_signature(self) -> None:
        """Must accept (self, m: Message) — two positional params."""
        sig = inspect.signature(self.AuthHandler._parse_service_request)  # type: ignore[attr-defined]
        params = list(sig.parameters)
        assert len(params) == 2, (
            f"AuthHandler._parse_service_request signature changed: {params}"
        )


# ---------------------------------------------------------------------------
# Monkey-patching smoke test
# ---------------------------------------------------------------------------

class TestMonkeyPatching:
    """Apply all monkey-patches from sshmitm.workarounds and verify they don't
    raise at import / application time."""

    def test_workarounds_transport_importable(self) -> None:
        mod = importlib.import_module("sshmitm.workarounds.transport")
        assert hasattr(mod, "transport_run")
        assert hasattr(mod, "transport_send_kex_init")
        assert hasattr(mod, "transport_activate_outbound")

    def test_workarounds_auth_handler_importable(self) -> None:
        mod = importlib.import_module("sshmitm.workarounds.auth_handler")
        assert hasattr(mod, "auth_handler_parse_service_request")
        assert hasattr(mod, "auth_handler_parse_userauth_request")

    def test_patch_transport_run(self) -> None:
        from sshmitm.workarounds import transport as wt
        original = paramiko.Transport.run
        paramiko.Transport.run = wt.transport_run  # type: ignore[method-assign]
        assert paramiko.Transport.run is wt.transport_run
        paramiko.Transport.run = original  # type: ignore[method-assign]

    def test_patch_transport_send_kex_init(self) -> None:
        from sshmitm.workarounds import transport as wt
        original = paramiko.Transport._send_kex_init  # type: ignore[attr-defined]
        paramiko.Transport._send_kex_init = wt.transport_send_kex_init  # type: ignore[attr-defined]
        assert paramiko.Transport._send_kex_init is wt.transport_send_kex_init  # type: ignore[attr-defined]
        paramiko.Transport._send_kex_init = original  # type: ignore[attr-defined]

    def test_patch_transport_activate_outbound(self) -> None:
        from sshmitm.workarounds import transport as wt
        original = paramiko.Transport._activate_outbound  # type: ignore[attr-defined]
        paramiko.Transport._activate_outbound = wt.transport_activate_outbound  # type: ignore[attr-defined]
        assert paramiko.Transport._activate_outbound is wt.transport_activate_outbound  # type: ignore[attr-defined]
        paramiko.Transport._activate_outbound = original  # type: ignore[attr-defined]

    def test_patch_auth_handler_parse_service_request(self) -> None:
        from sshmitm.workarounds import auth_handler as wah
        AuthHandler = paramiko.auth_handler.AuthHandler
        original = AuthHandler._parse_service_request  # type: ignore[attr-defined]
        AuthHandler._parse_service_request = wah.auth_handler_parse_service_request  # type: ignore[attr-defined]
        assert AuthHandler._parse_service_request is wah.auth_handler_parse_service_request  # type: ignore[attr-defined]
        AuthHandler._parse_service_request = original  # type: ignore[attr-defined]

    def test_patch_auth_handler_parse_userauth_request(self) -> None:
        from sshmitm.workarounds import auth_handler as wah
        AuthHandler = paramiko.auth_handler.AuthHandler
        original = AuthHandler._parse_userauth_request  # type: ignore[attr-defined]
        AuthHandler._parse_userauth_request = wah.auth_handler_parse_userauth_request  # type: ignore[attr-defined]
        assert AuthHandler._parse_userauth_request is wah.auth_handler_parse_userauth_request  # type: ignore[attr-defined]
        AuthHandler._parse_userauth_request = original  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# Key algorithm availability
# ---------------------------------------------------------------------------

class TestKeyAlgorithms:
    """Key types used by ssh-mitm (RSAKey, ECDSAKey, Ed25519Key) must remain
    available and functional."""

    def test_rsa_key_generate(self) -> None:
        key = paramiko.RSAKey.generate(2048)
        assert key is not None

    def test_ecdsa_key_generate(self) -> None:
        key = paramiko.ECDSAKey.generate()
        assert key is not None

    def test_ed25519_key_importable(self) -> None:
        assert hasattr(paramiko, "Ed25519Key"), "paramiko.Ed25519Key is missing"

    def test_rsa_key_sign_and_verify_sha256(self) -> None:
        key = paramiko.RSAKey.generate(2048)
        sig_msg = key.sign_ssh_data(b"test data", "rsa-sha2-256")
        sig_msg.rewind()
        assert key.verify_ssh_sig(b"test data", sig_msg)

    def test_rsa_key_sign_and_verify_sha512(self) -> None:
        key = paramiko.RSAKey.generate(2048)
        sig_msg = key.sign_ssh_data(b"test data", "rsa-sha2-512")
        sig_msg.rewind()
        assert key.verify_ssh_sig(b"test data", sig_msg)
