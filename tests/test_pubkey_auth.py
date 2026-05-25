"""Tests for the publickey authentication split in ServerInterface.

Covers:
- check_auth_publickey dispatcher (sig_attached routing, incompatible-Paramiko guard)
- check_auth_publickey_pk_lookup (all gate checks, key logging, remote probe, trivial auth)
- check_auth_publickey_authenticate (accept_first, cache hit, trivial auth, disallow)
- RFC 4252: client skips pk_lookup and sends signature directly
- Real end-to-end connection via paramiko transport
"""

from __future__ import annotations

import os
import socket
import tempfile
import threading
from argparse import Namespace
from typing import Generator
from unittest.mock import MagicMock, patch

import paramiko
import paramiko.common
import pytest

from sshmitm.interfaces.server import ServerInterface


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_server(
    session_log_dir: str | None = None,
    *,
    disable_pubkey_auth: bool = False,
    accept_first_publickey: bool = False,
    enable_trivial_auth: bool = False,
    disallow_publickey_auth: bool = False,
    address_reachable: bool = True,
    auth_result: int = paramiko.common.AUTH_SUCCESSFUL,
    enable_keyboard_interactive_auth: bool = False,
    disable_keyboard_interactive_prompts: bool = False,
) -> tuple[ServerInterface, MagicMock]:
    """Return a (server, session) pair with mocked dependencies."""
    session = MagicMock()
    session.session_log_dir = session_log_dir
    session.remote.address_reachable = address_reachable
    session.auth.accepted_key = None
    session.auth.username = "user"
    session.authenticator.authenticate.return_value = auth_result

    args = Namespace(
        disable_pubkey_auth=disable_pubkey_auth,
        accept_first_publickey=accept_first_publickey,
        enable_trivial_auth=enable_trivial_auth,
        disallow_publickey_auth=disallow_publickey_auth,
        enable_keyboard_interactive_auth=enable_keyboard_interactive_auth,
        disable_keyboard_interactive_prompts=disable_keyboard_interactive_prompts,
    )

    server: ServerInterface = ServerInterface.__new__(ServerInterface)
    server.session = session  # type: ignore[assignment]
    server.forwarders = []
    server.possible_auth_methods = None
    server.args = args  # type: ignore[assignment]
    return server, session


def _pk_lookup(server: ServerInterface, username: str, key: paramiko.PKey) -> int:
    """Call check_auth_publickey with sig_attached=False in *this* frame's locals
    so that inspect sees it exactly as Paramiko's _parse_userauth_request does."""
    sig_attached = False  # noqa: F841 — must live in locals for inspect
    return server.check_auth_publickey(username, key)


def _auth_sig(server: ServerInterface, username: str, key: paramiko.PKey) -> int:
    """Call check_auth_publickey with sig_attached=True."""
    sig_attached = True  # noqa: F841
    return server.check_auth_publickey(username, key)


@pytest.fixture(scope="module")
def rsa_key() -> paramiko.RSAKey:
    return paramiko.RSAKey.generate(1024)


# ---------------------------------------------------------------------------
# Dispatcher
# ---------------------------------------------------------------------------

class TestDispatcher:
    def test_routes_to_pk_lookup_when_sig_not_attached(self, rsa_key: paramiko.RSAKey) -> None:
        server, _ = _make_server()
        with patch.object(server, "check_auth_publickey_pk_lookup", return_value=paramiko.common.AUTH_SUCCESSFUL) as mock_lu, \
             patch.object(server, "check_auth_publickey_authenticate") as mock_au:
            result = _pk_lookup(server, "user", rsa_key)
        mock_lu.assert_called_once_with("user", rsa_key)
        mock_au.assert_not_called()
        assert result == paramiko.common.AUTH_SUCCESSFUL

    def test_routes_to_authenticate_when_sig_attached(self, rsa_key: paramiko.RSAKey) -> None:
        server, _ = _make_server()
        with patch.object(server, "check_auth_publickey_authenticate", return_value=paramiko.common.AUTH_SUCCESSFUL) as mock_au, \
             patch.object(server, "check_auth_publickey_pk_lookup") as mock_lu:
            result = _auth_sig(server, "user", rsa_key)
        mock_au.assert_called_once_with("user", rsa_key)
        mock_lu.assert_not_called()
        assert result == paramiko.common.AUTH_SUCCESSFUL

    def test_raises_when_sig_attached_missing(self, rsa_key: paramiko.RSAKey) -> None:
        """When sig_attached is not in the caller's frame, raise AuthenticationException."""
        server, _ = _make_server()
        with pytest.raises(paramiko.ssh_exception.AuthenticationException):
            # Direct call — sig_attached NOT in locals
            server.check_auth_publickey("user", rsa_key)

    def test_returns_auth_failed_on_submethod_exception(self, rsa_key: paramiko.RSAKey) -> None:
        server, _ = _make_server()
        with patch.object(server, "check_auth_publickey_pk_lookup", side_effect=RuntimeError("boom")):
            result = _pk_lookup(server, "user", rsa_key)
        assert result == paramiko.common.AUTH_FAILED


# ---------------------------------------------------------------------------
# pk_lookup
# ---------------------------------------------------------------------------

class TestPkLookup:
    def test_disabled_pubkey_auth_returns_failed(self, rsa_key: paramiko.RSAKey) -> None:
        server, session = _make_server(disable_pubkey_auth=True)
        assert server.check_auth_publickey_pk_lookup("user", rsa_key) == paramiko.common.AUTH_FAILED
        session.authenticator.authenticate.assert_not_called()

    def test_accept_first_returns_successful_without_probe(self, rsa_key: paramiko.RSAKey) -> None:
        server, session = _make_server(accept_first_publickey=True)
        assert server.check_auth_publickey_pk_lookup("user", rsa_key) == paramiko.common.AUTH_SUCCESSFUL
        session.authenticator.authenticate.assert_not_called()

    def test_remote_unreachable_returns_failed(self, rsa_key: paramiko.RSAKey) -> None:
        server, session = _make_server(address_reachable=False)
        assert server.check_auth_publickey_pk_lookup("user", rsa_key) == paramiko.common.AUTH_FAILED
        session.authenticator.authenticate.assert_not_called()

    def test_valid_key_returns_successful_and_stores_accepted_key(self, rsa_key: paramiko.RSAKey) -> None:
        server, session = _make_server(auth_result=paramiko.common.AUTH_SUCCESSFUL)
        result = server.check_auth_publickey_pk_lookup("user", rsa_key)
        assert result == paramiko.common.AUTH_SUCCESSFUL
        assert session.auth.accepted_key is rsa_key

    def test_invalid_key_returns_failed_and_does_not_store_accepted_key(self, rsa_key: paramiko.RSAKey) -> None:
        server, session = _make_server(auth_result=paramiko.common.AUTH_FAILED)
        result = server.check_auth_publickey_pk_lookup("user", rsa_key)
        assert result == paramiko.common.AUTH_FAILED
        assert session.auth.accepted_key is None

    def test_trivial_auth_returns_failed_even_for_valid_key(self, rsa_key: paramiko.RSAKey) -> None:
        """Valid key must still return AUTH_FAILED so the client falls back to
        keyboard-interactive where the trivial-auth catch fires."""
        server, session = _make_server(
            enable_trivial_auth=True,
            auth_result=paramiko.common.AUTH_SUCCESSFUL,
        )
        result = server.check_auth_publickey_pk_lookup("user", rsa_key)
        assert result == paramiko.common.AUTH_FAILED
        # accepted_key must be set so check_auth_interactive can detect trivial auth
        assert session.auth.accepted_key is rsa_key

    def test_disallow_pubkey_returns_failed_even_for_valid_key(self, rsa_key: paramiko.RSAKey) -> None:
        server, session = _make_server(
            disallow_publickey_auth=True,
            auth_result=paramiko.common.AUTH_SUCCESSFUL,
        )
        assert server.check_auth_publickey_pk_lookup("user", rsa_key) == paramiko.common.AUTH_FAILED
        assert session.auth.accepted_key is rsa_key

    def test_key_logged_with_pk_lookup_comment(self, rsa_key: paramiko.RSAKey) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            server, _ = _make_server(session_log_dir=tmpdir)
            server.check_auth_publickey_pk_lookup("user", rsa_key)
            log_path = os.path.join(tmpdir, "publickeys")
            assert os.path.exists(log_path)
            content = open(log_path).read()
            assert "saved-from-pk-lookup" in content
            assert rsa_key.get_base64() in content

    def test_key_not_logged_when_no_session_log_dir(self, rsa_key: paramiko.RSAKey) -> None:
        server, _ = _make_server(session_log_dir=None)
        # must not raise
        server.check_auth_publickey_pk_lookup("user", rsa_key)

    def test_probe_called_once(self, rsa_key: paramiko.RSAKey) -> None:
        server, session = _make_server()
        server.check_auth_publickey_pk_lookup("user", rsa_key)
        session.authenticator.authenticate.assert_called_once_with("user", key=rsa_key)


# ---------------------------------------------------------------------------
# authenticate (with signature)
# ---------------------------------------------------------------------------

class TestAuthenticate:
    def test_disabled_pubkey_auth_returns_failed(self, rsa_key: paramiko.RSAKey) -> None:
        server, session = _make_server(disable_pubkey_auth=True)
        assert server.check_auth_publickey_authenticate("user", rsa_key) == paramiko.common.AUTH_FAILED
        session.authenticator.authenticate.assert_not_called()

    def test_accept_first_calls_authenticate_with_no_key(self, rsa_key: paramiko.RSAKey) -> None:
        server, session = _make_server(accept_first_publickey=True)
        result = server.check_auth_publickey_authenticate("user", rsa_key)
        assert result == paramiko.common.AUTH_SUCCESSFUL
        session.authenticator.authenticate.assert_called_once_with("user", key=None)
        assert session.auth.accepted_key is rsa_key

    def test_accept_first_with_disallow_still_accepts(self, rsa_key: paramiko.RSAKey) -> None:
        server, session = _make_server(accept_first_publickey=True, disallow_publickey_auth=True)
        assert server.check_auth_publickey_authenticate("user", rsa_key) == paramiko.common.AUTH_SUCCESSFUL

    def test_remote_unreachable_returns_failed(self, rsa_key: paramiko.RSAKey) -> None:
        server, session = _make_server(address_reachable=False)
        assert server.check_auth_publickey_authenticate("user", rsa_key) == paramiko.common.AUTH_FAILED
        session.authenticator.authenticate.assert_not_called()

    def test_valid_key_returns_successful(self, rsa_key: paramiko.RSAKey) -> None:
        server, session = _make_server(auth_result=paramiko.common.AUTH_SUCCESSFUL)
        assert server.check_auth_publickey_authenticate("user", rsa_key) == paramiko.common.AUTH_SUCCESSFUL
        assert session.auth.accepted_key is rsa_key

    def test_invalid_key_returns_failed(self, rsa_key: paramiko.RSAKey) -> None:
        server, session = _make_server(auth_result=paramiko.common.AUTH_FAILED)
        assert server.check_auth_publickey_authenticate("user", rsa_key) == paramiko.common.AUTH_FAILED

    def test_trivial_auth_returns_failed_when_accepted_key_is_set(self, rsa_key: paramiko.RSAKey) -> None:
        """Simulate the case where pk_lookup already validated the key."""
        server, session = _make_server(
            enable_trivial_auth=True,
            auth_result=paramiko.common.AUTH_SUCCESSFUL,
        )
        # pk_lookup already ran and set accepted_key
        session.auth.accepted_key = rsa_key
        result = server.check_auth_publickey_authenticate("user", rsa_key)
        assert result == paramiko.common.AUTH_FAILED

    def test_disallow_pubkey_returns_failed(self, rsa_key: paramiko.RSAKey) -> None:
        server, session = _make_server(
            disallow_publickey_auth=True,
            auth_result=paramiko.common.AUTH_SUCCESSFUL,
        )
        assert server.check_auth_publickey_authenticate("user", rsa_key) == paramiko.common.AUTH_FAILED

    def test_key_logged_with_auth_signature_comment(self, rsa_key: paramiko.RSAKey) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            server, _ = _make_server(session_log_dir=tmpdir)
            server.check_auth_publickey_authenticate("user", rsa_key)
            content = open(os.path.join(tmpdir, "publickeys")).read()
            assert "saved-from-auth-signature" in content
            assert rsa_key.get_base64() in content


# ---------------------------------------------------------------------------
# RFC 4252: client skips pk_lookup (sends signature without prior probe)
# ---------------------------------------------------------------------------

class TestRfc4252DirectSignature:
    def test_authenticate_works_without_prior_pk_lookup(self, rsa_key: paramiko.RSAKey) -> None:
        """No pk_lookup was called: accepted_key is None, cache is cold.
        authenticate must do a fresh probe and succeed."""
        server, session = _make_server(auth_result=paramiko.common.AUTH_SUCCESSFUL)
        assert session.auth.accepted_key is None
        result = server.check_auth_publickey_authenticate("user", rsa_key)
        assert result == paramiko.common.AUTH_SUCCESSFUL
        session.authenticator.authenticate.assert_called_once_with("user", key=rsa_key)

    def test_key_is_logged_even_when_pk_lookup_was_skipped(self, rsa_key: paramiko.RSAKey) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            server, _ = _make_server(session_log_dir=tmpdir)
            server.check_auth_publickey_authenticate("user", rsa_key)
            content = open(os.path.join(tmpdir, "publickeys")).read()
            assert rsa_key.get_base64() in content


# ---------------------------------------------------------------------------
# Full end-to-end: real paramiko transport
# ---------------------------------------------------------------------------

class _AcceptAllServerInterface(paramiko.ServerInterface):
    """Minimal paramiko ServerInterface for the mock target server."""

    def __init__(self, accepted_key: paramiko.PKey) -> None:
        self._accepted_key = accepted_key

    def check_auth_publickey(self, username: str, key: paramiko.PKey) -> int:
        if key.get_base64() == self._accepted_key.get_base64():
            return paramiko.common.AUTH_SUCCESSFUL
        return paramiko.common.AUTH_FAILED

    def get_allowed_auths(self, username: str) -> str:
        return "publickey"

    def check_channel_request(self, kind: str, chanid: int) -> int:
        return paramiko.common.OPEN_SUCCEEDED


def _public_only(key: paramiko.RSAKey) -> paramiko.RSAKey:
    """Return a public-only copy of *key* (can_sign() == False).

    This mirrors what paramiko passes to check_auth_publickey: the key blob in the
    SSH packet contains only the public material, so the resulting PKey cannot sign.
    """
    return paramiko.RSAKey(data=key.asbytes())


def _start_target_server(host_key: paramiko.RSAKey, client_key: paramiko.RSAKey) -> tuple[int, threading.Event]:
    """Start a minimal target SSH server in a background thread that loops
    and accepts multiple connections.  Returns (port, ready_event)."""
    ready = threading.Event()
    stop = threading.Event()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.listen(5)
    sock.settimeout(1.0)

    def _handle(conn: socket.socket) -> None:
        transport = paramiko.Transport(conn)
        transport.add_server_key(host_key)
        transport.start_server(server=_AcceptAllServerInterface(client_key))
        transport.join(timeout=5)

    def _serve() -> None:
        ready.set()
        while not stop.is_set():
            try:
                conn, _ = sock.accept()
                threading.Thread(target=_handle, args=(conn,), daemon=True).start()
            except socket.timeout:
                continue
        sock.close()

    threading.Thread(target=_serve, daemon=True).start()
    ready.wait(timeout=2)
    return port, ready


class _MITMServerInterface(ServerInterface):
    """ServerInterface wired to a real (mock) remote via AuthenticatorPassThrough."""

    def __init__(
        self,
        session: MagicMock,
        args: Namespace,
    ) -> None:
        # Bypass BaseModule.__init__ which would parse sys.argv
        self.session = session
        self.forwarders = []
        self.possible_auth_methods = None
        self.args = args


@pytest.fixture(scope="module")
def target_keys() -> tuple[paramiko.RSAKey, paramiko.RSAKey]:
    host_key = paramiko.RSAKey.generate(1024)
    client_key = paramiko.RSAKey.generate(1024)
    return host_key, client_key


@pytest.fixture(scope="module")
def target_server(target_keys: tuple[paramiko.RSAKey, paramiko.RSAKey]) -> int:
    host_key, client_key = target_keys
    port, _ = _start_target_server(host_key, client_key)
    return port


class TestEndToEnd:
    """Tests that fire a real paramiko client through a stripped-down MITM
    ServerInterface and verify the complete pk_lookup → authenticate flow."""

    def _make_mitm_server(
        self,
        client_key: paramiko.RSAKey,
        target_port: int,
        *,
        enable_trivial_auth: bool = False,
    ) -> tuple[_MITMServerInterface, MagicMock]:
        from sshmitm.authentication import AuthenticatorPassThrough

        session = MagicMock()
        session.session_log_dir = None
        session.remote.address_reachable = True
        session.auth.accepted_key = None
        session.auth.agent = None
        session.auth.password = None
        session.auth.username = "user"
        session.auth.remote_key = None

        args = Namespace(
            disable_pubkey_auth=False,
            accept_first_publickey=False,
            enable_trivial_auth=enable_trivial_auth,
            disallow_publickey_auth=False,
            remote_host="127.0.0.1",
            remote_port=target_port,
            remote_fingerprints=None,
            disable_remote_fingerprint_warning=True,
            auth_username=None,
            auth_password=None,
            auth_key=None,
            auth_hide_credentials=False,
            enable_auth_fallback=False,
            fallback_host=None,
            fallback_port=None,
            fallback_username=None,
            fallback_password=None,
            close_pubkey_enumerator_with_session=False,
        )

        # Build authenticator without __init__ to avoid BaseModule arg parsing
        authenticator = AuthenticatorPassThrough.__new__(AuthenticatorPassThrough)
        authenticator.session = session
        authenticator.args = args
        authenticator.pubkey_enumerator = None
        authenticator.pubkey_auth_success = False
        authenticator.valid_key = None

        session.authenticator = authenticator
        session.proxyserver.transparent = False

        server = _MITMServerInterface(session, args)
        return server, session

    def test_pk_lookup_probes_remote_and_accepts_valid_key(
        self, target_keys: tuple[paramiko.RSAKey, paramiko.RSAKey], target_server: int
    ) -> None:
        _, client_key = target_keys
        pub_key = _public_only(client_key)
        server, session = self._make_mitm_server(client_key, target_server)

        result = server.check_auth_publickey_pk_lookup("user", pub_key)
        assert result == paramiko.common.AUTH_SUCCESSFUL
        assert session.auth.accepted_key is pub_key

    def test_pk_lookup_rejects_unknown_key(
        self, target_keys: tuple[paramiko.RSAKey, paramiko.RSAKey], target_server: int
    ) -> None:
        _, client_key = target_keys
        wrong_pub = _public_only(paramiko.RSAKey.generate(1024))
        server, session = self._make_mitm_server(client_key, target_server)

        result = server.check_auth_publickey_pk_lookup("user", wrong_pub)
        assert result == paramiko.common.AUTH_FAILED
        assert session.auth.accepted_key is None

    def test_authenticate_cache_hit_after_pk_lookup(
        self, target_keys: tuple[paramiko.RSAKey, paramiko.RSAKey], target_server: int
    ) -> None:
        """After pk_lookup validated the key, authenticate must succeed via
        the pubkey_auth_success cache — no second network round-trip.

        In the real paramiko flow both pk_lookup and authenticate receive the
        same public-only key object (reconstructed from the SSH packet blob),
        so the cache equality check (valid_key == key) works correctly.
        """
        _, client_key = target_keys
        pub_key = _public_only(client_key)
        server, session = self._make_mitm_server(client_key, target_server)

        # Phase 1: pk_lookup — probes the remote server
        lookup_result = server.check_auth_publickey_pk_lookup("user", pub_key)
        assert lookup_result == paramiko.common.AUTH_SUCCESSFUL
        assert server.session.authenticator.pubkey_auth_success is True
        assert server.session.authenticator.valid_key == pub_key  # equality by key content

        # Phase 2: authenticate — must be a cache hit (no second network round-trip)
        with patch.object(
            server.session.authenticator.pubkey_enumerator,
            "check_publickey",
            wraps=server.session.authenticator.pubkey_enumerator.check_publickey,
        ) as spy:
            auth_result = server.check_auth_publickey_authenticate("user", pub_key)
            spy.assert_not_called()  # cache hit — no network call

        assert auth_result == paramiko.common.AUTH_SUCCESSFUL

    def test_trivial_auth_pk_lookup_always_returns_failed(
        self, target_keys: tuple[paramiko.RSAKey, paramiko.RSAKey], target_server: int
    ) -> None:
        _, client_key = target_keys
        pub_key = _public_only(client_key)
        server, session = self._make_mitm_server(client_key, target_server, enable_trivial_auth=True)

        result = server.check_auth_publickey_pk_lookup("user", pub_key)
        # Must be AUTH_FAILED so client falls back to kb-interactive
        assert result == paramiko.common.AUTH_FAILED
        # But accepted_key must be set for check_auth_interactive to trigger trivial auth
        assert session.auth.accepted_key is pub_key


# ---------------------------------------------------------------------------
# Trivial auth: phishing flow — pk_lookup forces kb-interactive, then
# check_auth_interactive_response authenticates without requiring the client
# to prove ownership of the key.
# ---------------------------------------------------------------------------

class TestTrivialAuth:
    """Unit tests for the trivial-auth flow.

    Flow summary:
      1. pk_lookup: remote probe succeeds → accepted_key set → returns AUTH_FAILED
         (so client is forced to fall back to keyboard-interactive)
      2. check_auth_interactive: detects trivial auth → returns empty InteractiveQuery
         (0 prompts — client answers the empty challenge immediately)
      3. check_auth_interactive_response: detects trivial auth → calls
         authenticate(username, key=None) → AUTH_SUCCESSFUL
    """

    def test_interactive_returns_empty_query_when_accepted_key_is_set(
        self, rsa_key: paramiko.RSAKey
    ) -> None:
        server, session = _make_server(enable_trivial_auth=True)
        session.auth.accepted_key = rsa_key
        result = server.check_auth_interactive("user", "")
        assert isinstance(result, paramiko.server.InteractiveQuery)
        assert len(result.prompts) == 0

    def test_interactive_returns_failed_when_no_accepted_key(
        self, rsa_key: paramiko.RSAKey
    ) -> None:
        """Trivial auth can only fire after a valid key was found in pk_lookup."""
        server, session = _make_server(enable_trivial_auth=True)
        assert session.auth.accepted_key is None
        result = server.check_auth_interactive("user", "")
        assert result == paramiko.common.AUTH_FAILED

    def test_interactive_returns_failed_when_trivial_auth_disabled(
        self, rsa_key: paramiko.RSAKey
    ) -> None:
        server, session = _make_server(enable_trivial_auth=False)
        session.auth.accepted_key = rsa_key
        result = server.check_auth_interactive("user", "")
        assert result == paramiko.common.AUTH_FAILED

    def test_interactive_response_calls_authenticate_with_no_key(
        self, rsa_key: paramiko.RSAKey
    ) -> None:
        server, session = _make_server(enable_trivial_auth=True)
        session.auth.accepted_key = rsa_key
        session.auth.username = "user"
        result = server.check_auth_interactive_response([])
        session.authenticator.authenticate.assert_called_once_with("user", key=None)
        assert result == paramiko.common.AUTH_SUCCESSFUL

    def test_interactive_response_returns_failed_when_trivial_auth_disabled_and_no_responses(
        self, rsa_key: paramiko.RSAKey
    ) -> None:
        server, session = _make_server(enable_trivial_auth=False)
        session.auth.accepted_key = rsa_key
        session.auth.username = "user"
        result = server.check_auth_interactive_response([])
        assert result == paramiko.common.AUTH_FAILED

    def test_full_trivial_auth_flow(self, rsa_key: paramiko.RSAKey) -> None:
        """End-to-end unit test: pk_lookup (AUTH_FAILED) → interactive (empty
        query) → response (AUTH_SUCCESSFUL via key=None authenticate)."""
        server, session = _make_server(
            enable_trivial_auth=True,
            auth_result=paramiko.common.AUTH_SUCCESSFUL,
        )

        # Phase 1: pk_lookup — valid key but AUTH_FAILED due to trivial auth
        pk_result = server.check_auth_publickey_pk_lookup("user", rsa_key)
        assert pk_result == paramiko.common.AUTH_FAILED
        assert session.auth.accepted_key is rsa_key

        # Phase 2: keyboard-interactive — empty challenge (0 prompts)
        interactive_result = server.check_auth_interactive("user", "")
        assert isinstance(interactive_result, paramiko.server.InteractiveQuery)
        assert len(interactive_result.prompts) == 0
        assert session.auth.username == "user"

        # Phase 3: response — AUTH_SUCCESSFUL, no key ownership proof needed
        session.authenticator.authenticate.reset_mock()
        response_result = server.check_auth_interactive_response([])
        assert response_result == paramiko.common.AUTH_SUCCESSFUL
        session.authenticator.authenticate.assert_called_once_with("user", key=None)
