"""Unit tests for NETCONF framing helpers and RPC parsing.

Covers _parse_hello, _reassemble_chunks, and the NetconfBaseForwarder
methods _strip_framing, _apply_framing, _parse_rpc, _parse_rpc_reply.
No network access required.
"""

from __future__ import annotations

import types
import xml.etree.ElementTree as ET

import pytest

from sshmitm.forwarders.netconf import (
    NetconfBaseForwarder,
    _parse_hello,
    _reassemble_chunks,
)

# ---------------------------------------------------------------------------
# _parse_hello
# ---------------------------------------------------------------------------

_NS = "urn:ietf:params:xml:ns:netconf:base:1.0"
_CAP_1_0 = "urn:ietf:params:netconf:base:1.0"
_CAP_1_1 = "urn:ietf:params:netconf:base:1.1"


def _make_hello(caps: list[str], session_id: int | None = 1) -> bytes:
    cap_xml = "".join(f"<capability>{c}</capability>" for c in caps)
    sid_xml = f"<session-id>{session_id}</session-id>" if session_id else ""
    return (
        f'<hello xmlns="{_NS}">'
        f"<capabilities>{cap_xml}</capabilities>"
        f"{sid_xml}"
        f"</hello>]]>]]>"
    ).encode()


def test_parse_hello_base10_only() -> None:
    raw = _make_hello([_CAP_1_0])
    caps = _parse_hello(raw)
    assert caps == frozenset([_CAP_1_0])


def test_parse_hello_base11() -> None:
    raw = _make_hello([_CAP_1_0, _CAP_1_1])
    caps = _parse_hello(raw)
    assert _CAP_1_1 in caps
    assert _CAP_1_0 in caps


def test_parse_hello_strips_eom() -> None:
    raw = _make_hello([_CAP_1_0])
    assert _parse_hello(raw) == frozenset([_CAP_1_0])


def test_parse_hello_malformed() -> None:
    assert _parse_hello(b"not xml]]>]]>") == frozenset()


def test_parse_hello_empty() -> None:
    assert _parse_hello(b"") == frozenset()
    assert _parse_hello(b"]]>]]>") == frozenset()


# ---------------------------------------------------------------------------
# _reassemble_chunks
# ---------------------------------------------------------------------------

def _chunk(data: bytes) -> bytes:
    return f"\n#{len(data)}\n".encode() + data + b"\n##\n"


def _multichunk(*parts: bytes) -> bytes:
    body = b"".join(f"\n#{len(p)}\n".encode() + p for p in parts)
    return body + b"\n##\n"


def test_reassemble_single_chunk() -> None:
    xml = b"<rpc/>"
    assert _reassemble_chunks(_chunk(xml)) == xml


def test_reassemble_multiple_chunks() -> None:
    parts = [b"<rpc", b' message-id="1">', b"<get/></rpc>"]
    assert _reassemble_chunks(_multichunk(*parts)) == b"".join(parts)


def test_reassemble_empty_chunk() -> None:
    assert _reassemble_chunks(_chunk(b"")) == b""


def test_reassemble_binary_safe() -> None:
    data = bytes(range(256))
    assert _reassemble_chunks(_chunk(data)) == data


def test_reassemble_malformed_no_end_marker() -> None:
    """Missing ##-marker returns partial data without crashing."""
    raw = b"\n#4\nabcd"  # no \n##\n
    assert _reassemble_chunks(raw) == b"abcd"


def test_reassemble_malformed_bad_size() -> None:
    """Non-integer chunk size: function breaks out and returns empty."""
    raw = b"\n#abc\ndata\n##\n"
    assert _reassemble_chunks(raw) == b""


# ---------------------------------------------------------------------------
# NetconfBaseForwarder framing helpers and RPC parsing
# ---------------------------------------------------------------------------

class _TestForwarder(NetconfBaseForwarder):
    """Minimal forwarder for unit-testing the pure parsing/framing methods.

    Overrides __init__ to skip the real SSH setup, which requires a live
    transport.  Only ``session.netconf.use_chunked`` is needed by the methods
    under test.
    """

    def __init__(self, use_chunked: bool) -> None:  # type: ignore[override]
        # Deliberately skip super().__init__() — no real SSH session needed.
        self.session = types.SimpleNamespace(  # type: ignore[assignment]
            netconf=types.SimpleNamespace(use_chunked=use_chunked)
        )

    @property
    def _forwarded_command(self) -> bytes:  # type: ignore[override]
        return b""

    def forward(self) -> None:
        pass


def _make_forwarder(use_chunked: bool) -> _TestForwarder:
    return _TestForwarder(use_chunked)


@pytest.mark.parametrize("use_chunked", [False, True])
def test_strip_apply_roundtrip(use_chunked: bool) -> None:
    fwd = _make_forwarder(use_chunked)
    xml = b"<rpc/>"
    framed = fwd._apply_framing(xml)
    assert fwd._strip_framing(framed) == xml


@pytest.mark.parametrize("use_chunked", [False, True])
def test_strip_apply_large(use_chunked: bool) -> None:
    fwd = _make_forwarder(use_chunked)
    xml = b"<data>" + b"x" * 10_000 + b"</data>"
    assert fwd._strip_framing(fwd._apply_framing(xml)) == xml


@pytest.mark.parametrize("use_chunked", [False, True])
def test_parse_rpc_get(use_chunked: bool) -> None:
    fwd = _make_forwarder(use_chunked)
    xml = (
        f'<rpc xmlns="{_NS}" message-id="42"><get/></rpc>'
    ).encode()
    result = fwd._parse_rpc(xml)
    assert result is not None
    mid, op, elem = result
    assert mid == "42"
    assert op == "get"
    assert elem.tag == f"{{{_NS}}}rpc"


@pytest.mark.parametrize("use_chunked", [False, True])
def test_parse_rpc_edit_config(use_chunked: bool) -> None:
    fwd = _make_forwarder(use_chunked)
    xml = (
        f'<rpc xmlns="{_NS}" message-id="7">'
        f"<edit-config><target><running/></target></edit-config>"
        f"</rpc>"
    ).encode()
    result = fwd._parse_rpc(xml)
    assert result is not None
    _, op, _ = result
    assert op == "edit-config"


def test_parse_rpc_not_rpc() -> None:
    fwd = _make_forwarder(False)
    assert fwd._parse_rpc(b"<hello/>") is None


def test_parse_rpc_malformed() -> None:
    fwd = _make_forwarder(False)
    assert fwd._parse_rpc(b"not xml") is None


def test_parse_rpc_empty() -> None:
    fwd = _make_forwarder(False)
    assert fwd._parse_rpc(b"") is None


@pytest.mark.parametrize("use_chunked", [False, True])
def test_parse_rpc_reply_ok(use_chunked: bool) -> None:
    fwd = _make_forwarder(use_chunked)
    xml = (
        f'<rpc-reply xmlns="{_NS}" message-id="42"><data/></rpc-reply>'
    ).encode()
    result = fwd._parse_rpc_reply(xml)
    assert result is not None
    mid, elem = result
    assert mid == "42"
    assert "rpc-reply" in elem.tag


def test_parse_rpc_reply_not_reply() -> None:
    fwd = _make_forwarder(False)
    assert fwd._parse_rpc_reply(b"<rpc/>") is None


@pytest.mark.parametrize("use_chunked", [False, True])
def test_handle_client_data_passthrough(use_chunked: bool) -> None:
    """Default handle_rpc_request returns None → original bytes unchanged."""
    fwd = _make_forwarder(use_chunked)
    xml = f'<rpc xmlns="{_NS}" message-id="1"><get/></rpc>'.encode()
    raw = fwd._apply_framing(xml)
    assert fwd.handle_client_data(raw) == raw


@pytest.mark.parametrize("use_chunked", [False, True])
def test_handle_server_data_passthrough(use_chunked: bool) -> None:
    """Default handle_rpc_reply returns None → original bytes unchanged."""
    fwd = _make_forwarder(use_chunked)
    xml = f'<rpc-reply xmlns="{_NS}" message-id="1"><data/></rpc-reply>'.encode()
    raw = fwd._apply_framing(xml)
    assert fwd.handle_server_data(raw) == raw


@pytest.mark.parametrize("use_chunked", [False, True])
def test_handle_client_data_rewrite(use_chunked: bool) -> None:
    """A hook that returns a modified element rewrites the forwarded bytes."""

    class _RewritingForwarder(_TestForwarder):
        def handle_rpc_request(  # type: ignore[override]
            self,
            message_id: str,
            operation: str,
            element: ET.Element,
        ) -> ET.Element | None:
            element.set("rewritten", "yes")
            return element

    fwd = _RewritingForwarder(use_chunked)
    xml = f'<rpc xmlns="{_NS}" message-id="5"><get/></rpc>'.encode()
    raw = fwd._apply_framing(xml)
    result = fwd.handle_client_data(raw)
    assert result != raw
    result_xml = fwd._strip_framing(result)
    root = ET.fromstring(result_xml)
    assert root.get("rewritten") == "yes"


# ---------------------------------------------------------------------------
# Bug-fix regression tests
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("use_chunked", [False, True])
def test_rewrite_preserves_default_namespace(use_chunked: bool) -> None:
    """Bug 1 fix: ET.tostring must not produce ns0: prefixes after rewrite.

    ET.register_namespace("", _NETCONF_NS) must be called at module level so
    that the default namespace is preserved when a plugin returns a modified
    element.
    """

    class _TouchingForwarder(_TestForwarder):
        def handle_rpc_request(  # type: ignore[override]
            self,
            message_id: str,
            operation: str,
            element: ET.Element,
        ) -> ET.Element | None:
            element.set("touched", "1")
            return element

    fwd = _TouchingForwarder(use_chunked)
    xml = f'<rpc xmlns="{_NS}" message-id="1"><get/></rpc>'.encode()
    result = fwd.handle_client_data(fwd._apply_framing(xml))
    result_xml = fwd._strip_framing(result)
    # Must NOT contain "ns0" or similar auto-generated prefixes.
    assert b"ns0" not in result_xml
    assert b"ns1" not in result_xml
    # The default namespace must still be the NETCONF base namespace.
    root = ET.fromstring(result_xml)
    assert root.tag == f"{{{_NS}}}rpc" or root.tag == "rpc"
