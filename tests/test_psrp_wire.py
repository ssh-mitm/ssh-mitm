"""Tests for sshmitm.plugins.powershell.psrp_wire.

The fixture byte strings below were generated with the real psrpcore
library (create_message/create_fragment) and cross-checked byte-for-byte
against its own unpack_message/unpack_fragment output, to confirm this
independent reimplementation parses the wire format identically.
"""

import uuid

from sshmitm.plugins.powershell.psrp_wire import (
    PSRPMessageType,
    unpack_fragment,
    unpack_message,
)

_RPID = uuid.UUID("af955247-af54-4c1d-ab23-0576f683a08b")
_PID = uuid.UUID("7d70f55c-0b21-4af7-b3e7-b6cb430407bc")

_MESSAGE_HEX = (
    "0200000006100200475295af54af1d4cab230576f683a08b"
    "5cf5707d210bf74ab3e7b6cb430407bc"
    "3c4f626a3e68656c6c6f3c2f4f626a3e"
)
_FRAGMENT_HEX = (
    "0000000000003039" "0000000000000000" "03" "00000038" + _MESSAGE_HEX
)
_MESSAGE_WITH_BOM_NO_PID_HEX = (
    "0100000002000100475295af54af1d4cab230576f683a08b"
    "00000000000000000000000000000000"
    "efbbbf424f4d44415441"
)


def test_unpack_message() -> None:
    msg = unpack_message(bytearray.fromhex(_MESSAGE_HEX))
    assert msg.destination == 2
    assert msg.message_type == PSRPMessageType.CreatePipeline
    assert msg.rpid == _RPID
    assert msg.pid == _PID
    assert bytes(msg.data) == b"<Obj>hello</Obj>"


def test_unpack_message_strips_bom_and_empty_pid_becomes_none() -> None:
    msg = unpack_message(bytearray.fromhex(_MESSAGE_WITH_BOM_NO_PID_HEX))
    assert msg.destination == 1
    assert msg.message_type == PSRPMessageType.SessionCapability
    assert msg.rpid == _RPID
    assert msg.pid is None
    assert bytes(msg.data) == b"BOMDATA"


def test_unpack_fragment() -> None:
    frag = unpack_fragment(bytearray.fromhex(_FRAGMENT_HEX))
    assert frag.object_id == 12345
    assert frag.fragment_id == 0
    assert frag.start is True
    assert frag.end is True
    assert bytes(frag.data) == bytes.fromhex(_MESSAGE_HEX)


def test_unpack_fragment_start_and_end_flags() -> None:
    # start-only fragment (flag byte 0x01), 1 byte of payload
    frag = unpack_fragment(bytearray.fromhex("00000000000007e7" "0000000000000000" "01" "00000001" "aa"))
    assert frag.start is True
    assert frag.end is False
    assert bytes(frag.data) == b"\xaa"

    # end-only fragment (flag byte 0x02)
    frag = unpack_fragment(bytearray.fromhex("00000000000007e7" "0000000000000001" "02" "00000001" "bb"))
    assert frag.start is False
    assert frag.end is True


def test_psrp_message_type_values_match_spec() -> None:
    # Spot-check a few MS-PSRP 2.2.2 message type identifiers.
    assert PSRPMessageType.SessionCapability == 0x00010002
    assert PSRPMessageType.CreatePipeline == 0x00021006
    assert PSRPMessageType.ErrorRecord == 0x00041005
    assert PSRPMessageType.PipelineHostResponse == 0x00041101
