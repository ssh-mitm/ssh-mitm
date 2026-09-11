"""Minimal PSRP wire-format parsing.

ssh-mitm only ever reads PSRP traffic to log it - it never drives a session
(the actual relay is a transparent byte-for-byte copy, see
sshmitm.forwarders.powershell) - so this implements just the two binary
structures needed to reassemble and decode a PSRP message from the fragment
stream, directly against the public MS-PSRP spec. It deliberately does not
depend on the psrpcore package: the full PSRP client/server state machine
that package implements is far more than ssh-mitm needs, and part of what
ssh-mitm used from it (psrpcore._payload) was a private, unversioned module
with no stability guarantees.

References:
    MS-PSRP 2.2.1 PowerShell Remoting Protocol Message
        https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/497ac440-89fb-4cb3-9cc1-3434c1aa74c3
    MS-PSRP 2.2.2 Message Type
        https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/33d75f2b-8869-4e1d-a736-4d64d3f28542
    MS-PSRP 2.2.4 Packet Fragment
        https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-psrp/3610dae4-67f7-4175-82da-a3fab83af288
"""

import enum
import struct
import typing
import uuid

_EMPTY_UUID = uuid.UUID(int=0)


class PSRPMessageType(enum.IntEnum):
    """PSRP message type identifiers (MS-PSRP 2.2.2).

    Member names match the spec's own CamelCase naming, not Python's
    UPPER_CASE enum convention, since this reads and is read against
    MS-PSRP documentation and psrpcore-derived tooling.
    """

    # pylint: disable=invalid-name
    SessionCapability = 0x00010002
    InitRunspacePool = 0x00010004
    PublicKey = 0x00010005
    EncryptedSessionKey = 0x00010006
    PublicKeyRequest = 0x00010007
    ConnectRunspacePool = 0x00010008
    SetMaxRunspaces = 0x00021002
    SetMinRunspaces = 0x00021003
    RunspaceAvailability = 0x00021004
    RunspacePoolState = 0x00021005
    CreatePipeline = 0x00021006
    GetAvailableRunspaces = 0x00021007
    UserEvent = 0x00021008
    ApplicationPrivateData = 0x00021009
    GetCommandMetadata = 0x0002100A
    RunspacePoolInitData = 0x0002100B
    ResetRunspaceState = 0x0002100C
    RunspacePoolHostCall = 0x00021100
    RunspacePoolHostResponse = 0x00021101
    PipelineInput = 0x00041002
    EndOfPipelineInput = 0x00041003
    PipelineOutput = 0x00041004
    ErrorRecord = 0x00041005
    PipelineState = 0x00041006
    DebugRecord = 0x00041007
    VerboseRecord = 0x00041008
    WarningRecord = 0x00041009
    ProgressRecord = 0x00041010
    InformationRecord = 0x00041011
    PipelineHostCall = 0x00041100
    PipelineHostResponse = 0x00041101


class Fragment(typing.NamedTuple):
    """A PSRP fragment - a whole PSRP message, or one piece of one."""

    object_id: int
    fragment_id: int
    start: bool
    end: bool
    data: bytearray


class Message(typing.NamedTuple):
    """A PSRP message, reassembled from one or more fragments."""

    destination: int
    message_type: PSRPMessageType
    rpid: uuid.UUID
    pid: "uuid.UUID | None"
    data: bytearray


def unpack_fragment(data: bytearray) -> Fragment:
    """Parses a 21-byte-header PSRP fragment (MS-PSRP 2.2.4)."""
    object_id = struct.unpack_from(">Q", data, 0)[0]
    fragment_id = struct.unpack_from(">Q", data, 8)[0]
    start_end_byte = data[16]
    start = bool(start_end_byte & 0x1)
    end = bool(start_end_byte & 0x2)
    length = struct.unpack_from(">I", data, 17)[0]
    return Fragment(object_id, fragment_id, start, end, data[21 : 21 + length])


def unpack_message(data: bytearray) -> Message:
    """Parses a 40-byte-header PSRP message (MS-PSRP 2.2.1)."""
    destination = struct.unpack_from("<I", data, 0)[0]
    message_type = PSRPMessageType(struct.unpack_from("<I", data, 4)[0])
    rpid = uuid.UUID(bytes_le=bytes(data[8:24]))
    pid: uuid.UUID | None = uuid.UUID(bytes_le=bytes(data[24:40]))
    if pid == _EMPTY_UUID:
        pid = None
    body = data[40:]
    if body.startswith(b"\xef\xbb\xbf"):
        body = body[3:]  # strip optional UTF-8 BOM
    return Message(destination, message_type, rpid, pid, body)
