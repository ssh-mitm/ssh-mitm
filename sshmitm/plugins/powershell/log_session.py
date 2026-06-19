"""PSRP session logging forwarder.

Parses the PowerShell Remoting Protocol (PSRP) stream on-the-fly and logs each
message type together with key fields (command names, output, error records, state
transitions).  The raw byte stream is forwarded unchanged.

PSRP over SSH uses a text-based framing (MS-PSRP §2.2.4 SSH transport):

    <Data Stream='Default' PSGuid='...'>BASE64</Data>

Each element's base64 content decodes to a binary PSRP fragment:

    ObjectId    8 bytes  big-endian uint64
    FragmentId  8 bytes  big-endian uint64
    Flags       1 byte   bit 0 = start fragment, bit 1 = end fragment
    BlobLength  4 bytes  big-endian uint32
    Blob        variable (part of the PSRP message)

Multiple fragments with the same ObjectId are reassembled into a PSRP message.
Each message starts with a 40-byte header followed by CLIXML.
"""

import base64
import logging
import re
import struct
from typing import TYPE_CHECKING, Generator

from lxml import etree
from psrpcore._payload import Message, unpack_fragment, unpack_message
from psrpcore.types import PSRPMessageType

from sshmitm.forwarders.powershell import PowerShellForwarder

if TYPE_CHECKING:
    import sshmitm


_FRAGMENT_HEADER = 21  # ObjectId(8) + FragmentId(8) + Flags(1) + BlobLength(4)
# Matches a complete <Data ...>BASE64</Data> element in the SSH PSRP stream.
_DATA_RE = re.compile(rb"<Data[^>]*>([^<]*)</Data>")

# lxml parser with all dangerous features disabled (no XXE, no DTD, no network).
_XML_PARSER = etree.XMLParser(
    resolve_entities=False,
    no_network=True,
    load_dtd=False,
    dtd_validation=False,
    huge_tree=False,
)

# PipelineState integer → name (MS-PSRP §2.3.5)
_PIPELINE_STATES: dict[int, str] = {
    0: "NotStarted",
    1: "Running",
    2: "Stopping",
    3: "Stopped",
    4: "Completed",
    5: "Disconnected",
    6: "Failed",
}

# RunspacePoolState integer → name (MS-PSRP §2.3.4)
_RUNSPACE_STATES: dict[int, str] = {
    0: "BeforeOpen",
    1: "Opening",
    2: "Opened",
    3: "Closing",
    4: "Closed",
    5: "Broken",
    6: "Disconnecting",
    7: "Disconnected",
    8: "Connecting",
}

# Message types logged at INFO level; all others are DEBUG.
_INFO_TYPES = frozenset({
    PSRPMessageType.SessionCapability,
    PSRPMessageType.InitRunspacePool,
    PSRPMessageType.RunspacePoolState,
    PSRPMessageType.CreatePipeline,
    PSRPMessageType.PipelineState,
    PSRPMessageType.ErrorRecord,
    PSRPMessageType.WarningRecord,
    PSRPMessageType.InformationRecord,
})


class _PSRPStreamParser:
    """Reassembles PSRP messages from the SSH <Data>BASE64</Data> stream."""

    def __init__(self) -> None:
        self._buf: bytearray = bytearray()
        self._fragments: dict[int, bytearray] = {}

    def feed(self, data: bytes) -> Generator[Message, None, None]:
        self._buf.extend(data)
        last_end = 0
        for match in _DATA_RE.finditer(self._buf):
            last_end = match.end()
            try:
                raw = bytearray(base64.b64decode(match.group(1)))
            except Exception:  # pylint: disable=broad-exception-caught
                continue
            if len(raw) < _FRAGMENT_HEADER:
                continue
            blob_len = struct.unpack_from(">I", raw, 17)[0]
            if len(raw) < _FRAGMENT_HEADER + blob_len:
                continue
            try:
                frag = unpack_fragment(raw[:_FRAGMENT_HEADER + blob_len])
            except Exception:  # pylint: disable=broad-exception-caught
                continue
            if frag.start:
                self._fragments[frag.object_id] = bytearray()
            buf = self._fragments.get(frag.object_id)
            if buf is not None:
                buf.extend(frag.data)
            if frag.end and frag.object_id in self._fragments:
                msg_data = self._fragments.pop(frag.object_id)
                try:
                    yield unpack_message(msg_data)
                except Exception:  # pylint: disable=broad-exception-caught
                    logging.debug("psrp: failed to unpack message", exc_info=True)
        del self._buf[:last_end]


def _parse_clixml(xml_data: bytes) -> "etree._Element | None":
    """Parse CLIXML safely. Returns None on any parse error."""
    try:
        # Strip optional UTF-8 BOM before parsing.
        payload = xml_data.lstrip(b"\xef\xbb\xbf")
        return etree.fromstring(payload, parser=_XML_PARSER)
    except etree.XMLSyntaxError:
        return None


def _attr_texts(root: "etree._Element", tag: str, attr: str) -> list[str]:
    """Collect text of all <{tag} N='{attr}'> elements anywhere in the tree."""
    return [
        el.text or ""
        for el in root.iter()
        if etree.QName(el.tag).localname == tag
        and el.get("N") == attr
        and el.text
    ]


def _int_attr(root: "etree._Element", tag: str, attr: str) -> int | None:
    """Return the integer value of the first matching <{tag} N='{attr}'> element."""
    for el in root.iter():
        if etree.QName(el.tag).localname == tag and el.get("N") == attr and el.text:
            try:
                return int(el.text)
            except ValueError:
                return None
    return None


def _all_strings(root: "etree._Element") -> list[str]:
    """Collect text of all bare <S> elements (no N attribute required)."""
    return [el.text for el in root.iter() if etree.QName(el.tag).localname == "S" and el.text]


class PSRPLoggingForwarder(PowerShellForwarder):
    """Logs PSRP messages (commands, output, errors) while relaying the stream unchanged.

    Activate with::

        ssh-mitm server --remote-host <target> --powershell-interface log-session
    """

    def __init__(self, session: "sshmitm.session.Session") -> None:
        super().__init__(session)
        self._client_parser = _PSRPStreamParser()
        self._server_parser = _PSRPStreamParser()

    def handle_client_data(self, data: bytes) -> bytes:
        for msg in self._client_parser.feed(data):
            self._log_message(msg, "client→server")
        return data

    def handle_server_data(self, data: bytes) -> bytes:
        for msg in self._server_parser.feed(data):
            self._log_message(msg, "server→client")
        return data

    def _log_message(self, msg: Message, direction: str) -> None:
        mtype = msg.message_type
        xml_bytes = bytes(msg.data)
        extra: dict[str, object] = {
            "event": "psrp_message",
            "direction": direction,
            "message_type": mtype.name,
            "pipeline_id": str(msg.pid) if msg.pid else None,
        }

        root = _parse_clixml(xml_bytes)

        if mtype == PSRPMessageType.CreatePipeline:
            cmds = _attr_texts(root, "S", "Cmd") if root is not None else []
            extra["commands"] = cmds
            logging.info(
                "psrp %s CreatePipeline: %s",
                direction,
                " | ".join(cmds) if cmds else "(no commands extracted)",
                extra=extra,
            )

        elif mtype == PSRPMessageType.PipelineOutput:
            values = _all_strings(root) if root is not None else []
            extra["output"] = values
            logging.debug(
                "psrp %s PipelineOutput: %s",
                direction,
                " ".join(values)[:200] if values else f"({len(xml_bytes)} bytes)",
                extra=extra,
            )

        elif mtype == PSRPMessageType.ErrorRecord:
            values = (
                (_attr_texts(root, "S", "Message") or _all_strings(root))
                if root is not None
                else []
            )
            extra["error"] = values
            logging.warning(
                "psrp %s ErrorRecord: %s",
                direction,
                " ".join(values)[:200] if values else f"({len(xml_bytes)} bytes)",
                extra=extra,
            )

        elif mtype == PSRPMessageType.WarningRecord:
            values = _all_strings(root) if root is not None else []
            extra["warning"] = values
            logging.warning(
                "psrp %s WarningRecord: %s",
                direction,
                " ".join(values)[:200],
                extra=extra,
            )

        elif mtype == PSRPMessageType.PipelineState:
            code = _int_attr(root, "I32", "PipelineState") if root is not None else None
            state = _PIPELINE_STATES.get(code, str(code)) if code is not None else "unknown"
            extra["state"] = state
            logging.info("psrp %s PipelineState: %s", direction, state, extra=extra)

        elif mtype == PSRPMessageType.RunspacePoolState:
            code = _int_attr(root, "I32", "RunspaceState") if root is not None else None
            state = _RUNSPACE_STATES.get(code, str(code)) if code is not None else "unknown"
            extra["state"] = state
            logging.info("psrp %s RunspacePoolState: %s", direction, state, extra=extra)

        elif mtype in _INFO_TYPES:
            logging.info("psrp %s %s", direction, mtype.name, extra=extra)

        else:
            logging.debug(
                "psrp %s %s (%d bytes)", direction, mtype.name, len(xml_bytes), extra=extra
            )
