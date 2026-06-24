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
import os
import re
import struct
from datetime import datetime, timezone
from typing import IO, TYPE_CHECKING, Generator

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

# Transcript column widths for human-readable output.
_COL_DIR = 13    # "client→server" / "server→client"
_COL_TYPE = 20   # message type name


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
    """Parse CLIXML safely with lxml. Returns None on any parse error."""
    try:
        payload = xml_data.lstrip(b"\xef\xbb\xbf")  # strip optional UTF-8 BOM
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
    """Collect text of all scalar leaf elements per MS-PSRP CLIXML schema.

    The CLIXML namespace is http://schemas.microsoft.com/powershell/2004/04;
    we compare only the local name to stay namespace-agnostic.
    Note: Double is serialised as <Db>, not <Dbl>.
    """
    _SCALAR_TAGS = frozenset({
        "S", "I8", "I16", "I32", "I64", "U8", "U16", "U32", "U64",
        "Db", "Dec", "Sg", "B", "C", "SB", "By", "DT", "TS",
    })
    return [el.text for el in root.iter() if etree.QName(el.tag).localname in _SCALAR_TAGS and el.text]


class PSRPLoggingForwarder(PowerShellForwarder):
    """Logs PSRP messages (commands, output, errors) while relaying the stream unchanged.

    Parses the PowerShell Remoting Protocol stream on-the-fly and logs each message
    type together with key fields such as command names, pipeline output, error records,
    and state transitions.  The raw byte stream is forwarded to the remote host unchanged
    — this plugin is fully transparent to both client and server.

    Optionally writes a structured per-session transcript to a file.

    **Usage example**

    ::

        ssh-mitm server --powershell-interface log-session

    To save a transcript to a directory::

        ssh-mitm server --powershell-interface log-session \\
            --psrp-transcript-dir /tmp/psrp-transcripts/

    **Notes**

    * High-level message types (``CreatePipeline``, ``PipelineState``,
      ``ErrorRecord``, etc.) are logged at INFO level; all others at DEBUG.
    * Transcript files are named ``<session-id>.log`` and written into the
      configured directory, falling back to the session log directory.
    """

    @classmethod
    def parser_arguments(cls) -> None:
        plugin_group = cls.argument_group()
        plugin_group.add_argument(
            "--psrp-transcript-dir",
            dest="psrp_transcript_dir",
            default=None,
            metavar="DIR",
            help=(
                "Write a human-readable PSRP transcript file for each session into DIR. "
                "The filename is <session-id>.log.  "
                "Falls back to the session log directory when not set."
            ),
        )

    def __init__(self, session: "sshmitm.session.Session") -> None:
        """Initializes per-direction PSRP stream parsers and opens the transcript file.

        :param session: the active SSH session being intercepted.
        """
        super().__init__(session)
        self._client_parser = _PSRPStreamParser()
        self._server_parser = _PSRPStreamParser()
        self._transcript: IO[str] | None = self._open_transcript()

    def _open_transcript(self) -> "IO[str] | None":
        transcript_dir = self.args.psrp_transcript_dir or self.session.session_log_dir
        if not transcript_dir:
            return None
        try:
            os.makedirs(transcript_dir, exist_ok=True)
            path = os.path.join(transcript_dir, f"{self.session.sessionid}.log")
            fh = open(path, "w", encoding="utf-8", buffering=1)  # line-buffered
            fh.write(f"# PSRP transcript  session={self.session.sessionid}\n")
            fh.write(f"# started={datetime.now(tz=timezone.utc).isoformat()}\n")
            fh.write(f"# {'timestamp':<26}  {'direction':<{_COL_DIR}}  {'type':<{_COL_TYPE}}  detail\n")
            fh.write("#" + "-" * 100 + "\n")
            logging.info(
                "psrp: writing transcript to %s", path, extra={"event": "psrp_transcript_open"}
            )
            return fh
        except OSError:
            logging.warning("psrp: could not open transcript file in %s", transcript_dir, exc_info=True)
            return None

    def forward(self) -> None:
        try:
            super().forward()
        finally:
            if self._transcript:
                self._transcript.write(
                    f"# ended={datetime.now(tz=timezone.utc).isoformat()}\n"
                )
                self._transcript.close()
                self._transcript = None

    def handle_client_data(self, data: bytes) -> bytes:
        for msg in self._client_parser.feed(data):
            self._log_message(msg, "client→server")
        return data

    def handle_server_data(self, data: bytes) -> bytes:
        for msg in self._server_parser.feed(data):
            self._log_message(msg, "server→client")
        return data

    def _write_transcript(self, direction: str, mtype_name: str, detail: str) -> None:
        if self._transcript is None:
            return
        ts = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        self._transcript.write(
            f"  {ts}  {direction:<{_COL_DIR}}  {mtype_name:<{_COL_TYPE}}  {detail}\n"
        )

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
            detail = " | ".join(cmds) if cmds else "(no commands extracted)"
            extra["commands"] = cmds
            logging.info("psrp %s CreatePipeline: %s", direction, detail, extra=extra)
            self._write_transcript(direction, "CreatePipeline", detail)

        elif mtype == PSRPMessageType.PipelineOutput:
            values = _all_strings(root) if root is not None else []
            detail = " ".join(values)[:200] if values else f"({len(xml_bytes)} bytes)"
            extra["output"] = values
            logging.debug("psrp %s PipelineOutput: %s", direction, detail, extra=extra)
            self._write_transcript(direction, "PipelineOutput", detail)

        elif mtype == PSRPMessageType.ErrorRecord:
            values = (
                (_attr_texts(root, "S", "Message") or _all_strings(root))
                if root is not None
                else []
            )
            detail = " ".join(values)[:200] if values else f"({len(xml_bytes)} bytes)"
            extra["error"] = values
            logging.warning("psrp %s ErrorRecord: %s", direction, detail, extra=extra)
            self._write_transcript(direction, "ErrorRecord", detail)

        elif mtype == PSRPMessageType.WarningRecord:
            values = _all_strings(root) if root is not None else []
            detail = " ".join(values)[:200]
            extra["warning"] = values
            logging.warning("psrp %s WarningRecord: %s", direction, detail, extra=extra)
            self._write_transcript(direction, "WarningRecord", detail)

        elif mtype == PSRPMessageType.PipelineState:
            code = _int_attr(root, "I32", "PipelineState") if root is not None else None
            state = _PIPELINE_STATES.get(code, str(code)) if code is not None else "unknown"
            extra["state"] = state
            logging.info("psrp %s PipelineState: %s", direction, state, extra=extra)
            self._write_transcript(direction, "PipelineState", state)

        elif mtype == PSRPMessageType.RunspacePoolState:
            code = _int_attr(root, "I32", "RunspaceState") if root is not None else None
            state = _RUNSPACE_STATES.get(code, str(code)) if code is not None else "unknown"
            extra["state"] = state
            logging.info("psrp %s RunspacePoolState: %s", direction, state, extra=extra)
            self._write_transcript(direction, "RunspacePoolState", state)

        elif mtype in _INFO_TYPES:
            logging.info("psrp %s %s", direction, mtype.name, extra=extra)
            self._write_transcript(direction, mtype.name, "")

        else:
            logging.debug(
                "psrp %s %s (%d bytes)", direction, mtype.name, len(xml_bytes), extra=extra
            )
