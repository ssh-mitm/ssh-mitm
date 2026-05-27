"""Low-level paramiko channel helpers that rely on paramiko internals."""

from __future__ import annotations

import paramiko
from paramiko.common import cMSG_CHANNEL_REQUEST
from paramiko.message import Message


def send_signal(channel: paramiko.Channel, signame: str) -> None:
    """Send a signal over *channel* to the remote process (RFC 4254 §6.9).

    Paramiko does not expose this as a public API, so we build the
    SSH_MSG_CHANNEL_REQUEST message directly.  No reply is expected.
    """
    m = Message()
    m.add_byte(cMSG_CHANNEL_REQUEST)
    m.add_int(channel.remote_chanid)  # noqa: SLF001
    m.add_string("signal")
    m.add_boolean(False)  # want_reply always False for signals
    m.add_string(signame)
    channel.transport._send_user_message(m)  # noqa: SLF001


def request_pty_with_modes(
    channel: paramiko.Channel,
    term: bytes | str,
    width: int,
    height: int,
    width_pixels: int,
    height_pixels: int,
    modes: bytes,
) -> None:
    """Request a PTY and forward terminal-mode bytes to the remote server.

    Equivalent to Channel.get_pty() but passes *modes* instead of the
    empty byte string that paramiko hardcodes (RFC 4254 §8).
    """
    m = Message()
    m.add_byte(cMSG_CHANNEL_REQUEST)
    m.add_int(channel.remote_chanid)  # noqa: SLF001
    m.add_string("pty-req")
    m.add_boolean(True)  # want_reply
    m.add_string(term)
    m.add_int(width)
    m.add_int(height)
    m.add_int(width_pixels)
    m.add_int(height_pixels)
    m.add_string(modes)
    channel._event_pending()  # noqa: SLF001
    channel.transport._send_user_message(m)  # noqa: SLF001
    channel._wait_for_event()  # noqa: SLF001
