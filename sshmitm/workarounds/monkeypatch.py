import threading
from typing import Any
import paramiko
import wrapt
from paramiko.common import MSG_CHANNEL_REQUEST
from sshmitm.logger import THREAD_DATA


def patch_channel() -> None:
    """Patch channel request dispatch to support signal forwarding (RFC 4254 §6.9).

    Paramiko's server-side channel handler has no "signal" branch, so signal
    requests from clients are silently dropped.  This patch intercepts "signal"
    requests and dispatches them to server.check_channel_signal_request().
    All other request types are forwarded to the original handler unchanged.

    Implementation note: wrapt patching of Channel._handle_request is not
    sufficient because Transport._channel_handler_table stores a direct
    reference to the original function captured at class-definition time.
    The transport dispatch loop calls that table entry directly, bypassing
    any class-attribute patch.  We must update the table entry itself.
    """
    _table: dict[int, Any] = getattr(
        paramiko.transport.Transport, "_channel_handler_table"
    )
    original = _table[MSG_CHANNEL_REQUEST]

    def _handle_request_with_signal(chan: Any, m: Any) -> Any:
        # Save the current read position — the transport has already consumed
        # the channel ID, so we are positioned at the request-type string.
        saved_pos = m.packet.tell()
        key = m.get_text()
        m.get_boolean()  # want_reply (always False for signals; consumed and discarded)

        if key == "signal":
            signame = m.get_text()
            server = chan.transport.server_object
            if server is not None and hasattr(server, "check_channel_signal_request"):
                server.check_channel_signal_request(chan, signame)
            # signals never request a reply — nothing to send back
            return None

        # All other request types: restore position and let the original handler
        # read key + want_reply itself.
        m.packet.seek(saved_pos)
        return original(chan, m)

    _table[MSG_CHANNEL_REQUEST] = _handle_request_with_signal


def do_init(wrapped: Any, instance: Any, *args: Any, **kwargs: Any) -> Any:
    instance.session = getattr(THREAD_DATA, "session", None)
    if instance.session is not None:
        instance.session.register_session_thread()
    wrapped(*args, **kwargs)


def do_run(wrapped: Any, instance: Any, *args: Any, **kwargs: Any) -> Any:
    if instance.session is not None:
        instance.session.register_session_thread()
    return wrapped(*args, **kwargs)


def patch_thread() -> None:
    @wrapt.patch_function_wrapper(threading.Thread, "__init__")
    def thread_init(wrapped: Any, instance: Any, args: Any, kwargs: Any) -> None:
        do_init(wrapped, instance, *args, **kwargs)

    @wrapt.patch_function_wrapper(threading.Thread, "run")
    def thread_run(wrapped: Any, instance: Any, args: Any, kwargs: Any) -> None:
        do_run(wrapped, instance, *args, **kwargs)

    @wrapt.patch_function_wrapper(paramiko.transport.Transport, "run")
    def transport_run(wrapped: Any, instance: Any, args: Any, kwargs: Any) -> None:
        do_run(wrapped, instance, *args, **kwargs)

    @wrapt.patch_function_wrapper(threading.Timer, "run")
    def timer_run(wrapped: Any, instance: Any, args: Any, kwargs: Any) -> None:
        do_run(wrapped, instance, *args, **kwargs)
