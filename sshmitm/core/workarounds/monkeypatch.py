"""
Thread and transport monkeypatch helpers to propagate session context into threads.

This module provides small wrappers that attach the current session object (if any)
stored in the thread-local ``THREAD_DATA`` to newly created threads and certain
Paramiko transports. The goal is to ensure that worker threads and transport
threads created during an SSH session have access to the same session object so
they can register themselves with the session lifecycle (for example to allow
clean shutdown or resource tracking).

The implementation uses ``wrapt`` to patch constructors and run methods of
``threading.Thread``, ``threading.Timer`` and ``paramiko.transport.Transport``.
Patching is limited to the minimal points necessary to transfer the session
reference and register the thread with the session.
"""

import threading
from typing import Any
import paramiko
import wrapt  # type: ignore[import-untyped]

from sshmitm.core.logger import THREAD_DATA


def do_init(wrapped: Any, instance: Any, *args: Any, **kwargs: Any) -> Any:
    """
    Helper invoked inside patched Thread.__init__ to attach session context.

    This function reads the session from the thread-local storage object
    ``THREAD_DATA`` and sets it on the newly created thread instance as the
    attribute ``session``. If a session is found, it also calls
    ``register_session_thread`` on that session to mark that this thread is
    associated with the session.

    :param wrapped: The original wrapped function (constructor).
    :param instance: The thread instance being initialized.
    :param args: Positional arguments forwarded to the original constructor.
    :param kwargs: Keyword arguments forwarded to the original constructor.
    :returns: Whatever the wrapped constructor returns (typically None).
    """
    # Attach any currently active session (if present) to the new thread object.
    instance.session = getattr(THREAD_DATA, "session", None)

    # If we obtained a session, let it know that a new thread was created for it.
    if instance.session is not None:
        instance.session.register_session_thread()

    # Call the original __init__ method with the original arguments.
    return wrapped(*args, **kwargs)


def do_run(wrapped: Any, instance: Any, *args: Any, **kwargs: Any) -> Any:
    """
    Helper invoked inside patched Thread.run / Transport.run / Timer.run.

    When a thread (or transport/timer) begins execution, ensure the session is
    registered again. Some frameworks create threads in one context but execute
    them in another — re-registering on run guarantees consistent tracking.

    :param wrapped: The original wrapped run method.
    :param instance: The executing thread/transport/timer instance.
    :param args: Positional arguments forwarded to the original run.
    :param kwargs: Keyword arguments forwarded to the original run.
    :returns: The return value of the wrapped run method.
    """
    # If the instance already has an attached session, register it now.
    if getattr(instance, "session", None) is not None:
        instance.session.register_session_thread()

    # Execute the original run method and return its result.
    return wrapped(*args, **kwargs)


def patch_thread() -> None:
    """
    Apply function wrappers to propagate session context into threads and transports.

    This function patches the following call points using ``wrapt``:
    * ``threading.Thread.__init__`` — to attach a session attribute when a Thread
      object is constructed.
    * ``threading.Thread.run`` — to register the thread with the session when it
      actually starts executing.
    * ``paramiko.transport.Transport.run`` — to register Paramiko transport threads
      used by the SSH library.
    * ``threading.Timer.run`` — to register timer callback threads that execute later.

    The wrappers intentionally keep behavior minimal and forward all original
    arguments to the wrapped functions.
    """

    # Patch Thread.__init__ so newly created Thread instances get the session.
    @wrapt.patch_function_wrapper(threading.Thread, "__init__")  # type: ignore[misc]
    def thread_init(wrapped: Any, instance: Any, args: Any, kwargs: Any) -> None:
        # Delegate to the shared init helper which attaches the session and calls
        # the original constructor.
        return do_init(wrapped, instance, *args, **kwargs)

    # Patch Thread.run so the session is registered on thread start.
    @wrapt.patch_function_wrapper(threading.Thread, "run")  # type: ignore[misc]
    def thread_run(wrapped: Any, instance: Any, args: Any, kwargs: Any) -> None:
        # Delegate to the shared run helper which registers the session before
        # executing the original run implementation.
        return do_run(wrapped, instance, *args, **kwargs)

    # Patch Paramiko Transport.run so transport threads also register with the session.
    @wrapt.patch_function_wrapper(paramiko.transport.Transport, "run")  # type: ignore[misc]
    def transport_run(wrapped: Any, instance: Any, args: Any, kwargs: Any) -> None:
        # Transport objects may create their own internal threads; ensure the
        # session tracking is applied when they start.
        return do_run(wrapped, instance, *args, **kwargs)

    # Patch Timer.run to handle timer-based callback threads in the same way.
    @wrapt.patch_function_wrapper(threading.Timer, "run")  # type: ignore[misc]
    def timer_run(wrapped: Any, instance: Any, args: Any, kwargs: Any) -> None:
        # Timer threads are short-lived; still register them for completeness.
        return do_run(wrapped, instance, *args, **kwargs)
