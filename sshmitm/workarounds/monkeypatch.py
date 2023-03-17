import threading
from typing import Any
import paramiko
import wrapt  # type: ignore
from sshmitm.logging import THREAD_DATA


def do_init(wrapped: Any, instance: Any, *args: Any, **kwargs: Any) -> Any:
    instance.session = getattr(THREAD_DATA, 'session', None)
    if instance.session is not None:
        instance.session.register_session_thread()
    wrapped(*args, **kwargs)


def do_run(wrapped: Any, instance: Any, *args: Any, **kwargs: Any) -> Any:
    if instance.session is not None:
        instance.session.register_session_thread()
    return wrapped(*args, **kwargs)


def patch_thread() -> None:

    @wrapt.patch_function_wrapper(threading.Thread, '__init__')  # type: ignore
    def thread_init(wrapped: Any, instance: Any, args: Any, kwargs: Any) -> None:
        do_init(wrapped, instance, *args, **kwargs)

    @wrapt.patch_function_wrapper(threading.Thread, 'run')  # type: ignore
    def thread_run(wrapped: Any, instance: Any, args: Any, kwargs: Any) -> None:
        do_run(wrapped, instance, *args, **kwargs)

    @wrapt.patch_function_wrapper(paramiko.transport.Transport, 'run')  # type: ignore
    def transport_run(wrapped: Any, instance: Any, args: Any, kwargs: Any) -> None:
        do_run(wrapped, instance, *args, **kwargs)

    @wrapt.patch_function_wrapper(threading.Timer, 'run')  # type: ignore
    def timer_run(wrapped: Any, instance: Any, args: Any, kwargs: Any) -> None:
        do_run(wrapped, instance, *args, **kwargs)
