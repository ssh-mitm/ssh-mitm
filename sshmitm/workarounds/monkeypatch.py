import threading
from typing import Any
import paramiko
import wrapt
from sshmitm.logger import THREAD_DATA


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
