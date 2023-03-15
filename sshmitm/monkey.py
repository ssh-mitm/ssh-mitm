import threading
import logging
import paramiko
import wrapt
from sshmitm.logging import THREAD_DATA


def fullname(o):
    klass = o.__class__
    module = klass.__module__
    if module == 'builtins':
        return klass.__qualname__ # avoid outputs like 'builtins.str'
    return module + '.' + klass.__qualname__


def do_init(wrapped, instance, *args, **kwargs):
    instance.session = getattr(THREAD_DATA, 'session', None)
    if instance.session is not None:
        instance.session.register_session_thread()
    wrapped(*args, **kwargs)

def do_run(wrapped, instance, *args, **kwargs):
    if instance.session is not None:
        instance.session.register_session_thread()
    return wrapped(*args, **kwargs)

def monkey_patch_thread():

    @wrapt.patch_function_wrapper(threading.Thread, '__init__')
    def thread_init(wrapped, instance, args, kwargs):
        do_init(wrapped, instance, *args, **kwargs)

    @wrapt.patch_function_wrapper(threading.Thread, 'run')
    def thread_run(wrapped, instance, args, kwargs) -> None:
        do_run(wrapped, instance, *args, **kwargs)

    @wrapt.patch_function_wrapper(paramiko.transport.Transport, 'run')
    def transport_run(wrapped, instance, args, kwargs) -> None:
        do_run(wrapped, instance, *args, **kwargs)

    @wrapt.patch_function_wrapper(threading.Timer, 'run')
    def timer_run(wrapped, instance, args, kwargs) -> None:
        do_run(wrapped, instance, *args, **kwargs)