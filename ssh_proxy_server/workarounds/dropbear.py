# Copyright (C) 2003-2007  Robey Pointer <robeypointer@gmail.com>
# Copyright (C) 2003-2007  Robey Pointer <robeypointer@gmail.com>
#
# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.

"""
Core protocol implementation
"""

from __future__ import print_function
import socket
import sys

from paramiko import util
from paramiko.common import (
    xffffffff,
    DEBUG,
    MSG_KEXINIT,
    MSG_IGNORE,
    MSG_DISCONNECT,
    MSG_DEBUG,
    ERROR,
    WARNING,
    cMSG_UNIMPLEMENTED,
    MSG_UNIMPLEMENTED,
    MSG_NAMES,
)
from paramiko.message import Message
from paramiko.packet import NeedRekeyException
from paramiko.py3compat import long, b
from paramiko.ssh_exception import (
    SSHException
)


from paramiko.transport import _active_threads


def transport_run(self):
    # (use the exposed "run" method, because if we specify a thread target
    # of a private method, threading.Thread will keep a reference to it
    # indefinitely, creating a GC cycle and not letting Transport ever be
    # GC'd. it's a bug in Thread.)

    # Hold reference to 'sys' so we can test sys.modules to detect
    # interpreter shutdown.
    self.sys = sys

    # active=True occurs before the thread is launched, to avoid a race
    _active_threads.append(self)
    tid = hex(long(id(self)) & xffffffff)
    if self.server_mode:
        self._log(DEBUG, "starting thread (server mode): {}".format(tid))
    else:
        self._log(DEBUG, "starting thread (client mode): {}".format(tid))
    try:
        try:
            self.packetizer.write_all(b(self.local_version + "\r\n"))
            self._log(
                DEBUG,
                "Local version/idstring: {}".format(self.local_version),
            )  # noqa
            self._check_banner()
            # The above is actually very much part of the handshake, but
            # sometimes the banner can be read but the machine is not
            # responding, for example when the remote ssh daemon is loaded
            # in to memory but we can not read from the disk/spawn a new
            # shell.
            # Make sure we can specify a timeout for the initial handshake.
            # Re-use the banner timeout for now.
            self.packetizer.start_handshake(self.handshake_timeout)
            self._send_kex_init()
            self._expect_packet(MSG_KEXINIT)

            while self.active:
                if self.packetizer.need_rekey() and not self.in_kex:
                    self._send_kex_init()
                try:
                    ptype, m = self.packetizer.read_message()
                except NeedRekeyException:
                    continue
                if ptype == MSG_IGNORE:
                    continue
                elif ptype == MSG_DISCONNECT:
                    self._parse_disconnect(m)
                    break
                elif ptype == MSG_DEBUG:
                    self._parse_debug(m)
                    continue
                if len(self._expected_packet) > 0:
                    if ptype not in self._expected_packet:
                        if ptype == 30:
                            continue
                        raise SSHException(
                            "Expecting packet from {!r}, got {:d}".format(
                                self._expected_packet, ptype
                            )
                        )  # noqa
                    self._expected_packet = tuple()
                    if (ptype >= 30) and (ptype <= 41):
                        self.kex_engine.parse_next(ptype, m)
                        continue

                if ptype in self._handler_table:
                    error_msg = self._ensure_authed(ptype, m)
                    if error_msg:
                        self._send_message(error_msg)
                    else:
                        self._handler_table[ptype](self, m)
                elif ptype in self._channel_handler_table:
                    chanid = m.get_int()
                    chan = self._channels.get(chanid)
                    if chan is not None:
                        self._channel_handler_table[ptype](chan, m)
                    elif chanid in self.channels_seen:
                        self._log(
                            DEBUG,
                            "Ignoring message for dead channel {:d}".format(  # noqa
                                chanid
                            ),
                        )
                    else:
                        self._log(
                            ERROR,
                            "Channel request for unknown channel {:d}".format(  # noqa
                                chanid
                            ),
                        )
                        break
                elif (
                    self.auth_handler is not None
                    and ptype in self.auth_handler._handler_table
                ):
                    handler = self.auth_handler._handler_table[ptype]
                    handler(self.auth_handler, m)
                    if len(self._expected_packet) > 0:
                        continue
                else:
                    # Respond with "I don't implement this particular
                    # message type" message (unless the message type was
                    # itself literally MSG_UNIMPLEMENTED, in which case, we
                    # just shut up to avoid causing a useless loop).
                    name = MSG_NAMES[ptype]
                    warning = "Oops, unhandled type {} ({!r})".format(
                        ptype, name
                    )
                    self._log(WARNING, warning)
                    if ptype != MSG_UNIMPLEMENTED:
                        msg = Message()
                        msg.add_byte(cMSG_UNIMPLEMENTED)
                        msg.add_int(m.seqno)
                        self._send_message(msg)
                self.packetizer.complete_handshake()
        except SSHException as e:
            self._log(ERROR, "Exception: " + str(e))
            self._log(ERROR, util.tb_strings())
            self.saved_exception = e
        except EOFError as e:
            self._log(DEBUG, "EOF in transport thread")
            self.saved_exception = e
        except socket.error as e:
            if type(e.args) is tuple:
                if e.args:
                    emsg = "{} ({:d})".format(e.args[1], e.args[0])
                else:  # empty tuple, e.g. socket.timeout
                    emsg = str(e) or repr(e)
            else:
                emsg = e.args
            self._log(ERROR, "Socket exception: " + emsg)
            self.saved_exception = e
        except Exception as e:
            self._log(ERROR, "Unknown exception: " + str(e))
            self._log(ERROR, util.tb_strings())
            self.saved_exception = e
        _active_threads.remove(self)
        for chan in list(self._channels.values()):
            chan._unlink()
        if self.active:
            self.active = False
            self.packetizer.close()
            if self.completion_event is not None:
                self.completion_event.set()
            if self.auth_handler is not None:
                self.auth_handler.abort()
            for event in self.channel_events.values():
                event.set()
            try:
                self.lock.acquire()
                self.server_accept_cv.notify()
            finally:
                self.lock.release()
        self.sock.close()
    except Exception:
        # Don't raise spurious 'NoneType has no attribute X' errors when we
        # wake up during interpreter shutdown. Or rather -- raise
        # everything *if* sys.modules (used as a convenient sentinel)
        # appears to still exist.
        if self.sys.modules is not None:
            raise
