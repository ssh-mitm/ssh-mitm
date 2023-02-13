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
# pylint: skip-file

from __future__ import print_function
import socket
import sys
import os

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
    cMSG_KEXINIT
)
from paramiko.message import Message
from paramiko.packet import NeedRekeyException
from paramiko.util import b
from paramiko.ssh_exception import (
    SSHException
)


from paramiko.transport import _active_threads  # type: ignore


def transport_send_kex_init(self):  # type: ignore
    """
    announce to the other side that we'd like to negotiate keys, and what
    kind of key negotiation we support.
    """
    self.clear_to_send_lock.acquire()
    try:
        self.clear_to_send.clear()
    finally:
        self.clear_to_send_lock.release()
    self.gss_kex_used = False
    self.in_kex = True
    kex_algos = list(self.preferred_kex)
    if self.server_mode:
        mp_required_prefix = "diffie-hellman-group-exchange-sha"
        kex_mp = [k for k in kex_algos if k.startswith(mp_required_prefix)]
        if (self._modulus_pack is None) and (len(kex_mp) > 0):
            # can't do group-exchange if we don't have a pack of potential
            # primes
            kex_algos = [
                k
                for k in self.get_security_options().kex
                if not k.startswith(mp_required_prefix)
            ]
            self.get_security_options().kex = kex_algos
        available_server_keys = list(
            filter(
                list(self.server_key_dict.keys()).__contains__,
                # TODO: ensure tests will catch if somebody streamlines
                # this by mistake - case is the admittedly silly one where
                # the only calls to add_server_key() contain keys which
                # were filtered out of the below via disabled_algorithms.
                # If this is streamlined, we would then be allowing the
                # disabled algorithm(s) for hostkey use
                # TODO: honestly this prob just wants to get thrown out
                # when we make kex configuration more straightforward
                self.preferred_keys,
            )
        )
    else:
        available_server_keys = self.preferred_keys
        # Signal support for MSG_EXT_INFO.
        # NOTE: doing this here handily means we don't even consider this
        # value when agreeing on real kex algo to use (which is a common
        # pitfall when adding this apparently).
        if "ext-info-c" not in kex_algos:
            kex_algos.append("ext-info-c")

    m = Message()
    m.add_byte(cMSG_KEXINIT)
    m.add_bytes(os.urandom(16))
    m.add_list(kex_algos)
    m.add_list(available_server_keys)
    m.add_list(self.preferred_ciphers)
    m.add_list(self.preferred_ciphers)
    m.add_list(self.preferred_macs)
    m.add_list(self.preferred_macs)
    m.add_list(self.preferred_compression)
    m.add_list(self.preferred_compression)
    m.add_string(bytes())
    m.add_string(bytes())
    m.add_boolean(False)
    m.add_int(0)
    # save a copy for later (needed to compute a hash)
    self.local_kex_init = self._latest_kex_init = m.asbytes()
    self._send_message(m)


def transport_run(self):  # type: ignore
    # (use the exposed "run" method, because if we specify a thread target
    # of a private method, threading.Thread will keep a reference to it
    # indefinitely, creating a GC cycle and not letting Transport ever be
    # GC'd. it's a bug in Thread.)

    # Hold reference to 'sys' so we can test sys.modules to detect
    # interpreter shutdown.
    self.sys = sys

    # active=True occurs before the thread is launched, to avoid a race
    _active_threads.append(self)
    tid = hex(id(self) & xffffffff)
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
            try:
                self._check_banner()
            except SSHException:
                self._log(DEBUG, "error reading ssh protocol banner {}".format(tid))
                pass
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
                            # according to rfc 4253, the next packet should be ignored,
                            # when first_kex_packet_follows is True
                            # this is a workarround at the moment, but connection works
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
            self._log(
                ERROR,
                "Exception ({}): {}".format(
                    "server" if self.server_mode else "client", e
                ),
            )
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
                emsg = e.args  # type: ignore
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
