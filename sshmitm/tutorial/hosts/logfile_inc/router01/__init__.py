"""Mock host: router01.logfileinc.internal

Core network router managed by Thomas Webb.  SNMP is enabled with a read-write
community string stored in the running configuration.  Thomas's SSH sessions
tend to stay open for hours.
"""
from __future__ import annotations

import asyncio

import paramiko

from sshmitm.tutorial.hosts import Host, SNMPService, SSHService
from sshmitm.tutorial.hosts.logfile_inc import ManagementSegment, ThomasWebb

SHELL_PROMPT = b"router01> "

_HELP_TEXT = (
    b"Available commands:\r\n"
    b"  help                           - show this help\r\n"
    b"  show version                   - display firmware version\r\n"
    b"  show running-config            - display current configuration\r\n"
    b"  show startup-config            - display saved configuration\r\n"
    b"  show ip route                  - display routing table\r\n"
    b"  show interfaces                - display interface status\r\n"
    b"  show users                     - display active sessions\r\n"
    b"  show logging                   - display system log\r\n"
    b"  ping <host>                    - test connectivity\r\n"
    b"  traceroute <host>              - trace route to host\r\n"
    b"  write memory                   - save running config to flash\r\n"
    b"  copy running-config tftp       - copy config to TFTP server\r\n"
    b"  reload                         - reload the system\r\n"
    b"  exit                           - close session\r\n"
)


class Router01(Host):
    """router01.logfileinc.internal — core network router."""

    label    = "router01"
    hostname = "router01.logfileinc.internal"
    address  = "127.4.0.1"
    segment  = ManagementSegment
    users    = [ThomasWebb]
    services = [
        SSHService(port=20022, auth=["publickey"]),
        SNMPService(port=20161),
    ]

    def __init__(self) -> None:
        super().__init__()
        self._authorized_keys: dict[str, list[paramiko.PKey]] = {}
        self._snmp_secret: str = "public"

    def configure(self, session_data: dict) -> None:
        for user in self.__class__.users:
            auth_key = f"authorize_key_{user.username}"
            if auth_key in session_data:
                self._authorized_keys.setdefault(user.username, []).append(
                    session_data[auth_key]
                )
        if "router01_snmp_secret" in session_data:
            self._snmp_secret = str(session_data["router01_snmp_secret"])

    # ── behavior ────────────────────────────────────────────────────────

    def shell_prompt(self) -> bytes:
        return SHELL_PROMPT

    def shell_outputs(self, session_data: dict) -> dict[str, bytes]:
        secret = str(session_data.get("router01_snmp_secret", self._snmp_secret))
        running_config = (
            f"# router01 running configuration\r\n"
            f"hostname router01\r\n"
            f"domain logfileinc.internal\r\n"
            f"\r\n"
            f"interface eth0\r\n"
            f"  address 127.4.0.1/24\r\n"
            f"  enabled true\r\n"
            f"\r\n"
            f"interface eth1\r\n"
            f"  address 127.2.0.254/24\r\n"
            f"  enabled true\r\n"
            f"\r\n"
            f"route default via 127.4.0.254\r\n"
            f"\r\n"
            f"snmp community public access read-only\r\n"
            f"snmp community {secret} access read-write\r\n"
            f"\r\n"
            f"service ssh port 20022\r\n"
            f"service sftp enabled\r\n"
        ).encode()
        return {
            "help": _HELP_TEXT,
            "show version": (
                b"Device:   router01\r\n"
                b"Firmware: 3.7.2 (2024-03-01)\r\n"
                b"Uptime:   47 days 3 h 12 min\r\n"
            ),
            "show running-config": running_config,
            "show startup-config": running_config,
            "show ip route": (
                b"Destination       Gateway         Interface  Metric\r\n"
                b"0.0.0.0/0         127.4.0.254     eth0       10\r\n"
                b"127.2.0.0/24      directly        eth1        0\r\n"
                b"127.4.0.0/24      directly        eth0        0\r\n"
            ),
            "show interfaces": (
                b"eth0   up   127.4.0.1/24    rx:  4.2 GB  tx:  1.8 GB\r\n"
                b"eth1   up   127.2.0.254/24  rx:  8.7 GB  tx: 12.3 GB\r\n"
            ),
            "show users": (
                b"Session  User    Source          Since\r\n"
                b"ssh/0    twebb   127.1.0.1       09:14:32\r\n"
            ),
            "show logging": (
                b"2024-06-01 06:00:01  INFO   system started\r\n"
                b"2024-06-01 07:23:14  INFO   ssh login: twebb from 127.1.0.1\r\n"
                b"2024-06-01 09:14:32  INFO   ssh login: twebb from 127.1.0.1\r\n"
            ),
            "write memory": b"Saving configuration... done\r\n",
            "copy running-config tftp": b"TFTP server address: ",
            "reload": b"The system has unsaved changes. Save before reload? [y/n]: ",
            "ping 127.4.0.254": (
                b"PING 127.4.0.254: 5 packets, 0 lost\r\n"
                b"rtt min/avg/max = 0.4/0.6/0.9 ms\r\n"
            ),
            "ping 127.2.0.1": (
                b"PING 127.2.0.1: 5 packets, 0 lost\r\n"
                b"rtt min/avg/max = 0.8/1.1/1.4 ms\r\n"
            ),
            "traceroute 127.4.0.254": b" 1  127.4.0.254  0.9 ms\r\n",
        }

    def sftp_files(self, session_data: dict) -> dict[str, bytes]:
        secret = str(session_data.get("router01_snmp_secret", self._snmp_secret))
        config = (
            f"# router01 configuration\r\n"
            f"hostname router01\r\n"
            f"snmp community {secret} access read-write\r\n"
        ).encode()
        return {
            "running-config": config,
            "startup-config": config,
        }

    # ── lifecycle ────────────────────────────────────────────────────────

    async def start(self, events: asyncio.Queue) -> None:
        await super().start(events)

    async def stop(self) -> None:
        pass
