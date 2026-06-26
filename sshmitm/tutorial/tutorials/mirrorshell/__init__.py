"""Tutorial: SSH Session Mirroring (mirrorshell)."""

import secrets

from sshmitm.tutorial._client_actions import KeepAliveShellAction
from sshmitm.tutorial._conditions import PortOpen, TRUE, UserInput
from sshmitm.tutorial._definitions import Step, Tutorial
from sshmitm.tutorial._server_config import MockServerConfig, PublicKeyAuth, UserConfig

_PROMPT = b"router> "

_HELP = (
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


class MirrorshellTutorial(Tutorial):
    id          = "05-mirrorshell"
    title       = "SSH Session Mirroring"
    category    = "Session Interception"
    description = (
        "Learn how SSH-MITM mirrors a live shell session to the attacker, "
        "allowing command injection into an unattended terminal."
    )
    tags = ["Mirrorshell", "Session Hijacking"]
    docs = {
        "Logfile Inc. Assessment": "https://docs.ssh-mitm.at/get_started/scenario.html",
        "Terminal Sessions": "https://docs.ssh-mitm.at/user_guide/sessions.html",
    }
    lab_service_labels = {"mock_port": "router01.logfileinc.internal"}

    server = MockServerConfig(users=[UserConfig(auth=PublicKeyAuth())])

    steps = [
        Step(
            id="intro",
            title="What you will learn",
            condition=TRUE(),
            hint_done="Introduction read. ✓",
        ),
        Step(
            id="start-sshmitm",
            title="Start SSH-MITM",
            condition=PortOpen("sshmitm_port"),
            command=(
                "ssh-mitm server"
                " --remote-host 127.0.0.1"
                " --remote-port {mock_port}"
                " --listen-port {sshmitm_port}"
            ),
            hint_waiting="Waiting for SSH-MITM to start on port {sshmitm_port}…",
            hint_done="SSH-MITM is running on port {sshmitm_port}. ✓",
        ),
        Step(
            id="intercept",
            title="Connect to the mirrored session and find the SNMP secret",
            condition=UserInput(
                "found_secret",
                prompt="Enter the SNMP community string you found in the router config:",
            ),
            victim_action=KeepAliveShellAction(duration=600.0),
            hint_waiting=(
                "The network admin's session is open. "
                "Check the SSH-MITM terminal for the mirrorshell port and connect. "
                "The terminal may appear blank — type 'help' to get started."
            ),
            hint_done="Correct! You successfully extracted the SNMP community string. ✓",
        ),
    ]

    def shell_prompt(self) -> bytes:
        return _PROMPT

    def generate_tutorial_session_data(self) -> dict[str, object]:
        return {"found_secret": secrets.token_hex(8)}

    def generate_shell_outputs(self, session_data: dict[str, object]) -> dict[str, bytes]:
        secret = str(session_data.get("found_secret", ""))
        running_config = (
            f"# prod-router-01 running configuration\r\n"
            f"hostname prod-router-01\r\n"
            f"domain internal.example.com\r\n"
            f"\r\n"
            f"interface eth0\r\n"
            f"  address 10.0.0.1/24\r\n"
            f"  enabled true\r\n"
            f"\r\n"
            f"interface eth1\r\n"
            f"  address 192.168.1.1/24\r\n"
            f"  enabled true\r\n"
            f"\r\n"
            f"route default via 10.0.0.254\r\n"
            f"\r\n"
            f"snmp community public access read-only\r\n"
            f"snmp community {secret} access read-write\r\n"
            f"\r\n"
            f"service ssh port 22\r\n"
            f"service sftp enabled\r\n"
        ).encode()
        return {
            "help": _HELP,
            "show version": (
                b"Device:   prod-router-01\r\n"
                b"Firmware: 3.7.2 (2024-03-01)\r\n"
                b"Uptime:   47 days 3 h 12 min\r\n"
            ),
            "show running-config": running_config,
            "show startup-config": running_config,
            "show ip route": (
                b"Destination       Gateway         Interface  Metric\r\n"
                b"0.0.0.0/0         10.0.0.254      eth0       10\r\n"
                b"10.0.0.0/24       directly        eth0        0\r\n"
                b"192.168.1.0/24    directly        eth1        0\r\n"
            ),
            "show interfaces": (
                b"eth0   up   10.0.0.1/24      rx:  4.2 GB  tx:  1.8 GB\r\n"
                b"eth1   up   192.168.1.1/24   rx:  8.7 GB  tx: 12.3 GB\r\n"
            ),
            "show users": (
                b"Session  User   Source          Since\r\n"
                b"ssh/0    admin  10.0.0.50       09:14:32\r\n"
            ),
            "show logging": (
                b"2024-06-01 06:00:01  INFO   system started\r\n"
                b"2024-06-01 07:23:14  INFO   ssh login: admin from 10.0.0.50\r\n"
                b"2024-06-01 09:14:32  INFO   ssh login: admin from 10.0.0.50\r\n"
            ),
            "write memory": (
                b"Saving configuration... done\r\n"
            ),
            "copy running-config tftp": (
                b"TFTP server address: "
            ),
            "reload": (
                b"The system has unsaved changes. Save before reload? [y/n]: "
            ),
            "ping 10.0.0.254": (
                b"PING 10.0.0.254: 5 packets, 0 lost\r\n"
                b"rtt min/avg/max = 0.4/0.6/0.9 ms\r\n"
            ),
            "ping 192.168.1.254": (
                b"PING 192.168.1.254: 5 packets, 5 lost\r\n"
                b"Destination unreachable\r\n"
            ),
            "traceroute 10.0.0.254": (
                b" 1  10.0.0.254  0.9 ms\r\n"
            ),
        }

    def generate_sftp_files(self, session_data: dict[str, object]) -> dict[str, bytes]:
        secret = str(session_data.get("found_secret", ""))
        config = (
            f"# prod-router-01 configuration\r\n"
            f"hostname prod-router-01\r\n"
            f"snmp community {secret} access read-write\r\n"
        ).encode()
        return {
            "running-config": config,
            "startup-config": config,
        }
