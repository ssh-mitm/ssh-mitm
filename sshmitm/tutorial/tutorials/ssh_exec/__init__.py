"""Tutorial: SSH Command Execution Interception."""

import random

from sshmitm.tutorial._client_actions import SSHExecAction
from sshmitm.tutorial._conditions import PortOpen, TRUE, UserInput
from sshmitm.tutorial._definitions import Step, Tutorial

_COMMAND_OUTPUTS: dict[str, bytes] = {
    "cat /home/developer/.aws/credentials": (
        b"[default]\n"
        b"aws_access_key_id=AKIAIOSFODNN7EXAMPLE\n"
        b"aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        b"region=eu-central-1\n"
    ),
    "cat /home/developer/.ssh/id_rsa": (
        b"-----BEGIN OPENSSH PRIVATE KEY-----\n"
        b"b3BlbnNzaC1rZXktdjEAAAAA[...key data truncated...]\n"
        b"-----END OPENSSH PRIVATE KEY-----\n"
    ),
    "cat /etc/shadow": (
        b"root:$6$rounds=5000$saltsalt$hashedpassword:19800:0:99999:7:::\n"
        b"developer:$6$rounds=5000$devSalt$devHashedPw:19800:0:99999:7:::\n"
        b"deploy:$6$rounds=5000$deploySalt$deployHash:19800:0:99999:7:::\n"
    ),
    "cat /var/secrets/database_password.txt": (
        b"postgres://deploy:Xk9#mP2@Lq7!nR4vTz@db.internal:5432/production\n"
    ),
    "env | grep -i api_key": (
        b"PAYCLOUD_API_KEY=pc_live_4eC39HqLyjWDarjtT1zdp7dc\n"
        b"QUICKMAIL_API_KEY=QM.xYz9-Abc3.DeF1gHiJkL2mNoPqRsTuVwXyZ\n"
        b"INTERNAL_API_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\n"
    ),
    "cat /root/.gnupg/secring.gpg": (
        b"\x99\x01\xff\x04\x00"  # GPG packet header bytes
        b"[Binary GPG secret key data - 2048-bit RSA]\n"
    ),
    "cat /home/developer/.netrc": (
        b"machine code.internal login developer password tok_xYzAbCdEfGhIjKlMnOp\n"
        b"machine registry.internal login deploy password D3pl0y$ecret!\n"
    ),
    "cat /etc/ssl/private/server.key": (
        b"-----BEGIN RSA PRIVATE KEY-----\n"
        b"MIIEpAIBAAKCAQEA2a2rwplBQLzHPZe5RJr9GpnBBkDPWMBXFHPnFBFv[...]\n"
        b"-----END RSA PRIVATE KEY-----\n"
    ),
}

_COMMANDS = list(_COMMAND_OUTPUTS)


class SSHExecTutorial(Tutorial):
    id          = "04-ssh-exec"
    title       = "SSH Command Execution Interception"
    category    = "Command Execution"
    description = "Learn how SSH-MITM intercepts commands executed non-interactively via ssh."
    tags = ["SSH Exec", "CI/CD"]
    docs = {
        "Logfile Inc. Assessment": "https://docs.ssh-mitm.at/get_started/scenario.html",
        "Terminal Sessions": "https://docs.ssh-mitm.at/user_guide/sessions.html",
    }
    lab_service_labels = {"mock_port": "web01.logfileinc.internal"}

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
            title="Find the executed command",
            condition=UserInput(
                "exec_command",
                prompt="Enter the command that was executed:",
            ),
            victim_action=SSHExecAction("exec_command"),
            hint_waiting="A developer is running a command through SSH-MITM. Check the terminal and enter the command above.",
            hint_done="Correct! You intercepted the command execution. ✓",
        ),
    ]

    def generate_tutorial_session_data(self) -> dict[str, object]:
        return {"exec_command": random.choice(_COMMANDS)}

    def generate_exec_outputs(self, session_data: dict[str, object]) -> dict[str, bytes]:
        command = str(session_data.get("exec_command", ""))
        output = _COMMAND_OUTPUTS.get(command)
        if output is None:
            return {}
        return {command: output}
